#define OPEN_YAML_TO_JSON

#include <format>
#include <functional>
#include <regex>
#include <semaphore>
#include <string>

#include <stdio.h>
#include <stdlib.h>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <curl/curl.h>
#include <spdlog/spdlog.h>
#include <inja/inja.hpp>

#include "cfg.h"
#include "free_gpt.h"
#include "helper.hpp"

constexpr std::string_view ASSETS_PATH{"/assets"};
constexpr std::string_view API_PATH{"/backend-api/v2/conversation"};

using GptCallback = std::function<boost::asio::awaitable<void>(std::shared_ptr<FreeGpt::Channel>, nlohmann::json)>;
inline std::unordered_map<std::string, GptCallback> gpt_function;

#define ADD_METHOD(name, function) gpt_function[name] = std::bind_front(&function, app);

void setEnvironment(auto& cfg) {
    setenv("CURL_IMPERSONATE", "chrome110", 1);
    if (cfg.enable_proxy) {
        auto [lower_http_proxy, upper_http_proxy] = getEnv("http_proxy", "HTTP_PROXY");
        if (!lower_http_proxy.empty())
            cfg.http_proxy = std::move(lower_http_proxy);
        if (!upper_http_proxy.empty())
            cfg.http_proxy = std::move(upper_http_proxy);
    }
    if (auto [chat_path] = getEnv("CHAT_PATH"); !chat_path.empty()) {
        cfg.chat_path = std::move(chat_path);
    }
    if (cfg.chat_path.back() == '/')
        cfg.chat_path.pop_back();
    if (auto [port] = getEnv("PORT"); !port.empty())
        cfg.port = std::move(port);
    if (auto [host] = getEnv("HOST"); !host.empty())
        cfg.host = std::move(host);
    if (auto [work_thread_num] = getEnv("WORK_THREAD_NUM"); !work_thread_num.empty())
        cfg.work_thread_num = std::atol(work_thread_num.c_str());
    if (auto [providers] = getEnv("PROVIDERS"); !providers.empty()) {
        nlohmann::json providers_list = nlohmann::json::parse(providers, nullptr, false);
        if (!providers_list.is_discarded())
            cfg.providers = providers_list.get<std::vector<std::string>>();
    }
    if (auto [api_key] = getEnv("API_KEY"); !api_key.empty())
        cfg.api_key = std::move(api_key);
    if (auto [interval] = getEnv("INTERVAL"); !interval.empty())
        cfg.interval = std::atol(interval.c_str());
    // export IP_WHITE_LIST="[\"127.0.0.1\",\"192.168.1.1\"]"
    if (auto [ip_white_list_str] = getEnv("IP_WHITE_LIST"); !ip_white_list_str.empty()) {
        nlohmann::json ip_white_list = nlohmann::json::parse(ip_white_list_str, nullptr, false);
        if (!ip_white_list.is_discarded())
            cfg.ip_white_list = ip_white_list.get<std::vector<std::string>>();
    }
    if (auto [zeus] = getEnv("ZEUS"); !zeus.empty())
        cfg.zeus = std::move(zeus);
    if (auto [flaresolverr] = getEnv("FLARESOLVERR"); !flaresolverr.empty())
        cfg.flaresolverr = std::move(flaresolverr);
}

std::string createIndexHtml(const std::string& file, const Config& cfg) {
    inja::Environment env;
    nlohmann::json data;
    data["chat_id"] = createUuidString();
    data["chat_path"] = cfg.chat_path;
    if (!cfg.providers.empty()) {
        data["model_list"] = cfg.providers;
    } else {
        for (auto&& m : std::views::keys(gpt_function))
            data["model_list"].emplace_back(m);
    }
    return env.render_file(file, data);
}

boost::asio::awaitable<void> sendHttpResponse(auto& stream, auto& request, auto status) {
    boost::beast::http::response<boost::beast::http::string_body> res{status, request.version()};
    res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(boost::beast::http::field::content_type, "text/html");
    res.keep_alive(request.keep_alive());
    res.prepare_payload();
    boost::beast::http::message_generator rsp = std::move(res);
    co_await boost::beast::async_write(stream, std::move(rsp), use_nothrow_awaitable);
    co_return;
}

void setContentType(auto& res, const std::string& file) {
    SPDLOG_INFO("file: {}", file);
    if (file.ends_with("js")) {
        res.set(boost::beast::http::field::content_type, "text/javascript");
    } else if (file.ends_with("css")) {
        res.set(boost::beast::http::field::content_type, "text/css");
    } else if (file.ends_with("png")) {
        res.set(boost::beast::http::field::content_type, "image/png");
    } else
        SPDLOG_ERROR("invalid file type: {}", file);
}

boost::asio::awaitable<void> startSession(boost::asio::ip::tcp::socket sock, Config& cfg,
                                          boost::asio::io_context& context) {
    boost::beast::tcp_stream stream{std::move(sock)};
    using namespace boost::asio::experimental::awaitable_operators;
    ScopeExit auto_exit{[&stream] {
        boost::beast::error_code ec;
        stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    }};
    boost::beast::error_code ec{};
    boost::asio::ip::tcp::endpoint endpoint = boost::beast::get_lowest_layer(stream).socket().remote_endpoint(ec);
    if (ec) {
        SPDLOG_ERROR("get remote_endpoint error: {}", ec.message());
        co_return;
    }
    std::string remote_ip{endpoint.address().to_string()};
    if (!cfg.ip_white_list.empty() && std::ranges::find(cfg.ip_white_list, remote_ip) == cfg.ip_white_list.end()) {
        SPDLOG_INFO("[{}] not in ip white list.", remote_ip);
        boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::unauthorized,
                                                                          11};
        res.set(boost::beast::http::field::server, "CppFreeGpt");
        res.body() = "Invalid IP address";
        res.prepare_payload();
        boost::beast::http::message_generator rsp = std::move(res);
        co_await boost::beast::async_write(stream, std::move(rsp), use_nothrow_awaitable);
        co_return;
    }
    auto assets_path = std::format("{}{}", cfg.chat_path, ASSETS_PATH);
    auto api_path = std::format("{}{}", cfg.chat_path, API_PATH);
    SPDLOG_INFO("assets_path: [{}], api_path: [{}]", assets_path, api_path);
    while (true) {
        boost::beast::flat_buffer buffer;
        boost::beast::http::request<boost::beast::http::string_body> request;
        auto result = co_await (boost::beast::http::async_read(stream, buffer, request, use_nothrow_awaitable) ||
                                timeout(std::chrono::seconds(cfg.interval)));
        if (result.index() == 1) {
            SPDLOG_INFO("read timeout");
            co_return;
        }
        auto [ec, bytes_transferred] = std::get<0>(result);
        if (ec) {
            SPDLOG_INFO("async_read: {}", ec.message());
            co_return;
        }
        bool keep_alive = request.keep_alive();
        auto http_path = request.target();
        if (http_path.back() == '/')
            http_path.remove_suffix(1);
        if (http_path == cfg.chat_path) {
            auto html = createIndexHtml(std::format("{}/html/index.html", cfg.client_root_path), cfg);
            boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::ok,
                                                                              request.version()};
            res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(boost::beast::http::field::content_type, "text/html");
            res.keep_alive(request.keep_alive());
            res.body() = std::move(html);
            res.prepare_payload();
            boost::beast::http::message_generator rsp = std::move(res);
            co_await boost::beast::async_write(stream, std::move(rsp), use_nothrow_awaitable);
        } else if (request.target().starts_with(assets_path)) {
            std::string req_path{request.target()};
            SPDLOG_INFO("req_path: {}", req_path);
            req_path.erase(req_path.find(assets_path), assets_path.length());
            auto file = std::format("{}{}", cfg.client_root_path, req_path);
            SPDLOG_INFO("load: {}", file);
            if (file.contains("chat.js") || file.contains("site.webmanifest")) {
                inja::Environment env;
                nlohmann::json data;
                if (file.contains("chat.js")) {
                    auto format_string = [](const std::string& str) {
                        std::regex pattern("/");
                        std::string replacement = "\\/";
                        return std::regex_replace(str, pattern, replacement);
                    };
                    data["chat_path"] = format_string(cfg.chat_path);
                    data["api_path"] = cfg.chat_path;
                } else {
                    data["chat_path"] = cfg.chat_path;
                }
                auto chat_js_content = env.render_file(file, data);
                boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::ok,
                                                                                  request.version()};
                res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
                setContentType(res, file);
                res.keep_alive(request.keep_alive());
                res.body() = std::move(chat_js_content);
                res.prepare_payload();
                boost::beast::http::message_generator rsp = std::move(res);
                co_await boost::beast::async_write(stream, std::move(rsp), use_nothrow_awaitable);
            } else {
                boost::beast::error_code ec;
                boost::beast::http::file_body::value_type body;
                body.open(file.c_str(), boost::beast::file_mode::scan, ec);
                if (ec == boost::beast::errc::no_such_file_or_directory) {
                    co_await sendHttpResponse(stream, request, boost::beast::http::status::not_found);
                    co_return;
                }
                auto const size = body.size();
                boost::beast::http::response<boost::beast::http::file_body> res{
                    std::piecewise_construct, std::make_tuple(std::move(body)),
                    std::make_tuple(boost::beast::http::status::ok, request.version())};
                res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
                setContentType(res, file);
                res.content_length(size);
                res.keep_alive(request.keep_alive());
                boost::beast::http::message_generator rsp = std::move(res);
                co_await boost::beast::async_write(stream, std::move(rsp), use_nothrow_awaitable);
            }
        } else if (request.target() == api_path) {
            std::string model;
            nlohmann::json request_body;
            bool flag = false;
            try {
                request_body = nlohmann::json::parse(request.body());
                model = request_body.at("model");
                auto prompt = request_body.at("meta").at("content").at("parts").at(0).at("content");
                auto conversation = request_body.at("meta").at("content").at("conversation");
            } catch (const nlohmann::json::exception& e) {
                SPDLOG_ERROR("nlohmann json: [{}], [{}]", e.what(), request.body());
                flag = true;
            }
            if (flag) {
                co_await sendHttpResponse(stream, request, boost::beast::http::status::bad_request);
                co_return;
            }

            boost::beast::http::response<boost::beast::http::buffer_body> res;
            res.result(boost::beast::http::status::ok);
            res.version(request.version());
            res.set(boost::beast::http::field::server, "CppFreeGpt");
            res.set(boost::beast::http::field::transfer_encoding, "chunked");
            res.set(boost::beast::http::field::content_type, "text/event-stream");
            res.body().data = nullptr;
            res.body().more = true;

            boost::beast::http::response_serializer<boost::beast::http::buffer_body, boost::beast::http::fields> sr{
                res};
            auto [ec, count] = co_await boost::beast::http::async_write_header(stream, sr, use_nothrow_awaitable);
            if (ec) {
                SPDLOG_ERROR("{}", ec.message());
                co_return;
            }
            if (!gpt_function.contains(model)) {
                SPDLOG_ERROR("Invalid request model: {}", model);
                static std::string reject{"Invalid request model"};
                res.body().data = reject.data();
                res.body().size = reject.size();
                res.body().more = false;
                std::tie(ec, count) = co_await boost::beast::http::async_write(stream, sr, use_nothrow_awaitable);
                co_return;
            }
            auto ch = std::make_shared<FreeGpt::Channel>(co_await boost::asio::this_coro::executor, 4096);

            boost::asio::co_spawn(
                context,
                [](auto ch, auto model, auto request_body) -> boost::asio::awaitable<void> {
                    auto& func = gpt_function[model];
                    co_await func(std::move(ch), std::move(request_body));
                    co_return;
                }(ch, std::move(model), std::move(request_body)),
                [](std::exception_ptr eptr) {
                    try {
                        if (eptr)
                            std::rethrow_exception(eptr);
                    } catch (const std::exception& e) {
                        SPDLOG_ERROR("Caught exception: {}", e.what());
                    }
                });

            while (true) {
                auto [ec, str] = co_await ch->async_receive(use_nothrow_awaitable);
                if (ec) {
                    break;
                }
                res.body().data = str.data();
                res.body().size = str.size();
                res.body().more = true;
                std::tie(ec, count) = co_await boost::beast::http::async_write(stream, sr, use_nothrow_awaitable);
            }
            res.body().data = nullptr;
            res.body().more = false;
            std::tie(ec, count) = co_await boost::beast::http::async_write(stream, sr, use_nothrow_awaitable);
        } else {
            SPDLOG_ERROR("bad_request: [{}], Expected path is: [{}]", request.target(), cfg.chat_path);
            co_await sendHttpResponse(stream, request, boost::beast::http::status::bad_request);
            co_return;
        }
        if (!keep_alive)
            co_return;
    }
    co_return;
}

boost::asio::awaitable<void> doSession(boost::asio::ip::tcp::acceptor& acceptor, IoContextPool& pool, Config& cfg) {
    for (;;) {
        auto& context = pool.getIoContext();
        boost::asio::ip::tcp::socket socket(context);
        auto [ec] = co_await acceptor.async_accept(socket, use_nothrow_awaitable);
        if (ec) {
            if (ec == boost::asio::error::operation_aborted)
                break;
            SPDLOG_ERROR("Accept failed, error: {}", ec.message());
            continue;
        }
        boost::asio::co_spawn(context, startSession(std::move(socket), cfg, context), boost::asio::detached);
    }
    co_return;
}

int main(int, char** argv) {
    curl_global_init(CURL_GLOBAL_ALL);
    ScopeExit cleanup{[=] { curl_global_cleanup(); }};

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e][thread %t][%!][%s:%#][%l] %v");
    auto [config, error] = yaml_cpp_struct::from_yaml<Config>(argv[1]);
    if (!config) {
        SPDLOG_ERROR("{}", error);
        return EXIT_FAILURE;
    }
    auto& cfg = config.value();

    setEnvironment(cfg);
    auto [yaml_cfg_str, _] = yaml_cpp_struct::to_yaml(cfg);

    FreeGpt app{cfg};

    if (!cfg.api_key.empty())
        ADD_METHOD("gpt-3.5-turbo-stream-openai", FreeGpt::openAi);

    ADD_METHOD("gpt-3.5-turbo-stream-yqcloud", FreeGpt::yqcloud);
    ADD_METHOD("gpt-OpenAssistant-stream-HuggingChat", FreeGpt::huggingChat)
    ADD_METHOD("gpt-4-turbo-stream-you", FreeGpt::you);
    ADD_METHOD("gpt-3-stream-binjie", FreeGpt::binjie);
    ADD_METHOD("gpt-3.5-turbo-stream-GptGo", FreeGpt::gptGo);
    ADD_METHOD("gpt-3.5-turbo-stream-gptalk", FreeGpt::gptalk);
    ADD_METHOD("gpt-3.5-turbo-stream-ChatForAi", FreeGpt::chatForAi);
    ADD_METHOD("gpt-3.5-turbo-stream-gptforlove", FreeGpt::gptForLove);
    ADD_METHOD("gpt-3.5-turbo-stream-ChatgptDemo", FreeGpt::chatGptDemo);
    ADD_METHOD("gpt-3.5-turbo-stream-GeekGpt", FreeGpt::geekGpt);
    ADD_METHOD("llama2", FreeGpt::llama2);
    ADD_METHOD("gpt-3.5-turbo-stream-chatGptAi", FreeGpt::chatGptAi);
    ADD_METHOD("gpt-3.5-turbo-stream-FakeGpt", FreeGpt::fakeGpt);
    ADD_METHOD("gpt-3.5-turbo-stream-Vercel", FreeGpt::vercel);
    ADD_METHOD("gpt-3.5-turbo-stream-aivvm", FreeGpt::aivvm);
    ADD_METHOD("gpt-4-stream-aivvm", FreeGpt::aivvm);
    ADD_METHOD("gpt-4-ChatGpt4Online", FreeGpt::chatGpt4Online);
    ADD_METHOD("gpt-3.5-turbo-stream-ChatAnywhere", FreeGpt::chatAnywhere);
    ADD_METHOD("gpt-3.5-turbo-ChatgptNext", FreeGpt::chatGptNext);
    ADD_METHOD("gpt-3.5-turbo-stream-gptTalkRu", FreeGpt::gptTalkru);
    ADD_METHOD("Llama-2-70b-chat-hf-stream-DeepInfra", FreeGpt::deepInfra);

    SPDLOG_INFO("active provider:");
    for (auto& [provider, _] : gpt_function)
        SPDLOG_INFO("      {}", provider);

    SPDLOG_INFO("\n{}", yaml_cpp_struct::yaml_to_json(yaml_cfg_str.value()).dump(2));
    std::cout << "\033[32m"
              << "GitHub: https://github.com/fantasy-peak/cpp-freegpt-webui"
              << "\033[0m" << std::endl;

    IoContextPool pool{cfg.work_thread_num};
    pool.start();
    IoContextPool accept_pool{1};
    accept_pool.start();
    auto& context = accept_pool.getIoContext();
    boost::asio::ip::tcp::acceptor acceptor(context);

    boost::asio::ip::tcp::resolver resolver(context);
    boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(cfg.host, cfg.port).begin();

    acceptor.open(endpoint.protocol());
    boost::system::error_code ec;

    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor.bind(endpoint);
    SPDLOG_INFO("server start accept at {}:{} ...", endpoint.address().to_string(), cfg.port);
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        return EXIT_FAILURE;
    }
    boost::asio::co_spawn(context, doSession(acceptor, pool, cfg), boost::asio::detached);
    boost::asio::signal_set sigset(context, SIGINT, SIGTERM);
    std::binary_semaphore smph_signal_main_to_thread{0};
    sigset.async_wait([&](const boost::system::error_code&, int) {
        acceptor.close();
        smph_signal_main_to_thread.release();
    });
    smph_signal_main_to_thread.acquire();
    SPDLOG_INFO("stoped ...");
    accept_pool.stop();
    pool.stop();
    return EXIT_SUCCESS;
}
