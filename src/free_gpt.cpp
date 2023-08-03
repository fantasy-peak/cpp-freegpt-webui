#include <chrono>
#include <iostream>
#include <random>
#include <ranges>
#include <regex>

#include <fmt/chrono.h>
#include <openssl/md5.h>
#include <spdlog/spdlog.h>
#include <boost/asio/as_tuple.hpp>
#include <boost/scope_exit.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <plusaes/plusaes.hpp>
#include <tl/expected.hpp>

#include "free_gpt.h"

constexpr auto use_nothrow_awaitable = boost::asio::as_tuple(boost::asio::use_awaitable);

namespace {

namespace detail {

template <typename C>
struct to_helper {};

template <typename Container, std::ranges::range R>
    requires std::convertible_to<std::ranges::range_value_t<R>, typename Container::value_type>
Container operator|(R&& r, to_helper<Container>) {
    return Container{r.begin(), r.end()};
}

}  // namespace detail

template <std::ranges::range Container>
    requires(!std::ranges::view<Container>)
inline auto to() {
    return detail::to_helper<Container>{};
}

std::string md5(const std::string& str, bool reverse = true) {
    unsigned char hash[MD5_DIGEST_LENGTH];

    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str.c_str(), str.size());
    MD5_Final(hash, &md5);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    auto md5_str = ss.str();
    if (reverse)
        std::ranges::reverse(md5_str);
    return md5_str;
}

boost::asio::awaitable<tl::expected<boost::beast::ssl_stream<boost::beast::tcp_stream>, std::string>> createHttpClient(
    boost::asio::ssl::context& ctx, std::string_view host, std::string_view port) {
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream_{co_await boost::asio::this_coro::executor, ctx};
    boost::system::error_code err{};
    if (!SSL_set_tlsext_host_name(stream_.native_handle(), host.data())) {
        SPDLOG_ERROR("SSL_set_tlsext_host_name");
        co_return tl::make_unexpected(std::string("SSL_set_tlsext_host_name"));
    }
    auto resolver = boost::asio::ip::tcp::resolver(co_await boost::asio::this_coro::executor);
    auto [ec, results] = co_await resolver.async_resolve(host.data(), port.data(), use_nothrow_awaitable);
    if (ec) {
        SPDLOG_INFO("async_resolve: {}", ec.message());
        co_return tl::make_unexpected(ec.message());
    }
    for (auto& endpoint : results) {
        std::stringstream ss;
        ss << endpoint.endpoint();
        SPDLOG_INFO("resolver_results: [{}]", ss.str());
    }
    boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
    if (auto [ec, _] = co_await boost::beast::get_lowest_layer(stream_).async_connect(results, use_nothrow_awaitable);
        ec) {
        co_return tl::make_unexpected(ec.message());
    }
    boost::beast::get_lowest_layer(stream_).expires_never();
    std::tie(ec) = co_await stream_.async_handshake(boost::asio::ssl::stream_base::client, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_INFO("async_handshake: {}", ec.message());
        co_return tl::make_unexpected(ec.message());
    }
    co_return stream_;
}

std::string generateHexStr(int length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < length; i++)
        ss << std::nouppercase << std::setw(1) << std::setfill('0') << dis(gen);
    return ss.str();
}

std::string encrypt(const std::string& raw_data) {
    auto random_key_str = generateHexStr(16);
    auto random_iv_str = generateHexStr(16);
    char key_buffer[17]{};
    memcpy(key_buffer, random_key_str.c_str(), random_key_str.size());
    std::vector<unsigned char> key = plusaes::key_from_string(&key_buffer);  // 16-char = 128-bit
    unsigned char iv[16]{};
    memcpy(iv, random_iv_str.data(), 16);
    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);
    plusaes::encrypt_cbc((unsigned char*)raw_data.data(), raw_data.size(), &key[0], key.size(), &iv, &encrypted[0],
                         encrypted.size(), true);
    std::stringstream ss;
    std::transform(encrypted.begin(), encrypted.end(), std::ostream_iterator<std::string>(ss),
                   [](unsigned char c) -> std::string { return fmt::format("{:02x}", int(c)); });
    return ss.str() + random_key_str + random_iv_str;
}

auto splitString(const std::string& input, const std::string& delimiter) {
    std::vector<std::string> fields;
    std::string::size_type start = 0;
    std::string::size_type end = input.find(delimiter);

    while (end != std::string::npos) {
        fields.emplace_back(input.substr(start, end - start));
        start = end + delimiter.size();
        end = input.find(delimiter, start);
    }

    fields.emplace_back(input.substr(start));
    return fields;
}

std::vector<std::string> findAll(const std::string& pattern, const std::string& text) {
    std::regex re(pattern);
    std::sregex_iterator it(text.begin(), text.end(), re);
    std::sregex_iterator end;
    std::vector<std::string> matches;
    while (it != end) {
        matches.push_back(it->str());
        ++it;
    }
    return matches;
}

std::string charToHex(char c) {
    std::string result;
    char first, second;

    first = (c & 0xF0) / 16;
    first += first > 9 ? 'A' - 10 : '0';
    second = c & 0x0F;
    second += second > 9 ? 'A' - 10 : '0';

    result.append(1, first);
    result.append(1, second);

    return result;
}

std::string urlEncode(const std::string& src) {
    std::string result;
    std::string::const_iterator iter;

    for (iter = src.begin(); iter != src.end(); ++iter) {
        switch (*iter) {
            case ' ':
                result.append(1, '+');
                break;
            // alnum
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
            case 'G':
            case 'H':
            case 'I':
            case 'J':
            case 'K':
            case 'L':
            case 'M':
            case 'N':
            case 'O':
            case 'P':
            case 'Q':
            case 'R':
            case 'S':
            case 'T':
            case 'U':
            case 'V':
            case 'W':
            case 'X':
            case 'Y':
            case 'Z':
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
            case 'g':
            case 'h':
            case 'i':
            case 'j':
            case 'k':
            case 'l':
            case 'm':
            case 'n':
            case 'o':
            case 'p':
            case 'q':
            case 'r':
            case 's':
            case 't':
            case 'u':
            case 'v':
            case 'w':
            case 'x':
            case 'y':
            case 'z':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            // mark
            case '-':
            case '_':
            case '.':
            case '!':
            case '~':
            case '*':
            case '\'':
            case '(':
            case ')':
            case '&':
            case '=':
            case '/':
            case '\\':
            case '?':
                result.append(1, *iter);
                break;
            // escape
            default:
                result.append(1, '%');
                result.append(charToHex(*iter));
                break;
        }
    }

    return result;
}

enum class Status : uint8_t {
    Ok,
    Close,
    HasError,
};

boost::asio::awaitable<Status> sendRecvChunk(auto& ch, auto& stream_, auto& req, int http_code,
                                             std::function<void(std::string)> cb) {
    boost::system::error_code err{};
    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return Status::HasError;
    }

    boost::beast::flat_buffer buffer;
    boost::beast::http::parser<false, boost::beast::http::empty_body> p;
    std::tie(ec, count) = co_await boost::beast::http::async_read_header(stream_, buffer, p, use_nothrow_awaitable);
    if (ec == boost::beast::http::error::end_of_stream) {
        SPDLOG_INFO("server close!!!");
        co_return Status::Close;
    }
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return Status::HasError;
    }

    auto& headers = p.get();
    std::stringstream ss;
    ss << headers.base();
    SPDLOG_INFO("{}", ss.str());
    // boost::beast::http::status result = headers.result();
    int result_int = headers.result_int();
    SPDLOG_INFO("code: {}", result_int);
    if (result_int != http_code) {
        SPDLOG_ERROR("reason: {}", headers.reason().data());
        co_await ch->async_send(err, std::string{headers.reason()}, use_nothrow_awaitable);
        co_return Status::HasError;
    }

    boost::beast::http::chunk_extensions ce;
    std::string chunk;

    auto header_cb = [&](std::uint64_t size, std::string_view extensions, boost::beast::error_code& ev) {
        ce.parse(extensions, ev);
        if (ev)
            return;
        if (size > (std::numeric_limits<std::size_t>::max)()) {
            ev = boost::beast::http::error::body_limit;
            return;
        }
        chunk.reserve(static_cast<std::size_t>(size));
        chunk.clear();
    };
    p.on_chunk_header(header_cb);

    auto body_cb = [&](std::uint64_t remain, std::string_view body, boost::beast::error_code& ec) {
        if (remain == body.size())
            ec = boost::beast::http::error::end_of_chunk;
        chunk.append(body.data(), body.size());

        std::string chunk_str{body};
        cb(std::move(chunk_str));
        return body.size();
    };
    p.on_chunk_body(body_cb);

    while (!p.is_done()) {
        std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, buffer, p, use_nothrow_awaitable);
        if (!ec)
            continue;
        else if (ec != boost::beast::http::error::end_of_chunk) {
            co_return Status::HasError;
        } else
            ec = {};
    }
    co_return Status::Ok;
}

}  // namespace

FreeGpt::FreeGpt(Config& cfg) : m_cfg(cfg) {}

boost::asio::awaitable<void> FreeGpt::getGpt(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    constexpr std::string_view host{"chat.getgpt.world"};
    constexpr std::string_view port{"443"};

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/chat/stream", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36");
    req.set("Referer", "https://chat.getgpt.world/");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("Accept", "*/*");
    req.set("Accept-Encoding", "gzip, deflate");

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();
    boost::uuids::random_generator gen;
    nlohmann::json request_json{{{"role", "user"}, {"content", std::move(prompt)}}};
    nlohmann::json data{
        {"messages", std::move(request_json)},
        {"frequency_penalty", 0},
        {"max_tokens", 4000},
        {"model", "gpt-3.5-turbo"},
        {"presence_penalty", 0},
        {"temperature", 1},
        {"top_p", 1},
        {"stream", true},
        {"uuid", boost::uuids::to_string(gen())},
    };

    nlohmann::json request;
    request["signature"] = encrypt(data.dump());
    req.body() = request.dump();
    req.prepare_payload();
    std::stringstream ss;
    ss << req;
    SPDLOG_INFO("request:\n{}", ss.str());

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    std::string recv;
    auto ret = co_await sendRecvChunk(ch, stream_, req, 201, [&ch, &recv](std::string chunk_str) {
        recv.append(chunk_str);
        while (true) {
            auto position = recv.find("\n");
            if (position == std::string::npos)
                break;
            auto msg = recv.substr(0, position + 1);
            recv.erase(0, position + 1);
            msg.pop_back();
            if (msg.empty() || !msg.contains("content"))
                continue;
            auto fields = splitString(msg, "data: ");
            boost::system::error_code err{};
            nlohmann::json line_json = nlohmann::json::parse(fields.back(), nullptr, false);
            if (line_json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", fields.back());
                ch->try_send(err, fmt::format("json parse error: [{}]", fields.back()));
                continue;
            }
            auto str = line_json["choices"][0]["delta"]["content"].get<std::string>();
            if (!str.empty())
                ch->try_send(err, str);
        }
    });
    if (ret == Status::Close && recreate_num == 0) {
        recreate_num++;
        goto create_client;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::deepAi(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    std::string user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)"};
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<uint64_t> dist(0, 100000000);
    uint64_t part1{dist(mt)};
    auto part2 = md5(user_agent + md5(user_agent + md5(fmt::format("{}{}x", user_agent, part1))));
    auto api_key = fmt::format("tryit-{}-{}", part1, part2);

    constexpr char CRLF[] = "\r\n";
    constexpr char MULTI_PART_BOUNDARY[] = "9bc627aea4f77e150e6057f78036e73f";
    constexpr std::string_view host{"api.deepai.org"};
    constexpr std::string_view port{"443"};

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, "/make_me_a_pizza",
                                                                     11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Api-Key", api_key);
    req.set(boost::beast::http::field::content_type,
            fmt::format("multipart/form-data; boundary={}", MULTI_PART_BOUNDARY));

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();
    nlohmann::json request_json{{{"role", "user"}, {"content", std::move(prompt)}}};

    std::ostringstream payload;
    payload << "--" << MULTI_PART_BOUNDARY << CRLF << R"(Content-Disposition: form-data; name="chat_style")" << CRLF
            << CRLF << "chat" << CRLF << "--" << MULTI_PART_BOUNDARY << CRLF
            << R"(Content-Disposition: form-data; name="chatHistory")" << CRLF << CRLF << request_json.dump() << CRLF
            << "--" << MULTI_PART_BOUNDARY << "--" << CRLF;

    SPDLOG_INFO("{}", payload.str());
    req.body() = payload.str();
    req.prepare_payload();

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto ret = co_await sendRecvChunk(ch, stream_, req, 200, [&ch](std::string recv_str) {
        boost::system::error_code ec{};
        ch->try_send(ec, recv_str);
    });
    if (ret == Status::Close && recreate_num == 0) {
        recreate_num++;
        goto create_client;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aiTianhu(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "www.aitianhu.com";
    constexpr std::string_view port = "443";

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/chat-process", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(
        boost::beast::http::field::user_agent,
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)");
    req.set(boost::beast::http::field::content_type, "application/json");
    nlohmann::json data{
        {"prompt", fmt::format("user: {}\nassistant:", prompt)},
        {"options", std::unordered_map<std::string, std::string>{}},
        {"systemMessage",
         "You are ChatGPT, a large language model trained by OpenAI. Follow "
         "the user's instructions carefully. Respond using markdown."},
        {"temperature", 0.8},
        {"top_p", 1},
    };
    req.body() = data.dump();
    req.prepare_payload();

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    boost::beast::flat_buffer b;
    boost::beast::http::response<boost::beast::http::string_body> res;
    std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
    if (ec == boost::beast::http::error::end_of_stream) {
        if (recreate_num == 0) {
            recreate_num++;
            goto create_client;
        }
    }
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http code: {}", res.result_int());
        co_await ch->async_send(err, res.reason(), use_nothrow_awaitable);
        co_return;
    }
    auto lines = res.body() | std::views::split('\n') | std::views::transform([](auto&& rng) {
                     return std::string_view(&*rng.begin(), std::ranges::distance(rng.begin(), rng.end()));
                 }) |
                 to<std::vector<std::string_view>>();
    if (lines.empty()) {
        SPDLOG_ERROR("lines empty");
        co_return;
    }
    nlohmann::json rsp = nlohmann::json::parse(lines.back(), nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, fmt::format("json parse error: {}", lines.back()), use_nothrow_awaitable);
        co_return;
    }
    co_await ch->async_send(err, rsp.value("text", rsp.dump()), use_nothrow_awaitable);
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aiChat(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "chat-gpt.org";
    constexpr std::string_view port = "443";

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, "/api/text", 11};
    req.set(boost::beast::http::field::host, host);
    req.set("authority", "chat-gpt.org");
    req.set("accept", "*/*");
    req.set("cache-control", "no-cache");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set(boost::beast::http::field::origin, "https://chat-gpt.org");
    req.set("pragma", "no-cache");
    req.set(boost::beast::http::field::referer, "https://chat-gpt.org/chat");
    req.set("sec-ch-ua-mobile", "?0");
    req.set("sec-ch-ua-platform", R"("macOS")");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");
    req.set(
        boost::beast::http::field::user_agent,
        R"(Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36)");

    nlohmann::json data{
        {"message", fmt::format("user: {}\nassistant:", prompt)},
        {"temperature", 1},
        {"presence_penalty", 0},
        {"top_p", 1},
        {"frequency_penalty", 0},
    };
    req.body() = data.dump();
    req.prepare_payload();

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    boost::beast::flat_buffer b;
    boost::beast::http::response<boost::beast::http::string_body> res;
    std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
    if (ec == boost::beast::http::error::end_of_stream) {
        if (recreate_num == 0) {
            recreate_num++;
            goto create_client;
        }
    }
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http code: {}", res.result_int());
        co_await ch->async_send(err, res.reason(), use_nothrow_awaitable);
        co_return;
    }
    nlohmann::json rsp = nlohmann::json::parse(res.body(), nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, "json parse error", use_nothrow_awaitable);
        co_return;
    }
    SPDLOG_INFO("rsp: {}", rsp.dump());
    co_await ch->async_send(err, rsp.value("message", rsp.dump()), use_nothrow_awaitable);
    co_return;
}

boost::asio::awaitable<void> FreeGpt::chatGptAi(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    constexpr std::string_view host = "chatgpt.ai";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)"};

    boost::beast::http::request<boost::beast::http::empty_body> req{boost::beast::http::verb::get, "/", 11};
    req.set(boost::beast::http::field::host, "chatgpt.ai");
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "*/*");

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    std::string chunk_body;
    auto ret = co_await sendRecvChunk(
        ch, stream_, req, 200, [&ch, &chunk_body](std::string recv_str) { chunk_body.append(std::move(recv_str)); });
    if (ret == Status::Close && recreate_num == 0) {
        recreate_num++;
        goto create_client;
    }
    if (ret == Status::HasError)
        co_return;

    static std::string pattern{
        R"(data-nonce=".*"\n     data-post-id=".*"\n     data-url=".*"\n     data-bot-id=".*"\n     data-width)"};

    std::vector<std::string> matches = findAll(pattern, chunk_body);
    if (matches.size() != 1) {
        SPDLOG_ERROR("parsing login failed");
        co_await ch->async_send(err, chunk_body, use_nothrow_awaitable);
        co_return;
    }

    std::regex reg("\"([^\"]*)\"");
    std::sregex_iterator iter(matches[0].begin(), matches[0].end(), reg);
    std::sregex_iterator end;
    std::vector<std::string> results;
    while (iter != end) {
        results.emplace_back(iter->str(1));
        iter++;
    }
    if (results.size() != 4) {
        SPDLOG_ERROR("Failed to extract content");
        co_await ch->async_send(err, "Failed to extract content", use_nothrow_awaitable);
        co_return;
    }

    auto& nonce = results[0];
    auto& post_id = results[1];
    auto& data_url = results[2];
    auto& bot_id = results[3];

    SPDLOG_INFO("data_nonce: {}", nonce);
    SPDLOG_INFO("data_post_id: {}", post_id);
    SPDLOG_INFO("data_url: {}", data_url);
    SPDLOG_INFO("data_bot_id: {}", bot_id);

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    boost::beast::http::request<boost::beast::http::string_body> request{boost::beast::http::verb::post,
                                                                         "/wp-admin/admin-ajax.php", 11};
    request.set(boost::beast::http::field::host, host);
    request.set("authority", "chatgpt.ai");
    request.set("accept", "*/*");
    request.set("accept-language", R"(en,fr-FR;q=0.9,fr;q=0.8,es-ES;q=0.7,es;q=0.6,en-US;q=0.5,am;q=0.4,de;q=0.3)");
    request.set("cache-control", "no-cache");
    request.set("origin", "https://chatgpt.ai");
    request.set("pragma", "no-cache");
    request.set(boost::beast::http::field::referer, "https://chatgpt.ai/gpt-4/");
    request.set("sec-ch-ua", R"("Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114")");
    request.set("sec-ch-ua-mobile", "?0");
    request.set("sec-ch-ua-platform", R"("Windows")");
    request.set("sec-fetch-dest", "empty");
    request.set("sec-fetch-mode", "cors");
    request.set("sec-fetch-site", "same-origin");
    request.set(boost::beast::http::field::user_agent, user_agent);
    request.set("Content-Type", "application/x-www-form-urlencoded");

    std::stringstream ss;
    ss << "message=" << urlEncode(fmt::format("user: {}\nassistant: ", prompt)) << "&";
    ss << "_wpnonce=" << nonce << "&";
    ss << "post_id=" << post_id << "&";
    ss << "url=" << urlEncode("https://chatgpt.ai/gpt-4") << "&";
    ss << "action=wpaicg_chat_shortcode_message&";
    ss << "bot_id=" << bot_id;

    SPDLOG_INFO("request: {}", ss.str());
    request.body() = ss.str();
    request.prepare_payload();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, request, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    boost::beast::flat_buffer buffer;
    boost::beast::http::response<boost::beast::http::string_body> response;
    std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, buffer, response, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    if (boost::beast::http::status::ok != response.result()) {
        SPDLOG_ERROR("http code: {}", response.result_int());
        co_await ch->async_send(err, response.reason(), use_nothrow_awaitable);
        co_return;
    }
    ss.clear();
    ss << response.base();
    SPDLOG_INFO("{}", ss.str());
    SPDLOG_INFO("response.body(): {}", response.body());
    nlohmann::json rsp = nlohmann::json::parse(response.body(), nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, "json parse error", use_nothrow_awaitable);
        co_return;
    }
    SPDLOG_INFO("rsp: {}", rsp.dump());
    co_await ch->async_send(err, rsp.value("data", rsp.dump()), use_nothrow_awaitable);
    co_return;
}

boost::asio::awaitable<void> FreeGpt::chatFree(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    std::string user_agent{
        R"(Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)"};

    constexpr std::string_view host{"v.chatfree.cc"};
    constexpr std::string_view port{"443"};

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/openai/v1/chat/completions", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("authority", "chat.dfehub.com");
    req.set("accept", "*/*");
    req.set("accept-language", R"(en,fr-FR;q=0.9,fr;q=0.8,es-ES;q=0.7,es;q=0.6,en-US;q=0.5,am;q=0.4,de;q=0.3)");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("origin", "https://v.chatfree.cc");
    req.set("referer", "https://v.chatfree.cc");
    req.set("sec-ch-ua", R"("Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114")");
    req.set("sec-ch-ua-mobile", "?0");
    req.set("sec-ch-ua-platform", R"("macOS")");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");
    req.set("x-requested-with", "XMLHttpRequest");

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();
    nlohmann::json request_json{{{"role", "user"}, {"content", std::move(prompt)}}};

    nlohmann::json data{
        {"messages", std::move(request_json)},
        {"stream", true},
        {"model", "gpt-3.5-turbo"},
        {"temperature", 0.5},
        {"presence_penalty", 0},
        {"frequency_penalty", 0},
        {"top_p", 1},
    };

    SPDLOG_INFO("{}", data.dump());
    req.body() = data.dump();
    req.prepare_payload();

    int recreate_num{0};

create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    std::string recv;
    auto ret = co_await sendRecvChunk(ch, stream_, req, 200, [&ch, &recv](std::string chunk_str) {
        recv.append(chunk_str);
        while (true) {
            auto position = recv.find("\n");
            if (position == std::string::npos)
                break;
            auto msg = recv.substr(0, position + 1);
            recv.erase(0, position + 1);
            msg.pop_back();
            if (msg.empty() || !msg.contains("content"))
                continue;
            auto fields = splitString(msg, "data: ");
            boost::system::error_code err{};
            nlohmann::json line_json = nlohmann::json::parse(fields.back(), nullptr, false);
            if (line_json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", fields.back());
                ch->try_send(err, fmt::format("json parse error: [{}]", fields.back()));
                continue;
            }
            auto str = line_json["choices"][0]["delta"]["content"].get<std::string>();
            if (!str.empty())
                ch->try_send(err, str);
        }
    });
    if (ret == Status::Close && recreate_num == 0) {
        recreate_num++;
        goto create_client;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aiService(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "aiservice.vercel.app";
    constexpr std::string_view port = "443";

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/chat/answer", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::content_type, "text/plain;charset=UTF-8");
    req.set("sec-fetch-dest", "application/json");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");
    req.set(boost::beast::http::field::referer, "https://aiservice.vercel.app/chat");

    nlohmann::json data{{"input", fmt::format("user: {}\nassistant:", prompt)}};
    req.body() = data.dump();
    req.prepare_payload();

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    boost::beast::flat_buffer b;
    boost::beast::http::response<boost::beast::http::string_body> res;
    std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
    if (ec == boost::beast::http::error::end_of_stream) {
        if (recreate_num == 0) {
            recreate_num++;
            goto create_client;
        }
    }
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http code: {}", res.result_int());
        co_await ch->async_send(err, res.reason(), use_nothrow_awaitable);
        co_return;
    }
    nlohmann::json rsp = nlohmann::json::parse(res.body(), nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, fmt::format("json parse error: {}", res.body()), use_nothrow_awaitable);
        co_return;
    }
    co_await ch->async_send(err, rsp.value("data", rsp.dump()), use_nothrow_awaitable);
    co_return;
}

boost::asio::awaitable<void> FreeGpt::weWordle(std::shared_ptr<Channel> ch, nlohmann::json json) {
    BOOST_SCOPE_EXIT(&ch) { ch->close(); }
    BOOST_SCOPE_EXIT_END
    boost::system::error_code err{};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    auto random = [](int len) {
        static std::string chars{"abcdefghijklmnopqrstuvwxyz0123456789"};
        static std::string letter{"abcdefghijklmnopqrstuvwxyz"};
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 1000000);
        std::string random_string;
        random_string += chars[dis(gen) % letter.length()];
        len = len - 1;
        for (int i = 0; i < len; i++)
            random_string += chars[dis(gen) % chars.length()];
        return random_string;
    };
    auto user_id = random(16);
    auto app_id = random(31);
    auto now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
    auto request_date = fmt::format("{:%Y-%m-%dT%H:%M:%S.000Z}", now);

    constexpr std::string_view host = "wewordle.org";
    constexpr std::string_view port = "443";

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/gptapi/v1/android/turbo", 11};
    req.set(boost::beast::http::field::host, host);
    req.set("pragma", "no-cache");
    req.set("accept", "*/*");
    req.set(
        boost::beast::http::field::user_agent,
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("Accept-Encoding", "gzip, deflate");

    static std::string json_str = R"({
        "user":"j1b892x978flimoa",
        "messages":[
            {
                "role":"user",
                "content":"user: hello\nassistant:"
            }
        ],
        "subscriber":{
            "originalPurchaseDate":null,
            "originalApplicationVersion":null,
            "allPurchaseDatesMillis":{},
            "entitlements":{
                "active":{},
                "all":{}
            },
            "allPurchaseDates":{},
            "allExpirationDatesMillis":{},
            "allExpirationDates":{},
            "originalAppUserId":"$RCAnonymousID:z6xyxaasvt841d5zttw7q2iisb023tf",
            "latestExpirationDate":null,
            "requestDate":"2023-08-03T00:29:53.000Z",
            "latestExpirationDateMillis":null,
            "nonSubscriptionTransactions":[],
            "originalPurchaseDateMillis":null,
            "managementURL":null,
            "allPurchasedProductIdentifiers":[],
            "firstSeen":"2023-08-03T00:29:53.000Z",
            "activeSubscriptions":[]
        }
    })";

    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    request["user"] = user_id;
    request["subscriber"]["originalAppUserId"] = fmt::format("$RCAnonymousID:{}", app_id);
    request["subscriber"]["firstSeen"] = request_date;
    request["subscriber"]["requestDate"] = request_date;
    request["messages"][0]["content"] = fmt::format("user: {}\nassistant:", prompt);

    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    int recreate_num{0};
create_client:
    SPDLOG_INFO("create new client");
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    boost::beast::flat_buffer b;
    boost::beast::http::response<boost::beast::http::string_body> res;
    std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
    if (ec == boost::beast::http::error::end_of_stream) {
        if (recreate_num == 0) {
            recreate_num++;
            goto create_client;
        }
    }
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http code: {}", res.result_int());
        co_await ch->async_send(err, res.reason(), use_nothrow_awaitable);
        co_return;
    }
    nlohmann::json rsp = nlohmann::json::parse(res.body(), nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, fmt::format("json parse error: {}", res.body()), use_nothrow_awaitable);
        co_return;
    }
    if (!rsp.contains("message")) {
        SPDLOG_ERROR("not contains message: {}", rsp.dump());
        co_await ch->async_send(err, fmt::format("not contains message : {}", rsp.dump()), use_nothrow_awaitable);
        co_return;
    }
    co_await ch->async_send(err, rsp["message"].value("content", rsp.dump()), use_nothrow_awaitable);
    co_return;
}
