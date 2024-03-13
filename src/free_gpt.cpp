#include <chrono>
#include <format>
#include <iostream>
#include <random>
#include <ranges>
#include <regex>
#include <tuple>
#include <vector>

#include <concurrentqueue.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <spdlog/spdlog.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <plusaes/plusaes.hpp>

#include "free_gpt.h"
#include "helper.hpp"

namespace {

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

std::string paramsToQueryStr(const std::multimap<std::string, std::string>& params) {
    auto encode_query_param = [](const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;
        for (auto c : value) {
            if (std::isalnum(static_cast<uint8_t>(c)) || c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
                c == '*' || c == '\'' || c == '(' || c == ')') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
                escaped << std::nouppercase;
            }
        }
        return escaped.str();
    };
    std::string query;
    for (auto it = params.begin(); it != params.end(); ++it) {
        if (it != params.begin())
            query += "&";
        query += it->first;
        query += "=";
        query += encode_query_param(it->second);
    }
    return query;
}

enum class Status : uint8_t {
    Ok,
    Close,
    HasError,
    UnexpectedHttpCode,
};

void printHttpHeader(auto& http_packet) {
    std::stringstream ss;
    ss << http_packet.base();
    SPDLOG_INFO("\n{}", ss.str());
}

std::optional<std::smatch> parse(const std::string& url) {
    static const auto url_regex =
        std::regex(R"regex((http|https)://([^/ :]+):?([^/ ]*)((/?[^ #?]*)\x3f?([^ #]*)#?([^ ]*)))regex",
                   std::regex_constants::icase | std::regex_constants::optimize);
    auto match = std::smatch();
    if (!std::regex_match(url, match, url_regex)) {
        SPDLOG_ERROR("invalid http_proxy: {}", url);
        return std::nullopt;
    }
    return match;
}

boost::asio::awaitable<Status> sendRequestRecvChunk(
    std::string& error_info, auto& stream_, auto& req, std::size_t http_code, std::function<void(std::string)> cb,
    std::function<void(const boost::beast::http::parser<false, boost::beast::http::empty_body>&)> h_cb = nullptr) {
    boost::system::error_code err{};
    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        error_info = ec.message();
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
        error_info = ec.message();
        co_return Status::HasError;
    }

    if (h_cb)
        h_cb(p);
    auto& headers = p.get();
    printHttpHeader(headers);

    auto result_int = headers.result_int();
    if (result_int != http_code) {
        std::string reason{headers.reason()};
        SPDLOG_ERROR("http response code: {}, reason: {}", headers.result_int(), reason);
        error_info = std::format("return unexpected http status code: {}({})", result_int, reason);
        co_return Status::UnexpectedHttpCode;
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

boost::asio::awaitable<Status> sendRequestRecvChunk(
    auto& ch, auto& stream_, auto& req, std::size_t http_code, std::function<void(std::string)> cb,
    std::function<void(const boost::beast::http::parser<false, boost::beast::http::empty_body>&)> header_cb =
        nullptr) {
    std::string error_info;
    auto ret = co_await sendRequestRecvChunk(error_info, stream_, req, http_code, std::move(cb), header_cb);
    if (!error_info.empty()) {
        boost::system::error_code err{};
        co_await ch->async_send(err, std::move(error_info), use_nothrow_awaitable);
    }
    co_return ret;
}

boost::asio::awaitable<
    std::expected<std::tuple<boost::beast::http::response<boost::beast::http::string_body>, boost::asio::ssl::context,
                             boost::beast::ssl_stream<boost::beast::tcp_stream>>,
                  std::string>>
sendRequestRecvResponse(auto& req, std::string_view host, std::string_view port, auto create_http_client) {
    int recreate_num{0};
create_client:
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await create_http_client(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_return std::unexpected(client.error());
    }
    auto& stream_ = client.value();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_return std::unexpected(ec.message());
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
        co_return std::unexpected(ec.message());
    }
    co_return std::make_tuple(res, std::move(ctx), std::move(stream_));
}

auto getConversationJson(const nlohmann::json& json) {
    auto conversation = json.at("meta").at("content").at("conversation");
    conversation.push_back(json.at("meta").at("content").at("parts").at(0));
    return conversation;
}

template <typename T = std::chrono::milliseconds>
uint64_t getTimestamp(std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now()) {
    uint64_t timestamp = std::chrono::duration_cast<T>(now.time_since_epoch()).count();
    return timestamp;
}

class Curl final {
public:
    Curl() {
        m_curl = curl_easy_init();
        if (!m_curl)
            throw std::runtime_error("curl_easy_init() failed");
        curl_easy_setopt(m_curl, CURLOPT_MAXREDIRS, 20L);
        curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(m_curl, CURLOPT_TIMEOUT, 120L);
        curl_easy_setopt(m_curl, CURLOPT_CONNECTTIMEOUT, 30L);
        curl_easy_setopt(m_curl, CURLOPT_CAINFO, nullptr);
        curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    ~Curl() {
        if (m_headers)
            curl_slist_free_all(m_headers);
        if (m_curl)
            curl_easy_cleanup(m_curl);
    }
    Curl(const Curl&) = delete;
    Curl& operator=(const Curl&) = delete;

    auto& setUrl(std::string_view url) {
        m_url = url;
        curl_easy_setopt(m_curl, CURLOPT_URL, m_url.data());
        return *this;
    }
    auto& setBody(std::string body, CURLoption cur_loption = CURLoption::CURLOPT_POSTFIELDS) {
        if (!body.empty()) {
            m_body = std::move(body);
            curl_easy_setopt(m_curl, cur_loption, m_body.c_str());
        }
        return *this;
    }
    auto& setProxy(std::string_view http_proxy) {
        if (!http_proxy.empty()) {
            m_http_proxy = http_proxy;
            curl_easy_setopt(m_curl, CURLOPT_PROXY, m_http_proxy.data());
        }
        return *this;
    }
    auto& setHttpHeaders(const std::unordered_multimap<std::string, std::string>& http_headers) {
        for (auto& [k, v] : http_headers)
            m_headers_list.emplace_back(std::format("{}: {}", k, v));
        for (auto& header : m_headers_list)
            m_headers = curl_slist_append(m_headers, header.c_str());
        curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_headers);
        return *this;
    }
    static size_t recvCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        auto cb = static_cast<std::function<void(std::string)>*>(userp);
        std::string data{(char*)contents, size * nmemb};
        (*cb)(std::move(data));
        return size * nmemb;
    }
    auto& setRecvBodyCallback(std::function<void(std::string)> cb) {
        m_recv_body_cb = std::move(cb);
        curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &recvCallback);
        curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &m_recv_body_cb);
        return *this;
    }
    auto& setRecvHeadersCallback(std::function<void(std::string)> cb) {
        m_recv_headers_cb = std::move(cb);
        curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, &recvCallback);
        curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, &m_recv_headers_cb);
        return *this;
    }
    auto& setOpt(auto option, auto value) {
        curl_easy_setopt(m_curl, option, value);
        return *this;
    }
    std::optional<std::string> perform() {
        auto res = curl_easy_perform(m_curl);
        if (res != CURLE_OK) {
            auto error_info = std::format("[{}] -> [{}]", m_url, curl_easy_strerror(res));
            return error_info;
        }
        int32_t response_code;
        curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (m_http_status_code != response_code)
            return std::format("[{}] -> [Http Status Code:{}]", m_url, response_code);
        return std::nullopt;
    }
    auto& clearHeaders() {
        if (m_headers)
            curl_slist_free_all(m_headers);
        m_headers_list.clear();
        m_headers = nullptr;
        return *this;
    }
    auto& setHttpStatusCode(int32_t code) {
        m_http_status_code = code;
        return *this;
    }
    static auto parseHttpHeaders(const std::string& buffer) {
        std::regex pattern(R"(([^:\r\n]+):([^\r\n]+))");
        std::smatch matches;
        auto start = buffer.cbegin();
        auto end = buffer.cend();
        std::multimap<std::string, std::string> response_header;
        while (std::regex_search(start, end, matches, pattern)) {
            std::string field_name = matches[1].str();
            std::string field_value = matches[2].str();
            response_header.insert(std::pair{field_name, field_value});
            start = matches[0].second;
        }
        return response_header;
    }

private:
    CURL* m_curl{nullptr};
    std::string_view m_url;
    std::string m_body;
    std::string_view m_http_proxy;
    struct curl_slist* m_headers{nullptr};
    std::vector<std::string> m_headers_list;
    std::function<void(std::string)> m_recv_body_cb{[](std::string) {}};
    std::function<void(std::string)> m_recv_headers_cb{[](std::string) {}};
    int32_t m_http_status_code{200};
};

std::expected<nlohmann::json, std::string> callZeus(const std::string& host, const std::string& request_body) {
    static std::unordered_multimap<std::string, std::string> headers{
        {"Accept", "*/*"},
        {"Content-Type", "application/json"},
    };
    std::string recv;
    auto ret = Curl()
                   .setUrl(host)
                   .setRecvHeadersCallback([](std::string) { return; })
                   .setRecvBodyCallback([&](std::string str) { recv.append(str); })
                   .setBody(request_body)
                   .clearHeaders()
                   .setHttpHeaders(headers)
                   .perform();
    if (ret) {
        SPDLOG_ERROR("{}", ret.value());
        return std::unexpected(ret.value());
    }
    nlohmann::json rsp = nlohmann::json::parse(recv, nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error: {}", recv);
        return std::unexpected("parse callZeus error");
    }
    return rsp;
}

std::string decodeBase64(const std::string& to_decode) {
    auto predicted_len = 3 * to_decode.length() / 4;
    auto output_buffer{std::make_unique<char[]>(predicted_len + 1)};
    std::vector<unsigned char> vec_chars{to_decode.begin(), to_decode.end()};
    auto output_len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(output_buffer.get()), vec_chars.data(),
                                      static_cast<int>(vec_chars.size()));
    if (predicted_len != static_cast<unsigned long>(output_len)) {
        throw std::runtime_error("DecodeBase64 error");
    }
    return output_buffer.get();
}

}  // namespace

FreeGpt::FreeGpt(Config& cfg)
    : m_cfg(cfg), m_thread_pool_ptr(std::make_shared<boost::asio::thread_pool>(m_cfg.work_thread_num * 2)) {}

boost::asio::awaitable<std::expected<boost::beast::ssl_stream<boost::beast::tcp_stream>, std::string>>
FreeGpt::createHttpClient(boost::asio::ssl::context& ctx, std::string_view host, std::string_view port) {
    if (m_cfg.http_proxy.empty()) {
        boost::beast::ssl_stream<boost::beast::tcp_stream> stream_{co_await boost::asio::this_coro::executor, ctx};
        boost::system::error_code err{};
        if (!SSL_set_tlsext_host_name(stream_.native_handle(), host.data())) {
            SPDLOG_ERROR("SSL_set_tlsext_host_name");
            co_return std::unexpected(std::string("SSL_set_tlsext_host_name"));
        }
        auto resolver = boost::asio::ip::tcp::resolver(co_await boost::asio::this_coro::executor);
        auto [ec, results] = co_await resolver.async_resolve(host.data(), port.data(), use_nothrow_awaitable);
        if (ec) {
            SPDLOG_INFO("async_resolve: {}", ec.message());
            co_return std::unexpected(ec.message());
        }
        for (auto& endpoint : results) {
            std::stringstream ss;
            ss << endpoint.endpoint();
            SPDLOG_INFO("resolver_results: [{}]", ss.str());
        }
        boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
        if (auto [ec, _] =
                co_await boost::beast::get_lowest_layer(stream_).async_connect(results, use_nothrow_awaitable);
            ec) {
            co_return std::unexpected(ec.message());
        }
        boost::beast::get_lowest_layer(stream_).expires_never();
        std::tie(ec) = co_await stream_.async_handshake(boost::asio::ssl::stream_base::client, use_nothrow_awaitable);
        if (ec) {
            SPDLOG_INFO("async_handshake: {}", ec.message());
            co_return std::unexpected(ec.message());
        }
        co_return stream_;
    }

    std::string userinfo, proxy_host, proxy_port;
    auto is_auth_proxy = [](const std::string& str) -> bool {
        std::regex pattern("^http://[^:]+:[^@]+@[^:]+:[0-9]+$");
        return std::regex_match(str, pattern);
    };
    // http://username:password@proxy.example.com:8080
    if (is_auth_proxy(m_cfg.http_proxy)) {
        static std::regex pattern("(http|https)://([^:]+):([^@]+)@([^:]+):([0-9]+)");
        std::smatch matches;
        if (!std::regex_match(m_cfg.http_proxy, matches, pattern))
            co_return std::unexpected(std::format("invalid http_proxy: {}", m_cfg.http_proxy));
        // std::string protocol = matches[1];
        std::string username = matches[2];
        std::string password = matches[3];
        proxy_host = matches[4];
        proxy_port = matches[5];
        userinfo = std::format("{}:{}", username, password);
    } else {
        auto match_opt = parse(m_cfg.http_proxy);
        if (!match_opt.has_value())
            co_return std::unexpected(std::format("invalid http_proxy: {}", m_cfg.http_proxy));
        auto& match = match_opt.value();
        // auto& protocol = match[1];
        // auto& target = match[4];
        proxy_host = match[2];
        proxy_port = match[3];
    }
    SPDLOG_INFO("CONNECT TO HTTP_PROXY [{}:{}]", proxy_host, proxy_port);

    auto resolver = boost::asio::ip::tcp::resolver(co_await boost::asio::this_coro::executor);
    auto [ec, results] = co_await resolver.async_resolve(proxy_host, proxy_port, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_INFO("async_resolve: {}", ec.message());
        co_return std::unexpected(ec.message());
    }
    boost::asio::ip::tcp::socket socket_{co_await boost::asio::this_coro::executor};
    if (auto [ec, count] = co_await boost::asio::async_connect(socket_, results, use_nothrow_awaitable); ec) {
        SPDLOG_INFO("async_connect: {}", ec.message());
        co_return std::unexpected(ec.message());
    }

    boost::beast::ssl_stream<boost::beast::tcp_stream> stream_{std::move(socket_), ctx};
    int http_version = 11;
    boost::beast::http::request<boost::beast::http::string_body> connect_req{
        boost::beast::http::verb::connect, std::format("{}:{}", host, port), http_version};
    connect_req.set(boost::beast::http::field::host, host);

    if (!userinfo.empty()) {
        std::string result(boost::beast::detail::base64::encoded_size(userinfo.size()), 0);
        auto len =
            boost::beast::detail::base64::encode(static_cast<char*>(result.data()), userinfo.c_str(), userinfo.size());
        result.resize(len);
        result = "Basic " + result;
        connect_req.set(boost::beast::http::field::proxy_authorization, result);
    }

    std::size_t count;
    std::tie(ec, count) = co_await boost::beast::http::async_write(boost::beast::get_lowest_layer(stream_),
                                                                   connect_req, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_return std::unexpected(ec.message());
    }
    boost::beast::http::response<boost::beast::http::empty_body> res;
    boost::beast::http::parser<false, boost::beast::http::empty_body> http_parser(res);
    http_parser.skip(true);

    boost::beast::flat_buffer buffer;
    std::tie(ec, count) = co_await boost::beast::http::async_read(boost::beast::get_lowest_layer(stream_), buffer,
                                                                  http_parser, use_nothrow_awaitable);
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("Proxy response failed : {}", res.result_int());
        co_return std::unexpected(ec.message());
    }
    if (!SSL_set_tlsext_host_name(stream_.native_handle(), host.data())) {
        SPDLOG_ERROR("SSL_set_tlsext_host_name");
        co_return std::unexpected(std::string("SSL_set_tlsext_host_name"));
    }
    std::tie(ec) = co_await stream_.async_handshake(boost::asio::ssl::stream_base::client, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_INFO("async_handshake: {}", ec.message());
        co_return std::unexpected(ec.message());
    }
    co_return stream_;
}

boost::asio::awaitable<void> FreeGpt::openAi(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    constexpr std::string_view host = "api.openai.com";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)"};

    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);

    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/v1/chat/completions", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set(boost::beast::http::field::authorization, std::format("Bearer {}", m_cfg.api_key));

    constexpr std::string_view json_str = R"({
        "messages": [
            {
                "role": "user",
                "content": "hello"
            }
        ],
        "stream": true,
        "model": "gpt-3.5-turbo"
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    request["messages"] = getConversationJson(json);
    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    std::string recv;
    co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch, &recv](std::string chunk_str) {
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
                ch->try_send(err, std::format("json parse error: [{}]", fields.back()));
                continue;
            }
            auto str = line_json["choices"][0]["delta"]["content"].get<std::string>();
            if (!str.empty())
                ch->try_send(err, str);
        }
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::yqcloud(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "api.aichatos.cloud";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0)"};

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/generateStream", 11};
    req.set("authority", "p5.v50.ltd");
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("accept", "application/json, text/plain, */*");
    req.set("Content-Type", "application/json");
    req.set("origin", "https://chat9.yqcloud.top");

    constexpr std::string_view json_str = R"({
        "prompt":"hello",
        "network":true,
        "system":"",
        "withoutContext":false,
        "stream":false
    })";

    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);
    request["prompt"] = std::move(prompt);

    req.body() = request.dump();
    req.prepare_payload();

    int recreate_num{0};
create_client:
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto ret = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch](std::string str) {
        boost::system::error_code err{};
        ch->try_send(err, std::move(str));
    });
    if (ret == Status::Close && recreate_num == 0) {
        recreate_num++;
        goto create_client;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::you(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));
    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    using Tuple = std::tuple<std::chrono::time_point<std::chrono::system_clock>, std::string>;
    static moodycamel::ConcurrentQueue<Tuple> cookie_queue;
    Tuple item;
    bool found{false};
    if (cookie_queue.try_dequeue(item)) {
        auto& [time_point, cookie] = item;
        if (std::chrono::system_clock::now() - time_point < std::chrono::minutes(120))
            found = true;
    }
    if (!found) {
        std::string header_str;
        auto ret = Curl()
                       .setUrl("https://you.com")
                       .setProxy(m_cfg.http_proxy)
                       .setRecvHeadersCallback([&](std::string str) { header_str.append(str); })
                       .setRecvBodyCallback([&](std::string) { return; })
                       .perform();
        if (ret.has_value()) {
            SPDLOG_ERROR("{}", ret.value());
            co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
            ch->try_send(err, ret.value());
            co_return;
        }
        auto response_header = Curl::parseHttpHeaders(header_str);
        std::string cookie;
        auto range = response_header.equal_range("set-cookie");
        for (auto it = range.first; it != range.second; ++it) {
            if (!(it->second.contains("__cf_bm=")))
                continue;
            auto view = it->second | std::views::drop_while(isspace) | std::views::reverse |
                        std::views::drop_while(isspace) | std::views::reverse;
            auto fields = splitString(std::string{view.begin(), view.end()}, " ");
            if (fields.size() < 1) {
                co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
                ch->try_send(err, "can't get cookie");
                co_return;
            }
            cookie = std::move(fields[0]);
            break;
        }
        if (cookie.empty()) {
            co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
            ch->try_send(err, "cookie is empty");
            co_return;
        }
        item = std::make_tuple(std::chrono::system_clock::now(), std::move(cookie));
    }
    SPDLOG_INFO("cookie: {}", std::get<1>(item));
    ScopeExit auto_free([&] mutable {
        auto& [time_point, cookie] = item;
        if (std::chrono::system_clock::now() - time_point < std::chrono::minutes(120))
            cookie_queue.enqueue(std::move(item));
    });
    auto cookie_str = std::format("uuid_guest={}; safesearch_guest=Off; {}", createUuidString(), std::get<1>(item));

    std::multimap<std::string, std::string> params{
        {"q", prompt},
        {"page", "1"},
        {"count", "10"},
        {"safeSearch", "Off"},
        {"onShoppingPage", "False"},
        {"mkt", ""},
        {"responseFilter", "WebPages,Translations,TimeZone,Computation,RelatedSearches"},
        {"domain", "youchat"},
        {"queryTraceId", createUuidString()},
    };
    auto request_url = std::format("https://you.com/api/streamingSearch?{}", paramsToQueryStr(params));
    auto ret = Curl()
                   .setUrl(request_url)
                   .setProxy(m_cfg.http_proxy)
                   .setOpt(CURLOPT_COOKIE, std::get<1>(item).c_str())
                   .setRecvHeadersCallback([&](std::string) { return; })
                   .setRecvBodyCallback([&](std::string data) {
                       boost::system::error_code err{};
                       if (data.starts_with(R"(event: youChatToken)")) {
                           static std::string to_erase{"event: youChatToken\ndata: "};
                           size_t pos = data.find(to_erase);
                           if (pos != std::string::npos)
                               data.erase(pos, to_erase.length());
                           nlohmann::json line_json = nlohmann::json::parse(data, nullptr, false);
                           if (line_json.is_discarded()) {
                               SPDLOG_ERROR("json parse error: [{}]", data);
                               boost::asio::post(ch->get_executor(), [=] {
                                   ch->try_send(err, std::format("json parse error: [{}]", data));
                               });
                               return;
                           }
                           auto str = line_json["youChatToken"].get<std::string>();
                           boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, str); });
                       }
                       return;
                   })
                   .clearHeaders()
                   .setHttpHeaders([&] -> auto {
                       std::unordered_multimap<std::string, std::string> headers{
                           {"referer", "https://you.com/search?q=gpt4&tbm=youchat"},
                           {"Accept", "text/event-stream"},
                           {"cookie", cookie_str},
                       };
                       return headers;
                   }())
                   .perform();
    if (ret) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, ret.value());
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::binjie(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "api.binjie.fun";
    constexpr std::string_view port = "443";

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/generateStream", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(
        boost::beast::http::field::user_agent,
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)");
    req.set("Accept", "application/json, text/plain, */*");
    req.set("accept-language", "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("origin", "https://chat.jinshutuan.com");

    constexpr std::string_view json_str = R"({
        "prompt":"user: hello\nassistant:",
        "system": "Always talk in English.",
        "withoutContext":true,
        "stream":true
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);
    request["prompt"] = prompt;

    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }

    co_await sendRequestRecvChunk(ch, client.value(), req, 200, [&ch](std::string str) {
        boost::system::error_code err{};
        ch->try_send(err, std::move(str));
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::llama2(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};

    boost::system::error_code err{};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    static std::unordered_multimap<std::string, std::string> headers{
        {"Accept", "*/*"},
        {"Accept-Encoding", "gzip, deflate, br"},
        {"Sec-Fetch-Dest", "empty"},
        {"Sec-Fetch-Mode", "cors"},
        {"Sec-Fetch-Site", "same-origin"},
        {"origin", "https://www.llama2.ai"},
        {"referer", "https://www.llama2.ai/"},
        {"Content-Type", "text/plain;charset=UTF-8"},
        {"Host", "www.llama2.ai"},
    };
    auto ret = Curl()
                   .setUrl("https://www.llama2.ai/api")
                   .setProxy(m_cfg.http_proxy)
                   .setRecvHeadersCallback([](std::string) { return; })
                   .setRecvBodyCallback([&](std::string str) mutable {
                       boost::asio::post(ch->get_executor(), [=, str = std::move(str)] { ch->try_send(err, str); });
                       return;
                   })
                   .setBody([&] {
                       constexpr std::string_view ask_json_str = R"({
                            "prompt": "[INST] hello [/INST]\n",
                            "model": "meta/llama-2-70b-chat",
                            "systemPrompt": "You are a helpful assistant.",
                            "temperature": 0.75,
                            "topP": 0.9,
                            "maxTokens": 8000,
                            "image": null
                        })";
                       nlohmann::json ask_request = nlohmann::json::parse(ask_json_str, nullptr, false);
                       ask_request["prompt"] = std::format("[INST] {} [/INST]\n", prompt);
                       std::string ask_request_str = ask_request.dump();
                       SPDLOG_INFO("ask_request_str: [{}]", ask_request_str);
                       return ask_request_str;
                   }())
                   .clearHeaders()
                   .setHttpHeaders(headers)
                   .perform();

    if (ret) {
        SPDLOG_ERROR("{}", ret.value());
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, ret.value()); });
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::deepInfra(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    boost::system::error_code err{};
    std::unordered_multimap<std::string, std::string> headers{
        {"Accept", "text/event-stream"},
        {"content-type", "application/json"},
        {"Referer", "https://deepinfra.com/"},
        {"Origin", "https://deepinfra.com"},
        {"X-Deepinfra-Source", "web-embed"},
        {"sec-ch-ua", R"("Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24")"},
        {"sec-ch-ua-platform", R"("macOS")"},
        {"sec-ch-ua-mobile", "?0"},
        {"Sec-Fetch-Dest", "empty"},
        {"Sec-Fetch-Mode", "cors"},
        {"Sec-Fetch-Site", "same-site"},
    };
    std::string recv;
    auto ret = Curl()
                   .setUrl("https://api.deepinfra.com/v1/openai/chat/completions")
                   .setProxy(m_cfg.http_proxy)
                   .setRecvHeadersCallback([](std::string) { return; })
                   .setRecvBodyCallback([&](std::string str) mutable {
                       recv.append(str);
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
                               boost::asio::post(ch->get_executor(), [=] {
                                   ch->try_send(err, std::format("json parse error: [{}]", fields.back()));
                               });
                               continue;
                           }
                           auto str = line_json["choices"][0]["delta"]["content"].get<std::string>();
                           if (!str.empty())
                               boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, str); });
                       }
                   })
                   .setBody([&] {
                       constexpr std::string_view ask_json_str = R"({
                            "model":"meta-llama/Llama-2-70b-chat-hf",
                            "messages":[
                                {
                                    "role":"user",
                                    "content":"hello"
                                }
                            ],
                            "stream":true
                        })";
                       nlohmann::json ask_request = nlohmann::json::parse(ask_json_str, nullptr, false);
                       ask_request["messages"] = getConversationJson(json);
                       std::string ask_request_str = ask_request.dump();
                       SPDLOG_INFO("request: [{}]", ask_request_str);
                       return ask_request_str;
                   }())
                   .clearHeaders()
                   .setHttpHeaders(headers)
                   .perform();
    if (ret.has_value()) {
        SPDLOG_ERROR("{}", ret.value());
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, ret.value());
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::flowGpt(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    boost::system::error_code err{};
    std::unordered_multimap<std::string, std::string> headers{
        {"Accept", "*/*"},
        {"content-type", "application/json"},
        {"Referer", "https://flowgpt.com/"},
        {"Origin", "https://flowgpt.com"},
        {"Sec-Fetch-Dest", "empty"},
        {"Sec-Fetch-Mode", "cors"},
        {"Sec-Fetch-Site", "same-site"},
        {"Sec-Ch-Ua-Mobile", "?0"},
        {"Authorization", "Bearer null"},
    };
    std::string recv;
    auto ret = Curl()
                   .setUrl("https://backend-k8s.flowgpt.com/v2/chat-anonymous")
                   .setProxy(m_cfg.http_proxy)
                   .setRecvHeadersCallback([](std::string) { return; })
                   .setRecvBodyCallback([&](std::string str) mutable {
                       recv.append(str);
                       while (true) {
                           auto position = recv.find("\n");
                           if (position == std::string::npos)
                               break;
                           auto msg = recv.substr(0, position + 1);
                           recv.erase(0, position + 1);
                           msg.pop_back();
                           if (msg.empty() || !msg.contains("event"))
                               continue;
                           boost::system::error_code err{};
                           nlohmann::json line_json = nlohmann::json::parse(msg, nullptr, false);
                           if (line_json.is_discarded()) {
                               SPDLOG_ERROR("json parse error: [{}]", msg);
                               boost::asio::post(ch->get_executor(), [=] {
                                   ch->try_send(err, std::format("json parse error: [{}]", msg));
                               });
                               continue;
                           }
                           auto type = line_json["event"].get<std::string>();
                           if (type == "text") {
                               auto new_message = line_json["data"].get<std::string>();
                               if (new_message.empty())
                                   continue;
                               if (!new_message.empty())
                                   boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, new_message); });
                           }
                       }
                       return;
                   })
                   .setBody([&] {
                       constexpr std::string_view ask_json_str = R"({
                            "model": "gpt-3.5-turbo",
                            "nsfw": false,
                            "question": "hello",
                            "history": [
                                {
                                    "role": "assistant",
                                    "content": "Hello, how can I help you today?"
                                }
                            ],
                            "system": "You are helpful assistant. Follow the user's instructions carefully.",
                            "temperature": 0.7,
                            "promptId": "model-gpt-3.5-turbo",
                            "documentIds": [],
                            "chatFileDocumentIds": [],
                            "generateImage": false,
                            "generateAudio": false
                        })";
                       nlohmann::json ask_request = nlohmann::json::parse(ask_json_str, nullptr, false);
                       ask_request["question"] = prompt;
                       std::string ask_request_str = ask_request.dump();
                       SPDLOG_INFO("request: [{}]", ask_request_str);
                       return ask_request_str;
                   }())
                   .clearHeaders()
                   .setHttpHeaders(headers)
                   .perform();
    if (ret.has_value()) {
        SPDLOG_ERROR("{}", ret.value());
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, ret.value());
    }
    co_return;
}