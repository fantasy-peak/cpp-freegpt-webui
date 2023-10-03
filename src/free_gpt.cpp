#include <chrono>
#include <format>
#include <iostream>
#include <queue>
#include <random>
#include <ranges>
#include <regex>
#include <tuple>
#include <vector>

#include <curl/curl.h>
#include <openssl/md5.h>
#include <spdlog/spdlog.h>
#include <zlib.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/stream.hpp>
#include <plusaes/plusaes.hpp>

#include "free_gpt.h"
#include "helper.hpp"

namespace {

// clang-format off
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
// clang-format on

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
                   [](unsigned char c) -> std::string { return std::format("{:02x}", int(c)); });
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

std::expected<std::string, std::string> decompress(auto& res) {
    try {
        boost::iostreams::array_source src{res.body().data(), res.body().size()};
        boost::iostreams::filtering_istream is;
        if (res["Content-Encoding"] == "deflate") {
            SPDLOG_INFO("decompressing: {}", res["Content-Encoding"]);
            is.push(boost::iostreams::zlib_decompressor{-MAX_WBITS});  // deflate
        } else if (res["Content-Encoding"] == "gzip") {
            SPDLOG_INFO("decompressing: {}", res["Content-Encoding"]);
            is.push(boost::iostreams::gzip_decompressor{});  // gzip
        } else if (res["Content-Encoding"] == "") {
            SPDLOG_INFO("uncompressed: {}", res["Content-Encoding"]);
        }
        is.push(src);
        std::stringstream strstream;
        boost::iostreams::copy(is, strstream);
        return strstream.str();
    } catch (const std::exception& e) {
        return std::unexpected(e.what());
    }
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

void curlEasySetopt(CURL* curl) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, nullptr);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 20L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
}

auto getConversationJson(const nlohmann::json& json) {
    auto conversation = json.at("meta").at("content").at("conversation");
    conversation.push_back(json.at("meta").at("content").at("parts").at(0));
    return conversation;
}

struct HttpResponse {
    int32_t http_response_code;
    std::vector<std::unordered_multimap<std::string, std::string>> http_header;
    std::string body;
};

// export CURL_IMPERSONATE=chrome110
std::optional<HttpResponse> getCookie(CURL* curl, const std::string& url, const std::string& proxy) {
    bool auto_clean = curl ? false : true;

    if (!curl) {
        curl = curl_easy_init();
        if (!curl) {
            SPDLOG_ERROR("curl_easy_init() failed");
            return std::nullopt;
        }
    }

    HttpResponse http_response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (!proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, proxy.c_str());

    auto write_callback = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        static_cast<std::string*>(userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    };
    size_t (*fn_write_callback)(void* contents, size_t size, size_t nmemb, void* userp) = write_callback;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fn_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &http_response.body);

    auto header_callback = [](char* buffer, size_t size, size_t nitems, void* userdata) {
        static_cast<std::string*>(userdata)->append((char*)buffer, size * nitems);
        return nitems * size;
    };
    size_t (*fn_header_callback)(char* buffer, size_t size, size_t nitems, void* userdata) = header_callback;
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, fn_header_callback);

    std::string buffer;
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &buffer);
    curlEasySetopt(curl);

    ScopeExit auto_exit{[=] {
        if (auto_clean)
            curl_easy_cleanup(curl);
    }};

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        SPDLOG_ERROR("curl_easy_perform() failed: [{}]", curl_easy_strerror(res));
        return std::nullopt;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response.http_response_code);

    auto header_data = splitString(buffer, "\n");

    std::unordered_multimap<std::string, std::string> headers;
    for (auto& str : header_data) {
        // if (str.ends_with("Connection established\n\n"))
        //     continue;
        if (str.size() == 1 && !headers.empty()) {
            http_response.http_header.emplace_back(std::move(headers));
            headers.clear();
            continue;
        }
        if (!str.contains(": ")) {
            auto value = splitString(str, " ");
            if (value.size() >= 2)
                headers.emplace("http_response_code", value[1]);
        } else {
            auto value = splitString(str, ": ");
            if (value.size() >= 2)
                headers.emplace(value[0], value[1]);
        }
    }
    if (!headers.empty()) {
        http_response.http_header.emplace_back(std::move(headers));
    }
    for (auto& value : http_response.http_header) {
        SPDLOG_INFO("=========================================");
        for (auto& [k, v] : value)
            SPDLOG_INFO("{}: {}", k, v);
    }
    return http_response;
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

boost::asio::awaitable<void> FreeGpt::deepAi(std::shared_ptr<Channel> ch, nlohmann::json json) {
    ScopeExit auto_exit{[&] { ch->close(); }};
    boost::system::error_code err{};

    std::string user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)"};
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<uint64_t> dist(0, 100000000);
    uint64_t part1{dist(mt)};
    auto part2 = md5(user_agent + md5(user_agent + md5(std::format("{}{}x", user_agent, part1))));
    auto api_key = std::format("tryit-{}-{}", part1, part2);

    constexpr char CRLF[] = "\r\n";
    constexpr char MULTI_PART_BOUNDARY[] = "9bc627aea4f77e150e6057f78036e73f";
    constexpr std::string_view host{"api.deepai.org"};
    constexpr std::string_view port{"443"};

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/make_me_a_sandwich", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Api-Key", api_key);
    req.set(boost::beast::http::field::content_type,
            std::format("multipart/form-data; boundary={}", MULTI_PART_BOUNDARY));

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
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    auto ret = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch](std::string recv_str) {
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
    boost::asio::post(*m_thread_pool_ptr, [=, this] {
        ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
        boost::system::error_code err{};

        auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

        CURLcode res;
        CURL* curl = curl_easy_init();
        if (!curl) {
            auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
            boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, error_info); });
            return;
        }
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.aitianhu.com/api/chat-process");

        if (!m_cfg.http_proxy.empty())
            curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());

        auto cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
            auto recv_data_ptr = static_cast<std::string*>(userp);
            std::string data{(char*)contents, size * nmemb};
            recv_data_ptr->append(data);
            return size * nmemb;
        };
        size_t (*fn)(void* contents, size_t size, size_t nmemb, void* userp) = cb;

        std::string recv_data;
        curlEasySetopt(curl);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fn);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recv_data);

        constexpr std::string_view json_str = R"({
            "prompt":"hello",
            "options":{},
            "systemMessage":"You are ChatGPT, a large language model trained by OpenAI. Follow the user's instructions carefully.",
            "temperature":0.8,
            "top_p":1
        })";
        nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

        request["prompt"] = prompt;
        SPDLOG_INFO("{}", request.dump(2));
        auto str = request.dump();
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str.c_str());

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        ScopeExit auto_exit{[=] {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }};

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
            boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, error_info); });
            return;
        }
        int32_t response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code != 200) {
            boost::asio::post(ch->get_executor(),
                              [=] { ch->try_send(err, std::format("aiTianhu http code:{}", response_code)); });
            return;
        }
        auto lines = recv_data | std::views::split('\n') | std::views::transform([](auto&& rng) {
                         return std::string_view(&*rng.begin(), std::ranges::distance(rng.begin(), rng.end()));
                     }) |
                     to<std::vector<std::string_view>>();
        if (lines.empty()) {
            SPDLOG_ERROR("lines empty");
            return;
        }
        nlohmann::json rsp = nlohmann::json::parse(lines.back(), nullptr, false);
        if (rsp.is_discarded()) {
            SPDLOG_ERROR("json parse error");
            ch->try_send(err, std::format("json parse error: {}", lines.back()));
            return;
        }
        ch->try_send(err, rsp.value("text", rsp.dump()));
        return;
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aiChat(std::shared_ptr<Channel> ch, nlohmann::json json) {
    ScopeExit auto_exit{[&] { ch->close(); }};
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
        {"message", std::format("user: {}\nassistant:", prompt)},
        {"temperature", 0.5},
        {"presence_penalty", 0},
        {"top_p", 1},
        {"frequency_penalty", 0},
    };
    req.body() = data.dump();
    req.prepare_payload();

    auto ret = co_await sendRequestRecvResponse(req, host, port, std::bind_front(&FreeGpt::createHttpClient, *this));
    if (!ret.has_value()) {
        co_await ch->async_send(err, ret.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& [res, ctx, stream_] = ret.value();
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http status code: {}", res.result_int());
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
    ScopeExit auto_exit{[&] { ch->close(); }};
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
    std::string cookie;
    auto ret = co_await sendRequestRecvChunk(
        ch, stream_, req, 200, [&ch, &chunk_body](std::string recv_str) { chunk_body.append(std::move(recv_str)); },
        [&](const boost::beast::http::parser<false, boost::beast::http::empty_body>& p) {
            auto& headers = p.get();
            for (const auto& header : headers) {
                if (boost::beast::http::to_string(header.name()) == "Set-Cookie") {
                    cookie = header.value();
                    return;
                }
            }
        });
    SPDLOG_ERROR("cookie: {}", cookie);
    if (ret == Status::Close && recreate_num == 0) {
        recreate_num++;
        goto create_client;
    }
    if (ret == Status::HasError)
        co_return;

    static std::string pattern{R"(data-system='(.*?)')"};

    std::vector<std::string> matches = findAll(pattern, chunk_body);
    if (matches.empty()) {
        SPDLOG_ERROR("parsing login failed");
        co_await ch->async_send(err, chunk_body, use_nothrow_awaitable);
        co_return;
    }

    auto html_unescape = [](const std::string& text) {
        std::string result = text;
        boost::replace_all(result, "&amp;", "&");
        boost::replace_all(result, "&lt;", "<");
        boost::replace_all(result, "&gt;", ">");
        boost::replace_all(result, "&quot;", "\"");
        boost::replace_all(result, "&#39;", "'");
        return result;
    };
    std::string html_json_str;
    std::regex regex("'(.*?)'");
    std::smatch result;
    if (std::regex_search(matches[0], result, regex))
        html_json_str = html_unescape(result[1]);
    if (html_json_str.empty()) {
        SPDLOG_ERROR("extract json fail");
        co_await ch->async_send(err, chunk_body, use_nothrow_awaitable);
        co_return;
    }
    nlohmann::json j = nlohmann::json::parse(html_json_str, nullptr, false);
    if (j.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, "json parse error", use_nothrow_awaitable);
        co_return;
    }
    SPDLOG_INFO("json: {}", j.dump());

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    boost::beast::http::request<boost::beast::http::string_body> request{boost::beast::http::verb::post,
                                                                         "/wp-json/mwai-ui/v1/chats/submit", 11};
    request.set(boost::beast::http::field::host, host);
    request.set("authority", "chatgpt.ai");
    request.set("accept", "*/*");
    request.set("accept-language", R"(en,fr-FR;q=0.9,fr;q=0.8,es-ES;q=0.7,es;q=0.6,en-US;q=0.5,am;q=0.4,de;q=0.3)");
    request.set("cache-control", "no-cache");
    request.set("origin", "https://chatgpt.ai");
    request.set("pragma", "no-cache");
    request.set(boost::beast::http::field::referer, "https://chatgpt.ai/");
    request.set("sec-ch-ua", R"("Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114")");
    request.set("sec-ch-ua-mobile", "?0");
    request.set("sec-ch-ua-platform", R"("Windows")");
    request.set("sec-fetch-dest", "empty");
    request.set("sec-fetch-mode", "cors");
    request.set("sec-fetch-site", "same-origin");
    request.set("Cookie", cookie);
    request.set(boost::beast::http::field::user_agent, user_agent);
    request.set("Content-Type", "application/json");

    constexpr std::string_view json_str = R"({
        "botId":"chatbot-9vy3t5",
        "clientId":"",
        "contextId":1048,
        "id":"chatbot-9vy3t5",
        "messages":[],
        "newMessage":"hello",
        "session":"N/A",
        "stream":true
    })";
    nlohmann::json request_json = nlohmann::json::parse(json_str, nullptr, false);
    request_json["botId"] = j["botId"];
    request_json["clientId"] = "";
    request_json["contextId"] = j["contextId"];
    request_json["id"] = j["id"];
    request_json["session"] = j["sessionId"];
    request_json["newMessage"] = prompt;

    SPDLOG_INFO("request: {}", request_json.dump());
    request.body() = request_json.dump();
    request.prepare_payload();

    std::string recv;
    co_await sendRequestRecvChunk(ch, stream_, request, 200, [&](std::string str) {
        recv.append(str);
        while (true) {
            auto position = recv.find("\n");
            if (position == std::string::npos)
                break;
            auto msg = recv.substr(0, position + 1);
            recv.erase(0, position + 1);
            msg.pop_back();
            if (msg.empty())
                continue;
            auto fields = splitString(msg, "data: ");
            boost::system::error_code err{};
            nlohmann::json line_json = nlohmann::json::parse(fields.back(), nullptr, false);
            if (line_json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", fields.back());
                ch->try_send(err, std::format("json parse error: [{}]", fields.back()));
                continue;
            }
            auto type = line_json["type"].get<std::string>();
            if (type == "live")
                ch->try_send(err, line_json["data"].get<std::string>());
        }
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::weWordle(std::shared_ptr<Channel> ch, nlohmann::json json) {
    ScopeExit auto_exit{[&] { ch->close(); }};
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
    auto request_date = std::format("{:%Y-%m-%dT%H:%M:%S.000Z}", now);

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

    constexpr std::string_view json_str = R"({
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
    request["subscriber"]["originalAppUserId"] = std::format("$RCAnonymousID:{}", app_id);
    request["subscriber"]["firstSeen"] = request_date;
    request["subscriber"]["requestDate"] = request_date;
    request["messages"][0]["content"] = std::format("user: {}\nassistant:", prompt);

    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    auto ret = co_await sendRequestRecvResponse(req, host, port, std::bind_front(&FreeGpt::createHttpClient, *this));
    if (!ret.has_value()) {
        co_await ch->async_send(err, ret.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& [res, ctx, stream_] = ret.value();
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http status code: {}", res.result_int());
        co_await ch->async_send(err, res.reason(), use_nothrow_awaitable);
        co_return;
    }

    nlohmann::json rsp = nlohmann::json::parse(res.body(), nullptr, false);
    if (rsp.is_discarded()) {
        SPDLOG_ERROR("json parse error");
        co_await ch->async_send(err, std::format("json parse error: {}", res.body()), use_nothrow_awaitable);
        co_return;
    }
    if (!rsp.contains("message")) {
        SPDLOG_ERROR("not contains message: {}", rsp.dump());
        co_await ch->async_send(err, std::format("not contains message : {}", rsp.dump()), use_nothrow_awaitable);
        co_return;
    }
    co_await ch->async_send(err, rsp["message"].value("content", rsp.dump()), use_nothrow_awaitable);
    co_return;
}

boost::asio::awaitable<void> FreeGpt::acytoo(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "chat.acytoo.com";
    constexpr std::string_view port = "443";

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post,
                                                                     "/api/completions", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(
        boost::beast::http::field::user_agent,
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36)");
    req.set("Accept", "*/*");
    req.set("Accept-Encoding", "gzip, deflate");
    req.set(boost::beast::http::field::content_type, "application/json");

    constexpr std::string_view json_str = R"({
        "key":"",
        "model":"gpt-3.5-turbo",
        "messages":[
            {
                "role":"user",
                "content":"user: hello\nassistant:",
                "createdAt":1688518523500
            }
        ],
        "temperature":0.5,
        "password":""
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    request["messages"][0]["content"] = std::format("user: {}\nassistant:", prompt);
    auto time_now = std::chrono::system_clock::now();
    auto duration_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time_now.time_since_epoch());
    request["messages"][0]["createdAt"] = duration_in_ms.count();
    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    auto ret = co_await sendRequestRecvResponse(req, host, port, std::bind_front(&FreeGpt::createHttpClient, *this));
    if (!ret.has_value()) {
        co_await ch->async_send(err, ret.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& [res, ctx, stream_] = ret.value();
    if (boost::beast::http::status::ok != res.result()) {
        SPDLOG_ERROR("http status code: {}", res.result_int());
        co_await ch->async_send(err, res.reason(), use_nothrow_awaitable);
        co_return;
    }
    auto decompress_value = decompress(res);
    if (!decompress_value.has_value()) {
        SPDLOG_ERROR("decompress error");
        co_await ch->async_send(err, decompress_value.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& body = decompress_value.value();
    co_await ch->async_send(err, std::move(body), use_nothrow_awaitable);
    co_return;
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

boost::asio::awaitable<void> FreeGpt::h2o(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "gpt-gm.h2o.ai";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0)"};

    boost::beast::http::request<boost::beast::http::empty_body> req_init_cookie{boost::beast::http::verb::get, "/",
                                                                                11};
    req_init_cookie.set(boost::beast::http::field::host, host);
    req_init_cookie.set(boost::beast::http::field::user_agent, user_agent);

    auto ret = co_await sendRequestRecvResponse(req_init_cookie, host, port,
                                                std::bind_front(&FreeGpt::createHttpClient, *this));
    if (!ret.has_value()) {
        co_await ch->async_send(err, ret.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& [response, ctx, stream_] = ret.value();
    if (boost::beast::http::status::ok != response.result()) {
        SPDLOG_ERROR("http status code: {}", response.result_int());
        co_await ch->async_send(err, response.reason(), use_nothrow_awaitable);
        co_return;
    }
    auto fields = splitString(response["Set-Cookie"], " ");
    if (fields.empty()) {
        std::stringstream ss;
        ss << response.base();
        SPDLOG_ERROR("get cookie error: {}", ss.str());
        co_await ch->async_send(err, "can't get cookie", use_nothrow_awaitable);
        co_return;
    }
    fields[0].pop_back();
    std::string cookie{std::move(fields[0])};
    SPDLOG_INFO("cookie: {}", cookie);
    {
        boost::beast::http::request<boost::beast::http::string_body> req_init_setting{boost::beast::http::verb::post,
                                                                                      "/settings", 11};
        req_init_setting.set("Cookie", cookie);
        req_init_setting.set(boost::beast::http::field::host, host);
        req_init_setting.set(boost::beast::http::field::user_agent, user_agent);
        req_init_setting.set("Accept",
                             "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
        req_init_setting.set("Accept-Language", "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3");
        req_init_setting.set("Content-Type", "application/x-www-form-urlencoded");
        req_init_setting.set("Upgrade-Insecure-Requests", "1");
        req_init_setting.set("Sec-Fetch-Dest", "document");
        req_init_setting.set("Sec-Fetch-Mode", "navigate");
        req_init_setting.set("Sec-Fetch-Site", "same-origin");
        req_init_setting.set("Sec-Fetch-User", "?1");
        req_init_setting.set("Referer", "https://gpt-gm.h2o.ai/r/jGfKSwU");

        std::stringstream ss1;
        ss1 << "ethicsModalAccepted=true&";
        ss1 << "shareConversationsWithModelAuthors=true&";
        ss1 << "ethicsModalAcceptedAt="
            << "&";
        ss1 << "activeModel=h2oai/h2ogpt-gm-oasst1-en-2048-falcon-40b-v1&";
        ss1 << "searchEnabled=true";

        req_init_setting.body() = ss1.str();
        req_init_setting.prepare_payload();

        auto [ec, count] = co_await boost::beast::http::async_write(stream_, req_init_setting, use_nothrow_awaitable);
        if (ec) {
            SPDLOG_ERROR("{}", ec.message());
            co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
            co_return;
        }
        boost::beast::flat_buffer b;
        boost::beast::http::response<boost::beast::http::string_body> res;
        std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
        if (ec) {
            SPDLOG_ERROR("{}", ec.message());
            co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
            co_return;
        }
        if (res.result_int() != 303) {
            std::string reason{res.reason()};
            SPDLOG_ERROR("reason: {}", reason);
            co_await ch->async_send(
                err, std::format("return unexpected http status code: {}({})", res.result_int(), reason),
                use_nothrow_awaitable);
            co_return;
        }
        {
            boost::beast::http::request<boost::beast::http::empty_body> req_init_cookie{boost::beast::http::verb::get,
                                                                                        "/r/jGfKSwU", 11};
            req_init_cookie.set(boost::beast::http::field::host, host);
            req_init_cookie.set(boost::beast::http::field::user_agent, user_agent);
            auto [ec, count] =
                co_await boost::beast::http::async_write(stream_, req_init_cookie, use_nothrow_awaitable);
            if (ec) {
                SPDLOG_ERROR("{}", ec.message());
                co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
                co_return;
            }
            boost::beast::flat_buffer b;
            boost::beast::http::response<boost::beast::http::string_body> res;
            std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
            if (ec) {
                SPDLOG_ERROR("{}", ec.message());
                co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
                co_return;
            }
            if (res.result_int() != 200) {
                std::string reason{res.reason()};
                SPDLOG_ERROR("reason: {}", reason);
                co_await ch->async_send(
                    err, std::format("return unexpected http status code: {}({})", res.result_int(), reason),
                    use_nothrow_awaitable);
                co_return;
            }
        }
    }
    std::string conversation_id;
    {
        boost::beast::http::request<boost::beast::http::string_body> req_init_conversation{
            boost::beast::http::verb::post, "/conversation", 11};
        req_init_conversation.set("Cookie", cookie);
        req_init_conversation.set(boost::beast::http::field::host, host);
        req_init_conversation.set(boost::beast::http::field::user_agent, user_agent);
        req_init_conversation.set("Accept", "*/*");
        req_init_conversation.set("Accept-Encoding", "gzip, deflate");
        req_init_conversation.set("Content-Type", "application/json");
        req_init_conversation.set("Accept-Language", "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3");
        req_init_conversation.set("Sec-Fetch-Dest", "empty");
        req_init_conversation.set("Sec-Fetch-Mode", "cors");
        req_init_conversation.set("Sec-Fetch-Site", "same-origin");
        req_init_conversation.set("Referer", "https://gpt-gm.h2o.ai/");
        req_init_conversation.body() = R"({"model": "h2oai/h2ogpt-gm-oasst1-en-2048-falcon-40b-v1"})";
        req_init_conversation.prepare_payload();

        auto [ec, count] =
            co_await boost::beast::http::async_write(stream_, req_init_conversation, use_nothrow_awaitable);
        if (ec) {
            SPDLOG_ERROR("{}", ec.message());
            co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
            co_return;
        }
        boost::beast::flat_buffer b;
        boost::beast::http::response<boost::beast::http::string_body> res;
        std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
        if (ec) {
            SPDLOG_ERROR("{}", ec.message());
            co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
            co_return;
        }
        if (res.result_int() != 200) {
            std::string reason{res.reason()};
            SPDLOG_ERROR("reason: {}", reason);
            co_await ch->async_send(
                err, std::format("return unexpected http status code: {}({})", res.result_int(), reason),
                use_nothrow_awaitable);
            co_return;
        }
        std::cout << res.body() << std::endl;
        nlohmann::json rsp_json = nlohmann::json::parse(res.body(), nullptr, false);
        if (rsp_json.is_discarded()) {
            SPDLOG_ERROR("json parse error: [{}]", fields.back());
            ch->try_send(err, std::format("json parse error: [{}]", fields.back()));
            co_return;
        }
        if (!rsp_json.contains("conversationId")) {
            SPDLOG_ERROR("not contains conversationId: {}", res.body());
            co_await ch->async_send(err, res.body(), use_nothrow_awaitable);
            co_return;
        }
        conversation_id = rsp_json["conversationId"].get<std::string>();
    }

    constexpr std::string_view json_str = R"({
        "inputs":"user: hello\nassistant: ",
        "parameters":{
            "temperature":0.4,
            "truncate":2048,
            "max_new_tokens":1024,
            "do_sample":true,
            "repetition_penalty":1.2,
            "return_full_text":false
        },
        "stream":true,
        "options":{
            "id":"64cf9d83-7b0d-4851-82b5-6f9090652494",
            "response_id":"f76711da-6761-4055-9a05-84a8afce0198",
            "is_retry":false,
            "use_cache":false,
            "web_search_id":""
        }
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);
    request["inputs"] = std::format("user: {}\nassistant: ", prompt);
    request["response_id"] = conversation_id;
    request["id"] = createUuidString();

    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::post, std::format("/conversation/{}", conversation_id), 11};
    req.set("Cookie", cookie);
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "*/*");
    // req.set("Accept-Encoding", "gzip, deflate");
    req.set("Content-Type", "application/json");
    req.set("Accept-Language", "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3");
    req.set("Sec-Fetch-Dest", "empty");
    req.set("Sec-Fetch-Mode", "cors");
    req.set("Sec-Fetch-Site", "same-origin");
    req.set("Referer", "https://gpt-gm.h2o.ai/");
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
            if (msg.empty() || !msg.contains("text"))
                continue;
            auto fields = splitString(msg, "data:");
            boost::system::error_code err{};
            nlohmann::json line_json = nlohmann::json::parse(fields.back(), nullptr, false);
            if (line_json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", fields.back());
                ch->try_send(err, std::format("json parse error: [{}]", fields.back()));
                continue;
            }
            auto str = line_json["token"]["text"].get<std::string>();
            if (!str.empty() && str != "<|endoftext|>")
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

boost::asio::awaitable<void> FreeGpt::huggingChat(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "huggingface.co";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0)"};

    boost::beast::http::request<boost::beast::http::empty_body> req_init_cookie{boost::beast::http::verb::get,
                                                                                "/chat/", 11};
    req_init_cookie.set(boost::beast::http::field::host, host);
    req_init_cookie.set(boost::beast::http::field::user_agent, user_agent);

    auto ret = co_await sendRequestRecvResponse(req_init_cookie, host, port,
                                                std::bind_front(&FreeGpt::createHttpClient, *this));
    if (!ret.has_value()) {
        co_await ch->async_send(err, ret.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& [response, ctx, stream_] = ret.value();
    if (boost::beast::http::status::ok != response.result()) {
        SPDLOG_ERROR("http status code: {}", response.result_int());
        co_await ch->async_send(err, response.reason(), use_nothrow_awaitable);
        co_return;
    }
    auto fields = splitString(response["Set-Cookie"], " ");
    if (fields.empty()) {
        std::stringstream ss;
        ss << response.base();
        SPDLOG_ERROR("get cookie error: {}", ss.str());
        co_await ch->async_send(err, "can't get cookie", use_nothrow_awaitable);
        co_return;
    }
    fields[0].pop_back();
    std::string cookie{std::move(fields[0])};
    SPDLOG_INFO("cookie: {}", cookie);

    boost::beast::http::request<boost::beast::http::string_body> req_init_conversation{boost::beast::http::verb::post,
                                                                                       "/chat/conversation", 11};
    req_init_conversation.set("Cookie", cookie);
    req_init_conversation.set(boost::beast::http::field::host, host);
    req_init_conversation.set(boost::beast::http::field::user_agent, user_agent);
    req_init_conversation.set("Accept", "*/*");
    req_init_conversation.set("Content-Type", "application/json");
    req_init_conversation.body() = R"({"model": "meta-llama/Llama-2-70b-chat-hf"})";
    req_init_conversation.prepare_payload();

    auto [ec, count] = co_await boost::beast::http::async_write(stream_, req_init_conversation, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    boost::beast::flat_buffer b;
    boost::beast::http::response<boost::beast::http::string_body> res;
    std::tie(ec, count) = co_await boost::beast::http::async_read(stream_, b, res, use_nothrow_awaitable);
    if (ec) {
        SPDLOG_ERROR("{}", ec.message());
        co_await ch->async_send(err, ec.message(), use_nothrow_awaitable);
        co_return;
    }
    if (res.result_int() != 200) {
        std::string reason{res.reason()};
        SPDLOG_ERROR("reason: {}", reason);
        co_await ch->async_send(err,
                                std::format("return unexpected http status code: {}({})", res.result_int(), reason),
                                use_nothrow_awaitable);
        co_return;
    }
    nlohmann::json rsp_json = nlohmann::json::parse(res.body(), nullptr, false);
    if (rsp_json.is_discarded()) {
        SPDLOG_ERROR("json parse error: [{}]", fields.back());
        ch->try_send(err, std::format("json parse error: [{}]", fields.back()));
        co_return;
    }
    if (!rsp_json.contains("conversationId")) {
        SPDLOG_ERROR("not contains conversationId: {}", res.body());
        co_await ch->async_send(err, res.body(), use_nothrow_awaitable);
        co_return;
    }
    auto conversation_id = rsp_json["conversationId"].get<std::string>();
    SPDLOG_INFO("conversation_id: [{}]", conversation_id);

    constexpr std::string_view json_str = R"({
        "inputs":"hello",
        "parameters":{
            "temperature":0.2,
            "truncate":1000,
            "max_new_tokens":1024,
            "stop":[
                "</s>"
            ],
            "top_p":0.95,
            "repetition_penalty":1.2,
            "top_k":50,
            "return_full_text":false
        },
        "stream":true,
        "options":{
            "id":"9e9b8bc4-6604-40c6-994e-8eb78fa32e37",
            "response_id":"04ce2602-3bea-45e8-8efc-cef00680376a",
            "is_retry":false,
            "use_cache":false,
            "web_search_id":""
        }
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);
    request["inputs"] = prompt;
    request["options"]["response_id"] = createUuidString();
    request["options"]["id"] = createUuidString();

    boost::beast::http::request<boost::beast::http::string_body> req{
        boost::beast::http::verb::post, std::format("/chat/conversation/{}", conversation_id), 11};
    req.set("Cookie", cookie);
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "*/*");
    req.set("Content-Type", "application/json");
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
            if (msg.empty())
                continue;
            boost::system::error_code err{};
            nlohmann::json line_json = nlohmann::json::parse(msg, nullptr, false);
            if (line_json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", msg);
                ch->try_send(err, std::format("json parse error: [{}]", msg));
                continue;
            }
            if (!line_json.contains("type")) {
                SPDLOG_ERROR("invalid json format: [{}]", line_json.dump());
                continue;
            }
            auto type = line_json["type"].get<std::string>();
            if (type == "stream") {
                if (auto str = line_json["token"].get<std::string>(); !str.empty())
                    ch->try_send(err, str);
            } else if (type == "finalAnswer") {
                ch->close();
            }
        }
        return;
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::you(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::asio::post(*m_thread_pool_ptr, [=, this] {
        boost::system::error_code err{};
        ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};

        auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

        static std::mutex mtx;
        static std::queue<std::tuple<std::chrono::time_point<std::chrono::system_clock>, std::string>> cookie_queue;
        std::tuple<std::chrono::time_point<std::chrono::system_clock>, std::string> cookie_cache;
        std::queue<std::tuple<std::chrono::time_point<std::chrono::system_clock>, std::string>> tmp_queue;
        std::unique_lock lk(mtx);
        while (!cookie_queue.empty()) {
            auto& [time_point, code] = cookie_queue.front();
            if (std::chrono::system_clock::now() - time_point < std::chrono::minutes(15))
                tmp_queue.push(std::move(cookie_queue.front()));
            cookie_queue.pop();
        }
        cookie_queue = std::move(tmp_queue);
        SPDLOG_INFO("cookie_queue size: {}", cookie_queue.size());
        if (cookie_queue.empty()) {
            lk.unlock();
            auto cookie_opt = getCookie(nullptr, "https://you.com", m_cfg.http_proxy);
            if (!cookie_opt) {
                boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, "get cookie error!!!"); });
                return;
            }
            auto& [http_response_code, http_header, body] = cookie_opt.value();
            if (!cookie_opt) {
                boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, "http header is empty!!!"); });
                return;
            }
            SPDLOG_INFO("http_response_code: {}", http_response_code);
            std::string cookie;

            auto range = http_header.back().equal_range("set-cookie");
            for (auto it = range.first; it != range.second; ++it) {
                if (it->second.contains("__cf_bm=")) {
                    auto fields = splitString(it->second, " ");
                    if (fields.size() < 1) {
                        boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, "can't get cookie"); });
                        return;
                    }
                    cookie = std::move(fields[0]);
                    break;
                }
            }

            if (cookie.empty()) {
                boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, "cookie is empty"); });
                return;
            }
            cookie_cache = std::make_tuple(std::chrono::system_clock::now(), std::move(cookie));
        } else {
            cookie_cache = std::move(cookie_queue.front());
            cookie_queue.pop();
            lk.unlock();
        }
        SPDLOG_INFO("cookie: {}", std::get<1>(cookie_cache));

        CURL* curl = curl_easy_init();
        if (!curl) {
            auto error_info = std::format("curl_easy_init() failed");
            boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, error_info); });
            return;
        }
        auto url = std::format(
            "https://you.com/api/"
            "streamingSearch?q={}&page=1&count=10&safeSearch=Off&onShoppingPage=False&mkt=&responseFilter="
            "WebPages%"
            "2CTranslations%2CTimeZone%2CComputation%2CRelatedSearches&domain=youchat&queryTraceId={}",
            urlEncode(prompt), createUuidString());
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        if (!m_cfg.http_proxy.empty())
            curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());
        auto cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
            boost::system::error_code err{};
            auto ch_ptr = static_cast<FreeGpt::Channel*>(userp);
            std::string data{(char*)contents, size * nmemb};
            if (data.starts_with(R"(event: youChatToken)")) {
                static std::string to_erase{"event: youChatToken\ndata: "};
                size_t pos = data.find(to_erase);
                if (pos != std::string::npos)
                    data.erase(pos, to_erase.length());
                nlohmann::json line_json = nlohmann::json::parse(data, nullptr, false);
                if (line_json.is_discarded()) {
                    SPDLOG_ERROR("json parse error: [{}]", data);
                    boost::asio::post(ch_ptr->get_executor(),
                                      [=] { ch_ptr->try_send(err, std::format("json parse error: [{}]", data)); });
                    return size * nmemb;
                }
                auto str = line_json["youChatToken"].get<std::string>();
                boost::asio::post(ch_ptr->get_executor(), [=] { ch_ptr->try_send(err, str); });
            }
            return size * nmemb;
        };
        size_t (*fn)(void* contents, size_t size, size_t nmemb, void* userp) = cb;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fn);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, ch.get());
        auto cookie_str =
            std::format("uuid_guest={}; safesearch_guest=Off; {}", createUuidString(), std::get<1>(cookie_cache));
        curl_easy_setopt(curl, CURLOPT_COOKIE, std::get<1>(cookie_cache).c_str());
        curlEasySetopt(curl);
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "referer: https://you.com/search?q=gpt4&tbm=youchat");
        headers = curl_slist_append(headers, "Accept: text/event-stream");
        ScopeExit auto_exit{[=] {
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }};
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
            boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, error_info); });
            return;
        }
        int32_t response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code != 200) {
            boost::asio::post(ch->get_executor(),
                              [=] { ch->try_send(err, std::format("you http code:{}", response_code)); });
        }
        {
            std::lock_guard lk(mtx);
            cookie_queue.push(std::move(cookie_cache));
        }
        return;
    });
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

    auto ret = co_await sendRequestRecvChunk(ch, client.value(), req, 200, [&ch](std::string str) {
        boost::system::error_code err{};
        ch->try_send(err, std::move(str));
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::codeLinkAva(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "ava-alpha-api.codelink.io";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36)"};

    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);

    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, "/api/chat", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "*/*");
    req.set("accept-language", "en,fr-FR;q=0.9,fr;q=0.8,es-ES;q=0.7,es;q=0.6,en-US;q=0.5,am;q=0.4,de;q=0.3");
    req.set("origin", "https://ava-ai-ef611.web.app");
    req.set("referer", "https://ava-ai-ef611.web.app/");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");

    constexpr std::string_view json_str = R"({
        "messages": [
            {
                "role": "user",
                "content": "hello"
            }
        ],
        "stream": true,
        "temperature": 0.6
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    request["messages"][0]["content"] = prompt;
    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    std::string recv;
    auto result = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch, &recv](std::string chunk_str) {
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
            auto fields = splitString(msg, "data:");
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

boost::asio::awaitable<void> FreeGpt::chatBase(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "www.chatbase.co";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36)"};

    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);

    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, "/api/fe/chat",
                                                                     11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "*/*");
    req.set("accept-language", "en,fr-FR;q=0.9,fr;q=0.8,es-ES;q=0.7,es;q=0.6,en-US;q=0.5,am;q=0.4,de;q=0.3");
    req.set("origin", "https://www.chatbase.co");
    req.set("referer", "https://www.chatbase.co/");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");

    constexpr std::string_view json_str = R"({
        "messages": [
            {
                "role": "user",
                "content": "hello"
            }
        ],
        "captchaCode": "hadsa",
        "chatId": "quran---tafseer-saadi-pdf-wbgknt7zn",
        "conversationId": "kcXpqEnqUie3dnJlsRi_O-quran---tafseer-saadi-pdf-wbgknt7zn"
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    request["messages"][0]["content"] = prompt;
    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    auto result = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch](std::string str) {
        boost::system::error_code err{};
        if (!str.empty())
            ch->try_send(err, str);
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aivvm(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    constexpr std::string_view host = "chat.aivvm.com";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0)"};

    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
    ctx.set_verify_mode(boost::asio::ssl::verify_none);

    auto client = co_await createHttpClient(ctx, host, port);
    if (!client.has_value()) {
        SPDLOG_ERROR("createHttpClient: {}", client.error());
        co_await ch->async_send(err, client.error(), use_nothrow_awaitable);
        co_return;
    }
    auto& stream_ = client.value();

    boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, "/api/chat", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "*/*");
    req.set("accept-language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
    req.set("origin", "https://chat.aivvm.com");
    req.set("referer", "https://chat.aivvm.com/zh");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");

    constexpr std::string_view json_str = R"({
        "model":{
            "id":"gpt-3.5-turbo",
            "name":"GPT-3.5",
            "maxLength":12000,
            "tokenLimit":4096
        },
        "messages":[
            {
                "role":"user",
                "content":"hello"
            }
        ],
        "key":"",
        "prompt":"You are ChatGPT, a large language model trained by OpenAI. Follow the user's instructions carefully. Respond using markdown.",
        "temperature":0.7
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    request["messages"] = getConversationJson(json);
    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    auto result = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch](std::string str) {
        boost::system::error_code err{};
        if (!str.empty())
            ch->try_send(err, str);
    });
    co_return;
}

boost::asio::awaitable<void> FreeGpt::ylokh(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    constexpr std::string_view host = "chatapi.ylokh.xyz";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0)"};

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
    req.set("Accept", "*/*");
    req.set("accept-language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2");
    req.set("origin", "https://chat.ylokh.xyz");
    req.set("referer", "https://chat.ylokh.xyz/");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");

    constexpr std::string_view json_str = R"({
        "messages":[
            {
                "role":"system",
                "content":"Carefully heed the user's instructions and follow the user's will to the best of your ability.\nRespond using Markdown."
            }
        ],
        "model":"gpt-3.5-turbo-16k",
        "temperature":1,
        "presence_penalty":0,
        "top_p":1,
        "frequency_penalty":0,
        "allow_fallback":true,
        "stream":true
    })";
    nlohmann::json request = nlohmann::json::parse(json_str, nullptr, false);

    auto conversation = getConversationJson(json);
    for (const auto& item : conversation)
        request["messages"].push_back(item);

    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    std::string recv;
    auto result = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch, &recv](std::string str) {
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

boost::asio::awaitable<void> FreeGpt::vitalentum(std::shared_ptr<Channel> ch, nlohmann::json json) {
    boost::system::error_code err{};
    ScopeExit auto_exit{[&] { ch->close(); }};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    constexpr std::string_view host = "app.vitalentum.io";
    constexpr std::string_view port = "443";

    constexpr std::string_view user_agent{
        R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36)"};

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
                                                                     "/api/converse-edge", 11};
    req.set(boost::beast::http::field::host, host);
    req.set(boost::beast::http::field::user_agent, user_agent);
    req.set("Accept", "text/event-stream");
    req.set("accept-language", "de,en-US;q=0.7,en;q=0.3");
    req.set("origin", "https://app.vitalentum.io");
    req.set("referer", "https://app.vitalentum.io/");
    req.set(boost::beast::http::field::content_type, "application/json");
    req.set("sec-fetch-dest", "empty");
    req.set("sec-fetch-mode", "cors");
    req.set("sec-fetch-site", "same-origin");

    constexpr std::string_view conversation_str{R"({"history": [{"speaker": "human", "text": ""}]})"};
    nlohmann::json conversation_json = nlohmann::json::parse(conversation_str, nullptr, false);
    conversation_json["history"][0]["text"] = std::move(prompt);

    constexpr std::string_view request_str{R"({
        "conversation":"{\"history\": [{\"speaker\": \"human\", \"text\": \"hello\"}]}",
        "temperature":0.7
    })"};
    nlohmann::json request = nlohmann::json::parse(request_str, nullptr, false);

    request["conversation"] = conversation_json.dump();

    SPDLOG_INFO("{}", request.dump(2));

    req.body() = request.dump();
    req.prepare_payload();

    std::string recv;
    auto result = co_await sendRequestRecvChunk(ch, stream_, req, 200, [&ch, &recv](std::string str) {
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

boost::asio::awaitable<void> FreeGpt::gptGo(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));

    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
    auto get_token_url =
        std::format("https://gptgo.ai/action_get_token.php?q={}&hlgpt=default&hl=en", urlEncode(prompt));
    curl_easy_setopt(curl, CURLOPT_URL, get_token_url.c_str());
    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());
    auto cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto recv_ptr = static_cast<std::string*>(userp);
        std::string data{(char*)contents, size * nmemb};
        recv_ptr->append(data);
        return size * nmemb;
    };
    std::string recv_str;
    size_t (*fn)(void* contents, size_t size, size_t nmemb, void* userp) = cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recv_str);

    ScopeExit auto_exit{[=] { curl_easy_cleanup(curl); }};
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
    int32_t response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    SPDLOG_INFO("recv_str: [{}]", recv_str);
    nlohmann::json line_json = nlohmann::json::parse(recv_str, nullptr, false);
    if (line_json.is_discarded()) {
        SPDLOG_ERROR("json parse error: [{}]", recv_str);
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("json parse error:{}", recv_str));
        co_return;
    }
    auto status = line_json["status"].get<bool>();
    if (!status) {
        SPDLOG_ERROR("status is false: [{}]", recv_str);
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, recv_str);
        co_return;
    }
    auto token = line_json["token"].get<std::string>();
    SPDLOG_INFO("token: [{}]", token);

    auto url = std::format("https://gptgo.ai/action_ai_gpt.php?token={}", token);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());

    struct Input {
        std::shared_ptr<Channel> ch;
        std::string recv;
    };
    Input input{ch};
    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch, recv] = *input_ptr;
        recv.append(data);
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
                boost::asio::post(ch->get_executor(),
                                  [=] { ch->try_send(err, std::format("json parse error: [{}]", fields.back())); });
                continue;
            }
            auto str = line_json["choices"][0]["delta"]["content"].get<std::string>();
            if (!str.empty() && str != "[DONE]")
                boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, str); });
        }
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        ch->try_send(err, error_info);
        co_return;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aiTianhuSpace(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));

    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
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
    auto url = std::format("https://{}.aitianhu.space/api/chat-process", random(6));
    SPDLOG_INFO("url: [{}]", url);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());

    struct Input {
        std::shared_ptr<Channel> ch;
        std::string recv;
    };
    Input input{ch};
    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch, recv] = *input_ptr;
        recv.append(data);
        while (true) {
            auto position = recv.find("\n");
            if (position == std::string::npos)
                break;
            auto msg = recv.substr(0, position + 1);
            recv.erase(0, position + 1);
            msg.pop_back();
            if (msg.empty() || !msg.contains("content"))
                continue;
            boost::system::error_code err{};
            nlohmann::json line_json = nlohmann::json::parse(msg, nullptr, false);
            if (line_json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", msg);
                boost::asio::post(ch->get_executor(),
                                  [=] { ch->try_send(err, std::format("json parse error: [{}]", msg)); });
                continue;
            }
            auto str = line_json["detail"]["choices"][0]["delta"]["content"].get<std::string>();
            if (!str.empty())
                boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, str); });
        }
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    constexpr std::string_view request_str{R"({
        "prompt":"hello",
        "options":{},
        "systemMessage":"You are ChatGPT, a large language model trained by OpenAI. Follow the user's instructions carefully.",
        "temperature":0.8,
        "top_p":1
    })"};
    nlohmann::json request = nlohmann::json::parse(request_str, nullptr, false);
    request["prompt"] = prompt;
    auto str = request.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    ScopeExit auto_exit{[=] {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }};

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        ch->try_send(err, error_info);
        co_return;
    }
    int32_t response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::aibn(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));

    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, "https://aibn.cc/api/generate");
    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());

    struct Input {
        std::shared_ptr<Channel> ch;
        std::string recv;
    };
    Input input{ch};
    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch, recv] = *input_ptr;
        boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, data); });
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    auto generate_signature = [](int timestamp, const std::string& message, const std::string& secret = "undefined") {
        std::stringstream ss;
        ss << timestamp << ":" << message << ":" << secret;
        std::string data = ss.str();

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);

        std::stringstream sha_stream;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sha_stream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(digest[i]);
        }
        return sha_stream.str();
    };
    uint64_t timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string signature = generate_signature(timestamp, prompt);

    constexpr std::string_view request_str{R"({
        "messages":[
            {
                "role":"user",
                "content":"hello"
            }
        ],
        "pass":null,
        "sign":"7c2700b5813053ff8000cb9fb1ebdadbfcf62882829da59e4474bee466de7c89",
        "time":1695716667
    })"};
    nlohmann::json request = nlohmann::json::parse(request_str, nullptr, false);

    request["sign"] = signature;
    request["time"] = timestamp;
    request["messages"] = getConversationJson(json);

    auto str = request.dump();
    SPDLOG_INFO("request : [{}]", str);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    ScopeExit auto_exit{[=] {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }};

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        ch->try_send(err, error_info);
        co_return;
    }
    int32_t response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::chatGptDuo(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));

    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "https://chatgptduo.com/");
    auto request_data = urlEncode(std::format("prompt=('{}',)&search=('{}',)&purpose=ask", prompt, prompt));
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_data.c_str());

    struct Input {
        std::shared_ptr<Channel> ch;
    };
    Input input{ch};
    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch] = *input_ptr;
        boost::asio::post(ch->get_executor(), [=, data = std::move(data)] mutable {
            nlohmann::json json = nlohmann::json::parse(data, nullptr, false);
            if (json.is_discarded()) {
                SPDLOG_ERROR("json parse error: [{}]", data);
                ch->try_send(err, data);
                return;
            }
            if (json.contains("answer")) {
                auto str = json["answer"].get<std::string>();
                ch->try_send(err, str);
            } else {
                ch->try_send(err, std::format("Invalid JSON: {}", json.dump()));
            }
            return;
        });
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    ScopeExit auto_exit{[=] {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }};

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        ch->try_send(err, error_info);
        co_return;
    }
    int32_t response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::chatForAi(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));

    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, "https://chatforai.com/api/handle/provider-openai");
    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());

    struct Input {
        std::shared_ptr<Channel> ch;
        std::string recv;
    };
    Input input{ch};
    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch, recv] = *input_ptr;
        boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, data); });
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    auto generate_signature = [](int timestamp, const std::string& conversation_id, const std::string& message) {
        std::stringstream ss;
        ss << timestamp << ":" << conversation_id << ":" << message << ":6B46K4pt";
        std::string data = ss.str();

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);

        std::stringstream sha_stream;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sha_stream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(digest[i]);
        }
        return sha_stream.str();
    };
    uint64_t timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto onversation_id = std::format("id_{}", timestamp);
    std::string signature = generate_signature(timestamp, onversation_id, prompt);

    constexpr std::string_view request_str{R"({
        "conversationId": "id_1696338587",
        "conversationType": "chat_continuous",
        "botId": "chat_continuous",
        "globalSettings": {
            "baseUrl": "https://api.openai.com",
            "model": "gpt-3.5-turbo",
            "messageHistorySize": 5,
            "temperature": 0.7,
            "top_p": 1,
            "stream": true
        },
        "botSettings": {},
        "prompt": "hello",
        "messages": [{
            "role": "user",
            "content": "hello"
        }],
        "sign": "1505ec882d72d5f3175a74ac84d665b1b904e6671b2e7334268f540975929a26",
        "timestamp": 1696338587
    })"};
    nlohmann::json request = nlohmann::json::parse(request_str, nullptr, false);

    request["sign"] = signature;
    request["conversationId"] = onversation_id;
    request["messages"] = getConversationJson(json);
    request["timestamp"] = timestamp;

    auto str = request.dump();
    SPDLOG_INFO("request : [{}]", str);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    ScopeExit auto_exit{[=] {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }};

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        ch->try_send(err, error_info);
        co_return;
    }
    int32_t response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> FreeGpt::freeGpt(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));

    boost::system::error_code err{};
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    CURLcode res;
    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, "https://k.aifree.site/api/generate");
    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());

    struct Input {
        std::shared_ptr<Channel> ch;
        std::string recv;
    };
    Input input{ch};
    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        boost::system::error_code err{};
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch, recv] = *input_ptr;
        boost::asio::post(ch->get_executor(), [=] { ch->try_send(err, data); });
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curlEasySetopt(curl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    auto generate_signature = [](int timestamp, const std::string& message, const std::string& secret = "") {
        std::stringstream ss;
        ss << timestamp << ":" << message << ":" << secret;
        std::string data = ss.str();

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);

        std::stringstream sha_stream;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sha_stream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(digest[i]);
        }
        return sha_stream.str();
    };
    uint64_t timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string signature = generate_signature(timestamp, prompt);

    constexpr std::string_view request_str{R"({
        "messages":[
            {
                "role":"user",
                "content":"hello"
            }
        ],
        "pass":null,
        "sign":"7c2700b5813053ff8000cb9fb1ebdadbfcf62882829da59e4474bee466de7c89",
        "time":1695716667
    })"};
    nlohmann::json request = nlohmann::json::parse(request_str, nullptr, false);

    request["sign"] = signature;
    request["time"] = timestamp;
    request["messages"] = getConversationJson(json);

    auto str = request.dump();
    SPDLOG_INFO("request : [{}]", str);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str.c_str());

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    ScopeExit auto_exit{[=] {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }};

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        auto error_info = std::format("curl_easy_perform() failed:{}", curl_easy_strerror(res));
        ch->try_send(err, error_info);
        co_return;
    }
    int32_t response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("you http code:{}", response_code));
        co_return;
    }
    co_return;
}