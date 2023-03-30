#pragma once

#include <memory>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>
#include <yamail/resource_pool/async/pool.hpp>

#include "cfg.h"

struct HttpClient {
    HttpClient() {
        ctx = std::make_shared<boost::asio::ssl::context>(
            boost::asio::ssl::context::tls);
        ctx->set_verify_mode(boost::asio::ssl::verify_none);
    }

    std::shared_ptr<boost::asio::ssl::context> ctx;
    std::shared_ptr<boost::beast::ssl_stream<boost::beast::tcp_stream>> stream;
};

class FreeGpt final {
public:
    using Channel = boost::asio::experimental::channel<void(
        boost::system::error_code, std::string)>;
    using HttpClientPool =
        yamail::resource_pool::async::pool<std::unique_ptr<HttpClient>>;

    FreeGpt(Config&);

    boost::asio::awaitable<void> getgpt(std::shared_ptr<Channel> ch,
                                        nlohmann::json json,
                                        HttpClientPool::handle handle);
    boost::asio::awaitable<void> deepai(std::shared_ptr<Channel> ch,
                                        nlohmann::json json,
                                        HttpClientPool::handle handle);
    boost::asio::awaitable<void> aitianhu(std::shared_ptr<Channel> ch,
                                          nlohmann::json json,
                                          HttpClientPool::handle handle);
    boost::asio::awaitable<void> aichat(std::shared_ptr<Channel> ch,
                                        nlohmann::json json,
                                        HttpClientPool::handle handle);

private:
    Config& m_cfg;
};
