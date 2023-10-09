#pragma once

#include <expected>
#include <memory>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>

#include "cfg.h"

class FreeGpt final {
public:
    using Channel = boost::asio::experimental::channel<void(boost::system::error_code, std::string)>;

    FreeGpt(Config&);

    boost::asio::awaitable<void> deepAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatGptAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> openAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> h2o(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> yqcloud(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> huggingChat(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> you(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> binjie(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatBase(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aivvm(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> ylokh(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> vitalentum(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> gptGo(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aibn(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatGptDuo(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatForAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> freeGpt(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatGpt4Online(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> gptalk(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> gptForLove(std::shared_ptr<Channel>, nlohmann::json);

private:
    boost::asio::awaitable<std::expected<boost::beast::ssl_stream<boost::beast::tcp_stream>, std::string>>
    createHttpClient(boost::asio::ssl::context&, std::string_view /* host */, std::string_view /* port */);

    Config& m_cfg;
    std::shared_ptr<boost::asio::thread_pool> m_thread_pool_ptr;
};
