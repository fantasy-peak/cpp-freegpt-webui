#pragma once

#include <expected>
#include <memory>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>

#include "cfg.h"

class FreeGpt final {
public:
    using Channel = boost::asio::experimental::channel<void(boost::system::error_code, std::string)>;

    FreeGpt(Config&);

    boost::asio::awaitable<void> aiTianhu(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> deepAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatFree(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> getGpt(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aiChat(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatGptAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aiService(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> weWordle(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> opChatGpts(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> easyChat(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> acytoo(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> openAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> h2o(std::shared_ptr<Channel> ch, nlohmann::json json);
    boost::asio::awaitable<void> v50(std::shared_ptr<Channel> ch, nlohmann::json json);
    boost::asio::awaitable<void> yqcloud(std::shared_ptr<Channel> ch, nlohmann::json json);
    boost::asio::awaitable<void> wuguokai(std::shared_ptr<Channel> ch, nlohmann::json json);
    boost::asio::awaitable<void> liaobots(std::shared_ptr<Channel> ch, nlohmann::json json);

private:
    boost::asio::awaitable<std::expected<boost::beast::ssl_stream<boost::beast::tcp_stream>, std::string>>
    createHttpClient(boost::asio::ssl::context& ctx, std::string_view host, std::string_view port);

    Config& m_cfg;
};
