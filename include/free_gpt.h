#pragma once

#include <memory>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>

#include "cfg.h"

class FreeGpt final {
public:
    using Channel = boost::asio::experimental::channel<void(boost::system::error_code, std::string)>;

    FreeGpt(Config&);

    boost::asio::awaitable<void> getGpt(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> deepAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aiTianhu(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aiChat(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatGptAi(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> chatFree(std::shared_ptr<Channel>, nlohmann::json);
    boost::asio::awaitable<void> aiService(std::shared_ptr<Channel>, nlohmann::json);

private:
    Config& m_cfg;
};
