#pragma once

#include <yaml_cpp_struct.hpp>

struct Config {
    std::string client_root_path;
    std::size_t interval;
    std::size_t work_thread_num;
    std::string host;
    std::string port;
    std::string chat_path;
    std::vector<std::string> providers;
    bool enable_proxy;
    std::string http_proxy;
    std::string api_key;
    std::vector<std::string> ip_white_list;
    std::string zeus;
    std::string flaresolverr;
};
YCS_ADD_STRUCT(Config, client_root_path, interval, work_thread_num, host, port, chat_path, providers, enable_proxy,
               http_proxy, api_key, ip_white_list, zeus, flaresolverr)
