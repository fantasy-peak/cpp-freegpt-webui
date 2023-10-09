#pragma once

#include <yaml_cpp_struct.hpp>

struct Config {
    std::string client_root_path;
    std::size_t interval{300};
    std::size_t work_thread_num{8};
    std::string host{"0.0.0.0"};
    std::string port{"8858"};
    std::string chat_path{"/chat"};
    std::vector<std::string> providers;
    bool enable_proxy;
    std::string http_proxy;
    std::string api_key;
    std::vector<std::string> ip_white_list;
    std::string zeus{"http://127.0.0.1:8860"};
};
YCS_ADD_STRUCT(Config, client_root_path, interval, work_thread_num, host, port, chat_path, providers, enable_proxy,
               http_proxy, api_key, ip_white_list, zeus)
