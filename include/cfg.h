#pragma once

#include <yaml_cpp_struct.hpp>

struct Config {
    std::string client_root_path;
    std::size_t interval{300};
    std::size_t work_thread_num{8};
    std::size_t max_http_client_num{2};
    std::string host{"127.0.0.1"};
    std::string port{"8858"};
    std::string chat_path{"/chat"};
    std::vector<std::string> providers;
};
YCS_ADD_STRUCT(Config, client_root_path, interval, work_thread_num, max_http_client_num, host, port, chat_path,
               providers)
