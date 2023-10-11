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

boost::asio::awaitable<void> FreeGpt::gptgod(std::shared_ptr<Channel> ch, nlohmann::json json) {
    co_await boost::asio::post(boost::asio::bind_executor(*m_thread_pool_ptr, boost::asio::use_awaitable));
    ScopeExit _exit{[=] { boost::asio::post(ch->get_executor(), [=] { ch->close(); }); }};
    boost::system::error_code err{};

    auto prompt = json.at("meta").at("content").at("parts").at(0).at("content").get<std::string>();

    auto generate_token_hex = [](int32_t length) {
        std::random_device rd;
        std::stringstream ss;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        for (int i = 0; i < length; ++i)
            ss << std::hex << dis(gen);
        std::string token = ss.str();
        token = std::string(length * 2 - token.length(), '0') + token;
        return token;
    };

    CURLcode res;
    int32_t response_code;

    struct Input {
        std::shared_ptr<Channel> ch;
        std::string recv;
    };
    Input input{ch};

    CURL* curl = curl_easy_init();
    if (!curl) {
        auto error_info = std::format("curl_easy_init() failed:{}", curl_easy_strerror(res));
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, error_info);
        co_return;
    }
    auto url = std::format("https://gptgod.site/api/session/free/gpt3p5?content={}&id={}", urlEncode(prompt),
                           generate_token_hex(16));
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    if (!m_cfg.http_proxy.empty())
        curl_easy_setopt(curl, CURLOPT_PROXY, m_cfg.http_proxy.c_str());
    curlEasySetopt(curl);

    auto action_cb = [](void* contents, size_t size, size_t nmemb, void* userp) -> size_t {
        auto input_ptr = static_cast<Input*>(userp);
        std::string data{(char*)contents, size * nmemb};
        auto& [ch, recv] = *input_ptr;
        recv.append(data);
        auto remove_quotes = [](const std::string& str) {
            std::string result = str;
            if (result.size() >= 2 && result.front() == '"' && result.back() == '"') {
                result.erase(0, 1);
                result.erase(result.size() - 1);
            }
            return result;
        };
        while (true) {
            auto position = recv.find("\n");
            if (position == std::string::npos)
                break;
            auto msg = recv.substr(0, position + 1);
            recv.erase(0, position + 1);
            msg.pop_back();
            if (msg.empty() || !msg.starts_with("data: "))
                continue;
            msg.erase(0, 6);
            boost::system::error_code err{};
            msg = remove_quotes(msg);
            if (msg.empty())
                continue;
            boost::asio::post(ch->get_executor(), [=, content = std::move(msg)] { ch->try_send(err, content); });
        }
        return size * nmemb;
    };
    size_t (*action_fn)(void* contents, size_t size, size_t nmemb, void* userp) = action_cb;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, action_fn);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &input);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Referer: https://gptgod.site/");
    headers = curl_slist_append(headers, "Alt-Used: gptgod.site");
    headers = curl_slist_append(headers, "Accept: text/event-stream");
    uint64_t timestamp =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto auth_timestamp = std::format("x-auth-timestamp: {}", timestamp);
    headers = curl_slist_append(headers, auth_timestamp.c_str());
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
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        co_await boost::asio::post(boost::asio::bind_executor(ch->get_executor(), boost::asio::use_awaitable));
        ch->try_send(err, std::format("gptgod http code:{}", response_code));
        co_return;
    }
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

boost::asio::awaitable<void> FreeGpt::cromicle(std::shared_ptr<Channel> ch, nlohmann::json json) {
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
    curl_easy_setopt(curl, CURLOPT_URL, "https://cromicle.top/chat");
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

    auto generate_signature = [](const std::string& message) {
        std::stringstream ss;
        ss << "asdap" << message;
        std::string data = ss.str();

        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);

        std::stringstream sha_stream;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sha_stream << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(digest[i]);
        }
        return sha_stream.str();
    };
    std::string signature = generate_signature(prompt);

    constexpr std::string_view request_str{R"({
        "message": "hello",
        "hash": "dda6ea4e1dc215f198084018b1df20cfeafe9fbdfe31d8a350d6917509158d8a",
        "token": "asdap"
    })"};
    nlohmann::json request = nlohmann::json::parse(request_str, nullptr, false);

    request["hash"] = signature;
    request["message"] = prompt;

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
