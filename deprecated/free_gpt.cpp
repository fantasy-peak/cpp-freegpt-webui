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
