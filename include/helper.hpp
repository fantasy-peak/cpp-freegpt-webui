#pragma once

#include <list>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

constexpr auto use_nothrow_awaitable = boost::asio::as_tuple(boost::asio::use_awaitable);

class IoContextPool final {
public:
    explicit IoContextPool(std::size_t);

    void start();
    void stop();

    boost::asio::io_context& getIoContext();

private:
    std::vector<std::shared_ptr<boost::asio::io_context>> m_io_contexts;
    std::list<boost::asio::any_io_executor> m_work;
    std::size_t m_next_io_context;
    std::vector<std::jthread> m_threads;
};

inline IoContextPool::IoContextPool(std::size_t pool_size) : m_next_io_context(0) {
    if (pool_size == 0)
        throw std::runtime_error("IoContextPool size is 0");
    for (std::size_t i = 0; i < pool_size; ++i) {
        auto io_context_ptr = std::make_shared<boost::asio::io_context>();
        m_io_contexts.emplace_back(io_context_ptr);
        m_work.emplace_back(
            boost::asio::require(io_context_ptr->get_executor(), boost::asio::execution::outstanding_work.tracked));
    }
}

inline void IoContextPool::start() {
    for (auto& context : m_io_contexts)
        m_threads.emplace_back(std::jthread([&] { context->run(); }));
}

inline void IoContextPool::stop() {
    for (auto& context_ptr : m_io_contexts)
        context_ptr->stop();
}

inline boost::asio::io_context& IoContextPool::getIoContext() {
    boost::asio::io_context& io_context = *m_io_contexts[m_next_io_context];
    ++m_next_io_context;
    if (m_next_io_context == m_io_contexts.size())
        m_next_io_context = 0;
    return io_context;
}

inline boost::asio::awaitable<void> timeout(std::chrono::seconds duration) {
    auto now = std::chrono::steady_clock::now() + duration;
    boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor);
    timer.expires_at(now);
    [[maybe_unused]] auto [ec] = co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    co_return;
}

template <typename... Args>
inline auto getEnv(Args&&... args) {
    auto impl = []<std::size_t... I>(auto&& tp, std::index_sequence<I...>) {
        auto func = [](std::string_view env_name) {
            const char* env = std::getenv(env_name.data());
            if (env == nullptr)
                return std::string{};
            return std::string{env};
        };
        return std::make_tuple(func(std::get<I>(tp))...);
    };
    return impl(std::forward_as_tuple(args...), std::index_sequence_for<Args...>{});
}

class ScopeExit {
public:
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;

    template <typename Callable>
    explicit ScopeExit(Callable&& call) : m_call(std::forward<Callable>(call)) {}

    ~ScopeExit() {
        if (m_call)
            m_call();
    }

    void clear() { m_call = decltype(m_call)(); }

private:
    std::function<void()> m_call;
};

inline std::string createUuidString() {
    static thread_local boost::uuids::random_generator gen;
    return boost::uuids::to_string(gen());
}

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
