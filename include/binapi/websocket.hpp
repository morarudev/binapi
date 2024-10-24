
// ----------------------------------------------------------------------------
//                              Apache License
//                        Version 2.0, January 2004
//                     http://www.apache.org/licenses/
//
// This file is part of binapi(https://github.com/niXman/binapi) project.
//
// Copyright (c) 2019-2021 niXman (github dot nixman dog pm.me). All rights reserved.
// ----------------------------------------------------------------------------

#ifndef __binapi__websocket_hpp
#define __binapi__websocket_hpp

#define BINAPI_EXPORTS

#ifdef BINAPI_EXPORTS
#define BINAPI_API __declspec(dllexport)
#else
#define BINAPI_API __declspec(dllimport)
#endif

#include "message.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <boost/callable_traits.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <boost/intrusive/set.hpp>

#include <map>
#include <set>
#include <cstring>

#include "enums.hpp"

#include <memory>
#include <functional>
#include <string>

#define __BINAPI_CB_ON_ERROR(cb, ec) \
    cb(__FILE__ "(" BOOST_PP_STRINGIZE(__LINE__) ")", ec.value(), ec.message(), nullptr, 0);


namespace boost {
namespace asio {
class io_context;
} // ns asio
} // ns boost

namespace binapi {
namespace userdata {

struct account_update_t;
struct balance_update_t;
struct order_update_t;

} // ns userdata

namespace ws {

struct part_depths_t;
struct diff_depths_t;
struct trade_t;
struct agg_trade_t;
struct kline_t;
struct mini_ticker_t;
struct mini_tickers_t;
struct market_ticker_t;
struct markets_tickers_t;
struct book_ticker_t;

/*************************************************************************************************/


struct websocket : std::enable_shared_from_this<websocket> {
    friend struct websockets;

    explicit websocket(boost::asio::io_context& ioctx)
        :m_ioctx{ ioctx }
        , m_ssl{ boost::asio::ssl::context::sslv23_client }
        , m_resolver{ m_ioctx }
        , m_ws{ m_ioctx, m_ssl }
        , m_buf{}
        , m_host{}
        , m_target{}
        , m_stop_requested{}
    {}
    virtual ~websocket()
    {}

    using holder_type = std::shared_ptr<websocket>;

    template<typename CB>
    void async_start(
        const std::string& host
        , const std::string& port
        , const std::string& target
        , CB cb
        , holder_type holder
    ) {
        m_host = host;
        m_target = target;

        m_resolver.async_resolve(
            m_host
            , port
            , [this, cb = std::move(cb), holder = std::move(holder)]
            (boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type res) mutable {
                if (ec) {
                    if (!m_stop_requested) { __BINAPI_CB_ON_ERROR(cb, ec); }
                }
                else {
                    async_connect(std::move(res), std::move(cb), std::move(holder));
                }
            }
        );
    }

    void stop() {
        m_stop_requested = true;

        if (m_ws.next_layer().next_layer().is_open()) {
            boost::system::error_code ec;
            m_ws.close(boost::beast::websocket::close_code::normal, ec);
        }
    }

    void async_stop() {
        m_stop_requested = true;
        holder_type holder = shared_from_this();

        if (m_ws.next_layer().next_layer().is_open()) {
            m_ws.async_close(
                boost::beast::websocket::close_code::normal
                , [holder = std::move(holder)](const boost::system::error_code&) {}
            );
        }
    }

private:
    template<typename CB>
    void async_connect(boost::asio::ip::tcp::resolver::results_type res, CB cb, holder_type holder) {
        if (!SSL_set_tlsext_host_name(m_ws.next_layer().native_handle(), m_host.c_str())) {
            auto error_code = boost::beast::error_code(
                static_cast<int>(::ERR_get_error())
                , boost::asio::error::get_ssl_category()
            );

            __BINAPI_CB_ON_ERROR(cb, error_code);

            return;
        }

        boost::asio::async_connect(
            m_ws.next_layer().next_layer()
            , res.begin()
            , res.end()
            , [this, cb = std::move(cb), holder = std::move(holder)]
            (boost::system::error_code ec, boost::asio::ip::tcp::resolver::iterator) mutable {
                if (ec) {
                    if (!m_stop_requested) { __BINAPI_CB_ON_ERROR(cb, ec); }
                }
                else {
                    on_connected(std::move(cb), std::move(holder));
                }
            }
        );
    }
    template<typename CB>
    void on_connected(CB cb, holder_type holder) {
        m_ws.control_callback(
            [this]
            (boost::beast::websocket::frame_type kind, boost::beast::string_view payload) mutable {
                (void)kind; (void)payload;
                //std::cout << "control_callback(" << this << "): kind=" << static_cast<int>(kind) << ", payload=" << payload.data() << std::endl;
                m_ws.async_pong(
                    boost::beast::websocket::ping_data{}
                    , [](boost::beast::error_code ec)
                    { (void)ec; /*std::cout << "control_callback_cb(" << this << "): ec=" << ec << std::endl;*/ }
                );
            }
        );

        m_ws.next_layer().async_handshake(
            boost::asio::ssl::stream_base::client
            , [this, cb = std::move(cb), holder = std::move(holder)]
            (boost::system::error_code ec) mutable {
                if (ec) {
                    if (!m_stop_requested) { __BINAPI_CB_ON_ERROR(cb, ec); }
                }
                else {
                    on_async_ssl_handshake(std::move(cb), std::move(holder));
                }
            }
        );
    }
    template<typename CB>
    void on_async_ssl_handshake(CB cb, holder_type holder) {
        m_ws.async_handshake(
            m_host
            , m_target
            , [this, cb = std::move(cb), holder = std::move(holder)]
            (boost::system::error_code ec) mutable
            { start_read(ec, std::move(cb), std::move(holder)); }
        );
    }
    template<typename CB>
    void start_read(boost::system::error_code ec, CB cb, holder_type holder) {
        if (ec) {
            if (!m_stop_requested) {
                __BINAPI_CB_ON_ERROR(cb, ec);
            }

            stop();

            return;
        }

        m_ws.async_read(
            m_buf
            , [this, cb = std::move(cb), holder = std::move(holder)]
            (boost::system::error_code ec, std::size_t rd) mutable
            { on_read(ec, rd, std::move(cb), std::move(holder)); }
        );
    }
    template<typename CB>
    void on_read(boost::system::error_code ec, std::size_t rd, CB cb, holder_type holder) {
        if (ec) {
            if (!m_stop_requested) {
                __BINAPI_CB_ON_ERROR(cb, ec);
            }

            stop();

            return;
        }

        auto size = m_buf.size();
        assert(size == rd);

        std::string strbuf;
        strbuf.reserve(size);

        for (const auto& it : m_buf.data()) {
            strbuf.append(static_cast<const char*>(it.data()), it.size());
        }
        m_buf.consume(m_buf.size());

        bool ok = cb(nullptr, 0, std::string{}, strbuf.data(), strbuf.size());
        if (!ok) {
            stop();
        }
        else {
            start_read(boost::system::error_code{}, std::move(cb), std::move(holder));
        }
    }

    boost::asio::io_context& m_ioctx;
    boost::asio::ssl::context m_ssl;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> m_ws;
    boost::beast::multi_buffer m_buf;
    std::string m_host;
    std::string m_target;
    bool m_stop_requested;
    boost::intrusive::set_member_hook<> m_intrusive_set_hook;
};


struct websocket_id_getter {
    using type = const void*;
    type operator()(const websocket& sock) const { return std::addressof(sock); }
};



struct BINAPI_API websockets final {
public:
    websockets(const websockets &) = delete;
    websockets& operator= (const websockets &) = delete;
    websockets(websockets &&) noexcept = default;
    websockets& operator= (websockets &&) noexcept = default;

    using on_message_received_cb = std::function<void(const char *channel, const char *ptr, std::size_t size)>;
    using on_network_stat_cb = std::function<
        void(std::size_t msg_recvd, std::size_t msg_recvd_avg, std::size_t bytes_recvd, std::size_t bytes_recvd_avg)
    >;

    websockets(
         boost::asio::io_context &ioctx
        ,std::string host
        ,std::string port
        ,on_message_received_cb msg_cb = {}
        ,on_network_stat_cb stat_cb = {}
        ,std::size_t stat_interval = 1 // in seconds
    );
    ~websockets();

    using handle = void *;

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#partial-book-depth-streams
    using on_part_depths_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, part_depths_t msg)>;
    handle part_depth(const char *pair, e_levels level, e_freq freq, on_part_depths_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#diff-depth-stream
    using on_diff_depths_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, diff_depths_t msg)>;
    handle diff_depth(const char *pair, e_freq freq, on_diff_depths_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#klinecandlestick-streams
    using on_kline_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, kline_t msg)>;
    // interval - 1s, 1m, 3m, 5m, 15m, 30m, 1h, 2h, 4h, 6h, 8h, 12h, 1d, 3d, 1w, 1M
    handle klines(const char *pair, const char *interval, on_kline_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#trade-streams
    using on_trade_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, trade_t msg)>;
    handle trade(const char *pair, on_trade_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#aggregate-trade-streams
    using on_agg_trade_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, agg_trade_t msg)>;
    handle agg_trade(const char *pair, on_agg_trade_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#individual-symbol-mini-ticker-stream
    using on_mini_ticker_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, mini_ticker_t msg)>;
    handle mini_ticker(const char *pair, on_mini_ticker_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#all-market-mini-tickers-stream
    using on_mini_tickers_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, mini_tickers_t msg)>;
    handle mini_tickers(on_mini_tickers_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#individual-symbol-ticker-streams
    using on_market_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, market_ticker_t msg)>;
    handle market(const char *pair, on_market_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#all-market-tickers-stream
    using on_markets_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, markets_tickers_t msg)>;
    handle markets(on_markets_received_cb cb);

    // https://github.com/binance/binance-spot-api-docs/blob/master/web-socket-streams.md#individual-symbol-book-ticker-streams
    using on_book_received_cb = std::function<bool(const char *fl, int ec, std::string errmsg, book_ticker_t msg)>;
    handle book(const char *pair, on_book_received_cb cb);

    using on_account_update_cb = std::function<bool(const char *fl, int ec, std::string errmsg, userdata::account_update_t msg)>;
    using on_balance_update_cb = std::function<bool(const char *fl, int ec, std::string errmsg, userdata::balance_update_t msg)>;
    using on_order_update_cb = std::function<bool(const char *fl, int ec, std::string errmsg, userdata::order_update_t msg)>;
    handle userdata(
         const char *lkey
        ,on_account_update_cb account_update
        ,on_balance_update_cb balance_update
        ,on_order_update_cb order_update
    );

    void unsubscribe(const handle &h);
    void async_unsubscribe(const handle &h);
    void unsubscribe_all();
    void async_unsubscribe_all();

private:
    /*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

    struct impl {
        impl(
            boost::asio::io_context& ioctx
            , std::string host
            , std::string port
            , on_message_received_cb msg_cb
            , on_network_stat_cb stat_cb
            , std::size_t stat_interval
        )
            :m_ioctx{ ioctx }
            , m_host{ std::move(host) }
            , m_port{ std::move(port) }
            , m_on_message{ std::move(msg_cb) }
            , m_on_stat{ std::move(stat_cb) }
            , m_stat_interval{ stat_interval }
            , m_set{}
        {}
        ~impl() {
            unsubscribe_all();
        }

        static std::string make_channel_name(const char* pair, const char* channel) {
            std::string res{ "/ws/" };
            if (pair) {
                res += pair;
                if (*pair != '!') {
                    boost::algorithm::to_lower(res);
                }

                res += '@';
            }

            res += channel;

            return res;
        }

        template<typename F>
        websockets::handle start_channel(const char* pair, const char* channel, F cb) {
            using args_tuple = typename boost::callable_traits::args<F>::type;
            using message_type = typename std::tuple_element<3, args_tuple>::type;

            static const auto deleter = [this](websocket* ws) {
                auto it = m_set.find(ws);
                if (it != m_set.end()) {
                    m_set.erase(it);
                }

                delete ws;
                };
            std::shared_ptr<websocket> ws{ new websocket(m_ioctx), deleter };
            std::string schannel = make_channel_name(pair, channel);

            auto wscb = [this, schannel, cb = std::move(cb)]
            (const char* fl, int ec, std::string errmsg, const char* ptr, std::size_t size) -> bool
                {
                    if (ec) {
                        try {
                            cb(fl, ec, std::move(errmsg), message_type{});
                        }
                        catch (const std::exception& ex) {
                            std::fprintf(stderr, "%s: %s\n", __MAKE_FILELINE, ex.what());
                            std::fflush(stderr);
                        }

                        return false;
                    }

                    const flatjson::fjson json{ ptr, size };
                    if (json.is_object() && binapi::rest::is_api_error(json)) {
                        auto error = binapi::rest::construct_error(json);
                        auto ecode = error.first;
                        auto emsg = std::move(error.second);

                        try {
                            message_type message{};
                            return cb(__MAKE_FILELINE, ecode, std::move(emsg), std::move(message));
                        }
                        catch (const std::exception& ex) {
                            std::fprintf(stderr, "%s: %s\n", __MAKE_FILELINE, ex.what());
                            std::fflush(stderr);
                        }
                    }

                    try {
                        if (m_on_message) { m_on_message(schannel.c_str(), ptr, size); }
                    }
                    catch (const std::exception& ex) {
                        std::fprintf(stderr, "%s: %s\n", __MAKE_FILELINE, ex.what());
                        std::fflush(stderr);
                    }

                    try {
                        message_type message = message_type::construct(json);
                        return cb(nullptr, 0, std::string{}, std::move(message));
                    }
                    catch (const std::exception& ex) {
                        std::fprintf(stderr, "%s: %s\n", __MAKE_FILELINE, ex.what());
                        std::fflush(stderr);
                    }

                    return false;
                };

            auto* ws_ptr = ws.get();
            ws_ptr->async_start(
                m_host
                , m_port
                , schannel
                , std::move(wscb)
                , std::move(ws)
            );

            m_set.insert(*ws_ptr);

            return ws_ptr;
        }

        template<typename F>
        void stop_channel_impl(handle h, F f) {
            auto it = m_set.find(h);
            if (it == m_set.end()) { return; }

            auto* ws = static_cast<websocket*>(&(*it));
            f(ws);

            m_set.erase(it);
        }

        void stop_channel(handle h) {
            return stop_channel_impl(h, [](auto sp) { sp->stop(); });
        }
        void async_stop_channel(handle h) {
            return stop_channel_impl(h, [](auto sp) { sp->async_stop(); });
        }

        template<typename F>
        void unsubscribe_all_impl(F f) {
            for (auto it = m_set.begin(); it != m_set.end(); ) {
                auto* ws = static_cast<websocket*>(&(*it));
                f(ws);

                it = m_set.erase(it);
            }
        }
        void unsubscribe_all() {
            return unsubscribe_all_impl([](auto sp) { sp->stop(); });
        }
        void async_unsubscribe_all() {
            return unsubscribe_all_impl([](auto sp) { sp->async_stop(); });
        }

        boost::asio::io_context& m_ioctx;
        std::string m_host;
        std::string m_port;
        on_message_received_cb m_on_message;
        on_network_stat_cb m_on_stat;
        std::size_t m_stat_interval;
        boost::intrusive::set<
            websocket
            , boost::intrusive::key_of_value<websocket_id_getter>
            , boost::intrusive::member_hook<
            websocket
            , boost::intrusive::set_member_hook<>
            , &websocket::m_intrusive_set_hook
            >
        > m_set;
    };

    /*************************************************************************************************/
    std::unique_ptr<impl> pimpl;
};

/*************************************************************************************************/

} // ns ws
} // ns binapi

#endif // __binapi__websocket_hpp
