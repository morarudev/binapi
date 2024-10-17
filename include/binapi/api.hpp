
// ----------------------------------------------------------------------------
//                              Apache License
//                        Version 2.0, January 2004
//                     http://www.apache.org/licenses/
//
// This file is part of binapi(https://github.com/niXman/binapi) project.
//
// Copyright (c) 2019-2021 niXman (github dot nixman dog pm.me). All rights reserved.
// ----------------------------------------------------------------------------

#ifndef __binapi__api_hpp
#define __binapi__api_hpp

#define BINAPI_EXPORTS

#ifdef BINAPI_EXPORTS
#define BINAPI_API __declspec(dllexport)
#else
#define BINAPI_API __declspec(dllimport)
#endif


/*************************************************************************************************/

#define __CATCH_BLOCK_WRITES_TO_STDOUT

#ifndef __CATCH_BLOCK_WRITES_TO_STDOUT
#   define  __CATCH_BLOCK_WRITES_TO_STDOUT_EXPAND_EXPR(...)
#else
#   define  __CATCH_BLOCK_WRITES_TO_STDOUT_EXPAND_EXPR(...) __VA_ARGS__
#endif // __CATCH_BLOCK_WRITES_TO_STDOUT

#define __CATCH_BLOCK_WITH_USERCODE(os, exception, ...) \
    catch (const exception &ex) { \
        __CATCH_BLOCK_WRITES_TO_STDOUT_EXPAND_EXPR( \
            os << __MESSAGE("[" BOOST_PP_STRINGIZE(exception) "]: " << ex.what()) << std::endl; \
        ) \
        { BOOST_PP_EXPAND __VA_ARGS__; } \
    }

#define __CATCH_BLOCK_WITHOUT_USERCODE(os, exception, ...) \
    catch (const exception &ex) { \
        __CATCH_BLOCK_WRITES_TO_STDOUT_EXPAND_EXPR( \
            os << __MESSAGE("[" BOOST_PP_STRINGIZE(exception) "]: " << ex.what()) << std::endl; \
        ) \
    }

#define __CATCH_BLOCK_CB(unused0, data, elem) \
    BOOST_PP_IF( \
         BOOST_PP_GREATER(BOOST_PP_TUPLE_SIZE(elem), 1) \
        ,__CATCH_BLOCK_WITH_USERCODE \
        ,__CATCH_BLOCK_WITHOUT_USERCODE \
    )( \
         data \
        ,BOOST_PP_TUPLE_ELEM(0, elem) \
        ,BOOST_PP_TUPLE_POP_FRONT(elem) \
    )

#define __CATCH_BLOCK_WRAP_X(...) ((__VA_ARGS__)) __CATCH_BLOCK_WRAP_Y
#define __CATCH_BLOCK_WRAP_Y(...) ((__VA_ARGS__)) __CATCH_BLOCK_WRAP_X
#define __CATCH_BLOCK_WRAP_X0
#define __CATCH_BLOCK_WRAP_Y0

#define __CATCH_BLOCK(os, seq) \
    BOOST_PP_SEQ_FOR_EACH( \
         __CATCH_BLOCK_CB \
        ,os \
        ,BOOST_PP_CAT(__CATCH_BLOCK_WRAP_X seq, 0) \
    )

#define __TRY_BLOCK() \
    try

/*************************************************************************************************/
#include <binapi/invoker.hpp>
#include <binapi/errors.hpp>

#include <boost/preprocessor.hpp>
#include <boost/callable_traits.hpp>
#include <boost/variant.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <chrono>
#include <queue>
#include <type_traits>
#include <iostream>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <binapi/flatjson.hpp>


#include "types.hpp"
#include "enums.hpp"

#include <memory>
#include <functional>

namespace boost {
namespace asio {

class io_context;

} // ns asio
} // ns boost

namespace binapi {
namespace rest {

/*************************************************************************************************/

class BINAPI_API api {
public:
    template<typename T>
    struct result {
        result()
            :ec{0}
        {}

        int ec;
        std::string errmsg;
        std::string reply;
        T v;

        // returns FALSE when error
        explicit operator bool() const { return errmsg.empty(); }
    };

    api(
         boost::asio::io_context &ioctx
        ,std::string host
        ,std::string port
        ,std::string pk
        ,std::string sk
        ,std::size_t timeout
        ,std::string client_api_string = "binapi-0.0.1"
    );
    virtual ~api();

    api(const api &) = delete;
    api(api &&) = default;

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#test-connectivity
    using ping_cb = std::function<bool(const char *fl, int ec, std::string errmsg, ping_t res)>;
    result<ping_t>
    ping(ping_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#check-server-time
    using server_time_cb = std::function<bool(const char *fl, int ec, std::string errmsg, server_time_t res)>;
    result<server_time_t>
    server_time(server_time_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#exchange-information
    using exchange_info_cb = std::function<bool(const char *fl, int ec, std::string errmsg, exchange_info_t res)>;
    result<exchange_info_t>
    exchange_info(exchange_info_cb cb = {});
    result<exchange_info_t>
    exchange_info(const char *symbol, exchange_info_cb cb = {});
    result<exchange_info_t>
    exchange_info(const std::string &symbol, exchange_info_cb cb = {}) { return exchange_info(symbol.c_str(), std::move(cb)); }
    result<exchange_info_t>
    exchange_info(const std::vector<std::string> &symbols, exchange_info_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#order-book
    using depths_cb = std::function<bool(const char *fl, int ec, std::string errmsg, depths_t res)>;
    result<depths_t>
    depths(const std::string &symbol, std::size_t limit, depths_cb cb = {}) { return depths(symbol.c_str(), limit, std::move(cb)); }
    result<depths_t>
    depths(const char *symbol, std::size_t limit, depths_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#recent-trades-list
    using trade_cb = std::function<bool(const char *fl, int ec, std::string errmsg, trades_t::trade_t res)>;
    result<trades_t::trade_t>
    trade(const std::string &symbol, trade_cb cb = {}) { return trade(symbol.c_str(), std::move(cb)); }
    result<trades_t::trade_t>
    trade(const char *symbol, trade_cb cb = {});

    using trades_cb = std::function<bool(const char *fl, int ec, std::string errmsg, trades_t res)>;
    result<trades_t>
    trades(const std::string &symbol, std::size_t limit, trades_cb cb = {}) { return trades(symbol.c_str(), limit, std::move(cb)); }
    result<trades_t>
    trades(const char *symbol, std::size_t limit, trades_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#symbol-price-ticker
    using price_cb = std::function<bool(const char *fl, int ec, std::string errmsg, prices_t::price_t res)>;
    result<prices_t::price_t>
    price(const std::string &symbol, price_cb cb = {}) { return price(symbol.c_str(), std::move(cb)); }
    result<prices_t::price_t>
    price(const char *symbol, price_cb cb = {});

    using prices_cb = std::function<bool(const char *fl, int ec, std::string errmsg, prices_t res)>;
    result<prices_t>
    prices(prices_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#current-average-price
    using avg_price_cb = std::function<bool(const char *fl, int ec, std::string errmsg, avg_price_t res)>;
    result<avg_price_t>
    avg_price(const char *symbol, avg_price_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#24hr-ticker-price-change-statistics
    using _24hrs_ticker_cb = std::function<bool(const char *fl, int ec, std::string errmsg, _24hrs_tickers_t::_24hrs_ticker_t res)>;
    result<_24hrs_tickers_t::_24hrs_ticker_t>
    _24hrs_ticker(const std::string &symbol, _24hrs_ticker_cb cb = {}) { return _24hrs_ticker(symbol.c_str(), std::move(cb)); }
    result<_24hrs_tickers_t::_24hrs_ticker_t>
    _24hrs_ticker(const char *symbol, _24hrs_ticker_cb cb = {});

    using _24hrs_tickers_cb = std::function<bool(const char *fl, int ec, std::string errmsg, _24hrs_tickers_t res)>;
    result<_24hrs_tickers_t>
    _24hrs_tickers(_24hrs_tickers_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#compressedaggregate-trades-list
    using agg_trade_cb = std::function<bool(const char *fl, int ec, std::string errmsg, agg_trades_t::agg_trade_t res)>;
    result<agg_trades_t::agg_trade_t>
    agg_trade(const std::string &symbol, agg_trade_cb cb = {}) { return agg_trade(symbol.c_str(), std::move(cb)); }
    result<agg_trades_t::agg_trade_t>
    agg_trade(const char *symbol, agg_trade_cb cb = {});

    using agg_trades_cb = std::function<bool(const char *fl, int ec, std::string errmsg, agg_trades_t res)>;
    result<agg_trades_t>
    agg_trades(const std::string &symbol, std::size_t limit, agg_trades_cb cb = {}) { return agg_trades(symbol.c_str(), limit, std::move(cb)); }
    result<agg_trades_t>
    agg_trades(const char *symbol, std::size_t limit, agg_trades_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#klinecandlestick-data
    using klines_cb = std::function<bool(const char *fl, int ec, std::string errmsg, klines_t res)>;
    result<klines_t>
    klines(const std::string &symbol, const std::string &interval, std::size_t limit, klines_cb cb = {}) { return klines(symbol.c_str(), interval.c_str(), limit, std::move(cb)); }
    result<klines_t>
    klines(const char *symbol, const char *interval, std::size_t limit, klines_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#account-information-user_data
    using account_info_cb = std::function<bool(const char *fl, int ec, std::string errmsg, account_info_t res)>;
    result<account_info_t>
    account_info(account_info_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#query-order-user_data
    using order_info_cb = std::function<bool(const char *fl, int ec, std::string errmsg, order_info_t res)>;
    result<order_info_t>
    order_info(const std::string &symbol, std::size_t orderid, const std::string &client_orderid = std::string{}, order_info_cb cb = {})
    { return order_info(symbol.c_str(), orderid, client_orderid.empty() ? nullptr : client_orderid.c_str(), std::move(cb)); }
    result<order_info_t>
    order_info(const char *symbol, std::size_t orderid, const char *client_orderid = nullptr, order_info_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#current-open-orders-user_data
    using open_orders_cb = std::function<bool(const char *fl, int ec, std::string errmsg, orders_info_t res)>;
    result<orders_info_t>
    open_orders(const std::string &symbol, open_orders_cb cb = {}) { return open_orders(symbol.c_str(), std::move(cb)); }
    result<orders_info_t>
    open_orders(const char *symbol, open_orders_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#all-orders-user_data
    using all_orders_cb = std::function<bool(const char *fl, int ec, std::string errmsg, orders_info_t res)>;
    result<orders_info_t>
    all_orders(
         const std::string &symbol
        ,std::size_t orderid = 0
        ,std::size_t start_time = 0
        ,std::size_t end_time = 0
        ,std::size_t limit = 0
        ,all_orders_cb cb = {}
    ) {
        return all_orders(
             symbol.empty() ? nullptr : symbol.c_str()
            ,orderid
            ,start_time
            ,end_time
            ,limit
            ,std::move(cb)
        );
    }
    result<orders_info_t>
    all_orders(
         const char *symbol
        ,std::size_t orderid = 0
        ,std::size_t start_time = 0
        ,std::size_t end_time = 0
        ,std::size_t limit = 0
        ,all_orders_cb cb = {}
    );

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#new-order--trade
    // NOTE: if 'ec' not zero - the 'res' arg is in undefined state.
    using new_order_cb = std::function<bool(const char *fl, int ec, std::string errmsg, new_order_resp_type res)>;
    result<new_order_resp_type>
    new_order(
         const std::string &symbol
        ,const e_side side
        ,const e_type type
        ,const e_time time
        ,const e_trade_resp_type resp
        ,const std::string &amount
        ,const std::string &price
        ,const std::string &client_order_id
        ,const std::string &stop_price
        ,const std::string &iceberg_amount
        ,new_order_cb cb = {}
    ) {
        return new_order(
             symbol.c_str()
            ,side
            ,type
            ,time
            ,resp
            ,(amount.empty() ? nullptr : amount.c_str())
            ,(price.empty() ? nullptr : price.c_str())
            ,(client_order_id.empty() ? nullptr : client_order_id.c_str())
            ,(stop_price.empty() ? nullptr : stop_price.c_str())
            ,(iceberg_amount.empty() ? nullptr : iceberg_amount.c_str())
            ,std::move(cb)
        );
    }
    result<new_order_resp_type>
    new_order(
         const char *symbol
        ,const e_side side
        ,const e_type type
        ,const e_time time
        ,const e_trade_resp_type resp
        ,const char *amount
        ,const char *price
        ,const char *client_order_id
        ,const char *stop_price
        ,const char *iceberg_amount
        ,new_order_cb cb = {}
    );

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#test-new-order-trade
    result<new_order_resp_type>
    new_test_order(
         const std::string &symbol
        ,const e_side side
        ,const e_type type
        ,const e_time time
        ,const e_trade_resp_type resp
        ,const std::string &amount
        ,const std::string &price
        ,const std::string &client_order_id
        ,const std::string &stop_price
        ,const std::string &iceberg_amount
        ,new_order_cb cb = {}
    ) {
        return new_test_order(
             symbol.c_str()
            ,side
            ,type
            ,time
            ,resp
            ,(amount.empty() ? nullptr : amount.c_str())
            ,(price.empty() ? nullptr : price.c_str())
            ,(client_order_id.empty() ? nullptr : client_order_id.c_str())
            ,(stop_price.empty() ? nullptr : stop_price.c_str())
            ,(iceberg_amount.empty() ? nullptr : iceberg_amount.c_str())
            ,std::move(cb)
        );
    }
    result<new_order_resp_type>
    new_test_order(
         const char *symbol
        ,const e_side side
        ,const e_type type
        ,const e_time time
        ,const e_trade_resp_type resp
        ,const char *amount
        ,const char *price
        ,const char *client_order_id
        ,const char *stop_price
        ,const char *iceberg_amount
        ,new_order_cb cb = {}
    );

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#cancel-order-trade
    using cancel_order_cb = std::function<bool(const char *fl, int ec, std::string errmsg, cancel_order_info_t res)>;
    result<cancel_order_info_t>
    cancel_order(
         const std::string &symbol
        ,std::size_t order_id
        ,const std::string &client_order_id
        ,const std::string &new_client_order_id
        ,cancel_order_cb cb = {}
    ) {
        return cancel_order(
             symbol.c_str()
            ,order_id
            ,(client_order_id.empty() ? nullptr : client_order_id.c_str())
            ,(new_client_order_id.empty() ? nullptr : new_client_order_id.c_str())
            ,std::move(cb)
        );
    }
    result<cancel_order_info_t>
    cancel_order(const char *symbol, std::size_t order_id, const char *client_order_id, const char *new_client_order_id, cancel_order_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#account-trade-list-user_data
    using my_trades_cb = std::function<bool(const char *fl, int ec, std::string errmsg, my_trades_info_t res)>;
    result<my_trades_info_t>
    my_trades(
         const std::string &symbol
        ,std::size_t start_time
        ,std::size_t end_time
        ,std::size_t from_id
        ,std::size_t limit
        ,my_trades_cb cb = {}
    )
    { return my_trades(symbol.c_str(), start_time, end_time, from_id, limit, std::move(cb)); }
    result<my_trades_info_t>
    my_trades(
         const char *symbol
        ,std::size_t start_time
        ,std::size_t end_time
        ,std::size_t from_id
        ,std::size_t limit
        ,my_trades_cb cb = {}
    );

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#start-user-data-stream-user_stream
    using start_user_data_stream_cb = std::function<bool(const char *fl, int ec, std::string errmsg, start_user_data_stream_t res)>;
    result<start_user_data_stream_t>
    start_user_data_stream(start_user_data_stream_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#keepalive-user-data-stream-user_stream
    using ping_user_data_stream_cb = std::function<bool(const char *fl, int ec, std::string errmsg, ping_user_data_stream_t res)>;
    result<ping_user_data_stream_t>
    ping_user_data_stream(const std::string &listen_key, ping_user_data_stream_cb cb = {}) { return ping_user_data_stream(listen_key.c_str(), std::move(cb)); }
    result<ping_user_data_stream_t>
    ping_user_data_stream(const char *listen_key, ping_user_data_stream_cb cb = {});

    // https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#close-user-data-stream-user_stream
    using close_user_data_stream_cb = std::function<bool(const char *fl, int ec, std::string errmsg, close_user_data_stream_t res)>;
    result<close_user_data_stream_t>
    close_user_data_stream(const std::string &listen_key, close_user_data_stream_cb cb = {}) { return close_user_data_stream(listen_key.c_str(), std::move(cb)); }
    result<close_user_data_stream_t>
    close_user_data_stream(const char *listen_key, close_user_data_stream_cb cb = {});

private:
    struct impl {
        impl(
            boost::asio::io_context& ioctx
            , std::string host
            , std::string port
            , std::string pk
            , std::string sk
            , std::size_t timeout
            , std::string client_api_string
        )
            :m_ioctx{ ioctx }
            , m_host{ std::move(host) }
            , m_port{ std::move(port) }
            , m_pk{ std::move(pk) }
            , m_sk{ std::move(sk) }
            , m_timeout{ timeout }
            , m_client_api_string{ std::move(client_api_string) }
            , m_write_in_process{}
            , m_async_requests{}
            , m_ssl_ctx{ boost::asio::ssl::context::sslv23_client }
            , m_resolver{ m_ioctx }
        {}

        using val_type = boost::variant<std::size_t, const char*>;
        using kv_type = std::pair<const char*, val_type>;
        using init_list_type = std::initializer_list<kv_type>;

        template<
            typename CB
            , typename Args = typename boost::callable_traits::args<CB>::type
            , typename R = typename std::tuple_element<3, Args>::type
        >
        api::result<R>
            post(bool _signed, const char* target, boost::beast::http::verb action, const std::initializer_list<kv_type>& map, CB cb) {
            static_assert(std::tuple_size<Args>::value == 4, "callback signature is wrong!");

            auto is_valid_value = [](const val_type& v) -> bool {
                if (const auto* p = boost::get<const char*>(&v)) {
                    return *p != nullptr;
                }
                if (const auto* p = boost::get<std::size_t>(&v)) {
                    return *p != 0u;
                }

                assert(!"unreachable");

                return false;
                };

            auto to_string = [](char* buf, std::size_t bufsize, const val_type& v) -> const char* {
                if (const auto* p = boost::get<const char*>(&v)) {
                    return *p;
                }
                if (const auto* p = boost::get<std::size_t>(&v)) {
                    std::snprintf(buf, bufsize, "%zu", *p);

                    return buf;
                }

                assert(!"unreachable");

                return buf;
                };

            auto is_html = [](const char* str) -> bool {
                return std::strstr(str, "<HTML>")
                    || std::strstr(str, "<HEAD>")
                    || std::strstr(str, "<BODY>")
                    ;
                };

            std::string starget = target;
            std::string data;
            for (const auto& it : map) {
                if (is_valid_value(it.second)) {
                    if (!data.empty()) {
                        data += "&";
                    }
                    data += it.first;
                    data += "=";

                    char buf[32];
                    data += to_string(buf, sizeof(buf), it.second);
                }
            }

            if (_signed) {
                assert(!m_pk.empty() && !m_sk.empty());

                if (!data.empty()) {
                    data += "&";
                }
                data += "timestamp=";
                char buf[32];
                data += to_string(buf, sizeof(buf), get_current_ms_epoch());

                data += "&recvWindow=";
                data += to_string(buf, sizeof(buf), m_timeout);

                std::string signature = hmac_sha256(
                    m_sk.c_str()
                    , m_sk.length()
                    , data.c_str()
                    , data.length()
                );

                data += "&signature=";
                data += signature;
            }

            bool get_delete =
                action == boost::beast::http::verb::get ||
                action == boost::beast::http::verb::delete_
                ;
            if (get_delete && !data.empty()) {
                starget += "?";
                starget += data;
                data.clear();
            }

            api::result<R> res{};
            if (!cb) {
                try {
                    api::result<std::string> r = sync_post(starget.c_str(), action, std::move(data));
                    if (!r.v.empty() && is_html(r.v.c_str())) {
                        r.errmsg = std::move(r.v);
                    }
                    else {
                        std::string strbuf = std::move(r.v);
                        const flatjson::fjson json{ strbuf.c_str(), strbuf.length() };
                        if (json.error() != flatjson::FJ_EC_OK) {
                            res.ec = json.error();
                            __MAKE_ERRMSG(res, json.error_string())
                                res.reply.clear();

                            return res;
                        }

                        if (json.is_object() && binapi::rest::is_api_error(json)) {
                            auto error = binapi::rest::construct_error(json);
                            res.ec = error.first;
                            __MAKE_ERRMSG(res, error.second)
                                res.reply.clear();

                            return res;
                        }
                        else {
                            res.v = R::construct(json);
                        }
                    }
                }
                catch (const std::exception& ex) {
                    __MAKE_ERRMSG(res, ex.what())
                }

                return res;
            }
            else {
                using invoker_type = detail::invoker<typename boost::callable_traits::return_type<CB>::type, R, CB>;
                async_req_item item{
                     starget
                    ,action
                    ,std::move(data)
                    ,std::make_shared<invoker_type>(std::move(cb))
                };
                m_async_requests.push(std::move(item));

                async_post();
            }

            return res;
        }

        api::result<std::string>
            sync_post(const char* target, boost::beast::http::verb action, std::string data) {
            api::result<std::string> res{};

            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_stream(m_ioctx, m_ssl_ctx);

            if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), m_host.c_str())) {
                boost::system::error_code ec{ static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
                std::cerr << __MESSAGE("msg=" << ec.message()) << std::endl;

                __MAKE_ERRMSG(res, ec.message());
                return res;
            }

            boost::system::error_code ec;
            auto const results = m_resolver.resolve(m_host, m_port, ec);
            if (ec) {
                std::cerr << __MESSAGE("msg=" << ec.message()) << std::endl;

                __MAKE_ERRMSG(res, ec.message());
                return res;
            }

            boost::asio::connect(ssl_stream.next_layer(), results.begin(), results.end(), ec);
            if (ec) {
                std::cerr << __MESSAGE("msg=" << ec.message()) << std::endl;

                __MAKE_ERRMSG(res, ec.message());
                return res;
            }

            ssl_stream.handshake(boost::asio::ssl::stream_base::client, ec);
            if (ec) {
                std::cerr << __MESSAGE("msg=" << ec.message()) << std::endl;

                __MAKE_ERRMSG(res, ec.message());
                return res;
            }

            boost::beast::http::request<boost::beast::http::string_body> req;
            req.target(target);
            req.version(11);

            req.method(action);
            if (action != boost::beast::http::verb::get) {
                req.body() = std::move(data);
                req.set(boost::beast::http::field::content_length, std::to_string(req.body().length()));
            }

            req.insert("X-MBX-APIKEY", m_pk);
            req.set(boost::beast::http::field::host, m_host);
            req.set(boost::beast::http::field::user_agent, m_client_api_string);
            req.set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");

            boost::beast::http::write(ssl_stream, req, ec);
            if (ec) {
                std::cerr << __MESSAGE("msg=" << ec.message()) << std::endl;

                __MAKE_ERRMSG(res, ec.message());
                return res;
            }

            boost::beast::flat_buffer buffer;
            boost::beast::http::response<boost::beast::http::string_body> bres;

            boost::beast::http::read(ssl_stream, buffer, bres, ec);
            if (ec) {
                std::cerr << __MESSAGE("msg=" << ec.message()) << std::endl;

                __MAKE_ERRMSG(res, ec.message());
                return res;
            }

            res.v = std::move(bres.body());
            //        std::cout << target << " REPLY:\n" << res.v << std::endl << std::endl;

            ssl_stream.shutdown(ec);

            return res;
        }

        using request_ptr = std::unique_ptr<boost::beast::http::request<boost::beast::http::string_body>>;
        using request_type = typename request_ptr::element_type;
        using response_ptr = std::unique_ptr<boost::beast::http::response<boost::beast::http::string_body>>;
        using response_type = typename response_ptr::element_type;
        using ssl_socket_ptr = std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>;
        using ssl_socket_type = typename ssl_socket_ptr::element_type;

        void async_post() {
            if (m_write_in_process) {
                return;
            }

            m_write_in_process = true;

            auto& front = m_async_requests.front();
            auto action = front.action;
            std::string data = std::move(front.data);
            std::string target = front.target;
            //std::cout << "async_post(): target=" << target << std::endl;

            auto req = std::make_unique<request_type>();
            req->version(11);
            req->method(action);
            if (action != boost::beast::http::verb::get) {
                req->body() = std::move(data);
                req->set(boost::beast::http::field::content_length, std::to_string(req->body().length()));
            }

            req->target(target);
            req->insert("X-MBX-APIKEY", m_pk);
            req->set(boost::beast::http::field::host, m_host);
            req->set(boost::beast::http::field::user_agent, m_client_api_string);
            req->set(boost::beast::http::field::content_type, "application/x-www-form-urlencoded");

            //std::cout << target << " REQUEST:\n" << m_req << std::endl;

            // Look up the domain name
            m_resolver.async_resolve(
                m_host
                , m_port
                , [this, req = std::move(req)]
                (const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::results_type res) mutable
                { on_resolve(ec, std::move(req), std::move(res)); }
            );
        }
        void on_resolve(
            const boost::system::error_code& ec
            , request_ptr req
            , boost::asio::ip::tcp::resolver::results_type results)
        {
            if (ec) {
                m_write_in_process = false;
                process_reply(__MAKE_FILELINE, ec.value(), ec.message(), std::string{});
                return;
            }

            ssl_socket_ptr ssl_socket = std::make_unique<ssl_socket_type>(m_ioctx, m_ssl_ctx);

            if (!SSL_set_tlsext_host_name(ssl_socket->native_handle(), m_host.c_str())) {
                boost::system::error_code ec2{ static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() };
                std::cerr << __MESSAGE("msg=" << ec2.message()) << std::endl;

                return;
            }

            auto sptr = ssl_socket.get();

            boost::asio::async_connect(
                sptr->next_layer()
                , results.begin()
                , results.end()
                , [this, req = std::move(req), ssl_socket = std::move(ssl_socket)]
                (const boost::system::error_code& ec, auto) mutable
                { on_connect(ec, std::move(req), std::move(ssl_socket)); }
            );
        }
        void on_connect(
            const boost::system::error_code& ec
            , request_ptr req
            , ssl_socket_ptr ssl_socket)
        {
            if (ec) {
                m_write_in_process = false;
                process_reply(__MAKE_FILELINE, ec.value(), ec.message(), std::string{});
                return;
            }

            auto sptr = ssl_socket.get();

            // Perform the SSL handshake
            sptr->async_handshake(
                boost::asio::ssl::stream_base::client
                , [this, req = std::move(req), ssl_socket = std::move(ssl_socket)]
                (const boost::system::error_code& ec) mutable
                { on_handshake(ec, std::move(req), std::move(ssl_socket)); }
            );
        }
        void on_handshake(
            const boost::system::error_code& ec
            , request_ptr req
            , ssl_socket_ptr ssl_socket)
        {
            if (ec) {
                m_write_in_process = false;
                process_reply(__MAKE_FILELINE, ec.value(), ec.message(), std::string{});
                return;
            }

            auto* request_ptr = req.get();
            auto* socket_ptr = ssl_socket.get();

            // Send the HTTP request to the remote host
            boost::beast::http::async_write(
                *socket_ptr
                , *request_ptr
                , [this, req = std::move(req), ssl_socket = std::move(ssl_socket)]
                (const boost::system::error_code& ec, std::size_t wr) mutable
                { on_write(ec, std::move(req), std::move(ssl_socket), wr); }
            );
        }
        void on_write(const boost::system::error_code& ec, request_ptr req, ssl_socket_ptr ssl_socket, std::size_t wr) {
            boost::ignore_unused(wr);
            boost::ignore_unused(req);

            if (ec) {
                m_write_in_process = false;
                process_reply(__MAKE_FILELINE, ec.value(), ec.message(), std::string{});
                return;
            }

            auto resp = std::make_unique<response_type>();
            auto* resp_ptr = resp.get();
            auto* socket_ptr = ssl_socket.get();

            // Receive the HTTP response
            boost::beast::http::async_read(
                *socket_ptr
                , m_buffer
                , *resp_ptr
                , [this, resp = std::move(resp), ssl_socket = std::move(ssl_socket)]
                (const boost::system::error_code& ec, std::size_t rd) mutable
                { on_read(ec, std::move(resp), std::move(ssl_socket), rd); }
            );
        }
        void on_read(const boost::system::error_code& ec, response_ptr resp, ssl_socket_ptr ssl_socket, std::size_t rd) {
            boost::ignore_unused(rd);

            if (ec) {
                m_write_in_process = false;
                process_reply(__MAKE_FILELINE, ec.value(), ec.message(), std::string{});
                return;
            }

            auto* socket_ptr = ssl_socket.get();

            socket_ptr->async_shutdown(
                [this, resp = std::move(resp), ssl_socket = std::move(ssl_socket)]
                (const boost::system::error_code& ec) mutable
                { on_shutdown(ec, std::move(resp), std::move(ssl_socket)); }
            );
        }
        void on_shutdown(const boost::system::error_code& ec, response_ptr resp, ssl_socket_ptr ssl_socket) {
            boost::ignore_unused(ec);
            boost::ignore_unused(ssl_socket);

            std::string body = std::move(resp->body());
            process_reply(__MAKE_FILELINE, 0, std::string{}, std::move(body));

            m_write_in_process = false;

            if (!m_async_requests.empty()) {
                async_post();
            }
        }

        void process_reply(const char* fl, int ec, std::string errmsg, std::string body) {
            assert(!m_async_requests.empty());

            __TRY_BLOCK() {
                const auto item = std::move(m_async_requests.front());
                m_async_requests.pop();

                //std::cout << "process_reply(): target=" << item.target << std::endl;
                item.invoker->invoke(fl, ec, std::move(errmsg), body.c_str(), body.size());
            } __CATCH_BLOCK(
                std::cout,
                (std::exception)
            )
        }

        boost::asio::io_context& m_ioctx;
        const std::string m_host;
        const std::string m_port;
        const std::string m_pk;
        const std::string m_sk;
        const std::size_t m_timeout;
        const std::string m_client_api_string;

        bool m_write_in_process;
        struct async_req_item {
            std::string target;
            boost::beast::http::verb action;
            std::string data;
            detail::invoker_ptr invoker;
        };
        std::queue<async_req_item> m_async_requests;
        boost::asio::ssl::context m_ssl_ctx;
        boost::asio::ip::tcp::resolver m_resolver;
        boost::beast::flat_buffer m_buffer; // (Must persist between reads)
    };
    std::unique_ptr<impl> pimpl;
};

/*************************************************************************************************/

} // ns rest
} // ns binapi

#endif // __binapi__api_hpp
