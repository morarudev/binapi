
// ----------------------------------------------------------------------------
//                              Apache License
//                        Version 2.0, January 2004
//                     http://www.apache.org/licenses/
//
// This file is part of binapi(https://github.com/niXman/binapi) project.
//
// Copyright (c) 2019-2021 niXman (github dot nixman dog pm.me). All rights reserved.
// ----------------------------------------------------------------------------

#include <binapi/websocket.hpp>
#include <binapi/types.hpp>

#include <binapi/fnv1a.hpp>
#include <binapi/flatjson.hpp>
#include <binapi/errors.hpp>

//#include <iostream> // TODO: comment out


namespace binapi {
namespace ws {

struct websockets;

/*************************************************************************************************/

websockets::websockets(
     boost::asio::io_context &ioctx
    ,std::string host
    ,std::string port
    ,on_message_received_cb msg_cb
    ,on_network_stat_cb stat_cb
    ,std::size_t stat_interval
)
    :pimpl{std::make_unique<impl>(
         ioctx
        ,std::move(host)
        ,std::move(port)
        ,std::move(msg_cb)
        ,std::move(stat_cb)
        ,stat_interval
    )}
{}

websockets::~websockets()
{}

/*************************************************************************************************/

websockets::handle websockets::part_depth(const char *pair, e_levels level, e_freq freq, on_part_depths_received_cb cb) {
    std::string ch = "depth";
    ch += std::to_string(static_cast<std::size_t>(level));
    ch += "@";
    ch += std::to_string(static_cast<std::size_t>(freq)) + "ms";
    return pimpl->start_channel(pair, ch.c_str(), std::move(cb));
}

/*************************************************************************************************/

websockets::handle websockets::diff_depth(const char *pair, e_freq freq, on_diff_depths_received_cb cb) {
    std::string ch = "depth@" + std::to_string(static_cast<std::size_t>(freq)) + "ms";
    return pimpl->start_channel(pair, ch.c_str(), std::move(cb));
}

/*************************************************************************************************/

websockets::handle websockets::klines(const char *pair, const char *interval, on_kline_received_cb cb) {
    static const auto switch_ = [](const char *interval) -> const char * {
        const auto hash = fnv1a(interval);
        switch ( hash ) {
            // secs
            case fnv1a("1s"): return "kline_1s";
            // mins
            case fnv1a("1m"): return "kline_1m";
            case fnv1a("3m"): return "kline_3m";
            case fnv1a("5m"): return "kline_5m";
            case fnv1a("15m"): return "kline_15m";
            case fnv1a("30m"): return "kline_30m";
            // hours
            case fnv1a("1h"): return "kline_1h";
            case fnv1a("2h"): return "kline_2h";
            case fnv1a("4h"): return "kline_4h";
            case fnv1a("6h"): return "kline_6h";
            case fnv1a("8h"): return "kline_8h";
            case fnv1a("12h"): return "kline_12h";
            // days
            case fnv1a("1d"): return "kline_1d";
            case fnv1a("3d"): return "kline_3d";
            // other
            case fnv1a("1w"): return "kline_1w";
            case fnv1a("1M"): return "kline_1M";
            //
            default: return nullptr;
        }
    };

    const char *p = switch_(interval);
    assert(p != nullptr);

    return pimpl->start_channel(pair, p, std::move(cb));
}

/*************************************************************************************************/

websockets::handle websockets::trade(const char *pair, on_trade_received_cb cb)
{ return pimpl->start_channel(pair, "trade", std::move(cb)); }

/*************************************************************************************************/

websockets::handle websockets::agg_trade(const char *pair, on_agg_trade_received_cb cb)
{ return pimpl->start_channel(pair, "aggTrade", std::move(cb)); }

/*************************************************************************************************/

websockets::handle websockets::mini_ticker(const char *pair, on_mini_ticker_received_cb cb)
{ return pimpl->start_channel(pair, "miniTicker", std::move(cb)); }

websockets::handle websockets::mini_tickers(on_mini_tickers_received_cb cb)
{ return pimpl->start_channel("!miniTicker", "arr", std::move(cb)); }

/*************************************************************************************************/

websockets::handle websockets::market(const char *pair, on_market_received_cb cb)
{ return pimpl->start_channel(pair, "ticker", std::move(cb)); }

websockets::handle websockets::markets(on_markets_received_cb cb)
{ return pimpl->start_channel("!ticker", "arr", std::move(cb)); }

/*************************************************************************************************/

BINAPI_API websockets::handle websockets::book(const char *pair, on_book_received_cb cb)
{ return pimpl->start_channel(pair, "bookTicker", std::move(cb)); }

/*************************************************************************************************/

websockets::handle websockets::userdata(
     const char *lkey
    ,on_account_update_cb account_update
    ,on_balance_update_cb balance_update
    ,on_order_update_cb order_update)
{
    auto cb = [acb=std::move(account_update), bcb=std::move(balance_update), ocb=std::move(order_update)]
        (const char *fl, int ec, std::string errmsg, userdata::userdata_stream_t msg)
    {
        if ( ec ) {
            acb(fl, ec, errmsg, userdata::account_update_t{});
            bcb(fl, ec, errmsg, userdata::balance_update_t{});
            ocb(fl, ec, std::move(errmsg), userdata::order_update_t{});

            return false;
        }

        const flatjson::fjson json{msg.data.c_str(), msg.data.length()};
        assert(json.contains("e"));
        const auto e = json.at("e");
        const auto es = e.to_sstring();
        const auto ehash = fnv1a(es.data(), es.size());
        switch ( ehash ) {
            case fnv1a("outboundAccountPosition"): {
                userdata::account_update_t res = userdata::account_update_t::construct(json);
                return acb(fl, ec, std::move(errmsg), std::move(res));
            }
            case fnv1a("balanceUpdate"): {
                userdata::balance_update_t res = userdata::balance_update_t::construct(json);
                return bcb(fl, ec, std::move(errmsg), std::move(res));
            }
            case fnv1a("executionReport"): {
                userdata::order_update_t res = userdata::order_update_t::construct(json);
                return ocb(fl, ec, std::move(errmsg), std::move(res));
            }
            case fnv1a("listStatus"): {
                assert(!"not implemented");
                return false;
            }
            default: {
                assert(!"unreachable");
                return false;
            }
        }

        return false;
    };

    return pimpl->start_channel(nullptr, lkey, std::move(cb));
}

/*************************************************************************************************/

void websockets::unsubscribe(const handle &h) { return pimpl->stop_channel(h); }
void websockets::async_unsubscribe(const handle &h) { return pimpl->async_stop_channel(h); }

void websockets::unsubscribe_all() { return pimpl->unsubscribe_all(); }
void websockets::async_unsubscribe_all() { return pimpl->async_unsubscribe_all(); }

/*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

} // ns ws
} // ns binapi
