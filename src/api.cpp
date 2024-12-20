
// ----------------------------------------------------------------------------
//                              Apache License
//                        Version 2.0, January 2004
//                     http://www.apache.org/licenses/
//
// This file is part of binapi(https://github.com/niXman/binapi) project.
//
// Copyright (c) 2019-2021 niXman (github dot nixman dog pm.me). All rights reserved.
// ----------------------------------------------------------------------------

#include <binapi/api.hpp>


namespace binapi {
namespace rest {

api::api(
     boost::asio::io_context &ioctx
    ,std::string host
    ,std::string port
    ,std::string pk
    ,std::string sk
    ,std::size_t timeout
    ,std::string client_api_string
)
    :pimpl{std::make_unique<impl>(
         ioctx
        ,std::move(host)
        ,std::move(port)
        ,std::move(pk)
        ,std::move(sk)
        ,timeout
        ,std::move(client_api_string)
    )}
{}

api::~api()
{}

/*************************************************************************************************/

api::result<ping_t> api::ping(ping_cb cb) {
    return pimpl->post(false, "/api/v3/ping", boost::beast::http::verb::get, {}, std::move(cb));
}

/*************************************************************************************************/

api::result<server_time_t> api::server_time(server_time_cb cb) {
    return pimpl->post(false, "/api/v3/time", boost::beast::http::verb::get, {}, std::move(cb));
}

/*************************************************************************************************/

api::result<prices_t::price_t> api::price(const char *symbol, price_cb cb) {
    const impl::init_list_type map = {
        {"symbol", symbol}
    };

    return pimpl->post(false, "/api/v3/ticker/price", boost::beast::http::verb::get, map, std::move(cb));
}

api::result<prices_t> api::prices(prices_cb cb) {
    return pimpl->post(false, "/api/v3/ticker/price", boost::beast::http::verb::get, {}, std::move(cb));
}

/*************************************************************************************************/

api::result<avg_price_t> api::avg_price(const char *symbol, avg_price_cb cb) {
    const impl::init_list_type map = {
        {"symbol", symbol}
    };

    return pimpl->post(false, "/api/v3/avgPrice", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<_24hrs_tickers_t::_24hrs_ticker_t> api::_24hrs_ticker(const char *symbol, api::_24hrs_ticker_cb cb) {
    const impl::init_list_type map = {
        {"symbol", symbol}
    };

    return pimpl->post(false, "/api/v3/ticker/24hr", boost::beast::http::verb::get, map, std::move(cb));
}

api::result<_24hrs_tickers_t> api::_24hrs_tickers(api::_24hrs_tickers_cb cb) {
    return pimpl->post(false, "/api/v3/ticker/24hr", boost::beast::http::verb::get, {}, std::move(cb));
}

/*************************************************************************************************/

api::result<exchange_info_t> api::exchange_info(exchange_info_cb cb) {
    return pimpl->post(false, "/api/v3/exchangeInfo", boost::beast::http::verb::get, {}, std::move(cb));
}

api::result<exchange_info_t> api::exchange_info(const char *symbol, exchange_info_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
    };

    return pimpl->post(false, "/api/v3/exchangeInfo", boost::beast::http::verb::get, map, std::move(cb));
}

api::result<exchange_info_t> api::exchange_info(const std::vector<std::string> &symbols, exchange_info_cb cb) {
    std::string symstr = "[";
    for ( auto it = symbols.begin(); it != symbols.end(); ++it) {
        symstr += "\"";
        symstr += *it;
        symstr += "\"";
        if ( std::next(it) != symbols.end()) {
            symstr += ",";
        }
    }
    symstr += "]";

    const impl::init_list_type map = {
         {"symbols", symstr.c_str()}
    };

    return pimpl->post(false, "/api/v3/exchangeInfo", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<depths_t> api::depths(const char *symbol, std::size_t limit, depths_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"limit", limit}
    };

    return pimpl->post(false, "/api/v3/depth", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<trades_t::trade_t> api::trade(const char *symbol, trade_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"limit", 1u}
    };

    return pimpl->post(false, "/api/v3/trades", boost::beast::http::verb::get, map, std::move(cb));
}

api::result<trades_t> api::trades(const char *symbol, std::size_t limit, trades_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"limit", limit}
    };

    return pimpl->post(false, "/api/v3/trades", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<agg_trades_t::agg_trade_t> api::agg_trade(const char *symbol, agg_trade_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"limit", 1u}
    };

    return pimpl->post(false, "/api/v3/aggTrades", boost::beast::http::verb::get, map, std::move(cb));
}

api::result<agg_trades_t> api::agg_trades(const char *symbol, std::size_t limit, agg_trades_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"limit", limit}
    };

    return pimpl->post(false, "/api/v3/aggTrades", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<klines_t> api::klines(const char *symbol, const char *interval, std::size_t limit, klines_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"limit", limit}
        ,{"interval", interval}
    };

    return pimpl->post(false, "/api/v3/klines", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

api::result<account_info_t> api::account_info(account_info_cb cb) {
    return pimpl->post(true, "/api/v3/account", boost::beast::http::verb::get, {}, std::move(cb));
}

/*************************************************************************************************/

api::result<order_info_t> api::order_info(const char *symbol, std::size_t orderid, const char *client_orderid, order_info_cb cb) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"orderId", orderid}
        ,{"origClientOrderId", client_orderid}
    };

    return pimpl->post(true, "/api/v3/order", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<orders_info_t> api::open_orders(const char *symbol, open_orders_cb cb) {
    const impl::init_list_type map = {
        {"symbol", symbol}
    };

    return pimpl->post(true, "/api/v3/openOrders", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<orders_info_t> api::all_orders(
     const char *symbol
    ,std::size_t orderid
    ,std::size_t start_time
    ,std::size_t end_time
    ,std::size_t limit
    ,all_orders_cb cb
) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"orderId", orderid}
        ,{"startTime", start_time}
        ,{"endTime", end_time}
        ,{"limit", limit}
    };

    return pimpl->post(true, "/api/v3/allOrders", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<new_order_resp_type>
api::new_order(
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
    ,new_order_cb cb
) {
    const char *side_str = e_side_to_string(side);
    assert(side_str);

    const char *type_str = e_type_to_string(type);
    assert(type_str);

    const char *time_str = type == e_type::market
        ? nullptr
        : e_time_to_string(time)
    ;

    const char *response_type = e_trade_resp_type_to_string(resp);
    assert(response_type);

    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"side", side_str}
        ,{"type", type_str}
        ,{"timeInForce", time_str}
        ,{"quantity", amount}
        ,{"price", price}
        ,{"newClientOrderId", client_order_id}
        ,{"stopPrice", stop_price}
        ,{"icebergQty", iceberg_amount}
        ,{"newOrderRespType", response_type}
    };

    return pimpl->post(true, "/api/v3/order", boost::beast::http::verb::post, map, std::move(cb));
}

/*************************************************************************************************/

api::result<new_order_resp_type>
api::new_test_order(
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
    ,new_order_cb cb
) {
    const char *side_str = e_side_to_string(side);
    assert(side_str);

    const char *type_str = e_type_to_string(type);
    assert(type_str);

    const char *time_str = type == e_type::market ? nullptr : e_time_to_string(time);

    const char *response_type = e_trade_resp_type_to_string(resp);
    assert(response_type);

    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"side", side_str}
        ,{"type", type_str}
        ,{"timeInForce", time_str}
        ,{"quantity", amount}
        ,{"price", price}
        ,{"newClientOrderId", client_order_id}
        ,{"stopPrice", stop_price}
        ,{"icebergQty", iceberg_amount}
        ,{"newOrderRespType", response_type}
    };

    return pimpl->post(true, "/api/v3/order/test", boost::beast::http::verb::post, map, std::move(cb));
}

/*************************************************************************************************/

api::result<cancel_order_info_t> api::cancel_order(
     const char *symbol
    ,std::size_t order_id
    ,const char *client_order_id
    ,const char *new_client_order_id
    ,cancel_order_cb cb
) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"orderId", order_id}
        ,{"origClientOrderId", client_order_id}
        ,{"newClientOrderId", new_client_order_id}
    };

    return pimpl->post(true, "/api/v3/order", boost::beast::http::verb::delete_, map, std::move(cb));
}

/*************************************************************************************************/

api::result<my_trades_info_t> api::my_trades(
     const char *symbol
    ,std::size_t start_time
    ,std::size_t end_time
    ,std::size_t from_id
    ,std::size_t limit
    ,my_trades_cb cb
) {
    const impl::init_list_type map = {
         {"symbol", symbol}
        ,{"startTime", start_time}
        ,{"endTime", end_time}
        ,{"fromId", from_id}
        ,{"limit", limit}
    };

    return pimpl->post(true, "/api/v3/myTrades", boost::beast::http::verb::get, map, std::move(cb));
}

/*************************************************************************************************/

api::result<start_user_data_stream_t> api::start_user_data_stream(start_user_data_stream_cb cb) {
    return pimpl->post(false, "/api/v3/userDataStream", boost::beast::http::verb::post, {}, std::move(cb));
}

/*************************************************************************************************/

api::result<ping_user_data_stream_t> api::ping_user_data_stream(const char *listen_key, ping_user_data_stream_cb cb) {
    const impl::init_list_type map = {
        {"listenKey", listen_key}
    };

    return pimpl->post(false, "/api/v3/userDataStream", boost::beast::http::verb::put, map, std::move(cb));
}

/*************************************************************************************************/

api::result<close_user_data_stream_t> api::close_user_data_stream(const char *listen_key, close_user_data_stream_cb cb) {
    const impl::init_list_type map = {
        {"listenKey", listen_key}
    };

    return pimpl->post(false, "/api/v3/userDataStream", boost::beast::http::verb::delete_, map, std::move(cb));
}

/*************************************************************************************************/
/*************************************************************************************************/
/*************************************************************************************************/

} // ns rest
} // ns binapi
