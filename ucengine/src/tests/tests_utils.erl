%%
%%  U.C.Engine - Unified Colloboration Engine
%%  Copyright (C) 2011 af83
%%
%%  This program is free software: you can redistribute it and/or modify
%%  it under the terms of the GNU Affero General Public License as published by
%%  the Free Software Foundation, either version 3 of the License, or
%%  (at your option) any later version.
%%
%%  This program is distributed in the hope that it will be useful,
%%  but WITHOUT ANY WARRANTY; without even the implied warranty of
%%  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%  GNU Affero General Public License for more details.
%%
%%  You should have received a copy of the GNU Affero General Public License
%%  along with this program.  If not, see <http://www.gnu.org/licenses/>.
%%
-module(tests_utils).

-include("uce.hrl").

-export([ post/3
        , post/5
        , post_raw/5
        , get_raw/3
        , get/2
        , get/3
        , options_raw/2
        , put/3
        , delete/3
        ]).
-export([url_encode/1]).

options_raw(BaseUrl, Path) ->
    request(BaseUrl, Path, options, [], "", "").

get_raw(BaseUrl, Path, Params) ->
    request(BaseUrl, Path, get, Params, "", "").

get(BaseUrl, Path) ->
    get(BaseUrl, Path, []).
get(BaseUrl, Path, Params) ->
    {ok, _, _, JSON} = get_raw(BaseUrl, Path, Params),
    mochijson:decode(JSON).

post_raw(BaseUrl, Path, Params, ContentType, Body) ->
    request(BaseUrl, Path, post, Params, ContentType, Body).

post(BaseUrl, Path, Params) ->
    post(BaseUrl, Path, [], "application/x-www-form-urlencoded", url_encode(Params)).
post(BaseUrl, Path, Params, ContentType, Body) ->
    {ok, _, _, JSON} = post_raw(BaseUrl, Path, Params, ContentType, Body),
    mochijson:decode(JSON).

put(BaseUrl, Path, Params) ->
    {ok, _, _, JSON} = request(BaseUrl, Path, put, Params, "application/x-www-form-urlencoded", []),
    mochijson:decode(JSON).

delete(BaseUrl, Path, Params) ->
    {ok, _, _, JSON} =
        ibrowse:send_req(BaseUrl ++ Path ++ "?" ++ url_encode(Params), [], delete),
    mochijson:decode(JSON).

request(BaseUrl, Path, Method, Params, ContentType, Body) ->
    Query = case Params of
                [] ->
                    "";
                _ ->
                    "?" ++ url_encode(Params)
            end,
   ibrowse:send_req(BaseUrl ++ Path ++ Query, [{"Content-type", ContentType}], Method, Body, [{content_type, ContentType}]).

url_encode(Params) ->
    UrlEncodedParams = [yaws_api:url_encode(Elem) ++ "=" ++
                            yaws_api:url_encode(Value) ||
                           {Elem, Value} <- Params],
    string:join(UrlEncodedParams, "&").
