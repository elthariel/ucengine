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
-module(uce_event).

-author('tbomandouki@af83.com').

-export([add/1, get/1, exists/1, list/11, search/11]).

-include("uce.hrl").
-include("uce_async.hrl").

add(#uce_event{id=none}=Event) ->
    ?MODULE:add(Event#uce_event{id=utils:random()});
add(#uce_event{datetime=undefined}=Event) ->
    ?MODULE:add(Event#uce_event{datetime=utils:now()});
add(#uce_event{location=Location, from=From, to=To, parent=Parent} = Event) ->
    LocationExists = uce_meeting:exists(Location),
    FromExists = uce_user:exists(From),
    ToExists = uce_user:exists(To),
    ParentExists = uce_event:exists(Parent),

    if
        LocationExists == true,
        FromExists == true,
        ToExists == true,
        ParentExists == true ->
            {ok, Id} = ?DB_MODULE:add(Event),
            catch ?PUBSUB_MODULE:publish(Event),
            catch ?SEARCH_MODULE:add(Event),
            catch uce_acl:trigger(Event),
            {ok, Id};
        true ->
            throw({error, not_found})
    end.

get(Id) ->
    ?DB_MODULE:get(Id).

exists(Id) ->
    case Id of
        "" -> % "" is the root of the event hierarchy
            true;
        _ ->
            case catch ?MODULE:get(Id) of
                {error, not_found} ->
                   false;
                {error, Reason} ->
                    throw({error, Reason});
                _ ->
                    true
            end
    end.

filter_private(Events, Uid) ->
    lists:filter(fun(#uce_event{to=To}) ->
                         case To of
                             {"", _} -> % all
                                 true;
                             Uid ->
                                 true;
                             _ ->
                                 false
                         end
                 end,
                 Events).

search(Location, Search, From, Types, Uid, DateStart, DateEnd, Parent, Start, Max, Order) ->
    {ok, Events} = ?SEARCH_MODULE:list(Location,
                                       Search,
                                       From,
                                       Types,
                                       DateStart,
                                       DateEnd,
                                       Parent,
                                       Start,
                                       Max,
                                       Order),
    {ok, filter_private(Events, Uid)}.

list(Location, Search, From, Types, Uid, DateStart, DateEnd, Parent, Start, Max, Order) ->
    {ok, Events} =
        uce_event_erlang_search:list(Location,
                                     Search,
                                     From,
                                     Types,
                                     DateStart,
                                     DateEnd,
                                     Parent,
                                     Start,
                                     Max,
                                     Order),
    {ok, filter_private(Events, Uid)}.
