%%
%%  U.C.Engine - Unified Collaboration Engine
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
-module(mnesia_pubsub).

-behaviour(gen_server).

-author('victor.goya@af83.com').

-export([init/1,
         start_link/0,
         publish/2,
         subscribe/9,
         unsubscribe/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         code_change/3,
         terminate/2]).

-include("uce.hrl").

-record(uce_mnesia_pubsub, {pid, domain, location, uid, search, type, from}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    mnesia:create_table(uce_mnesia_pubsub,
                        [{ram_copies, [node()]},
                         {type, bag},
                         {attributes, record_info(fields, uce_mnesia_pubsub)}]),
    {ok, {}}.

publish(Domain, #uce_event{location=Location, type=Type, from=From, id=Id}) ->
    ?COUNTER('pubsub:publish'),
    case Location of
        "" ->
            gen_server:call(?MODULE, {publish, Domain, Location, Type, From, Id}),
            gen_server:call(?MODULE, {publish, Domain, Location, [], From, Id});
        Location ->
            gen_server:call(?MODULE, {publish, Domain, Location, Type, From, Id}),
            gen_server:call(?MODULE, {publish, Domain, Location, [], From, Id}),
            gen_server:call(?MODULE, {publish, Domain, "", Type, From, Id}),
            gen_server:call(?MODULE, {publish, Domain, "", [], From, Id})
    end.

subscribe(Pid, Domain, Location, Search, From, "", Uid, Start, Parent) ->
    subscribe(Pid, Domain, Location, Search, From, [""], Uid, Start, Parent);
subscribe(Pid, Domain, Location, Search, From, Types, Uid, _Start, _Parent) ->
    ?COUNTER('pubsub:suscribe'),
    [gen_server:cast(?MODULE, {subscribe,
                               Domain,
                               Location,
                               Uid,
                               Search,
                               Type,
                               From,
                               Pid}) || Type <- Types].

unsubscribe(Pid) ->
    ?COUNTER('pubsub:unsubscribe'),
    gen_server:cast(?MODULE, {unsubscribe, Pid}).

get_subscribers(Domain, Location, Type, From) ->
    case mnesia:transaction(fun() ->
                                    mnesia:match_object(#uce_mnesia_pubsub{domain=Domain,
                                                                           location=Location,
                                                                           uid='_',
                                                                           search='_',
                                                                           type='_',
                                                                           from='_',
                                                                           pid='_'})
                            end) of
        {aborted, _} ->
            {error, bad_parameters};
        {atomic, Subscribers} ->
            lists:filter(fun(#uce_mnesia_pubsub{type=SubType, from=SubFrom}) ->
                                 if
                                     SubType == Type ->
                                         case SubFrom of
                                             "" ->
                                                 true;
                                             From ->
                                                 true;
                                             _ ->
                                                 false
                                         end;
                                     SubType == [] ->
                                         case SubFrom of
                                             "" ->
                                                 true;
                                             From ->
                                                 true;
                                             _ ->
                                                 false
                                         end;
                                     true ->
                                         false
                                 end
                         end,
                         Subscribers)
    end.

handle_call({publish, Domain, Location, Type, From, Message}, _From, State) ->
    Return =
        case get_subscribers(Domain, Location, Type, From) of
            {error, Reason} ->
                {error, Reason};
            Subscribers ->
                [Subscriber#uce_mnesia_pubsub.pid ! {message, Message} || Subscriber <- Subscribers],
                ok
        end,
    {reply, Return, State}.

handle_cast({subscribe, Domain, Location, Uid, Search, Type, From, Pid}, State) ->
    mnesia:transaction(fun() ->
                               mnesia:write(#uce_mnesia_pubsub{pid=Pid,
                                                               domain=Domain,
                                                               location=Location,
                                                               uid=Uid,
                                                               search=Search,
                                                               type=Type,
                                                               from=From})
                       end),
    {noreply, State};
handle_cast({unsubscribe, Pid}, State) ->
    mnesia:transaction(fun() ->
                               mnesia:delete({uce_mnesia_pubsub, Pid})
                       end),
    {noreply, State}.

code_change(_,State,_) ->
    {ok, State}.

handle_info(_Info, State) ->
    {reply, State}.

terminate(_Reason, _State) ->
    ok.
