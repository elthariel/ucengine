%% @author Justin Sheehy <justin@basho.com>
%% @author Andy Gross <andy@basho.com>
%% @copyright 2007-2008 Basho Technologies
%%
%%    Licensed under the Apache License, Version 2.0 (the "License");
%%    you may not use this file except in compliance with the License.
%%    You may obtain a copy of the License at
%%
%%        http://www.apache.org/licenses/LICENSE-2.0
%%
%%    Unless required by applicable law or agreed to in writing, software
%%    distributed under the License is distributed on an "AS IS" BASIS,
%%    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%    See the License for the specific language governing permissions and
%%    limitations under the License.

-module(uce_logger).
-author('Justin Sheehy <justin@basho.com>').
-author('Andy Gross <andy@basho.com>').
-behaviour(gen_server).
-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-export([refresh/0, log/5]).
%-include("webmachine_logger.hrl").

-record(wm_log_data, 
        {resource_module :: atom(),
         start_time :: tuple(),
         method :: atom(),
         headers,
         peer, 
         path :: string(),
         version,
         response_code,
         response_length,
         end_time :: tuple(),
         finish_time :: tuple(),
         notes}).

-record(state, {hourstamp, filename, handle}).

alog_path(BaseDir) ->
    filename:join(BaseDir, "ucengine.log").

start_link(BaseDir) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [BaseDir], []).

init([BaseDir]) ->
    defer_refresh(),
    FileName = alog_path(BaseDir),
    DateHour = datehour(),
    filelib:ensure_dir(FileName),
    Handle = log_open(FileName, DateHour),
    {ok, #state{filename=FileName, handle=Handle, hourstamp=DateHour}}.

refresh() ->
    refresh(now()).

refresh(Time) ->
    gen_server:cast(?MODULE, {refresh, Time}).

log(Level, Module, Line, Format, Args) ->
    gen_server:cast(?MODULE, {log, [Level, Module, Line, Format, Args]}).

handle_call(_Msg,_From,State) -> {noreply,State}.

handle_cast({log_access, LogData}, State) ->
    NewState = maybe_rotate(State, now()),
    Msg = format_req(LogData),
    log_write(NewState#state.handle, Msg),
    {noreply, NewState};
handle_cast({log, [Level, Module, Line, Format, Args]}, State) ->
    NewState = maybe_rotate(State, now()),
    Msg = [Level, Module, Line, Format, Args],
    log_write(NewState#state.handle, Msg),
    {noreply, NewState};
handle_cast({refresh, Time}, State) ->
    {noreply, maybe_rotate(State, Time)}.

handle_info({_Label, {From, MRef}, get_modules}, State) ->
    From ! {MRef, [?MODULE]},
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

log_open(FileName, DateHour) ->
    LogName = FileName ++ suffix(DateHour),
    io:format("opening log file: ~p~n", [LogName]),
    {ok, FD} = file:open(LogName, [read, write, raw]),
    {ok, Location} = file:position(FD, eof),
    fix_log(FD, Location),
    file:truncate(FD),
    {?MODULE, LogName, FD}.

log_write({?MODULE, _Name, FD}, [Level, Module, Line, Format, Args]) ->
    ok = file:write(FD, lists:flatten(format_log(Level, Module, Line, Format, Args))).

log_close({?MODULE, Name, FD}) ->
    io:format("~p: closing log file: ~p~n", [?MODULE, Name]),
    file:close(FD).

maybe_rotate(State, Time) ->
    ThisHour = datehour(Time),
    if ThisHour == State#state.hourstamp ->
            State;
       true ->
            defer_refresh(),
            log_close(State#state.handle),
            Handle = log_open(State#state.filename, ThisHour),
            State#state{hourstamp=ThisHour, handle=Handle}
    end.    

format_log(Level, Module, Line, Format, Args) ->
    Msg = io_lib:format(Format, Args),
    Time = fmtnow(),
    Lev = lists:nth(Level, ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    io_lib:format("~s ~s [~s:~w] ~s", [Time, Lev, Module, Line, Msg]).

format_req(#wm_log_data{method=Method, 
                        headers=Headers, 
                        peer=Peer, 
                        path=Path,
                        version=Version,
                        response_code=ResponseCode,
                        response_length=ResponseLength}) ->
    User = "-",
    Time = fmtnow(),
    Status = integer_to_list(ResponseCode),
    Length = integer_to_list(ResponseLength),
    Referer = 
        case mochiweb_headers:get_value("Referer", Headers) of
            undefined -> "";
            R -> R
        end,
    UserAgent = 
        case mochiweb_headers:get_value("User-Agent", Headers) of
            undefined -> "";
            U -> U
        end,
    fmt_alog(Time, Peer, User, fmt_method(Method), Path, Version,
             Status, Length, Referer, UserAgent).

fmt_method(M) when is_atom(M) -> atom_to_list(M).


%% Seek backwards to the last valid log entry
fix_log(_FD, 0) ->
    ok;
fix_log(FD, 1) ->
    {ok, 0} = file:position(FD, 0),
    ok;
fix_log(FD, Location) ->
    case file:pread(FD, Location - 1, 1) of
        {ok, [$\n | _]} ->
            ok;
        {ok, _} ->
            fix_log(FD, Location - 1)
    end.

defer_refresh() ->
    {_, {_, M, S}} = calendar:universal_time(),
    Time = 1000 * (3600 - ((M * 60) + S)),
    timer:apply_after(Time, ?MODULE, refresh, []).

datehour() ->
    datehour(now()).

datehour(Now) ->
    {{Y, M, D}, {H, _, _}} = calendar:now_to_universal_time(Now),
    {Y, M, D, H}.

zeropad_str(NumStr, Zeros) when Zeros > 0 ->
    zeropad_str([$0 | NumStr], Zeros - 1);
zeropad_str(NumStr, _) ->
    NumStr.

zeropad(Num, MinLength) ->
    NumStr = integer_to_list(Num),
    zeropad_str(NumStr, MinLength - length(NumStr)).

suffix({Y, M, D, H}) ->
    YS = zeropad(Y, 4),
    MS = zeropad(M, 2),
    DS = zeropad(D, 2),
    HS = zeropad(H, 2),
    lists:flatten([$., YS, $_, MS, $_, DS, $_, HS]).

fmt_alog(Time, Ip, User, Method, Path, {VM,Vm},
         Status,  Length, Referrer, UserAgent) ->
    [fmt_ip(Ip), " - ", User, [$\s], Time, [$\s, $"], Method, " ", Path,
     " HTTP/", integer_to_list(VM), ".", integer_to_list(Vm), [$",$\s],
     Status, [$\s], Length, [$\s,$"], Referrer,
     [$",$\s,$"], UserAgent, [$",$\n]].

month(1) ->
    "Jan";
month(2) ->
    "Feb";
month(3) ->
    "Mar";
month(4) ->
    "Apr";
month(5) ->
    "May";
month(6) ->
    "Jun";
month(7) ->
    "Jul";
month(8) ->
    "Aug";
month(9) ->
    "Sep";
month(10) ->
    "Oct";
month(11) ->
    "Nov";
month(12) ->
    "Dec".
zone() ->
    Time = erlang:universaltime(),
    LocalTime = calendar:universal_time_to_local_time(Time),
    DiffSecs = calendar:datetime_to_gregorian_seconds(LocalTime) - calendar:datetime_to_gregorian_seconds(Time),
    zone((DiffSecs/3600)*100).

%% Ugly reformatting code to get times like +0000 and -1300

zone(Val) when Val < 0 ->
    io_lib:format("-~4..0w", [trunc(abs(Val))]);
zone(Val) when Val >= 0 ->
    io_lib:format("+~4..0w", [trunc(abs(Val))]).

fmt_ip(IP) when is_tuple(IP) ->
    inet_parse:ntoa(IP);
fmt_ip(undefined) ->
    "0.0.0.0";
fmt_ip(HostName) ->
    HostName.

fmtnow() ->
    {{Year, Month, Date}, {Hour, Min, Sec}} = calendar:local_time(),
    io_lib:format("[~2..0w/~s/~4..0w:~2..0w:~2..0w:~2..0w ~s]",
                  [Date,month(Month),Year, Hour, Min, Sec, zone()]).
