-module(uce_log_event).
-author('Mathieu Lecarme mathieu.lecarme@af83.com').

-export([init/1, terminate/2, handle_event/2, handle_info/2, handle_call/2]).

init(_) ->
    {ok, []}.
terminate(_, State) ->
    State.
% handle_event({error, Gleader, {Pid, Format, Data}}, _Data2) ->
%     uce_logger:log(4, error_logger, 0, "[~w ~w] " ++ Format, [Gleader, Pid] ++ Data);
% handle_event({error_report, Gleader, {Pid, std_error, Report}}, _Data) ->
%     uce_logger:log(4, error_logger, 0, "[~w ~w] ~s" , [Gleader, Pid, fmt_report(Report)]);
    
% handle_event({error_report, Gleader, {Pid, Type, Report}}, Data) ->
%     ok;
% handle_event({warning_msg, Gleader, {Pid, Format, Data}}, Data) ->
%     ok;
% handle_event({warning_report, Gleader, {Pid, std_warning, Report}}, Data) ->
%     ok;
% handle_event({warning_report, Gleader, {Pid, Type, Report}}, Data) ->
%     ok;
handle_event({info_msg, Gleader, {Pid, Format, Data}}, State) ->
    uce_logger:log(2, error_logger, 0, "[~w ~w] " ++ Format, [Gleader, Pid] ++ Data),
    {ok, State};
% handle_event({info_report, Gleader, {Pid, std_info, Report}}, State) ->
%     {ok, State};
% handle_event({info_report, Gleader, {Pid, Type, Report}}, State) ->
%     {ok, State};
handle_event(Event, State) ->
    uce_logger:log(4, error_logger, 0, "Event received: ~p" , [Event]),
    {ok, State}.


handle_info(_, State) ->
    {ok, State}.
    
handle_call(null, State) ->
    {ok, null, State}.

% fmt_report(Report) when is_list(Report) ->
%     lists:concat(lists:map(
%         fun ({Tag, Data}) when is_list(Data) -> io_lib:format("~p : ~s ", [Tag, Data]);
%             ({Tag, Data}) -> io_lib:format("~p : ~p ", [Tag, Data]);
%             (A) when is_list(A) ->  io_lib:format("~s ", [A]);
%             (A) -> io_lib:format("~p ", [A])
%         end
%     , Report));
% fmt_report(Report) ->
%     fmt_report([Report]).

% -ifdef(TEST).
% -include_lib("eunit/include/eunit.hrl").
%     fmt_report_test() ->
%         fmt_report([{tag, "popo"}, "aussi"]).
% -endif.    