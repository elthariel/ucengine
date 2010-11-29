-module(uce_event_mongodb).

-author('victor.goya@af83.com').

-export([
	 add/1,
	 get/1,
	 list/6,
	 from_collection/1,
	 to_collection/1
	 ]).

-include("uce.hrl").
-include("mongodb.hrl").

add(#uce_event{} = Event) ->
    ?MODULE:to_collection(Event),
    case catch emongo:insert_sync(?MONGO_POOL, "uce_event", ?MODULE:to_collection(Event)) of
	{'EXIT', _} ->
	    {error, bad_parameters};
	_ ->
	    ok
    end.

get(Id) ->
    case emongo:find_one(?MONGO_POOL, "uce_event", [{"id", Id}]) of
	[Collection] ->
	    ?MODULE:from_collection(Collection);
	_ ->
	    {error, not_found}
    end.

list(Location, From, Type, Start, End, Parent) ->
    SelectLocation = case Location of
			 ["", ""] ->
			     [];
			 [Org, ""] ->
			     [{"org", Org}];
			 [Org, Meeting] ->
			     [{"org", Org}, {"meeting", Meeting}]
		     end,
    SelectFrom = if
		       From  == '_' ->
			   [];
		       true ->
			   [{"from", From}]
		   end,
    SelectType = if
		       Type == '_' ->
			   [];
		       true ->
			   [{"type", Type}]
		   end,
    SelectParent = if
		       Parent == '_' ->
			   [];
		       true ->
			   [{"parent", Type}]
		   end,
    SelectTime = if
		       Start == 0, End == infinity -> 
			   [];
		       Start /= 0, End == infinity ->
			   [{"datetime", [{'>=', Start}]}];
		       Start /= 0, End /= infinity ->
			   [{"datetime", [{'>=', Start},
					  {'=<', End}]}];
		       Start == 0, End /= infinity ->
			   [{"datetime", [{'=<', End}]}];
		       true ->
			   []
	       end,
    lists:map(fun(Collection) ->
		      ?MODULE:from_collection(Collection)
	      end,
	      emongo:find_all(?MONGO_POOL,"uce_event",
			      SelectLocation ++
				  SelectFrom ++
				  SelectType ++
				  SelectParent ++
				  SelectTime,
			      [{orderby, [{"this.datetime", asc}]}])).

from_collection(Collection) ->
    case utils:get(mongodb_helpers:collection_to_list(Collection),
		  ["id", "org", "meeting", "from", "metadata", "datetime", "type", "parent", "to"]) of
	[Id, Org, Meeting, From, Metadata, Datetime, Type, Parent, To] ->
	    #uce_event{id=Id,
		       datetime=Datetime,
		       from=From,
		       to=To,
		       location=[Org, Meeting],
		       type=Type,
		       parent=Parent,
		       metadata=Metadata};
	_ ->
	    {error, bad_parameters}
    end.

to_collection(#uce_event{id=Id,
			 location=[Org, Meeting],
			 from=From,
			 to=To,
			 metadata=Metadata,
			 datetime=Datetime,
			 type=Type,
			 parent=Parent}) ->
    [{"id", Id},
     {"org", Org},
     {"meeting", Meeting},
     {"from", From},
     {"to", To},
     {"metadata", Metadata},
     {"datetime", Datetime},
     {"type", Type},
     {"parent", Parent}].
