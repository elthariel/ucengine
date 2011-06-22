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
-module(file_helpers).

-author('victor.goya@af83.com').

-include("uce.hrl").

-export([to_json/2,
         download/3]).

to_json(Domain, #uce_file{id=Id,
                          name=Name,
                          location=Location,
                          uri=Uri,
                          metadata=Metadata}) ->
    JSONLocation = [{location, Location}],
    {struct, [{id, Id},
              {domain, Domain},
              {name, Name},
              {uri, Uri}] ++ JSONLocation ++
         [{metadata, {struct, Metadata}}]}.

download(_Domain, Id, Content) ->
    [{status, 200},
     {header, {"Content-Disposition", "filename=" ++ yaws_api:url_encode(Id)}},
     {content, "application/octet-stream", Content}].
