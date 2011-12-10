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

%
% BCrypt authentication backend.

% This module assumes password stored in the database is a bcrypt hash
% of the actual password. This module has been primarily meant to
% allow easy synchronisation between uce user and rails-devise users
%
% You must provide an already hashed password when adding an user to
% uce if it is to auth himself using this backend
%
-module(bcrypt_auth).

-include("uce.hrl").

-export([assert/2, check/2]).

assert(User, Credential) ->
    case check(User, Credential) of
        {ok, true} ->
            {ok, true};
        {ok, false} ->
            throw({error, bad_credentials})
    end.

check(User, Credential) ->
    {ok, Hash} = bcrypt:hashpw(Credential, User#uce_user.credential),
    case Hash =:= User#uce_user.credential of
        true ->
            {ok, true};
        _ ->
            {ok, false}
    end.
