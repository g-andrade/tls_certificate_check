%% Copyright (c) 2021 Guilherme Andrade
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy  of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

%% @private
-module(tls_certificate_check_authorities_updater).
-behaviour(gen_server).

-include_lib("stdlib/include/assert.hrl").
-include_lib("kernel/include/file.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [child_spec/0,
    start_link/0
   ]).

-ignore_xref(
   [start_link/0
   ]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export(
   [init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
   ]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(SERVER, ?MODULE).
-define(HIBERNATE_AFTER, (timer:seconds(10))).

%% ------------------------------------------------------------------
%% Record and Type Definitions
%% ------------------------------------------------------------------

-record(state, {
         }).
-type state() :: #state{}.

% -type check_result()
%     :: {ok, successful_update()}
%     |  {dismissed, cache_still_valid}
%     |  {error, failed_update()}.
%
% -type successful_update()
%     :: #{}. % TODO
%
% -type failed_update()
%     :: term(). % TODO


%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    #{ id => ?SERVER,
       start => {?MODULE, start_link, []}
     }.

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [],
                          [{hibernate_after, ?HIBERNATE_AFTER}]).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init([]) -> {ok, state()}.
init([]) ->
    State = #state{},
    case check_for_update() of
        {updated, #{datetime := NewAuthoritiesDateTime}} ->
            {{Year, Month, Day}, {Hours, Minutes, Seconds}} = NewAuthoritiesDateTime,
            tls_certificate_check_log:notice("Authorities updated to ~4..0b/~2..0b/~2..0b"
                                             ", ~2..0bh~2..0bm~2..0b",
                                             [Year, Month, Day, Hours, Minutes, Seconds]),
            {ok, State};

        {dismissed, #{datetime := CurrentAuthoritiesDateTime}} ->
            {{Year, Month, Day}, {Hours, Minutes, Seconds}} = CurrentAuthoritiesDateTime,
            tls_certificate_check_log:debug("Authorities kept at ~4..0b/~2..0b/~2..0b"
                                             ", ~2..0bh~2..0bm~2..0b",
                                             [Year, Month, Day, Hours, Minutes, Seconds]),
            {ok, State};

        {error, Reason} ->
            tls_certificate_check_log:debug("Update check failed: ~p", [Reason]),
            {ok, State}
    end.

-spec handle_call(term(), {pid(), reference()}, state())
        -> {stop, {unexpected_call, #{request := _, from := {pid(), reference()}}}, state()}.
handle_call(Request, From, State) ->
    ErrorDetails = #{request => Request, from => From},
    {stop, {unexpected_call, ErrorDetails}, State}.

-spec handle_cast(term(), state())
        -> {stop, {unexpected_cast, term()}, state()}.
handle_cast(Request, State) ->
    {stop, {unexpected_cast, Request}, State}.

-spec handle_info(term(), state())
        -> {stop, {unexpected_info, term()}, state()}.
handle_info(Info, State) ->
    {stop, {unexpected_info, Info}, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state() | term(), term())
        -> {ok, state()} | {error, {cannot_convert_state, term()}}.
code_change(_OldVsn, #state{} = State, _Extra) ->
    {ok, State};
code_change(_OldVsn, State, _Extra) ->
    {error, {cannot_convert_state, State}}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

check_for_update() ->
    case check_for_update_from_cache() of
        {updated, NewAuthoritiesInfo} ->
            case maybe_check_for_update_from_source(NewAuthoritiesInfo) of
                {updated, NewestAuthoritiesInfo} ->
                    {updated, NewestAuthoritiesInfo};
                {dismissed, NewAuthoritiesInfo} ->
                    {updated, NewAuthoritiesInfo};
                {error, Reason} ->
                    {error, Reason}
            end;
        {dismissed, CurrentAuthoritiesInfo} ->
            case maybe_check_for_update_from_source(CurrentAuthoritiesInfo) of
                {updated, NewestAuthoritiesInfo} ->
                    {updated, NewestAuthoritiesInfo};
                {dismissed, CurrentAuthoritiesInfo} ->
                    {dismissed, CurrentAuthoritiesInfo};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.


check_for_update_from_cache() ->
    CurrentAuthoritiesInfo = tls_certificate_check_shared_state:authorities_info(),
    #{url := CurrentAuthoritiesURL} = CurrentAuthoritiesInfo,
    CachePath = cache_path(CurrentAuthoritiesURL),
    tls_certificate_check_log:debug("Checking authorities cache under \"~ts\"",
                                    [CachePath]),

    case file:open(CachePath, [read, binary, raw]) of
        {ok, CacheIoDevice} ->
            try
                maybe_update_from_cache(CachePath, CacheIoDevice, CurrentAuthoritiesInfo)
            after
                _ = file:close(CacheIoDevice)
            end;
        {error, Reason} when Reason =:= enoent; Reason =:= enotdir ->
            deal_with_missing_cache(CachePath, CurrentAuthoritiesInfo);
        {error, enotdir} ->
            deal_with_missing_cache(CachePath, CurrentAuthoritiesInfo);
        {error, Reason} ->
            {error, {unable_to_open_cache_file, #{path => CachePath,
                                                  reason => Reason}}}
    end.

deal_with_missing_cache(Path, CurrentAuthoritiesInfo) ->
    case can_i_write_to_files_directory(Path) of
        {yes, directory_ensured} ->
            {dismissed, CurrentAuthoritiesInfo};
        {no, Reason} ->
            {error, {unable_to_cache, #{path => Path, reason => Reason}}}
    end.

maybe_update_from_cache(Path, IoDevice, CurrentAuthoritiesInfo) ->
    #{datetime := CurrentAuthoritiesDateTime} = CurrentAuthoritiesInfo,

    case file:read_file_info(IoDevice, [{time, universal}]) of
        {ok, #file_info{mtime = ModificationDateTime, size = Size}}
          when ModificationDateTime > CurrentAuthoritiesDateTime ->
            try_updating_from_cache(Path, IoDevice, Size, ModificationDateTime,
                                    CurrentAuthoritiesInfo);
        {ok, #file_info{}} ->
            {dismissed, CurrentAuthoritiesInfo};
        {error, enoent} ->
            not_found;
        {error, enotdir} ->
            not_found;
        {error, Reason} ->
            {error, {unable_to_read_cache_file_info, #{path => Path,
                                                       reason => Reason}}}
    end.

try_updating_from_cache(Path, IoDevice, Size, ModificationDateTime, CurrentAuthoritiesInfo) ->
    case file:read(IoDevice, Size) of
        {ok, EncodedAuthorities} ->
            try_updating_from_cache_content(Path, EncodedAuthorities, ModificationDateTime,
                                            CurrentAuthoritiesInfo);
        {error, Reason} ->
            {error, {unable_to_read_cache_file_content, #{path => Path,
                                                          reason => Reason}}}
    end.

try_updating_from_cache_content(Path, EncodedAuthorities, ModificationDateTime,
                                CurrentAuthoritiesInfo) ->
    #{url := URL} = CurrentAuthoritiesInfo,
    AuthoritiesUpdate = #{url => URL,
                          datetime => ModificationDateTime,
                          encoded_list => EncodedAuthorities},

    case tls_certificate_check_shared_state:maybe_update_shared_state(AuthoritiesUpdate) of
        ok ->
            NewAuthoritiesInfo = #{url => URL, datetime => ModificationDateTime},
            {updated, NewAuthoritiesInfo};
        {error, Reason} ->
            {error, {unable_to_update_from_cache, #{path => Path, reason => Reason}}}
    end.




maybe_check_for_update_from_source(CurrentAuthoritiesInfo) ->
    #{url := URL} = CurrentAuthoritiesInfo,
    RateLimiterPath = rate_limiter_path(URL),
    RateLimiterExpiryDateTime = rate_limiter_expiry_datetime(),
    tls_certificate_check_log:debug("Checking rate limiter under \"~ts\"", [RateLimiterPath]),

    case read_file_modification_datetime(RateLimiterPath) of
        {ok, LastCheckDateTime}
          when LastCheckDateTime =< RateLimiterExpiryDateTime ->
            update_rate_limiter_and_check_for_update_from_source(CurrentAuthoritiesInfo);
        {ok, _LastCheckDateTime} ->
            {dismissed, CurrentAuthoritiesInfo};
        not_found ->
            update_rate_limiter_and_check_for_update_from_source(CurrentAuthoritiesInfo);
        {error, Reason} ->
            {error, {unable_to_read_rate_limiter, #{path => RateLimiterPath, reason => Reason}}}
    end.

read_file_modification_datetime(PathOrIoDevice) ->
    case file:read_file_info(PathOrIoDevice, [{time, universal}]) of
        {ok, #file_info{mtime = ModificationDateTime}} ->
            {ok, ModificationDateTime};
        {error, enoent} ->
            not_found;
        {error, enotdir} ->
            not_found;
        {error, Reason} ->
            {error, Reason}
    end.

update_rate_limiter_and_check_for_update_from_source(CurrentAuthoritiesInfo) ->
    #{url := AuthoritiesURL} = CurrentAuthoritiesInfo,
    RateLimiterPath = rate_limiter_path(AuthoritiesURL),
    Now = calendar:universal_time(),
    case update_file_modification_datetime(RateLimiterPath, Now) of
        ok ->
            check_for_update_from_source(CurrentAuthoritiesInfo);
        {error, Reason} ->
            {error, {unable_to_update_rate_limiter_file, #{path => RateLimiterPath,
                                                           reason => Reason}}}
    end.

check_for_update_from_source(CurrentAuthoritiesInfo) ->
    #{url := URL,
      datetime := CurrentAuthoritiesDateTime} = CurrentAuthoritiesInfo,

    IfModifiedSince= calendar:universal_time_to_local_time(CurrentAuthoritiesDateTime),
    RequestHeaders = [{"if-modified-since", httpd_util:rfc1123_date(IfModifiedSince)},
                      {"connection", "close"}],

    % Autoredirect causes issues for HTTPS downloads,
    % since the TLS validation set up below
    % can only account for the current URL's hostname.
    HttpOpts
        = [{autoredirect, false},
           {ssl, tls_certificate_check:options(URL)},
           {connect_timeout, timer:seconds(3)}, % FIXME
           {timeout, timer:seconds(5)}], % FIXME
    Opts
        = [{body_format, binary}],

    case httpc:request(get, {URL, RequestHeaders}, HttpOpts, Opts) of
        {ok, {{_Prelude, 200, _StatusString}, ResponseHeaders, EncodedAuthorities}} ->
            load_update_from_source(URL, ResponseHeaders, EncodedAuthorities);
        {ok, {{_Prelude, 304, _StatusString}, _ResponseHeaders, _Responsebody}} ->
            {dismissed, CurrentAuthoritiesInfo};
        {ok, {{_Prelude, StatusCode, StatusString}, ResponseHeaders, ResponseBody}} ->
            {error, {failed_to_check_for_update_from_source,
                     {http, #{status => {StatusCode, StatusString},
                              response_headers => ResponseHeaders,
                              response_body => ResponseBody}}}};
        {error, Reason} ->
            {error, {failed_to_check_for_update_from_source, Reason}}
    end.

load_update_from_source(URL, ResponseHeaders, EncodedAuthorities) ->
    case get_and_parse_last_modified_header(ResponseHeaders) of
        {ok, ModificationDateTime} ->
            AuthoritiesUpdate = #{url => URL,
                                  datetime => ModificationDateTime,
                                  encoded_list => EncodedAuthorities},
            load_update_from_source(AuthoritiesUpdate);
        {error, Reason} ->
            {error, {remote_modification_datetime, Reason}}
    end.

get_and_parse_last_modified_header(ResponseHeaders) ->
    case lists:keyfind("last-modified", 1, ResponseHeaders) of
        {"last-modified", LastModified} ->
            parse_last_modified_header(LastModified);
        false ->
            {error, {response_header_missing, "last-modified"}}
    end.

parse_last_modified_header(LastModified) ->
    try httpd_util:convert_request_date(LastModified) of
        {_,_} = ModificationDateTime ->
            {ok, ModificationDateTime};
        ErrorReason ->
            {error, {ErrorReason, LastModified}}
    catch
        Class:Reason:Stacktrace ->
            {error, {Class, Reason, Stacktrace}}
    end.

load_update_from_source(AuthoritiesUpdate) ->
    case tls_certificate_check_shared_state:maybe_update_shared_state(AuthoritiesUpdate) of
        ok ->
            save_update_in_cache(AuthoritiesUpdate);
        {error, Reason} ->
            {error, {failed_to_load_update_from_source, Reason}}
    end.

save_update_in_cache(AuthoritiesUpdate) ->
    #{url := URL,
      datetime := DateTime,
      encoded_list := EncodedAuthorities} = AuthoritiesUpdate,

    Path = cache_path(URL),
    case save_file(Path, EncodedAuthorities, {modification_datetime, DateTime}) of
        ok ->
            NewAuthoritiesInfo = #{url => URL, datetime => DateTime},
            {updated, NewAuthoritiesInfo};
        {error, Reason} ->
            {error, {unable_to_update_cache, #{path => Path, reason => Reason}}}
    end.

save_file(Path, Content, {modification_datetime, ModificationDateTime}) ->
    case filelib:ensure_dir(Path) of
        ok ->
            FileInfo = #file_info{mtime = ModificationDateTime},
            save_file_under_ensured_dir(Path, Content, FileInfo);
        {error, Reason} ->
            {error, {ensure_dir, Reason}}
    end.

save_file_under_ensured_dir(Path, Content, FileInfo) ->
    TmpSuffix = ".tmp." ++ integer_to_list(rand:uniform(1 bsl 32), 36),
    TmpPath = Path ++ TmpSuffix,

    case file:open(TmpPath, [write, exclusive, raw]) of
        {ok, IoDevice} ->
            save_file_with_tmp_io_device(Path, TmpPath, IoDevice, Content, FileInfo);
        {error, Reason} ->
            {error, {open, Reason}}
    end.

save_file_with_tmp_io_device(Path, TmpPath, IoDevice, Content, FileInfo) ->
    case file:write(IoDevice, Content) of
        ok ->
            save_file_info_with_tmp_io_device(Path, TmpPath, IoDevice, FileInfo);
        {error, Reason} ->
            {error, {write, Reason}}
    end.

save_file_info_with_tmp_io_device(Path, TmpPath, IoDevice, FileInfo) ->
    case file:write_file_info(TmpPath, FileInfo, [{time, universal}]) of
        ok ->
            _ = file:close(IoDevice),
            persist_saved_temporary_file(Path, TmpPath);
        {error, Reason} ->
            _ = file:close(IoDevice),
            {error, {write_file_info, Reason}}
    end.

persist_saved_temporary_file(Path, TmpPath) ->
    case file:rename(TmpPath, Path) of
        ok ->
            ok;
        {error, Reason} ->
            {error, {rename, #{from => TmpPath, reason => Reason}}}
    end.

update_file_modification_datetime(Path, DateTime) ->
    FileInfo = #file_info{mtime = DateTime},
    case file:write_file_info(Path, FileInfo, [{time, universal}]) of
        ok ->
            ok;
        {error, Reason} when Reason =:= enoent; Reason =:= enotdir ->
            save_file(Path, _Content = <<>>, {modification_datetime, DateTime});
        {error, Reason} ->
            {error, Reason}
    end.

can_i_write_to_files_directory(Path) ->
    case filelib:ensure_dir(Path) of
        ok ->
            Dir = filename:dirname(Path),
            can_i_write_to_ensured_files_directory(Dir);
        {error, Reason} ->
            {no, {ensure_dir, Reason}}
    end.

can_i_write_to_ensured_files_directory(Dir) ->
    Noise = rand:uniform(1 bsl 64),
    TestFile = "permissions_test." ++ integer_to_list(Noise, 36),
    TestPath = filename:join(Dir, TestFile),
    tls_certificate_check_log:debug("TestPath: ~p", [TestPath]),

    case file:write_file(TestPath, <<>>) of
        ok ->
            ok = file:delete(TestPath),
            {yes, directory_ensured};
        {error, Reason} ->
            {no, {write_test_file, Reason}}
    end.

rate_limiter_expiry_datetime() ->
    Now = calendar:universal_time(),
    NowSeconds = calendar:datetime_to_gregorian_seconds(Now),
    calendar:gregorian_seconds_to_datetime(NowSeconds - 86400).


cache_path(AuthoritiesURL) ->
    auxiliary_file_path(AuthoritiesURL, "pem").

rate_limiter_path(AuthoritiesURL) ->
     auxiliary_file_path(AuthoritiesURL, "rlim").

auxiliary_file_path(AuthoritiesURL, Extension) ->
    Dir = filename:basedir(user_cache, "erlang.tls_certificate_check"),
    Infix = filesystem_safe_name(AuthoritiesURL),
    FileName = unicode:characters_to_list(["cacerts-from.", Infix, ".", Extension]),
    filename:join(Dir, FileName).

filesystem_safe_name(Name) ->
    OnlyWordsAndSpaces = re:replace(Name, "[^\\w\\s-]+", "-", [global, unicode, ucp]),
    re:replace(OnlyWordsAndSpaces, "[-\\s]+", "-", [global, unicode, ucp, {return, binary}]).
