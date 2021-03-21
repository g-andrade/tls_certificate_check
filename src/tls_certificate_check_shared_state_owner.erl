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
-module(tls_certificate_check_shared_state_owner).
-behaviour(gen_server).

-include_lib("stdlib/include/assert.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [child_spec/0,
    start_link/0,
    authoritative_certificate_values/0,
    find_trusted_authority/1,
    maybe_update_shared_state/1
   ]).

-ignore_xref(
   [start_link/0
   ]).

%%-------------------------------------------------------------------
%% OTP Process Function Exports
%%-------------------------------------------------------------------

-export(
   [proc_lib_init/0
   ]).

-ignore_xref(
   [proc_lib_init/0
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
%% Internal Function Exports
%% ------------------------------------------------------------------

-ifdef(TEST).
-export(
   [latest_shared_state_key/0
   ]).

-ignore_xref(
   [latest_shared_state_key/0
   ]).
-endif.

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(SERVER, ?MODULE).
-define(INFO_TABLE, ?SERVER).
-define(HIBERNATE_AFTER, (timer:seconds(10))).

-define(SHARED_STATE_KEY_PREFIX, "__$tls_certificate_check.shared_state.").

%% ------------------------------------------------------------------
%% Record and Type Definitions
%% ------------------------------------------------------------------

-record(state, {
          shared_state_initialized :: boolean()
         }).
-type state() :: #state{}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    #{ id => ?SERVER,
       start => {?MODULE, start_link, []},
       shutdown => infinity % ensure `:terminate/2' has time to run unless killed
     }.

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    proc_lib:start_link(?MODULE, proc_lib_init, []).

-spec authoritative_certificate_values() -> [public_key:der_encoded(), ...] | no_return().
authoritative_certificate_values() ->
    SharedStateKey = latest_shared_state_key(),
    tls_certificate_check_shared_state:authoritative_certificate_values(SharedStateKey).

-spec find_trusted_authority([public_key:der_encoded()])
        -> {trusted_ca, public_key:der_encoded()}
           | unknown_ca
           | no_return().
find_trusted_authority(EncodedCertificates) ->
    SharedStateKey = latest_shared_state_key(),
    tls_certificate_check_shared_state:find_trusted_authority(SharedStateKey, EncodedCertificates).

-spec maybe_update_shared_state(binary()) -> ok | {error, term()}.
maybe_update_shared_state(EncodedAuthorities) ->
    try
        gen_server:call(?SERVER, {update_shared_state, EncodedAuthorities}, infinity)
    catch
        exit:{noproc, {gen_server, call, [?SERVER | _]}} ->
            ok
    end.

%% ------------------------------------------------------------------
%% OTP Process Function Definitions
%% ------------------------------------------------------------------

-spec proc_lib_init() -> no_return().
proc_lib_init() ->
    % do this before registering to ensure initialization is triggered before any update
    EncodedAuthorities = tls_certificate_check_hardcoded_authorities:encoded_list(),
    gen_server:cast(self(), {initialize_shared_state, EncodedAuthorities}),

    try register(?SERVER, self()) of
        true ->
            _ = process_flag(trap_exit, true), % ensure `terminate/2' is called unless killed
            _ = new_info_table(),
            GenServerOptions = [{hibernate_after, ?HIBERNATE_AFTER}],
            State = #state{shared_state_initialized = false},
            gen_server:enter_loop(?MODULE, GenServerOptions, State)
    catch
        error:badarg when is_atom(?SERVER) ->
            proc_lib:init_ack({error, {already_started, whereis(?SERVER)}}),
            exit(normal)
    end.

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

-spec init(_) -> no_return().
init(_) ->
    error('Not to be called').

-spec handle_call(term(), {pid(), reference()}, state())
        -> {reply, ok, state()} |
           {reply, {error, term()}, state()} |
           {stop, {unexpected_call, #{request := _, from := {pid(), reference()}}}, state()}.
handle_call({update_shared_state, EncodedAuthorities}, _From, State)
  when State#state.shared_state_initialized ->
    handle_shared_state_update(EncodedAuthorities, State);
handle_call(Request, From, State) ->
    ErrorDetails = #{request => Request, from => From},
    {stop, {unexpected_call, ErrorDetails}, State}.

-spec handle_cast(term(), state())
        -> {noreply, state()} |
           {stop, normal, state()} |
           {stop, {unexpected_cast, term()}, state()}.
handle_cast({initialize_shared_state, EncodedAuthorities}, State)
  when not State#state.shared_state_initialized ->
    handle_shared_state_initialization(EncodedAuthorities, State);
handle_cast(Request, State) ->
    {stop, {unexpected_cast, Request}, State}.

-spec handle_info(term(), state())
        -> {stop, {unexpected_info, term()}, state()}.
handle_info(Info, State) ->
    {stop, {unexpected_info, Info}, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ets:delete_all_objects(?INFO_TABLE),
    erlang:yield(),
    _ = tls_certificate_check_shared_state:destroy_all(?SHARED_STATE_KEY_PREFIX),
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

new_info_table() ->
    Opts = [named_table, protected, {read_concurrency, true}],
    ets:new(?INFO_TABLE, Opts).

handle_shared_state_initialization(EncodedAuthorities, State) ->
    case new_shared_state(EncodedAuthorities) of
        {ok, Key} ->
            ?assert( ets:insert_new(?INFO_TABLE, [{latest_shared_state_key, Key}]) ),
            proc_lib:init_ack({ok, self()}),
            UpdatedState = State#state{shared_state_initialized = true},
            {noreply, UpdatedState};
        {error, Reason} ->
            proc_lib:init_ack({error, Reason}),
            {stop, normal, State}
    end.

handle_shared_state_update(EncodedAuthorities, State) ->
    case new_shared_state(EncodedAuthorities) of
        {ok, Key} ->
            ets:insert(?INFO_TABLE, [{latest_shared_state_key, Key}]),
            {reply, ok, State};
        {error, _Reason} = Error ->
            {reply, Error, State}
    end.

new_shared_state(EncodedAuthorities) ->
    Key = shared_state_key(EncodedAuthorities),
    case tls_certificate_check_shared_state:new(Key, EncodedAuthorities) of
        ok ->
            {ok, Key};
        {error, _} = Error ->
            Error
    end.

shared_state_key(EncodedAuthorities) ->
    EncodedAuthoritiesDigest = crypto:hash(sha256, EncodedAuthorities),
    Suffix = binary:decode_unsigned(EncodedAuthoritiesDigest, big),
    String = ?SHARED_STATE_KEY_PREFIX ++ integer_to_list(Suffix, 16),
    list_to_atom(String).

latest_shared_state_key() ->
    try ets:lookup(?INFO_TABLE, latest_shared_state_key) of
        [{latest_shared_state_key, Key}] ->
            Key;
        [] ->
            throw({application_not_ready, tls_certificate_check})
    catch
        error:badarg when is_atom(?INFO_TABLE) ->
            throw({application_either_not_started_or_not_ready, tls_certificate_check})
    end.
