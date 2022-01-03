%% Copyright (c) 2021-2022 Guilherme Andrade
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
-module(tls_certificate_check_shared_state).
-behaviour(gen_server).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").
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

-record(shared_state, {
          authoritative_certificate_values :: [public_key:der_encoded(), ...],
          trusted_public_keys :: #{public_key_info() := []}
         }).

-type public_key_info() :: #'OTPSubjectPublicKeyInfo'{}.

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
    SharedState = get_latest_shared_state(),
    SharedState#shared_state.authoritative_certificate_values.

-spec find_trusted_authority([public_key:der_encoded()])
        -> {trusted_ca, public_key:der_encoded()}
           | unknown_ca
           | no_return().
find_trusted_authority(EncodedCertificates) ->
    SharedState = get_latest_shared_state(),
    TrustedPublicKeys = #{} = SharedState#shared_state.trusted_public_keys,
    Now = universal_time_in_certificate_format(),
    find_trusted_authority_recur(EncodedCertificates, Now, TrustedPublicKeys).

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
    _ = destroy_all_shared_states(),
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
    case tls_certificate_check_util:parse_encoded_authorities(EncodedAuthorities) of
        {ok, AuthoritativeCertificateValues} ->
            NewSharedState
                = #shared_state{
                     authoritative_certificate_values = AuthoritativeCertificateValues,
                     trusted_public_keys = trusted_public_keys(AuthoritativeCertificateValues)
                    },
            save_shared_state(NewSharedState);
        {error, Reason} ->
            {error, {failed_to_decode_authorities, Reason}}
    end.

trusted_public_keys(AuthoritativeCertificateValues) ->
    lists:foldl(
      fun (CertificateValue, Acc) ->
              DecodedCertificateValue = public_key:pkix_decode_cert(CertificateValue, otp),
              #'OTPCertificate'{tbsCertificate = TbsCertificate} = DecodedCertificateValue,
              #'OTPTBSCertificate'{subjectPublicKeyInfo = PKI} = TbsCertificate,
              maps:put(PKI, [], Acc)
      end,
      #{}, AuthoritativeCertificateValues).

save_shared_state(SharedState) ->
    Key = shared_state_key(SharedState),
    persistent_term:put(Key, SharedState),
    {ok, Key}.

shared_state_key(SharedState) ->
    CanonicalSharedStateRepresentation = canonical_shared_state_representation(SharedState),
    CanonicalSharedStateDigest
        = crypto:hash(sha256, term_to_binary(CanonicalSharedStateRepresentation)),

    KeySuffixInteger = binary:decode_unsigned(CanonicalSharedStateDigest, big),
    KeySuffix = integer_to_list(KeySuffixInteger, 16),
    list_to_atom(?SHARED_STATE_KEY_PREFIX ++ KeySuffix).

canonical_shared_state_representation(SharedState) ->
    TupleIndices = lists:seq(1, tuple_size(SharedState)),
    TupleValues = tuple_to_list(SharedState),
    KvPairs = lists:zip(TupleIndices, TupleValues),
    lists:map(
      fun ({1, RecordTag}) ->
              RecordTag;
          ({#shared_state.authoritative_certificate_values, AuthoritativeCertificateValues}) ->
              % Order matters - or rather, if the order is to change,
              % this should not provoke a VM-wide garbage collection
              % with a potentially disastrous explosion in memory
              % consumption.
              AuthoritativeCertificateValues;
          ({#shared_state.trusted_public_keys, TrustedPublicKeys}) ->
              % `term_to_binary/1' doesn't guarantee any particular encoding order;
              % therefore equivalent shared states could end up under different keys
              % (depending on VM implementation)
              lists:sort( maps:to_list(TrustedPublicKeys) )
      end,
      KvPairs).

destroy_all_shared_states() ->
    AllPersistentTermObjects = persistent_term:get(),
    lists:filtermap(
      fun ({Key, Value}) ->
              is_atom(Key)
              andalso lists:prefix(?SHARED_STATE_KEY_PREFIX,
                                   atom_to_list(Key))
              andalso is_record(Value, shared_state)
              andalso persistent_term:erase(Key)
              andalso {true, Key}
      end,
      AllPersistentTermObjects).

get_latest_shared_state() ->
    Key = latest_shared_state_key(),
    try
        persistent_term:get(Key)
    catch
        error:badarg ->
            throw({tls_certificate_check,
                   #{reason => shared_state_not_found,
                     persistent_term_key => Key}})
    end.

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

universal_time_in_certificate_format() ->
    % http://erlang.org/doc/apps/public_key/public_key_records.html
    % * {utcTime, "YYMMDDHHMMSSZ"
    % * {generalTime, "YYYYMMDDHHMMSSZ"}

    {{Year, Month, Day}, {Hour, Minute, Second}} = calendar:universal_time(),
    IoData = io_lib:format("~4..0B~2..0B~2..0B" "~2..0B~2..0B~2..0BZ",
                           [Year, Month, Day, Hour, Minute, Second]),
    lists:flatten(IoData).

find_trusted_authority_recur([EncodedCertificate | NextEncodedCertificates], Now, TrustedPublicKeys) ->
    Certificate = public_key:pkix_decode_cert(EncodedCertificate, otp),
    #'OTPCertificate'{tbsCertificate = TbsCertificate} = Certificate,
    #'OTPTBSCertificate'{subjectPublicKeyInfo = PublicKeyInfo,
                         validity = Validity} = TbsCertificate,

    case is_certificate_valid(Validity, Now)
         andalso maps:is_key(PublicKeyInfo, TrustedPublicKeys)
    of
        true ->
            {trusted_ca, EncodedCertificate};
        false ->
            find_trusted_authority_recur(NextEncodedCertificates, Now, TrustedPublicKeys)
    end;
find_trusted_authority_recur([], _Now, _TrustedPublicKeys) ->
    unknown_ca.

is_certificate_valid(Validity, Now) ->
    #'Validity'{notBefore = NotBefore, notAfter = NotAfter} = Validity,
    compare_certificate_timestamps(NotAfter, Now) =/= lesser
    andalso compare_certificate_timestamps(NotBefore, Now) =/= greater.

compare_certificate_timestamps({utcTime, String}, Now) ->
    compare_certificate_timestamps_("20" ++ String, Now);
compare_certificate_timestamps({generalTime, String}, Now) ->
    compare_certificate_timestamps_(String, Now).

compare_certificate_timestamps_([X|A], [Y|B]) ->
    if X < Y ->
           lesser;
       X > Y ->
           greater;
       true ->
           compare_certificate_timestamps_(A, B)
    end;
compare_certificate_timestamps_([], []) ->
    equal.
