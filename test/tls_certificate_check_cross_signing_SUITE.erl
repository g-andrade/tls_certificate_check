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

-module(tls_certificate_check_cross_signing_SUITE).
-compile(export_all).

-include_lib("stdlib/include/assert.hrl").

%% ------------------------------------------------------------------
%% Macros
%% ------------------------------------------------------------------

-define(PEMS_PATH, "../../../../test/cross_signing").

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [good_chain_with_expired_root_test,
     bad_chain_with_expired_root_test,
     cross_signing_with_one_recognized_ca_test,
     cross_signing_with_one_other_recognized_ca_test].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(tls_certificate_check).

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

good_chain_with_expired_root_test(_Config) ->
    connect("good_ca_store_for_expiry.pem",
            "localhost_chain_for_expiry.pem",
            fun ({ok, Socket}) ->
                    ssl:close(Socket)
            end).

bad_chain_with_expired_root_test(_Config) ->
    connect("bad_ca_store_for_expiry.pem",
            "localhost_chain_for_expiry.pem",
            fun ({error, {tls_alert, {certificate_expired, _}}}) ->
                    ok
            end).

cross_signing_with_one_recognized_ca_test(_Config) ->
    connect("ca_store1_for_cross_signing.pem",
            "localhost_chain_for_cross_signing.pem",
            fun ({ok, Socket}) ->
                    ssl:close(Socket)
            end).

cross_signing_with_one_other_recognized_ca_test(_Config) ->
    connect("ca_store2_for_cross_signing.pem",
            "localhost_chain_for_cross_signing.pem",
            fun ({ok, Socket}) ->
                    ssl:close(Socket)
            end).

%% ------------------------------------------------------------------
%% Internal
%% ------------------------------------------------------------------

connect(AuthoritiesFilename, ChainFilename, Fun) ->
    AuthoritiesPath = filename:join([?PEMS_PATH, "CA_stores", AuthoritiesFilename]),
    {ok, EncodedAuthorities} = file:read_file(AuthoritiesPath),
    ok = tls_certificate_check_shared_state:maybe_update_shared_state(EncodedAuthorities),

    {ListenSocket, Port, AcceptorPid} = start_server_with_chain(ChainFilename),
    try
        Hostname = "localhost",
        Options = tls_certificate_check:options(Hostname),
        Timeout = timer:seconds(5),
        _ = Fun( ssl:connect(Hostname, Port, Options, Timeout) ),
        ok
    after
        stop_ssl_acceptor(AcceptorPid),
        _ = ssl:close(ListenSocket)
    end.

start_server_with_chain(ChainFilename) ->
    CertsPath = filename:join([?PEMS_PATH, "certificate_chains", ChainFilename]),
    KeyPath = filename:join([?PEMS_PATH, "leaf_certificates", "localhost_key.pem"]),
    Options = [{ip, {127, 0, 0, 1}},
               {certfile, CertsPath},
               {keyfile, KeyPath},
               {reuseaddr, true}],

    {ok, ListenSocket} = ssl:listen(_Port = 0, Options),
    {ok, {_Address, Port}} = ssl:sockname(ListenSocket),
    AcceptorPid = start_ssl_acceptor(ListenSocket),
    {ListenSocket, Port, AcceptorPid}.

start_ssl_acceptor(ListenSocket) ->
    spawn_link(fun () -> run_ssl_acceptor(ListenSocket) end).

run_ssl_acceptor(ListenSocket) ->
    receive
        stop -> exit(normal)
    after
        0 -> ok
    end,

    case ssl:transport_accept(ListenSocket, _Timeout = 100) of
        {ok, Transportsocket} ->
            _ = ssl:handshake(Transportsocket),
            run_ssl_acceptor(ListenSocket);
        {error, Reason}
          when Reason =:= timeout; Reason =:= closed ->
            run_ssl_acceptor(ListenSocket)
    end.

stop_ssl_acceptor(AcceptorPid) ->
    AcceptorPid ! stop.
