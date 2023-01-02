%% Copyright (c) 2021-2023 Guilherme Andrade
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

-module(tls_certificate_check_test_utils).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([connect/5, connect/6]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, ChainOrLeafFilename, Fun) ->
    connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, ChainOrLeafFilename,
            _KeyFilename = "localhost_key.pem", Fun).

connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, ChainOrLeafFilename, KeyFilename, Fun) ->
    AuthoritiesPath = filename:join([PemsPath, "CA_stores", AuthoritiesFilename]),
    {ok, EncodedAuthorities} = file:read_file(AuthoritiesPath),
    ok = tls_certificate_check_shared_state:maybe_update_shared_state(EncodedAuthorities,
                                                                      [force_hardcoded]),

    {ListenSocket, Port, AcceptorPid} = start_server_with_chain(PemsPath, ChainOrLeaf,
                                                                ChainOrLeafFilename,
                                                                KeyFilename),
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

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

start_server_with_chain(PemsPath, ChainOrLeaf, ChainOrLeafFilename, KeyFilename) ->
    ChainOrLeafDir = chain_or_leaf_dir(ChainOrLeaf),
    CertsPath = filename:join([PemsPath, ChainOrLeafDir, ChainOrLeafFilename]),
    KeyPath = filename:join([PemsPath, "leaf_certificates", KeyFilename]),
    Options = [{ip, {127, 0, 0, 1}},
               {certfile, CertsPath},
               % Ugh: http://erlang.org/pipermail/erlang-questions/2020-May/099521.html
               {cacertfile, CertsPath},
               {keyfile, KeyPath},
               {reuseaddr, true}],

    {ok, ListenSocket} = ssl:listen(_Port = 0, Options),
    {ok, {_Address, Port}} = ssl:sockname(ListenSocket),
    AcceptorPid = start_ssl_acceptor(ListenSocket),
    {ListenSocket, Port, AcceptorPid}.

chain_or_leaf_dir(chain) ->
    "certificate_chains";
chain_or_leaf_dir(leaf) ->
    "leaf_certificates".

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
