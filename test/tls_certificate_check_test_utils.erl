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

connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, CertsConf, Fun) ->
    connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, CertsConf, Fun,
            _Opts = []).

connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, CertsConf, KeyFilename, Fun)
  when is_function(Fun) ->
    connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, CertsConf, Fun,
            _Opts = [{key, KeyFilename}]);
connect(PemsPath, AuthoritiesFilename, ChainOrLeaf, CertsConf, Fun,
        Opts)  ->
    KeyConf = proplists:get_value(key, Opts, "localhost_key.pem"),
    AuthoritiesPath = filename:join([PemsPath, "CA_stores", AuthoritiesFilename]),
    ok = tls_certificate_check:override_trusted_authorities({file, AuthoritiesPath}),

    {ListenSocket, Port, AcceptorPid} = start_server_with_chain(PemsPath, ChainOrLeaf,
                                                                CertsConf,
                                                                KeyConf),
    try
        ConnectRes = connect(Opts, Port),
        _ = Fun(ConnectRes)
    after
        stop_ssl_acceptor(AcceptorPid),
        _ = ssl:close(ListenSocket)
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

connect(Opts, Port) ->
    Timeout = timer:seconds(5),

    case proplists:get_value(hostname, Opts) of
        undefined ->
            Hostname = "localhost",
            Options = tls_certificate_check:options(Hostname),
            ssl:connect(Hostname, Port, Options, Timeout);
        {Hostname, IpAddress} ->
            Options = tls_certificate_check:options(Hostname),
            case gen_tcp:connect(IpAddress, Port, [], Timeout) of
                {ok, TcpSocket} ->
                    ssl:connect(TcpSocket, Options, Timeout);
                {error, _} = Error ->
                    Error
            end
    end.

start_server_with_chain(PemsPath, ChainOrLeaf, CertsConf, KeyConf) ->
    Options = server_options(PemsPath, ChainOrLeaf, CertsConf, KeyConf),
    ct:pal("server options: ~p", [Options]),

    {ok, ListenSocket} = ssl:listen(_Port = 0, Options),
    {ok, {_Address, Port}} = ssl:sockname(ListenSocket),
    AcceptorPid = start_ssl_acceptor(ListenSocket),
    {ListenSocket, Port, AcceptorPid}.

server_options(PemsPath, ChainOrLeaf, CertsConf, KeyConf) ->
    [{ip, {127, 0, 0, 1}},
     {reuseaddr, true}
     | certs_options(PemsPath, ChainOrLeaf, CertsConf, KeyConf)].

certs_options(PemsPath, ChainOrLeaf, CertFilename, KeyFilename)
  when is_list(CertFilename), is_list(KeyFilename) ->
    cert_options_for_paths(PemsPath, ChainOrLeaf, CertFilename, KeyFilename);
certs_options(PemsPath, ChainOrLeaf,
              {multiple, CertFilenames},
              {multiple, KeyFilenames}) ->
    [{sni_hosts, maps:fold(
        fun (Hostname, CertFilename, Acc) ->
                KeyFilename = maps:get(Hostname, KeyFilenames),
                Opts = cert_options_for_paths(PemsPath, ChainOrLeaf, CertFilename, KeyFilename),
                [{Hostname, Opts} | Acc]
        end,
        _Acc0 = [],
        CertFilenames)}].

cert_options_for_paths(PemsPath, ChainOrLeaf, CertFilename, KeyFilename) ->
    ChainOrLeafDir = chain_or_leaf_dir(ChainOrLeaf),
    CertsPath = filename:join([PemsPath, ChainOrLeafDir, CertFilename]),
    KeyPath = filename:join([PemsPath, "leaf_certificates", KeyFilename]),

    [{certfile, CertsPath},
     % Ugh: http://erlang.org/pipermail/erlang-questions/2020-May/099521.html
     {cacertfile, CertsPath},
     {keyfile, KeyPath}].

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
