%% Copyright (c) 2020-2021 Guilherme Andrade
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

-module(tls_certificate_check_options_SUITE).
-compile(export_all).

-include_lib("stdlib/include/assert.hrl").

%% ------------------------------------------------------------------
%% Macros
%% ------------------------------------------------------------------

-define(PEMS_PATH, "../../../../test/common_scenarios").

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [real_certificate_test,
     good_certificate_test,
     expired_certificate_test,
     future_certificate_test,
     wrong_host_certificate_test,
     self_signed_certificate_test,
     unknown_ca_test,
     misordered_chain_test].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(tls_certificate_check).

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

real_certificate_test(_Config) ->
    {ok, _} = application:ensure_all_started(inets),
    try
        URLs = shuffle_list(["https://example.com",
                             "https://google.com",
                             "https://microsoft.com"]),
        real_certificate_test_recur(URLs)
    after
        application:stop(inets)
    end.

good_certificate_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "good_certificate.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).

expired_certificate_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "expired_certificate.pem",
      fun ({error, {tls_alert, {certificate_expired, _}}}) ->
              ok
      end).

future_certificate_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "future_certificate.pem",
      fun ({error, {tls_alert, {certificate_expired, _}}}) ->
              ok
      end).

wrong_host_certificate_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "wrong.host.pem", "wrong.host_key.pem",
      fun ({error, {tls_alert, {handshake_failure, _}}}) ->
              ok
      end).

self_signed_certificate_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "self_signed.pem", "self_signed_key.pem",
      fun ({error, {tls_alert, {bad_certificate, _}}}) ->
              ok
      end).

unknown_ca_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "unknown_ca.pem",
      fun ({error, {tls_alert, {unknown_ca, _}}}) ->
              ok
      end).

misordered_chain_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      chain, "misordered_chain.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).

%% ------------------------------------------------------------------
%% Internal
%% ------------------------------------------------------------------

real_certificate_test_recur([Url | Next]) ->
    ct:pal("Trying ~p", [Url]),
    Headers = [{"connection", "close"}],
    HttpOpts = [{ssl, tls_certificate_check:options(Url)}],
    Opts = [],

    case httpc:request(head, {Url, Headers}, HttpOpts, Opts) of
        {ok, {{_, StatusCode, _}, _, _}}
          when is_integer(StatusCode) ->
            ok;
        {error, Reason} ->
            ?assertNotMatch({error, {failed_connect, [{to_address, {_, _}},
                                                      {inet, [inet], {tls_alert, _}}]}},
                            Reason),
            ct:pal("Failed: ~p", [Reason]),
            real_certificate_test_recur(Next)
    end;
real_certificate_test_recur([]) ->
    error('All test URLs are down (or we have no internet access)').

shuffle_list(List) ->
    Weighed = [{rand:uniform(), V} || V <- List],
    Sorted = lists:sort(Weighed),
    [V || {_, V} <- Sorted].
