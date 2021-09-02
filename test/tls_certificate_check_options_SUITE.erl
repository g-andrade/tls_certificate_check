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

%% ------------------------------------------------------------------
%% Macros
%% ------------------------------------------------------------------

-define(PEMS_PATH, "../../../../test/common_scenarios").

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [good_certificate_test,
     expired_certificate_test,
     future_certificate_test,
     wrong_host_certificate_test,
     self_signed_certificate_test,
     unknown_ca_test].

init_per_testcase(_TestConfig, Config) ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    Config.

end_per_testcase(_TestConfig, _Config) ->
    ok = application:stop(tls_certificate_check).

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

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
