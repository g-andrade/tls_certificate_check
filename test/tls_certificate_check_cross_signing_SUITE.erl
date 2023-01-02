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

-module(tls_certificate_check_cross_signing_SUITE).
-compile(export_all).

%% ------------------------------------------------------------------
%% Macros
%% ------------------------------------------------------------------

-define(PEMS_PATH, "../../../../test/cross_signing").

-define(REPEAT_N, 20).

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [{group, GroupName} || {GroupName, _Options, _TestCases} <- groups()].

groups() ->
    [{individual_tests, [{repeat, ?REPEAT_N}, shuffle], test_names()}].

test_names() ->
    [good_chain_with_expired_root_test,
     bad_chain_with_expired_root_test,
     cross_signing_with_one_recognized_ca_test,
     cross_signing_with_one_other_recognized_ca_test].

init_per_testcase(_TestConfig, Config) ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    Config.

end_per_testcase(_TestConfig, _Config) ->
    ok = application:stop(tls_certificate_check).

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

good_chain_with_expired_root_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "good_ca_store_for_expiry.pem",
      chain, "localhost_chain_for_expiry.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).

-ifdef(EXPIRED_CAs_ARE_CONSIDERED_VALID).

-ifdef(FLAKY_CROSS_SIGNING_VALIDATION).
bad_chain_with_expired_root_test(_Config) ->
    {skip, "This test fails non-deterministically on the present OTP version"}.
-else.
bad_chain_with_expired_root_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "bad_ca_store_for_expiry.pem",
      chain, "localhost_chain_for_expiry.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).
-endif. % ifdef(FLAKY_CROSS_SIGNING_VALIDATION

-else. % ifdef(EXPIRED_CAs_ARE_CONSIDERED_VALID)
bad_chain_with_expired_root_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "bad_ca_store_for_expiry.pem",
      chain, "localhost_chain_for_expiry.pem",
      fun ({error, {tls_alert, {certificate_expired, _}}}) ->
              ok
      end).

-endif. % -ifdef(EXPIRED_CAs_ARE_CONSIDERED_VALID)

cross_signing_with_one_recognized_ca_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "ca_store1_for_cross_signing.pem",
      chain, "localhost_chain_for_cross_signing.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).

-ifdef(FLAKY_CROSS_SIGNING_VALIDATION).
cross_signing_with_one_other_recognized_ca_test(_Config) ->
    {skip, "This test fails non-deterministically on the present OTP version"}.

-else.
cross_signing_with_one_other_recognized_ca_test(_Config) ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "ca_store2_for_cross_signing.pem",
      chain, "localhost_chain_for_cross_signing.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).

-endif. % -ifdef(FLAKY_CROSS_SIGNING_VALIDATION)
