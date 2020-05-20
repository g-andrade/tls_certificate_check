%% Copyright (c) 2020 Guilherme Andrade
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

-module(validation_SUITE).
-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

-define(OTP_21_3__INITIAL_SSL_VERSION, [9,2]).

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [{group, GroupName} || {GroupName, _, _} <- groups()].

groups() ->
    [group_definition(GroupName)
     || GroupName
        <- [hostname_target,
            https_url_target,
            http_url_target,
            custom_chain_depth_limit]].

group_definition(GroupName) ->
    {GroupName, [parallel], group_test_cases(GroupName)}.

group_test_cases(GroupName) ->
    Exports = ?MODULE:module_info(exports),
    Candidates = [Name || {Name,1} <- Exports, lists:suffix("_test", atom_to_list(Name))],
    lists:filter(
      fun (Candidate) ->
              case ?MODULE:Candidate(groups) of
                  all ->
                      true;
                  {all_but, ExcludedGroupNames} ->
                      not lists:member(GroupName, ExcludedGroupNames);
                  TargetGroupNames ->
                      lists:member(GroupName, TargetGroupNames)
              end
      end,
      Candidates).

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(tls_certificate_validation),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_group(GroupName, Config) ->
    case GroupName of
        hostname_target ->
            Config;
        https_url_target ->
            [{validation_target, https_url} | Config];
        http_url_target ->
            [{validation_target, http_url} | Config];
        custom_chain_depth_limit ->
            [{validation_overrides, [{depth, 50}]} | Config]
    end.

end_per_group(_GroupName, _Config) ->
    ok.

%% ------------------------------------------------------------------
%% Boilerplate Macros
%% ------------------------------------------------------------------

-define(do_https_test(Config, Host, ExpectedResultMatch),
        (begin
             URL = "https://" ++ Host ++ "/",
             Headers = [{"connection", "close"}],
             HTTPOpts = httpc_http_opts(Config, Host),
             Opts = [],
             ?assertMatch(
                ExpectedResultMatch,
                httpc:request(head, {URL, Headers}, HTTPOpts, Opts))
         end)).

-define(expect_success(Config, Host),
        ?do_https_test(
           (Config), (Host),
           {ok, {{_, 200, _}, _, _}})).

-define(expect_tls_alert(Config, Host, ExpectedTlsAlert),
        ?do_https_test(
           (Config), (Host),
           {error, {failed_connect,
                    [{to_address, {Host,_}},
                     {inet, [inet], {tls_alert,ExpectedTlsAlert}}
                    ]}})).

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

good_certificate_test(groups) ->
    all;
good_certificate_test(Config) ->
    ?expect_success(Config, "badssl.com").

disorderly_certificate_chain_test(groups) ->
    {all_but, [http_url_target]};
disorderly_certificate_chain_test(_Config) ->
    {skip, "Dependent on https://github.com/chromium/badssl.com/pull/443 being approved"}.

expired_certificate_test(groups) ->
    {all_but, [http_url_target]};
expired_certificate_test(Config) ->
    case ssl_app_version() >= ?OTP_21_3__INITIAL_SSL_VERSION of
        true ->
            ?expect_tls_alert(Config, "expired.badssl.com", {certificate_expired, _});
        false ->
            ?expect_tls_alert(Config, "expired.badssl.com", "certificate expired")
    end.

wrong_host_certificate_test(groups) ->
    {all_but, [http_url_target]};
wrong_host_certificate_test(Config) ->
    case ssl_app_version() >= ?OTP_21_3__INITIAL_SSL_VERSION of
        true ->
            ?expect_tls_alert(Config, "wrong.host.badssl.com", {handshake_failure, _});
        false ->
            ?expect_tls_alert(Config, "wrong.host.badssl.com", "handshake failure")
    end.

self_signed_certificate_test(groups) ->
    {all_but, [http_url_target]};
self_signed_certificate_test(Config) ->
    case ssl_app_version() >= ?OTP_21_3__INITIAL_SSL_VERSION of
        true ->
            ?expect_tls_alert(Config, "self-signed.badssl.com", {bad_certificate, _});
        false ->
            ?expect_tls_alert(Config, "self-signed.badssl.com", "bad certificate")
    end.

unknown_authority_test(groups) ->
    {all_but, [http_url_target]};
unknown_authority_test(Config) ->
    case ssl_app_version() >= ?OTP_21_3__INITIAL_SSL_VERSION of
        true ->
            ?expect_tls_alert(Config, "untrusted-root.badssl.com", {unknown_ca, _});
        false ->
            ?expect_tls_alert(Config, "untrusted-root.badssl.com", "unknown ca")
    end.

%% ------------------------------------------------------------------
%% Internal
%% ------------------------------------------------------------------

ssl_app_version() ->
    {ok, _} = application:ensure_all_started(ssl),
    {ssl, _, VersionStr} = lists:keyfind(ssl, 1, application:which_applications()),
    VersionBin = list_to_binary(VersionStr),
    Parts = binary:split(VersionBin, <<".">>, [global]),
    lists:map(fun binary_to_integer/1, Parts).

httpc_http_opts(Config, Host) ->
    ValidationTarget = validation_target(Config, Host),
    TLSValidationOpts = tls_validation_opts(Config, ValidationTarget),
    assert_validation_overrides_were_kept(Config, TLSValidationOpts),
    [{ssl, TLSValidationOpts}].

validation_target(Config, Host) ->
    case proplists:get_value(validation_target, Config) of
        https_url ->
            "https://" ++ Host;
        http_url ->
            "http://" ++ Host;
        _ ->
            Host
    end.

tls_validation_opts(Config, ValidationTarget) ->
    case proplists:get_value(validation_overrides, Config) of
        Overrides when is_list(Overrides) ->
            tls_certificate_validation:options(ValidationTarget, Overrides);
        _ ->
            tls_certificate_validation:options(ValidationTarget)
    end.

assert_validation_overrides_were_kept(Config, TLSValidationOpts) ->
    Overrides = proplists:get_value(validation_overrides, Config, []),
    lists:foreach(
      fun (Opt) ->
              ?assert( lists:member(Opt, TLSValidationOpts) )
      end,
      Overrides).
