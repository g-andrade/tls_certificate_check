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
%% Setup
%% ------------------------------------------------------------------

all() ->
    [{group, GroupName} || {GroupName, _, _} <- groups()].

groups() ->
    [group_definition(GroupName)
     || GroupName
        <- [hostname_target,
            https_url_target,
            http_url_target]].

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
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(tls_certificate_check).

init_per_group(GroupName, Config) ->
    case GroupName of
        hostname_target ->
            Config;
        https_url_target ->
            [{check_target, https_url} | Config];
        http_url_target ->
            [{check_target, http_url} | Config]
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
    ?expect_tls_alert(Config, "expired.badssl.com", {certificate_expired, _}).

wrong_host_certificate_test(groups) ->
    {all_but, [http_url_target]};
wrong_host_certificate_test(Config) ->
    ?expect_tls_alert(Config, "wrong.host.badssl.com", {handshake_failure, _}).

self_signed_certificate_test(groups) ->
    {all_but, [http_url_target]};
self_signed_certificate_test(Config) ->
    ?expect_tls_alert(Config, "self-signed.badssl.com", {bad_certificate, _}).

unknown_authority_test(groups) ->
    {all_but, [http_url_target]};
unknown_authority_test(Config) ->
    ?expect_tls_alert(Config, "untrusted-root.badssl.com", {unknown_ca, _}).

%% ------------------------------------------------------------------
%% Internal
%% ------------------------------------------------------------------

httpc_http_opts(Config, Host) ->
    CheckTarget = check_target(Config, Host),
    CheckOpts = tls_certificate_check:options(CheckTarget),
    [{ssl, CheckOpts}].

check_target(Config, Host) ->
    case proplists:get_value(check_target, Config) of
        https_url ->
            "https://" ++ Host;
        http_url ->
            "http://" ++ Host;
        _ ->
            Host
    end.
