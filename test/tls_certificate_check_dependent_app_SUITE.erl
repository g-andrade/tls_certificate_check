%% Copyright (c) 2025 Guilherme Andrade
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

-module(tls_certificate_check_dependent_app_SUITE).
-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% ------------------------------------------------------------------
%% Macros
%% ------------------------------------------------------------------

-define(SHARED_STATE_PROC_NAME, tls_certificate_check_shared_state).

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [
        get_options_forces_tls_cert_check_to_start
    ].

init_per_suite(Config) ->
    % Build the test consumer app
    TestAppDir = filename:join(?config(data_dir, Config), "dependent_app"),
    % logger:emergency("TestAppDir: ~p", [TestAppDir]),

    % Compile the test app
    {ok, OldDir} = file:get_cwd(),
    ok = file:set_cwd(TestAppDir),

    % Run rebar3 compile in the test app directory
    os:cmd("rebar3 compile"),

    ok = file:set_cwd(OldDir),
    TestAppEbin = filename:join([TestAppDir, "_build", "default", "lib", "dependent_app", "ebin"]),
    true = code:add_patha(TestAppEbin),

    [{test_app_dir, TestAppDir} | Config].

end_per_suite(_Config) ->
    %_ = application:stop(dependent_app),
    _ = application:stop(tls_certificate_check),
    ok.

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

get_options_forces_tls_cert_check_to_start(_Config) ->
    % Ensure that the workaround starts `tls_certificate_check'
    ?assertEqual(undefined, whereis(?SHARED_STATE_PROC_NAME)),
    ?assertMatch([_ | _], tls_certificate_check:options("example.com")),
    ?assertNotEqual(undefined, whereis(?SHARED_STATE_PROC_NAME)),

    % Ensure that `dependent_app' is not yet started
    ?assertMatch(false, lists:keyfind(dependent_app, 1, application:which_applications())),

    % Ensure that we can start `dependent_app'
    ?assertMatch({ok, _}, application:ensure_all_started(dependent_app)),
    ?assertNotMatch(false, lists:keyfind(dependent_app, 1, application:which_applications())),

    % Ensure that options are still available
    ?assertMatch([_ | _], tls_certificate_check:options("example.com")).
