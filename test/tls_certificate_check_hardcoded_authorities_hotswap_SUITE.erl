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

-module(tls_certificate_check_hardcoded_authorities_hotswap_SUITE).
-compile(export_all).

-include_lib("stdlib/include/assert.hrl").

%% ------------------------------------------------------------------
%% Setup
%% ------------------------------------------------------------------

all() ->
    [code_swap_success,
     code_swap_failure
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(tls_certificate_check).

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

code_swap_success(_Config) ->
    EncodedAuthorities = tls_certificate_check_hardcoded_authorities:encoded_list(),
    SharedStateKeyBefore = tls_certificate_check_shared_state:latest_shared_state_key(),

    % existing list, twice
    NewEncodedAuthorities = <<EncodedAuthorities/bytes, EncodedAuthorities/bytes>>,
    ok = file:write_file("tls_certificate_check_hardcoded_authorities_mock_value.txt",
                         io_lib:format("~p.", [NewEncodedAuthorities])),
    try
        ?assertEqual(false, code:purge(tls_certificate_check_hardcoded_authorities)),
        ?assertMatch({module, _}, code:load_file(tls_certificate_check_hardcoded_authorities)),

        SharedStateKeyAfter = tls_certificate_check_shared_state:latest_shared_state_key(),
        ?assertNotEqual(SharedStateKeyBefore, SharedStateKeyAfter) % because the hotswap succeeded
    after
        ok = file:delete("tls_certificate_check_hardcoded_authorities_mock_value.txt")
    end.

code_swap_failure(_Config) ->
    SharedStateKeyBefore = tls_certificate_check_shared_state:latest_shared_state_key(),

    % gibberish
    NewEncodedAuthorities = crypto:strong_rand_bytes(32),
    ok = file:write_file("tls_certificate_check_hardcoded_authorities_mock_value.txt",
                         io_lib:format("~p.", [NewEncodedAuthorities])),
    try
        ?assertEqual(false, code:purge(tls_certificate_check_hardcoded_authorities)),
        ?assertEqual({error, on_load_failure}, code:load_file(tls_certificate_check_hardcoded_authorities)),

        SharedStateKeyAfter = tls_certificate_check_shared_state:latest_shared_state_key(),
        ?assertEqual(SharedStateKeyBefore, SharedStateKeyAfter) % because the hotswap failed
    after
        ok = file:delete("tls_certificate_check_hardcoded_authorities_mock_value.txt")
    end.
