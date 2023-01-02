%% Copyright (c) 2023 Guilherme Andrade
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

-module(tls_certificate_check_override_SUITE).
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
    [empty_override_test,
     badly_encoded_override_test,
     non_existent_file_test,
     app_stopped_test,
     decoded_test,
     certifi_test,
     castore_test].

init_per_testcase(TestCase, Config) ->
    _ = TestCase =/= app_stopped_test
        andalso begin {ok, _} = application:ensure_all_started(tls_certificate_check) end,
    Config.

end_per_testcase(TestCase, _Config) ->
    _ = TestCase =/= app_stopped_test
        andalso begin ok = application:stop(tls_certificate_check) end,
    ok.

%% ------------------------------------------------------------------
%% Test Cases
%% ------------------------------------------------------------------

%
% The success path is tested in `tls_certificate_check_test_utils:connect()'
%

empty_override_test(_Config) ->
    ?assertThrow({failed_to_process_authorities, no_authoritative_certificates_found},
                 tls_certificate_check:override_trusted_authorities({encoded, <<>>})),
    assert_good_conn().

badly_encoded_override_test(_Config) ->
    EncodedAuthorities = <<
      "GlobalSign Root CA\n",
      "==================\n",
      "-----BEGIN CERTIFICATE-----\n",
      "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx\n",
      "GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkds\n",
      "b2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNV\n",
      "BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYD\n",
      "VQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDa\n",
      "DuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6sc\n",
      "THAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlb\n",
      "Kk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNP\n",
      "c1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrX\n",
      "gzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n",
      "HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUF\n"
    >>,
    ?assertThrow({failed_to_process_authorities, {failed_to_decode, _}},
                 tls_certificate_check:override_trusted_authorities({encoded, EncodedAuthorities})),

    assert_good_conn().

non_existent_file_test(_Config) ->
    Filename = base64:encode(crypto:strong_rand_bytes(32)),
    ?assertThrow({read_file, _},
                 tls_certificate_check:override_trusted_authorities({file, Filename})),

    assert_good_conn().

app_stopped_test(_Config) ->
    ?assertThrow({application_either_not_started_or_not_ready, tls_certificate_check},
                 tls_certificate_check:override_trusted_authorities({encoded, <<>>})).

decoded_test(_Config) ->
    CAs = tls_certificate_check:trusted_authorities(),
    ok = tls_certificate_check:override_trusted_authorities(CAs),
    assert_good_conn().

certifi_test(_Config) ->
    {ok, _} = application:ensure_all_started(certifi),
    try
        do_file_test(fun certifi:cacertfile/0)
    after
        ok = application:stop(certifi)
    end.

castore_test(_Config) ->
    case application:ensure_all_started(castore) of
        {ok, _} ->
            try
                do_file_test(fun 'Elixir.CAStore':file_path/0)
            after
                ok = application:stop(castore)
            end;
        {error, Reason} ->
            {skip, {"Elixir's CAStore not available", Reason}}
    end.

%% ------------------------------------------------------------------
%% Internal
%% ------------------------------------------------------------------

do_file_test(PathFun) ->
    ok = tls_certificate_check:override_trusted_authorities({file, PathFun()}),
    assert_good_conn().

assert_good_conn() ->
    tls_certificate_check_test_utils:connect(
      ?PEMS_PATH, "foobar.pem",
      leaf, "good_certificate.pem",
      fun ({ok, Socket}) ->
              ssl:close(Socket)
      end).
