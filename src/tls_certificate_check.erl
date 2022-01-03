%% Copyright (c) 2020-2022 Guilherme Andrade
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

%% @doc Main API
-module(tls_certificate_check).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [options/1,
    trusted_authorities/0
   ]).

-ignore_xref(
   [options/1,
    trusted_authorities/0
   ]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

% Same as OpenSSL.
% See: https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_verify_depth.html
-define(DEFAULT_MAX_CERTIFICATE_CHAIN_DEPTH, 100).

%% ------------------------------------------------------------------
%% Record and Type Definitions
%% ------------------------------------------------------------------

-type option() :: ssl:tls_client_option().
-export_type([option/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

%% @doc Returns the list of `ssl:connect' options
%% necessary to validate the server certificate against
%% a list of trusted authorities, as well as to verify
%% whether the server hostname matches one in the server
%% certificate.
%%
%% <ul>
%% <li>`Target' can be either a hostname or an HTTP URL, as `iodata()'</li>
%% </ul>
-spec options(Target) -> Options
        when Target :: Hostname | URL,
             Hostname :: iodata(),
             URL :: iodata(),
             Options :: [option()].
options(Target) ->
    try target_to_hostname(Target) of
        Hostname ->
            CAs = trusted_authorities(),
            CertificateVerificationFunOptions = [{check_hostname, Hostname}],
            CertificateVerificationFun = {fun ssl_verify_hostname:verify_fun/3,
                                          CertificateVerificationFunOptions},

            HostnameCheckOptions = hostname_check_opts(),
            [{verify, verify_peer},
             {depth, ?DEFAULT_MAX_CERTIFICATE_CHAIN_DEPTH},
             {cacerts, CAs},
             {verify_fun, CertificateVerificationFun},
             {partial_chain, fun tls_certificate_check_shared_state:find_trusted_authority/1}
             | HostnameCheckOptions]
    catch
        http_target ->
            []
    end.

%% @doc Returns the list of trusted authorities.
-spec trusted_authorities() -> CAs
      when CAs :: [public_key:der_encoded(), ...].
trusted_authorities() ->
    tls_certificate_check_shared_state:authoritative_certificate_values().

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

target_to_hostname(Target) ->
    BinaryTarget = iolist_to_binary(Target),
    case uri_string:parse(BinaryTarget) of
        #{scheme := <<"http">>} ->
            throw(http_target);
        #{host := Hostname} ->
            binary_to_list(Hostname);
        _ ->
            binary_to_list(BinaryTarget)
    end.

hostname_check_opts() ->
    % Required for OTP 23 as they fixed TLS hostname validation.
    % See: https://bugs.erlang.org/browse/ERL-1232
    Protocol = https,
    MatchFun = public_key:pkix_verify_hostname_match_fun(Protocol),
    [{customize_hostname_check, [{match_fun, MatchFun}]}].

%% ------------------------------------------------------------------
%% Unit Test Definitions
%% ------------------------------------------------------------------
-ifdef(TEST).

trusted_authorities_is_exported_test() ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    ?assertMatch([_|_], ?MODULE:trusted_authorities()).

http_target_test() ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    ?assertEqual([], ?MODULE:options("http://example.com/")).

https_target_test() ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    ?assertMatch([_|_], ?MODULE:options("https://example.com/")).

generic_tls_target_test() ->
    {ok, _} = application:ensure_all_started(tls_certificate_check),
    ?assertMatch([_|_], ?MODULE:options("example.com")).

https_and_generic_tls_targets_equivalence_test() ->
    ?assertEqual(
       ?MODULE:options("example.com"),
       ?MODULE:options("https://example.com/")
      ).

-endif. % -ifdef(TEST).
