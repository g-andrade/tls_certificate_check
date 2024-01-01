%% Copyright (c) 2020-2024 Guilherme Andrade
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

-export([options/1,
         trusted_authorities/0,
         override_trusted_authorities/1]).

-ignore_xref(
        [options/1,
         trusted_authorities/0,
         override_trusted_authorities/1]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

% Same as OpenSSL.
% See: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_verify_depth.html
-define(DEFAULT_MAX_CERTIFICATE_CHAIN_DEPTH, 100).

%% ------------------------------------------------------------------
%% Record and Type Definitions
%% ------------------------------------------------------------------

-type option() :: ssl:tls_client_option().
-export_type([option/0]).

-type override_source()
    :: {file, Path :: file:name_all()}
    |  {encoded, binary()}
    |  (CAs :: [public_key:der_encoded()])
    .
-export_type([override_source/0]).

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

            % Required for OTP 23 as it fixed TLS hostname validation.
            % See: https://bugs.erlang.org/browse/ERL-1232
            Protocol = https,
            HostnameMatchFun = public_key:pkix_verify_hostname_match_fun(Protocol),

            [{verify, verify_peer},
             {depth, ?DEFAULT_MAX_CERTIFICATE_CHAIN_DEPTH},
             {cacerts, CAs},
             {verify_fun, CertificateVerificationFun},
             {partial_chain, fun tls_certificate_check_shared_state:find_trusted_authority/1},
             {customize_hostname_check, [{match_fun, HostnameMatchFun}]}
             | maybe_sni_opts(Hostname)]
    catch
        http_target ->
            []
    end.

%% @doc Returns the list of trusted authorities.
-spec trusted_authorities() -> CAs
      when CAs :: [public_key:der_encoded(), ...].
trusted_authorities() ->
    tls_certificate_check_shared_state:authoritative_certificate_values().

%% @doc Overrides the trusted authorities with a custom source.
-spec override_trusted_authorities(From) -> ok
      when From :: override_source().
override_trusted_authorities(Source) ->
    case try_overriding_trusted_authorities(Source) of
        ok ->
            ok;
        {error, Reason} ->
            throw(Reason)
    end.

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

-spec try_overriding_trusted_authorities(From) -> ok | {error, Reason}
      when From :: override_source(),
           Reason :: term().
try_overriding_trusted_authorities({file, Path} = OverrideSource) ->
    case file:read_file(Path) of
        {ok, EncodedAuthorities} ->
            try_overriding_trusted_authorities(_Source = {override, OverrideSource},
                                               EncodedAuthorities);
        {error, Reason} ->
            {error, {read_file, #{path => Path, why => Reason}}}
    end;
try_overriding_trusted_authorities({encoded, <<EncodedAuthorities/bytes>>}) ->
    try_overriding_trusted_authorities(_Source = {override, encoded_binary},
                                       EncodedAuthorities);
try_overriding_trusted_authorities(Authorities) when is_list(Authorities) ->
    try_overriding_trusted_authorities(_Source = {override, list_of_cas},
                                       Authorities).

try_overriding_trusted_authorities(Source, UnprocessedAuthorities) ->
    case tls_certificate_check_shared_state:maybe_update_shared_state(Source,
                                                                      UnprocessedAuthorities)
    of
        noproc ->
            {error, {application_either_not_started_or_not_ready, tls_certificate_check}};
        Other ->
            Other
    end.

maybe_sni_opts(Hostname) ->
    case inet:parse_address(Hostname) of
        {ok, _IpAddress} ->
            % "Literal IPv4 and IPv6 addresses are not permitted in HostName"
            % * https://www.ietf.org/rfc/rfc4366.html#section-3.1
            [];
        {error, einval} ->
            % This probably doesn't cover IDNs...
            [{server_name_indication, Hostname}]
    end.

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

sni_restrictions_test() ->
    % Ip addresses have no SNI
    ?assertEqual(
        false,
        lists:keyfind(server_name_indication, 1,
                      ?MODULE:options("93.184.216.34"))
    ),
    ?assertEqual(
        false,
        lists:keyfind(server_name_indication, 1,
                      ?MODULE:options("2606:2800:220:1:248:1893:25c8:1946"))
    ),

    % Regular hostnames do
    ?assertMatch(
        {server_name_indication, _},
        lists:keyfind(server_name_indication, 1,
                      ?MODULE:options("example.com"))
    ).

-endif. % -ifdef(TEST).
