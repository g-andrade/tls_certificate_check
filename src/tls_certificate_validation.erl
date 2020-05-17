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

-module(tls_certificate_validation).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [connect_opts/1,
    connect_opts/2
   ]).

-ignore_xref(
   [connect_opts/1,
    connect_opts/2
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

-ifdef(SSL_OLD_CLIENT_OPTIONS).
-type ssl_option() :: ssl:connect_option().
-else.
-type ssl_option() :: ssl:tls_client_option().
-endif.
-export_type([ssl_option/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec connect_opts(unicode:chardata()) -> [ssl_option(), ...].
connect_opts(Target) ->
    connect_opts(Target, []).

-spec connect_opts(unicode:chardata(), [ssl_option()]) -> [ssl_option(), ...].
connect_opts(Target, Overrides) ->
    try target_to_hostname(Target) of
        Hostname ->
            AuthorityCertificate = certifi:cacerts(),
            CertificateVerificationFunOpts = [{check_hostname, Hostname}],
            CertificateVerificationFun = {fun ssl_verify_hostname:verify_fun/3,
                                          CertificateVerificationFunOpts},

            % Required for OTP 23 as they fixed TLS hostname validation.
            % See: https://bugs.erlang.org/browse/ERL-1232
            HostnameVerificationProtocol = https, % FIXME
            HostnameVerificationMatchFun = public_key:pkix_verify_hostname_match_fun(
                                             HostnameVerificationProtocol),

            merge_opts(
              [{verify, verify_peer},
               {depth, ?DEFAULT_MAX_CERTIFICATE_CHAIN_DEPTH},
               {cacerts, AuthorityCertificate},
               {partial_chain, fun tls_certificate_validation_chain:find_authority/1},
               {verify_fun, CertificateVerificationFun},
               {customize_hostname_check, [{match_fun, HostnameVerificationMatchFun}]}
              ],
              Overrides)
    catch
        http_target ->
            Overrides
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-ifdef(NO_URI_STRING).
target_to_hostname(Target) ->
    StrTarget = binary_to_list( iolist_to_binary(Target) ),
    case http_uri:parse(StrTarget) of
        {ok, {http, _, _, _, _, _}} ->
            throw(http_target);
        {ok, {_, _, Hostname, _, _, _}} ->
            Hostname;
        _ ->
            StrTarget
    end.
-else.
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
-endif.

merge_opts(BaseOpts, []) ->
    % optimization
    BaseOpts;
merge_opts(BaseOpts, OptsToMerge) ->
    OptKeysToRemove = [opt_key(Opt) || Opt <- OptsToMerge],
    ReversePurgedBaseOpts = reverse_purged_base_opts_before_merge(BaseOpts, OptKeysToRemove),
    lists:reverse(ReversePurgedBaseOpts, OptsToMerge).

reverse_purged_base_opts_before_merge(BaseOpts, OptKeysToRemove) ->
    lists:foldl(
      fun (Opt, Acc) ->
              OptKey = opt_key(Opt),
              case lists:member(OptKey, OptKeysToRemove) of
                  false -> [Opt | Acc];
                  true -> Acc
              end
      end,
      [], BaseOpts).

opt_key({Key, _}) ->
    Key;
opt_key(Key) when is_atom(Key) ->
    Key.
