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

-module(tls_certificate_check).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [options/1,
    options/2
   ]).

-ignore_xref(
   [options/1,
    options/2
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
-type option() :: ssl:connect_option().
-else.
-type option() :: ssl:tls_client_option().
-endif.
-export_type([option/0]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec options(unicode:chardata()) -> [option(), ...].
options(Target) ->
    options(Target, []).

-spec options(unicode:chardata(), [option()]) -> [option(), ...].
options(Target, OptionOverrides) ->
    try target_to_hostname(Target) of
        Hostname ->
            EncodedAuthoritativeCertificates = tls_certificate_chain:authorities(),
            CertificateVerificationFunOptions = [{check_hostname, Hostname}],
            CertificateVerificationFun = {fun ssl_verify_hostname:verify_fun/3,
                                          CertificateVerificationFunOptions},

            HostnameCheckOptions = hostname_check_opts(),
            merge_opts(
              [{verify, verify_peer},
               {depth, ?DEFAULT_MAX_CERTIFICATE_CHAIN_DEPTH},
               {cacerts, EncodedAuthoritativeCertificates},
               {partial_chain, fun tls_certificate_chain:find_authority/1},
               {verify_fun, CertificateVerificationFun}
               | HostnameCheckOptions],
              OptionOverrides)
    catch
        http_target ->
            OptionOverrides
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

-ifdef(NO_CUSTOM_HOSTNAME_CHECK).
hostname_check_opts() ->
    [].
-else.
hostname_check_opts() ->
    % Required for OTP 23 as they fixed TLS hostname validation.
    % See: https://bugs.erlang.org/browse/ERL-1232
    Protocol = https, % FIXME
    MatchFun = public_key:pkix_verify_hostname_match_fun(Protocol),
    [{customize_hostname_check, [{match_fun, MatchFun}]}].
-endif.

merge_opts(BaseOptions, []) ->
    % optimization
    BaseOptions;
merge_opts(BaseOptions, OptionsToMerge) ->
    KeysToRemove = [option_key(Option) || Option <- OptionsToMerge],
    ReversePurgedBaseOptions
        = reverse_purged_base_opts_before_merge(BaseOptions, KeysToRemove),
    lists:reverse(ReversePurgedBaseOptions, OptionsToMerge).

reverse_purged_base_opts_before_merge(BaseOptions, KeysToRemove) ->
    lists:foldl(
      fun (Option, Acc) ->
              Key = option_key(Option),
              case lists:member(Key, KeysToRemove) of
                  false -> [Option | Acc];
                  true -> Acc
              end
      end,
      [], BaseOptions).

option_key({Key, _}) ->
    Key;
option_key(Key) when is_atom(Key) ->
    Key.
