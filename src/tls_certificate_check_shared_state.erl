%% Copyright (c) 2021 Guilherme Andrade
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

%% @private
-module(tls_certificate_check_shared_state).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
    [init/0,
     authoritative_certificate_values/0,
     find_trusted_authority/1,
     destroy/0
     ]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(PERSISTENT_TERM_KEY, '__$tls_certificate_check_shared_state').

%% ------------------------------------------------------------------
%% Record and Type Definitions
%% ------------------------------------------------------------------

-record(shared_state, {
          authoritative_certificate_values :: [public_key:der_encoded(), ...],
          trusted_public_keys :: #{public_key_info() := []}
         }).

-type public_key_info() :: #'OTPSubjectPublicKeyInfo'{}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec init() -> ok | {error, {failed_to_decode_authorities, tuple()}}.
init() ->
    EncodedAuthorities = tls_certificate_check_authorities:encoded_list(),
    case tls_certificate_check_util:parse_encoded_authorities(EncodedAuthorities) of
        {ok, AuthoritativeCertificateValues} ->
            NewSharedState = new_shared_state(AuthoritativeCertificateValues),
            save_shared_state(NewSharedState);
        {error, Reason} ->
            {error, {failed_to_decode_authorities, Reason}}
    end.

-spec authoritative_certificate_values() -> [public_key:der_encoded(), ...] | no_return().
authoritative_certificate_values() ->
    SharedState = get_shared_state(),
    SharedState#shared_state.authoritative_certificate_values.

-spec find_trusted_authority([public_key:der_encoded()])
        -> {trusted_ca, public_key:der_encoded()}
           | unknown_ca.
find_trusted_authority(EncodedCertificates) ->
    SharedState = get_shared_state(),
    TrustedPublicKeys = SharedState#shared_state.trusted_public_keys,
    find_trusted_authority_recur(EncodedCertificates, TrustedPublicKeys).

-spec destroy() -> boolean().
destroy() ->
    persistent_term:erase(?PERSISTENT_TERM_KEY).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

new_shared_state(AuthoritativeCertificateValues) ->
    #shared_state{authoritative_certificate_values = AuthoritativeCertificateValues,
                  trusted_public_keys = trusted_public_keys(AuthoritativeCertificateValues)}.

trusted_public_keys(AuthoritativeCertificateValues) ->
    lists:foldl(
      fun (CertificateValue, Acc) ->
              DecodedCertificateValue = public_key:pkix_decode_cert(CertificateValue, otp),
              #'OTPCertificate'{tbsCertificate = TbsCertificate} = DecodedCertificateValue,
              #'OTPTBSCertificate'{subjectPublicKeyInfo = PKI} = TbsCertificate,
              maps:put(PKI, [], Acc)
      end,
      #{}, AuthoritativeCertificateValues).

save_shared_state(SharedState) ->
    persistent_term:put(?PERSISTENT_TERM_KEY, SharedState).

get_shared_state() ->
    try
        persistent_term:get(?PERSISTENT_TERM_KEY)
    catch
        error:badarg ->
            error({application_not_started, tls_certificate_check})
    end.

find_trusted_authority_recur([EncodedCertificate | NextEncodedCertificates], TrustedPublicKeys) ->
    Certificate = public_key:pkix_decode_cert(EncodedCertificate, otp),
    #'OTPCertificate'{tbsCertificate = TbsCertificate} = Certificate,
    #'OTPTBSCertificate'{subjectPublicKeyInfo = PublicKeyInfo} = TbsCertificate,

    case maps:is_key(PublicKeyInfo, TrustedPublicKeys) of
        true ->
            {trusted_ca, EncodedCertificate};
        false ->
            find_trusted_authority_recur(NextEncodedCertificates, TrustedPublicKeys)
    end;
find_trusted_authority_recur([], _TrustedPublicKeys) ->
    unknown_ca.
