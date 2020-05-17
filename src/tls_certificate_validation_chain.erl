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

%% @private
-module(tls_certificate_validation_chain).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-compile({parse_transform, ct_expand}).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [find_authority/1
   ]).

%% ------------------------------------------------------------------
%% Record and Type Definitions
%% ------------------------------------------------------------------

-type encoded_certificate() :: public_key:der_encoded().
-export_type([encoded_certificate/0]).

-type certificate() :: #'OTPCertificate'{}.
-type certificate_pair() :: {certificate(), encoded_certificate()}.
-type authoritative_pkis() :: #{tls_certificate_validation_pki:t() => exists}.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec find_authority([encoded_certificate()])
        -> {trusted_ca, encoded_certificate()}
           | unknown_ca.
find_authority(EncodedCertificates) ->
    CertificatePairs = decoded_certificate_pairs(EncodedCertificates),
    AuthoritativePKIs = authoritative_pkis(),
    find_authority_recur(CertificatePairs, AuthoritativePKIs).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-spec authoritative_pkis() -> authoritative_pkis().
authoritative_pkis() ->
    ct_expand:term(
      % Evaluated at compile time
      lists:foldl(
        fun (EncodedAuthoritativeCertificate, Acc) ->
                AuthoritativeCertificate = decode_certificate(EncodedAuthoritativeCertificate),
                AuthoritativePKI = tls_certificate_validation_pki:extract(AuthoritativeCertificate),
                maps:put(AuthoritativePKI, exists, Acc)
        end,
        #{}, certifi:cacerts())
     ).

-spec decoded_certificate_pairs([encoded_certificate()])
        -> [certificate_pair()].
decoded_certificate_pairs(EncodedCertificates) ->
    lists:foldl(
      fun (EncodedCertificate, Acc) ->
              Certificate = decode_certificate(EncodedCertificate),
              [{Certificate, EncodedCertificate} | Acc]
      end,
      [], EncodedCertificates).

-spec decode_certificate(encoded_certificate()) -> certificate().
decode_certificate(EncodedCertificate) ->
    public_key:pkix_decode_cert(EncodedCertificate, otp).

-spec find_authority_recur([certificate_pair()], authoritative_pkis())
        -> {trusted_ca, encoded_certificate()} |
           unknown_ca.
find_authority_recur([Pair | NextPairs], AuthoritativePKIs) ->
    {Certificate, EncodedCertificate} = Pair,
    CertificatePKI = tls_certificate_validation_pki:extract(Certificate),
    case maps:is_key(CertificatePKI, AuthoritativePKIs) of
        true ->
            {trusted_ca, EncodedCertificate};
        false ->
            find_authority_recur(NextPairs, AuthoritativePKIs)
    end;
find_authority_recur([], _) ->
    unknown_ca.
