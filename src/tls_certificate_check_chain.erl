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

%% @private
-module(tls_certificate_check_chain).

-include_lib("public_key/include/OTP-PUB-KEY.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [find_authority/1
   ]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec find_authority([public_key:der_encoded()])
        -> {trusted_ca, public_key:der_encoded()}
           | unknown_ca.
find_authority([EncodedCertificate | NextEncodedCertificates]) ->
    Certificate = public_key:pkix_decode_cert(EncodedCertificate, otp),
    #'OTPCertificate'{tbsCertificate = TbsCertificate} = Certificate,
    #'OTPTBSCertificate'{subjectPublicKeyInfo = PublicKeyInfo} = TbsCertificate,

    case tls_certificate_check_authorities:is_trusted_public_key(PublicKeyInfo) of
        true ->
            {trusted_ca, EncodedCertificate};
        false ->
            find_authority(NextEncodedCertificates)
    end;
find_authority([]) ->
    unknown_ca.
