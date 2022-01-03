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

%% @private
-module(tls_certificate_check_util).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
    [parse_encoded_authorities/1
     ]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec parse_encoded_authorities(binary())
        -> {ok, [public_key:der_encoded(), ...]}
           | {error, no_authoritative_certificates_found}
           | {error, {failed_to_decode, {atom(), term(), list()}}}
           | {error, {certificate_encrypted, public_key:der_encoded()}}
           | {error, {unexpected_certificate_format, tuple()}}.
parse_encoded_authorities(EncodedAuthorities) ->
    try public_key:pem_decode(EncodedAuthorities) of
        [_|_] = AuthoritativeCertificates ->
            authoritative_certificate_values(AuthoritativeCertificates);
        [] ->
            {error, no_authoritative_certificates_found}
    catch
        Class:Reason:Stacktrace ->
            {error, {failed_to_decode, {Class, Reason, Stacktrace}}}
    end.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

authoritative_certificate_values(AuthoritativeCertificates) ->
    authoritative_certificate_values_recur(AuthoritativeCertificates, []).

authoritative_certificate_values_recur([Head | Next], ValuesAcc) ->
    case Head of
        {'Certificate', DerEncoded, not_encrypted} ->
            UpdatedValuesAcc = [DerEncoded | ValuesAcc],
            authoritative_certificate_values_recur(Next, UpdatedValuesAcc);
        {'Certificate', _, _} ->
            {error, {certificate_encrypted, Head}};
        Other ->
            {error, {unexpected_certificate_format, Other}}
    end;
authoritative_certificate_values_recur([], ValuesAcc) ->
    Values = lists:reverse(ValuesAcc),
    {ok, Values}.

