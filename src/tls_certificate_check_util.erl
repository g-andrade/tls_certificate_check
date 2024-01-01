%% Copyright (c) 2021-2024 Guilherme Andrade
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

-export([process_authorities/1,
         is_termination_reason_wholesome/1]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec process_authorities(binary() | [public_key:der_encoded()])
        -> {ok, [public_key:der_encoded(), ...]}
           | {error, no_authoritative_certificates_found}
           | {error, {failed_to_decode, {atom(), term(), list()}}}
           | {error, {certificate_encrypted, public_key:der_encoded()}}
           | {error, {unexpected_certificate_format, tuple()}}.
process_authorities(<<EncodedAuthorities/bytes>>) ->
    try public_key:pem_decode(EncodedAuthorities) of
        List when is_list(List) ->
            process_authorities(List)
    catch
        Class:Reason:Stacktrace ->
            {error, {failed_to_decode, {Class, Reason, Stacktrace}}}
    end;
process_authorities([_|_] = AuthoritativeCertificateValues) ->
    authoritative_certificate_values(AuthoritativeCertificateValues);
process_authorities([]) ->
    {error, no_authoritative_certificates_found}.

-spec is_termination_reason_wholesome(term()) -> boolean().
is_termination_reason_wholesome(normal) ->
    true;
is_termination_reason_wholesome(shutdown) ->
    true;
is_termination_reason_wholesome({shutdown, _}) ->
    true;
is_termination_reason_wholesome(_) ->
    false.

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
        <<DerEncoded/bytes>> ->
            UpdatedValuesAcc = [DerEncoded | ValuesAcc],
            authoritative_certificate_values_recur(Next, UpdatedValuesAcc);
        Other ->
            {error, {unexpected_certificate_format, Other}}
    end;
authoritative_certificate_values_recur([], ValuesAcc) ->
    Values = lists:reverse(ValuesAcc),
    {ok, Values}.

