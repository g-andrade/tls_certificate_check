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
-module(tls_certificate_check_authorities_update).

-ifdef(UPDATING_AUTHORITIES).

-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/OTP-PUB-KEY.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [main/1
   ]).

-ignore_xref(
   [main/1
   ]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(FAILURE_STATUS_CODE, 1).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec main([string(), ...]) -> no_return().
main([AuthoritiesFilePath, AuthoritiesSource, OutputModuleFilePath, ChangelogFilePath]) ->
    OutputModuleName = output_module_name(OutputModuleFilePath),

    read_authorities_date(#{authorities_file_path => AuthoritiesFilePath,
                            authorities_source => AuthoritiesSource,
                            output_module_file_path => OutputModuleFilePath,
                            output_module_name => OutputModuleName,
                            changelog_file_path => ChangelogFilePath});
main(Args) ->
    fail("Received ~b arg(s) instead of 4", [length(Args)]).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

output_module_name(OutputModuleFilePath) ->
    IoData = filename:basename(OutputModuleFilePath, ".erl"),
    String = unicode:characters_to_list(IoData),
    list_to_atom(String).

read_authorities_date(#{authorities_file_path := AuthoritiesFilePath} = UpdateArgs) ->
    case file:read_file_info(AuthoritiesFilePath, [{time, universal}]) of
        {ok, #file_info{mtime = ModificationDateTime}} ->
            ExtendedUpdateArgs = UpdateArgs#{authorities_date => ModificationDateTime},
            read_encoded_authorities(ExtendedUpdateArgs);
        {error, Reason} ->
            fail("Could not read certificate authorities file: ~p (path: \"~ts\")",
                 [Reason, AuthoritiesFilePath])
    end.

read_encoded_authorities(#{authorities_file_path := AuthoritiesFilePath} = UpdateArgs) ->
    case file:read_file(AuthoritiesFilePath) of
        {ok, EncodedAuthorities} ->
            parse_encoded_authorities(UpdateArgs, EncodedAuthorities);
        {error, Reason} ->
            fail("Could not read certificate authorities file: ~p (path: \"~ts\")",
                 [Reason, AuthoritiesFilePath])
    end.

parse_encoded_authorities(UpdateArgs, EncodedAuthorities) ->
    try public_key:pem_decode(EncodedAuthorities) of
        [_|_] = AuthoritativeCertificates ->
            extract_authoriative_certificate_values(UpdateArgs, AuthoritativeCertificates);
        [] ->
            #{authorities_file_path := AuthoritiesFilePath} = UpdateArgs,
            fail("No authoritative certificates found in \"~ts\"", [AuthoritiesFilePath])
    catch
        Class:Reason:Stacktrace ->
            #{authorities_file_path := AuthoritiesFilePath} = UpdateArgs,
            fail("Could not parse authoritative certificates in \"~ts\":~n~p",
                 [AuthoritiesFilePath, {Class, Reason, Stacktrace}])
    end.

extract_authoriative_certificate_values(UpdateArgs, AuthoritativeCertificates) ->
    case authoritative_certificate_values(AuthoritativeCertificates) of
        {ok, AuthoritativeCertificateValues} ->
            maybe_produce_code(UpdateArgs, AuthoritativeCertificateValues);
        {error, Reason} ->
            fail("Could not extract authoritative certificate value: ~p", [Reason])
    end.

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

maybe_produce_code(UpdateArgs, AuthoritativeCertificateValues) ->
    CurrentCodeIoData = current_code(UpdateArgs),
    NewCodeIoData = generate_code(UpdateArgs, AuthoritativeCertificateValues),
    case not string:equal(NewCodeIoData, CurrentCodeIoData, _IgnoreCase = false) of
        true ->
            produce_code(UpdateArgs, AuthoritativeCertificateValues, NewCodeIoData);
        false ->
            dismiss("No changes to generated code", [])
    end.

produce_code(#{output_module_file_path := OutputModuleFilePath} = UpdateArgs,
             AuthoritativeCertificateValues, NewCodeIoData)
->
    {NumberOfAdditions, NumberOfRemovals, UpdatedChangelog, NewVersionString}
        = compute_differences(UpdateArgs, AuthoritativeCertificateValues),

    case file:write_file(OutputModuleFilePath, NewCodeIoData) of
        ok ->
            write_updated_changelog(UpdateArgs, UpdatedChangelog),
            succeed("Authorities module updated (~b authority(ies) added, ~b removed)",
                    [NumberOfAdditions, NumberOfRemovals],
                    NewVersionString);
        {error, Reason} ->
            fail("Could not write output module: ~p (path: \"~ts\")",
                 [Reason, OutputModuleFilePath])
    end.

current_code(#{output_module_file_path := OutputModuleFilePath}) ->
    case file:read_file(OutputModuleFilePath) of
        {ok, CurrentCode} ->
            CurrentCode;
        {error, enoent} ->
            ""
    end.

generate_code(#{authorities_source := AuthoritiesSource,
                authorities_date := AuthoritiesDate,
                output_module_name := OutputModuleName}, AuthoritativeCertificateValues) ->

    {{CurrentYear, _, _}, {_, _, _}} = calendar:local_time(),
    CopyrightYearString = copyright_year_string(CurrentYear),
    AuthoritativePKIs = authoritative_pkis(AuthoritativeCertificateValues),

    io_lib:format(
      "%% Copyright (c) ~s Guilherme Andrade\n"
      "%%\n"
      "%% Permission is hereby granted, free of charge, to any person obtaining a\n"
      "%% copy  of this software and associated documentation files (the \"Software\"),\n"
      "%% to deal in the Software without restriction, including without limitation\n"
      "%% the rights to use, copy, modify, merge, publish, distribute, sublicense,\n"
      "%% and/or sell copies of the Software, and to permit persons to whom the\n"
      "%% Software is furnished to do so, subject to the following conditions:\n"
      "%%\n"
      "%% The above copyright notice and this permission notice shall be included in\n"
      "%% all copies or substantial portions of the Software.\n"
      "%%\n"
      "%% THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
      "%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
      "%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
      "%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
      "%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING\n"
      "%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER\n"
      "%% DEALINGS IN THE SOFTWARE.\n"
      "\n"
      "%% @private\n"
      "-module(~p).\n"
      "\n"
      "-include_lib(\"public_key/include/OTP-PUB-KEY.hrl\").\n"
      "\n"
      "%% Automatically generated; do not edit.\n"
      "%%\n"
      "%% Source: ~ts\n"
      "%% Date: ~ts\n"
      "\n"
      "%% ------------------------------------------------------------------\n"
      "%% API Function Exports\n"
      "%% ------------------------------------------------------------------\n"
      "\n"
      "-export(\n"
      "    [list/0,\n"
      "     is_trusted_public_key/1\n"
      "     ]).\n"
      "\n"
      "%% ------------------------------------------------------------------\n"
      "%% API Function Definitions\n"
      "%% ------------------------------------------------------------------\n"
      "\n"
      "-spec list() -> [public_key:der_encoded(), ...].\n"
      "list() ->\n"
      "    ~p.\n"
      "\n"
      "-spec is_trusted_public_key(#'OTPSubjectPublicKeyInfo'{}) -> boolean().\n"
      "is_trusted_public_key(#'OTPSubjectPublicKeyInfo'{} = PublicKeyInfo) ->\n"
      "    maps:is_key(PublicKeyInfo,\n"
      "                ~p).",

      [CopyrightYearString,
       OutputModuleName,
       AuthoritiesSource,
       format_date(AuthoritiesDate),
       AuthoritativeCertificateValues,
       AuthoritativePKIs]).

copyright_year_string(CurrentYear)
  when CurrentYear > 2021 ->
    io_lib:format("2021-~b", [CurrentYear]);
copyright_year_string(CurrentYear)
  when CurrentYear =:= 2021 ->
    "2021".

authoritative_pkis(AuthoritativeCertificateValues) ->
    lists:foldl(
      fun (CertificateValue, Acc) ->
              DecodedCertificateValue = public_key:pkix_decode_cert(CertificateValue, otp),
              #'OTPCertificate'{tbsCertificate = TbsCertificate} = DecodedCertificateValue,
              #'OTPTBSCertificate'{subjectPublicKeyInfo = PKI} = TbsCertificate,
              maps:put(PKI, exists, Acc)
      end,
      #{}, AuthoritativeCertificateValues).

format_date({{Year, Month, Day}, {Hour, Minute, _Second}}) ->
    io_lib:format("~4..0b/~2..0b/~2..0b, ~2..0b:~2..0b UTC",
                  [Year, Month, Day, Hour, Minute]).

compute_differences(UpdateArgs, AuthoritativeCertificateValues) ->
    #{changelog_file_path := ChangelogFilePath} = UpdateArgs,
    {Additions, Removals} = certificate_differences(UpdateArgs, AuthoritativeCertificateValues),

    case file:read_file(ChangelogFilePath) of
        {ok, Changelog} ->
            {UpdatedChangelog, NewVersionString}
                = updated_changelog(UpdateArgs, Changelog, Additions, Removals),

            {length(Additions), length(Removals), UpdatedChangelog, NewVersionString};

        {error, Reason} ->
            fail("Could not read changelog: ~p (path: \"~ts\")",
                 [Reason, ChangelogFilePath])
    end.

certificate_differences(UpdateArgs, AuthoritativeCertificateValues) ->
    PreviousAuthoritativeCertificateValues = previous_authoritative_certificate_values(UpdateArgs),
    Previous = ordsets:from_list(PreviousAuthoritativeCertificateValues),
    Current = ordsets:from_list(AuthoritativeCertificateValues),

    Additions = ordsets:subtract(Current, Previous),
    Removals = ordsets:subtract(Previous, Current),
    {ordsets:to_list(Additions), ordsets:to_list(Removals)}.

previous_authoritative_certificate_values(#{output_module_name := OutputModuleName}) ->
    try OutputModuleName:list() of
        [_|_] = List ->
            List
    catch
        error:undef ->
            []
    end.

updated_changelog(UpdateArgs, Changelog, Additions, Removals) ->
    case binary:match(Changelog, <<"\n## ">>) of
        {LastReleasePosMinusOne, _} ->
            LastReleasePos = LastReleasePosMinusOne + 1,
            {ok, CurrentVersion} = check_that_last_changelog_release_is_complete(Changelog,
                                                                                 LastReleasePos),
            updated_changelog_at_position(UpdateArgs, Changelog, LastReleasePos,
                                          CurrentVersion, Additions, Removals);
        nomatch ->
            fail("Could not find position of latest release in changelog", [])
    end.

check_that_last_changelog_release_is_complete(Changelog, LastReleasePos) ->
    <<_:LastReleasePos/bytes, LastRelease/bytes>> = Changelog,
    case re:run(LastRelease, <<"## \\[([0-9]+)\\.([0-9]+)\\.([0-9]+)">>,
                [{capture, [1, 2, 3], binary}])
    of
        {match, [BinMajorVersion, BinMinorVersion, BinPatchVersion]} ->
            MajorVersion = binary_to_integer(BinMajorVersion),
            MinorVersion = binary_to_integer(BinMinorVersion),
            PatchVersion = binary_to_integer(BinPatchVersion),
            {ok, {MajorVersion, MinorVersion, PatchVersion}};
        nomatch ->
            fail("Unexpected last release info on changelog: ~p", [LastRelease])
    end.


updated_changelog_at_position(UpdateArgs, Changelog, LastReleasePos,
                              CurrentVersion, Additions, Removals) ->
    {MajorVersion, MinorVersion, _PatchVersion} = CurrentVersion,
    NewMinorVersion = MinorVersion + 1,
    NewPatchVersion = 0,

    <<DataBefore:LastReleasePos/bytes, DataAfter/bytes>> = Changelog,

    NewVersionString = io_lib:format("~b.~b.~b", [MajorVersion, NewMinorVersion, NewPatchVersion]),
    {{CurrentYear, CurrentMonth, CurrentDay}, _} = calendar:local_time(),
    UpdatedChangelog
        = unicode:characters_to_binary(
            [DataBefore,
             io_lib:format(
               "## [~ts] - ~4..0b-~2..0b-~2..0b\n"
               "~ts"
               "~ts"
               "~ts",
               [NewVersionString,
                CurrentYear, CurrentMonth, CurrentDay,
                changelog_additions_string(Additions),
                changelog_changes_string(UpdateArgs),
                changelog_removals_string(Removals)
               ]),
             DataAfter]),

    {UpdatedChangelog, NewVersionString}.

changelog_additions_string([]) ->
    "";
changelog_additions_string(Additions) ->
    io_lib:format(
      "\n"
      "### Added\n"
      "\n"
      "~ts"
      "\n",
      [[certificate_changelog_string(Addition) || Addition <- Additions]]
     ).

changelog_changes_string(UpdateArgs) ->
    #{authorities_source := AuthoritiesSource,
      authorities_date := AuthoritiesDate} = UpdateArgs,

    io_lib:format(
      "\n"
      "### Changed\n"
      "\n"
      "- module with bundled CAs to latest as of ~ts\n"
      "(source: ~ts)\n"
      "\n",
      [format_date(AuthoritiesDate), AuthoritiesSource]).

changelog_removals_string([]) ->
    "";
changelog_removals_string(Removals) ->
    io_lib:format(
      "\n"
      "### Removed\n"
      "\n"
      "~ts"
      "\n",
      [[certificate_changelog_string(Removal) || Removal <- Removals]]
     ).

certificate_changelog_string(EncodedCertificate) ->
    SubjectId = public_key:pkix_subject_id(EncodedCertificate),
    {_SerialNr, SubjectName} = SubjectId,
    {rdnSequence, SubjectNameAttributeSets} = SubjectName,

    % * http://erlang.org/documentation/doc-5.7.4/lib/ssl-3.10.7/doc/html/pkix_certs.html
    % * http://www.umich.edu/~x509/ssleay/asn1-oids.html
    IdAtOrganizationUnitName = {2, 5, 4, 11},
    AttributesToTry = [?'id-at-commonName', IdAtOrganizationUnitName],
    AuthorityName = certificate_changelog_name_recur(AttributesToTry, SubjectNameAttributeSets),

    case string:length(AuthorityName) > 0
         andalso {printable, io_lib:printable_unicode_list(AuthorityName)}
    of
        {printable, true} ->
            io_lib:format("- [certificate authority] ~ts\n", [AuthorityName]);
        {printable, false} ->
            fail("Authority name not printable (~p): ~p", [AuthorityName, SubjectId]);
        false ->
            fail("Authority name empty: ~p", [SubjectId])
    end.

-dialyzer({no_match, certificate_changelog_name_recur/2}).
certificate_changelog_name_recur([Attribute | Next], SubjectNameAttributeSets) ->
    case certificate_changelog_name_subrecur(Attribute, SubjectNameAttributeSets) of
        {ok, AuthorityName} ->
            AuthorityName;
        error ->
            certificate_changelog_name_recur(Next, SubjectNameAttributeSets)
    end;
certificate_changelog_name_recur([], _SubjectNameAttributeSets) ->
    "".

-dialyzer({no_fail_call, certificate_changelog_name_subrecur/2}).
certificate_changelog_name_subrecur(Attribute, [SubjectNameAttributeSet | Next]) ->
    % * http://erlang.org/doc/apps/public_key/public_key_records.html

    case lists:keyfind(Attribute, #'AttributeTypeAndValue'.type, SubjectNameAttributeSet) of
        #'AttributeTypeAndValue'{value = {printableString, String}} ->
            {ok, String};
        #'AttributeTypeAndValue'{value = {universalString, String}} ->
            {ok, String};
        #'AttributeTypeAndValue'{value = {utf8String, Binary}} ->
            String = unicode:characters_to_list(Binary),
            {ok, String};
        #'AttributeTypeAndValue'{} ->
            certificate_changelog_name_subrecur(Attribute, Next);
        false ->
            certificate_changelog_name_subrecur(Attribute, Next)
    end;
certificate_changelog_name_subrecur(_Attribute, []) ->
    error.

write_updated_changelog(#{changelog_file_path := ChangelogFilePath}, UpdatedChangelog) ->
    case file:write_file(ChangelogFilePath, UpdatedChangelog) of
        ok ->
            ok;
        {error, Reason} ->
            fail("Could not update changelog: ~p (path: \"~ts\")",
                 [Reason, ChangelogFilePath])
    end.

succeed(Fmt, Args, NewVersionString) ->
    io:format(standard_error, "[updated] " ++ Fmt ++ "~n", Args),
    io:format("updated: ~ts~n", [NewVersionString]),
    halt_(0).

fail(Fmt, Args) ->
    io:format(standard_error, "[error] " ++ Fmt ++ "~n", Args),
    io:format("error~n"),
    halt_(?FAILURE_STATUS_CODE).

dismiss(Fmt, Args) ->
    io:format(standard_error, "[dismissed] " ++ Fmt ++ "~n", Args),
    io:format("dismissed~n"),
    halt_(0).

halt_(Status) ->
    % Get Dialyzer to stop complaining about functions 
    % having "no local return" all over this module.
    OpaqueFunctionName = binary_to_term( term_to_binary(halt) ),
    erlang:OpaqueFunctionName(Status).

-endif. % ifdef(UPDATING_AUTHORITIES).
