%% Copyright (c) 2021-2023 Guilherme Andrade
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
-module(tls_certificate_check_hardcoded_authorities_updater).

-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/OTP-PUB-KEY.hrl").
-include_lib("stdlib/include/assert.hrl").

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

-ifdef(HARDCODED_AUTHORITIES_UPDATER_SUPPORTED).

-spec main([string(), ...]) -> no_return().
main([AuthoritiesFilePath, AuthoritiesSource, OutputModuleFilePath, ChangelogFilePath]) ->
    OutputModuleName = output_module_name(OutputModuleFilePath),
    {ok, _} = application:ensure_all_started(changelog_updater),

    read_authorities_date(#{authorities_file_path => AuthoritiesFilePath,
                            authorities_source => AuthoritiesSource,
                            output_module_file_path => OutputModuleFilePath,
                            output_module_name => OutputModuleName,
                            changelog_file_path => ChangelogFilePath});
main(Args) ->
    fail("Received ~b arg(s) instead of 4", [length(Args)]).

-else.

-spec main([string(), ...]) -> no_return().
main(_) ->
    io:format(standard_error, "[error] This script requires Erlang/OTP 23.1+", []),
    erlang:halt(?FAILURE_STATUS_CODE).

-endif. % ifdef(HARDCODED_AUTHORITIES_UPDATER_SUPPORTED).

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

-ifdef(HARDCODED_AUTHORITIES_UPDATER_SUPPORTED).

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
            ExtendedUpdateArgs = UpdateArgs#{encoded_authorities => EncodedAuthorities},
            parse_encoded_authorities(ExtendedUpdateArgs);
        {error, Reason} ->
            fail("Could not read certificate authorities file: ~p (path: \"~ts\")",
                 [Reason, AuthoritiesFilePath])
    end.

parse_encoded_authorities(#{encoded_authorities := EncodedAuthorities} = UpdateArgs) ->
    case tls_certificate_check_util:parse_encoded_authorities(EncodedAuthorities) of
        {ok, AuthoritativeCertificateValues} ->
            ExtendedUpdateArgs = UpdateArgs#{authoritative_certificate_values
                                             => AuthoritativeCertificateValues},
            maybe_produce_code(ExtendedUpdateArgs);

        {error, no_authoritative_certificates_found} ->
            #{authorities_file_path := AuthoritiesFilePath} = UpdateArgs,
            fail("No authoritative certificates found in \"~ts\"", [AuthoritiesFilePath]);

        {error, {failed_to_decode, Reason}} ->
            #{authorities_file_path := AuthoritiesFilePath} = UpdateArgs,
            fail("Could not parse authoritative certificates in \"~ts\":~n~p",
                 [AuthoritiesFilePath, Reason]);

        {error, Reason} ->
            fail("Could not extract authoritative certificate value: ~p", [Reason])
    end.

maybe_produce_code(UpdateArgs) ->
    CurrentCodeIoData = current_code(UpdateArgs),
    NewCodeIoData = generate_code(UpdateArgs),
    case not string:equal(NewCodeIoData, CurrentCodeIoData, _IgnoreCase = false) of
        true ->
            produce_code(UpdateArgs, NewCodeIoData);
        false ->
            dismiss("No changes to generated code", [])
    end.

produce_code(#{output_module_file_path := OutputModuleFilePath} = UpdateArgs,
             NewCodeIoData)
->
    {NumberOfAdditions, NumberOfRemovals, UpdatedChangelog}
        = compute_differences(UpdateArgs),

    case file:write_file(OutputModuleFilePath, NewCodeIoData) of
        ok ->
            write_updated_changelog(UpdateArgs, UpdatedChangelog),
            succeed("Authorities module updated (~b authority(ies) added, ~b removed)",
                    [NumberOfAdditions, NumberOfRemovals]);
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
                encoded_authorities := EncodedAuthorities,
                output_module_name := OutputModuleName}) ->

    {{CurrentYear, _, _}, {_, _, _}} = calendar:local_time(),
    CopyrightYearString = copyright_year_string(CurrentYear),
    % AuthoritativePKIs = authoritative_pkis(AuthoritativeCertificateValues),
    EncodedAuthoritiesFormattedString = format_encoded_authorities(_Indentation = "    ",
                                                                   EncodedAuthorities),

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
      "-on_load(maybe_update_shared_state/0).\n"
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
      "    [encoded_list/0\n"
      "     ]).\n"
      "\n"
      "%% ------------------------------------------------------------------\n"
      "%% Hacks\n"
      "%% ------------------------------------------------------------------\n"
      "\n"
      "-ignore_xref(update_opts/0).\n"
      "\n"
      "%% ------------------------------------------------------------------\n"
      "%% API Function Definitions\n"
      "%% ------------------------------------------------------------------\n"
      "\n"
      "-dialyzer({nowarn_function, encoded_list/0}).\n"
      "-spec encoded_list() -> binary().\n"
      "\n"
      "-ifdef(TEST).\n"
      "encoded_list() ->\n"
      "    % We can't use `meck' to mock this because it can't mock local functions\n"
      "    % (and maybe_update_shared_state/0 needs to call us as a local function,\n"
      "    %  necessarily, because it runs upon the module being loaded.)\n"
      "    case file:consult(\"tls_certificate_check_hardcoded_authorities_mock_value.txt\") of\n"
      "        {ok, [EncodedList]} -> EncodedList;\n"
      "        {error, enoent} -> encoded_list_()\n"
      "    end.\n"
      "-else.\n"
      "encoded_list() ->\n"
      "    encoded_list_().\n"
      "-endif.\n"
      "\n"
      "%% ------------------------------------------------------------------\n"
      "%% Internal Function Definitions\n"
      "%% ------------------------------------------------------------------\n"
      "\n"
      "-spec maybe_update_shared_state() -> ok | {error, term()}.\n"
      "maybe_update_shared_state() ->\n"
      "    % For code swaps / release upgrades\n"
      "    EncodedCertificates = encoded_list(),\n"
      "    UpdateOpts = update_opts(),\n"
      "    case tls_certificate_check_shared_state:maybe_update_shared_state(_Source = 'Hardcoded authorities',\n"
      "                                                                      EncodedCertificates,\n"
      "                                                                      UpdateOpts) of\n"
      "        noproc -> ok;\n"
      "        Other -> Other\n"
      "    end.\n"
      "\n"
      "-ifdef(TEST).\n"
      "update_opts() -> [force_encoded].\n"
      "-else.\n"
      "update_opts() -> [].\n"
      "-endif.\n"
      "\n"
      "encoded_list_() ->\n"
      "~ts",

      [CopyrightYearString,
       OutputModuleName,
       AuthoritiesSource,
       format_date(AuthoritiesDate),
       EncodedAuthoritiesFormattedString]).

copyright_year_string(CurrentYear)
  when CurrentYear > 2021 ->
    io_lib:format("2021-~b", [CurrentYear]);
copyright_year_string(CurrentYear)
  when CurrentYear =:= 2021 ->
    "2021".

format_encoded_authorities(BaseIndentation, EncodedAuthorities) ->
    AllLines = string:split(EncodedAuthorities, "\n", all),
    {Lines, [<<>>]} = lists:split(length(AllLines) - 1, AllLines),
    NumberOfLines = length(Lines),
    LineIndices = lists:seq(1, NumberOfLines),

    lists:zipwith(
      fun (Line, Index) ->
              BinaryLine = unicode:characters_to_binary([Line, $\n]),
              FormattedLine = io_lib:format("~tp", [BinaryLine]),
              Indentation
                    = case Index =/= 1 of
                          true -> [BaseIndentation, "  "];
                          false -> [BaseIndentation, "<<"]
                      end,
              Punctuation
                    = case Index =/= NumberOfLines of
                          true  -> ",";
                          false -> ">>."
                      end,

              case unicode:characters_to_list(FormattedLine) of
                  "<<>>" ->
                      io_lib:format("~s\"\\n\"~s\n", [Indentation, Punctuation]);

                  "<<" ++ RestOfTheLine ->
                      {LineData, ">>"} = lists:split(length(RestOfTheLine) - 2, RestOfTheLine),
                      io_lib:format("~s~ts~s\n", [Indentation, LineData, Punctuation])
              end
      end,
      Lines, LineIndices).

format_date({{Year, Month, Day}, {Hour, Minute, _Second}}) ->
    io_lib:format("~4..0b/~2..0b/~2..0b, ~2..0b:~2..0b UTC",
                  [Year, Month, Day, Hour, Minute]).

compute_differences(UpdateArgs) ->
    #{changelog_file_path := ChangelogFilePath} = UpdateArgs,
    {Additions, Removals} = certificate_differences(UpdateArgs),

    case file:read_file(ChangelogFilePath) of
        {ok, Changelog} ->
            UpdatedChangelog = updated_changelog(UpdateArgs, Changelog, Additions, Removals),

            {length(Additions), length(Removals), UpdatedChangelog};

        {error, Reason} ->
            fail("Could not read changelog: ~p (path: \"~ts\")",
                 [Reason, ChangelogFilePath])
    end.

certificate_differences(#{authoritative_certificate_values
                          := AuthoritativeCertificateValues} = UpdateArgs) ->
    PreviousAuthoritativeCertificateValues = previous_authoritative_certificate_values(UpdateArgs),
    Previous = ordsets:from_list(PreviousAuthoritativeCertificateValues),
    Current = ordsets:from_list(AuthoritativeCertificateValues),

    Additions = ordsets:subtract(Current, Previous),
    Removals = ordsets:subtract(Previous, Current),
    {ordsets:to_list(Additions), ordsets:to_list(Removals)}.

previous_authoritative_certificate_values(#{output_module_name := OutputModuleName}) ->
    try OutputModuleName:encoded_list() of
        <<EncodedList/bytes>> ->
            {ok, List} = tls_certificate_check_util:parse_encoded_authorities(EncodedList),
            List
    catch
        error:undef ->
            []
    end.

updated_changelog(UpdateArgs, Changelog, Additions, Removals) ->
    AdditionEntries = lists:map(fun certificate_changelog_string/1, Additions),
    ChangeEntry = changelog_change_entry(UpdateArgs),
    RemovalEntries = lists:map(fun certificate_changelog_string/1, Removals),

    Changelog2
        = lists:foldl(
            fun (AdditionEntry, Acc) ->
                    {ok, UpdatedAcc} = changelog_updater:insert_addition(AdditionEntry, Acc),
                    UpdatedAcc
            end,
            Changelog,
            AdditionEntries),

    {ok, Changelog3} = changelog_updater:insert_change(ChangeEntry, Changelog2),

    _Changelog4
        = lists:foldl(
            fun (RemovalEntry, Acc) ->
                    {ok, UpdatedAcc} = changelog_updater:insert_removal(RemovalEntry, Acc),
                    UpdatedAcc
            end,
            Changelog3,
            RemovalEntries).

changelog_change_entry(UpdateArgs) ->
    #{authorities_source := AuthoritiesSource,
      authorities_date := AuthoritiesDate} = UpdateArgs,

    io_lib:format(
      "module with bundled CAs to latest as of ~ts\n"
      "(source: ~ts)",
      [format_date(AuthoritiesDate), AuthoritiesSource]).

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
            io_lib:format("[certificate authority] ~ts", [AuthorityName]);
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

succeed(Fmt, Args) ->
    io:format(standard_error, "[updated] " ++ Fmt ++ "~n", Args),
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

-endif. % ifdef(HARDCODED_AUTHORITIES_UPDATER_SUPPORTED).
