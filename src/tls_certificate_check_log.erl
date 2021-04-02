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
-module(tls_certificate_check_log).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export(
   [debug/2,
    info/2,
    notice/2,
    warning/2,
    error/2
   ]).

%% ------------------------------------------------------------------
%% Macro Definitions
%% ------------------------------------------------------------------

-define(PREFIX, "[tls_certificate_check] ").

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec debug(string(), list()) -> ok.
debug(Fmt, Args) ->
    case use_error_logger() of
        true ->
            error_logger:info_msg(?PREFIX ++ Fmt, Args);
        false -> 
            logger:debug(?PREFIX ++ Fmt, Args)
    end.

-spec info(string(), list()) -> ok.
info(Fmt, Args) ->
    case use_error_logger() of
        true ->
            error_logger:info_msg(?PREFIX ++ Fmt, Args);
        false -> 
            logger:info(?PREFIX ++ Fmt, Args)
    end.

-spec notice(string(), list()) -> ok.
notice(Fmt, Args) ->
    case use_error_logger() of
        true ->
            error_logger:warning_msg(?PREFIX ++ Fmt, Args);
        false -> 
            logger:notice(?PREFIX ++ Fmt, Args)
    end.

-spec warning(string(), list()) -> ok.
warning(Fmt, Args) ->
    case use_error_logger() of
        true ->
            error_logger:warning_msg(?PREFIX ++ Fmt, Args);
        false -> 
            logger:warning(?PREFIX ++ Fmt, Args)
    end.

-spec error(string(), list()) -> ok.
error(Fmt, Args) ->
    case use_error_logger() of
        true ->
            error_logger:error_msg(?PREFIX ++ Fmt, Args);
        false -> 
            logger:error(?PREFIX ++ Fmt, Args)
    end.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------


% `lager' and `logger' don`t play nice with each other (as of Jun 2019)
% * https://github.com/erlang-lager/lager/issues/492
% * https://github.com/erlang-lager/lager/pull/488
use_error_logger() ->
    has_lager() andalso not has_usable_logger().

% Taken from: https://github.com/ferd/cth_readable/pull/23
has_lager() ->
    % Module is present
    erlang:function_exported(logger, module_info, 0).

% Taken from: https://github.com/ferd/cth_readable/pull/23
has_usable_logger() ->
    %% The config is set (lager didn't remove it)
    erlang:function_exported(logger, get_handler_config, 1) andalso
    logger:get_handler_config(default) =/= {error, {not_found, default}}.
