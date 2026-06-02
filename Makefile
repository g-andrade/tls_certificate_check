SHELL := bash
.ONESHELL:
.SHELLFLAGS := -euc
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

##

AUTHORITIES_URL = https://curl.se/ca/cacert.pem
AUTHORITIES_FILE = tmp/cacerts.pem
AUTHORITIES_MODULE = src/tls_certificate_check_hardcoded_authorities.erl

MIX_CHECK=$(shell mix -v >/dev/null 2>/dev/null || /bin/echo "no")
ifeq (no, $(MIX_CHECK))
$(warning skipping Elixir-dependent tests)
TEST_PROFILES = test
else
# $(info "mix check: $(MIX_CHECK)")
TEST_PROFILES = test,elixir_test
endif

## General Rules

all: compile
.PHONY: all
.NOTPARALLEL: all

compile:
	@rebar3 compile
.PHONY: compile

clean:
	@rebar3 clean -a
.PHONY: clean

check: check-fast check-slow
.NOTPARALLEL: check
.PHONY: check

check-fast: check-formatted xref hank-dead-code-cleaner elvis-linter
.NOTPARALLEL: check-fast
.PHONY: check-fast

check-slow: dialyzer
.NOTPARALLEL: check-slow
.PHONY: check-slow

test: eunit ct
.NOTPARALLEL: test
.PHONY: test

format:
	@rebar3 fmt
.NOTPARALLEL: format
.PHONY: format

## Tests

ct:
	@rebar3 do ct, cover
.PHONY: ct

eunit:
	@rebar3 eunit
.PHONY: eunit

## Checks

check-formatted:
	@if rebar3 plugins list | grep '^erlfmt\>' >/dev/null; then \
		rebar3 fmt --check; \
	else \
		echo >&2 "WARN: skipping rebar3 erlfmt check"; \
	fi
.PHONY: check-formatted

xref:
	@rebar3 as hardcoded_CAs_update xref
.PHONY: xref

hank-dead-code-cleaner:
	@if rebar3 plugins list | grep '^rebar3_hank\>' >/dev/null; then \
		rebar3 hank; \
	else \
		echo >&2 "WARN: skipping rebar3_hank check"; \
	fi
.PHONY: hank-dead-code-cleaner

elvis-linter:
	@if rebar3 plugins list | grep '^rebar3_lint\>' >/dev/null; then \
		rebar3 lint; \
	else \
		echo >&2 "WARN: skipping rebar3_lint check"; \
	fi
.PHONY: elvis-linter

dialyzer:
	@rebar3 as hardcoded_CAs_update dialyzer
.PHONY: dialyzer

## Updating hardcoded CAs

hardcoded-CAs-update: hardcoded-CAs-updater
hardcoded-CAs-update: download-latest-CAs
hardcoded-CAs-update:
	@make invoke-hardcoded-CAs-updater
.PHONY: hardcoded-CAs-update

hardcoded-CAs-updater:
	@rebar3 as hardcoded_CAs_update escriptize
.PHONY: hardcoded-CAs-updater

download-latest-CAs:
	@curl \
		-o "$(AUTHORITIES_FILE)" \
		--remote-time \
		"$(AUTHORITIES_URL)"
.PHONY: download-latest-CAs

invoke-hardcoded-CAs-updater: hardcoded-CAs-updater
	@./_build/hardcoded_CAs_update/bin/tls_certificate_check_hardcoded_CAs_updater \
		"$(AUTHORITIES_FILE)" \
		"$(AUTHORITIES_URL)" \
		"$(AUTHORITIES_MODULE)" \
		"CHANGELOG.md"
.PHONY: invoke-hardcoded-CAs-updater

## Shell, docs and publication

publish: doc
publish:
	@rebar3 hex publish --doc-dir=doc
.NOTPARALLEL: publish

shell: export ERL_FLAGS = +pc unicode
shell:
	@rebar3 as shell shell

doc: SOURCE_REF := $(shell git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD)
doc: tmp/ex_doc
doc:
	rebar3 edoc; \
		./tmp/ex_doc "tls_certificate_check" "${SOURCE_REF}" \
		_build/docs/lib/tls_certificate_check/ebin \
		-c ex_doc.config \
		--source-ref "${SOURCE_REF}";
.PHONY: doc

tmp/ex_doc: EX_DOC_VER=0.40.2
tmp/ex_doc: OTP_VER := $(shell erl -noshell -eval 'io:fwrite("~s", [erlang:system_info(otp_release)]), init:stop().')
tmp/ex_doc: | tmp
tmp/ex_doc:
	curl -fL -o tmp/ex_doc \
		"https://github.com/elixir-lang/ex_doc/releases/download/v${EX_DOC_VER}/ex_doc_otp_${OTP_VER}"; \
		chmod a+x tmp/ex_doc

tmp:
	mkdir tmp
