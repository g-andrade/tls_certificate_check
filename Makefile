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

.PHONY: all build clean \
	check dialyzer xref \
	test cover \
	shell \
	doc-dry \
	publish \
	hardcoded-authorities-update \
	hardcoded-authorities-updater \
	download-latest-authorities \
	invoke-hardcoded-authorities-updater

.NOTPARALLEL: check


all: build

build:
	@rebar3 compile

rebar3:
	wget $(REBAR3_URL) || curl -Lo rebar3 $(REBAR3_URL)
	@chmod a+x rebar3

clean:
	@rebar3 clean

check: dialyzer xref

dialyzer:
	@rebar3 as hardcoded_authorities_update dialyzer

xref:
	@rebar3 as hardcoded_authorities_update xref

test:
	@rebar3 as $(TEST_PROFILES) do eunit, ct, cover

cover: test

hardcoded-authorities-update: hardcoded-authorities-updater
hardcoded-authorities-update: download-latest-authorities
hardcoded-authorities-update:
	@make invoke-hardcoded-authorities-updater

hardcoded-authorities-updater:
	@rebar3 as hardcoded_authorities_update escriptize

download-latest-authorities:
	@curl \
		-o "$(AUTHORITIES_FILE)" \
		--remote-time \
		"$(AUTHORITIES_URL)"

invoke-hardcoded-authorities-updater: hardcoded-authorities-updater
	@./_build/hardcoded_authorities_update/bin/tls_certificate_check_hardcoded_authorities_updater \
		"$(AUTHORITIES_FILE)" \
		"$(AUTHORITIES_URL)" \
		"$(AUTHORITIES_MODULE)" \
		"CHANGELOG.md"

## Shell, docs and publication

publish: doc
publish:
	@rebar3 hex publish --doc-dir=doc
.NOTPARALLEL: publish

shell: export ERL_FLAGS = +pc unicode
shell:
	@rebar3 as development shell

doc: SOURCE_REF := $(shell git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD)
doc: tmp/ex_doc
doc:
	rebar3 as docs edoc; \
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
