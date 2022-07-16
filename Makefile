AUTHORITIES_URL = https://curl.se/ca/cacert.pem
AUTHORITIES_FILE = tmp/cacerts.pem
AUTHORITIES_MODULE = src/tls_certificate_check_hardcoded_authorities.erl

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
	@rebar3 do eunit, ct, cover

cover: test

shell: export ERL_FLAGS = +pc unicode
shell:
	@rebar3 as development shell

doc-dry:
	@rebar3 hex docs --dry-run

publish:
	@rebar3 hex publish

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
