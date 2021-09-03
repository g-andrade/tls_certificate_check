REBAR3_URL=https://s3.amazonaws.com/rebar3/rebar3

ifeq ($(wildcard rebar3),rebar3)
	REBAR3 = $(CURDIR)/rebar3
endif

# ifdef RUNNING_ON_CI
# REBAR3 = ./rebar3
# else
REBAR3 ?= $(shell test -e `which rebar3` 2>/dev/null && which rebar3 || echo "./rebar3")
# endif

ifeq ($(REBAR3),)
	REBAR3 = $(CURDIR)/rebar3
endif

AUTHORITIES_URL = https://curl.se/ca/cacert.pem
AUTHORITIES_FILE = tmp/cacerts.pem
AUTHORITIES_MODULE = src/tls_certificate_check_hardcoded_authorities.erl

.PHONY: all build clean \
	check dialyzer xref \
	test cover \
	shell \
	doc \
	publish \
	hardcoded-authorities-update \
	hardcoded-authorities-updater \
	download-latest-authorities \
	invoke-hardcoded-authorities-updater

.NOTPARALLEL: check


all: build

build: $(REBAR3)
	@$(REBAR3) compile

$(REBAR3):
	wget $(REBAR3_URL) || curl -Lo rebar3 $(REBAR3_URL)
	@chmod a+x rebar3

clean: $(REBAR3)
	@$(REBAR3) clean

check: dialyzer xref

dialyzer: $(REBAR3)
	@$(REBAR3) as hardcoded_authorities_update dialyzer

xref: $(REBAR3)
	@$(REBAR3) as hardcoded_authorities_update xref

test: $(REBAR3)
	@$(REBAR3) do eunit, ct, cover

cover: test

shell: export ERL_FLAGS = +pc unicode
shell:
	@$(REBAR3) as development shell

doc: $(REBAR3)
	./support/scripts/generate_docs.sh

publish: $(REBAR3)
publish: doc
	@$(REBAR3) hex publish

hardcoded-authorities-update: hardcoded-authorities-updater
hardcoded-authorities-update: download-latest-authorities
hardcoded-authorities-update:
	@make invoke-hardcoded-authorities-updater

hardcoded-authorities-updater: $(REBAR3)
	@$(REBAR3) as hardcoded_authorities_update escriptize

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
