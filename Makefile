REBAR3_URL=https://s3.amazonaws.com/rebar3/rebar3

ifeq ($(wildcard rebar3),rebar3)
	REBAR3 = $(CURDIR)/rebar3
endif

ifdef RUNNING_ON_CI
REBAR3 = ./rebar3
else
REBAR3 ?= $(shell test -e `which rebar3` 2>/dev/null && which rebar3 || echo "./rebar3")
endif

ifeq ($(REBAR3),)
	REBAR3 = $(CURDIR)/rebar3
endif

AUTHORITIES_URL = https://curl.se/ca/cacert.pem
AUTHORITIES_FILE = tmp/cacerts.pem
AUTHORITIES_MODULE = src/tls_certificate_check_authorities.erl

.PHONY: all build clean \
	check dialyzer xref \
	test cover \
	shell \
	doc \
	publish \
	update-authorities \
	invoke-authorities-updater \
	build-authorities-updater

.NOTPARALLEL: check update-authorities

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
	@$(REBAR3) as update_authorities dialyzer

xref: $(REBAR3)
	@$(REBAR3) as update_authorities xref

test: $(REBAR3)
	@$(REBAR3) do ct, cover

cover: test

shell: export ERL_FLAGS = +pc unicode
shell:
	@$(REBAR3) as development shell

doc: $(REBAR3)
	@$(REBAR3) edoc

README.md: doc
	# non-portable dirty hack follows (pandoc 2.11.0.4 used)
	# gfm: "github-flavoured markdown"
	@pandoc --from html --to gfm doc/overview-summary.html -o README.md
	@tail -n +11 <"README.md"   >"README.md_"
	@head -n -12 <"README.md_"  >"README.md"
	@tail -n  2  <"README.md_" >>"README.md"
	@rm "README.md_"

publish: $(REBAR3)
	@$(REBAR3) as publish hex publish
	@$(REBAR3) as publish hex docs

update-authorities: download-latest-authorities
update-authorities: invoke-authorities-updater

download-latest-authorities:
	@curl \
		-o "$(AUTHORITIES_FILE)" \
		--remote-time \
		"$(AUTHORITIES_URL)"

invoke-authorities-updater: build-authorities-updater
	@./_build/update_authorities/bin/tls_certificate_check_authorities_update \
		"$(AUTHORITIES_FILE)" \
		"$(AUTHORITIES_URL)" \
		"$(AUTHORITIES_MODULE)" \
		"CHANGELOG.md"

build-authorities-updater:
	@$(REBAR3) as update_authorities escriptize
