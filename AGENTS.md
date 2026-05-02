# tls_certificate_check — Agent Guide

## What this is

An Erlang/OTP (and Elixir) library that provides safer TLS options for HTTPS and other
SSL/TLS connections. It bundles a CA trust store (Mozilla's, via curl) and integrates
with `ssl_verify_fun` for hostname verification and misordered chain handling.

On OTP 25+ it prefers OTP's own system CA store and falls back to the bundled one.

## Build & test

    make test          # eunit + ct + cover (includes Elixir tests if mix is available)
    make check         # dialyzer + xref
    make build         # compile only

Run `make test` before pushing any change. Elixir tests use `castore` and `certifi` as
test deps and require `mix` to be available; if not, they are silently skipped.

## Checking docs

    make doc-dry

Run this to verify that documentation builds cleanly. Do not break docs.

## Key source files

| File | Role |
|---|---|
| `src/tls_certificate_check.erl` | Public API |
| `src/tls_certificate_check_shared_state.erl` | Manages authorities in `persistent_term` |
| `src/tls_certificate_check_util.erl` | Internal helpers (certificate processing, supervision utils) |
| `src/tls_certificate_check_hardcoded_authorities.erl` | **Generated.** Do not edit by hand. |
| `src/tls_certificate_check_app.erl` | OTP application callback |
| `src/tls_certificate_check_sup.erl` | Supervisor |
| `util/tls_certificate_check_hardcoded_authorities_updater.erl` | Escript that regenerates the above |

## Test fixtures

`test/common_scenarios/` and `test/cross_signing/` contain generated certificate chains
and CA stores used by the CT suites. Do not edit them by hand.

## Bundled CA store

`src/tls_certificate_check_hardcoded_authorities.erl` is generated from Mozilla's CA
bundle (via curl) and **must not be edited by hand**. Updates are automated via a
scheduled GitHub Actions workflow (`.github/workflows/hardcoded-authorities-updater.yml`)
that runs on weekdays and opens a PR when the upstream bundle changes. Do not run
`make hardcoded-authorities-update` unless explicitly asked to.

## Code conventions

- **All public functions must have `-spec` attributes.** `warn_missing_spec` is enabled
  and `warnings_as_errors` is on — the build will fail without them.
- OTP version compatibility is handled via `platform_define` macros in `rebar.config`.
  When adding version-specific behaviour, add a new macro there rather than using
  runtime version checks.
- No `export_all` in production modules (`warn_export_all` is on).
- Keep the `rebar.config` profiles in mind: `test`, `elixir_test`,
  `hardcoded_authorities_update`, `development` — each has different deps and `erl_opts`.
