# tls\_certificate\_check

[![Hex downloads](https://img.shields.io/hexpm/dt/tls_certificate_check.svg)](https://hex.pm/packages/tls_certificate_check)
[![License](https://img.shields.io/hexpm/l/tls_certificate_check.svg)](https://github.com/g-andrade/tls_certificate_check/blob/master/LICENSE)
[![Erlang Versions](https://img.shields.io/badge/Erlang%2FOTP-22%20to%2027-blue)](https://www.erlang.org)
[![CI status](https://github.com/g-andrade/tls_certificate_check/actions/workflows/ci.yml/badge.svg)](https://github.com/g-andrade/tls_certificate_check/actions/workflows/ci.yml)
[![Latest version](https://img.shields.io/hexpm/v/tls_certificate_check.svg?style=flat)](https://hex.pm/packages/tls_certificate_check)
[![API reference](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/tls_certificate_check/)
[![Last commit](https://img.shields.io/github/last-commit/g-andrade/tls_certificate_check.svg)](https://github.com/g-andrade/tls_certificate_check/commits/master)

`tls_certificate_check` is a library for Erlang/OTP and Elixir that
tries to make it easier to establish [more secure HTTPS
connections](https://wiki.mozilla.org/index.php?title=CA/IncludedCertificates&redirect=no)
in ordinary setups.

Other kinds of TLS/SSL connections may also benefit from it.

It blends a CA trust store with
[ssl\_verify\_fun](https://github.com/deadtrickster/ssl_verify_fun.erl)
to verify remote hostnames,
as well as the boilerplate to validate [misordered
certificate chains](https://github.com/elixir-mint/mint/issues/95).

The
[OTP-trusted CAs](https://www.erlang.org/doc/man/public_key.html#cacerts_get-0)
(typically provided by the OS) are used on OTP 25+ unless unavailable or opted-out[^1],
in which case `tls_certificate_check` falls back to a hardcoded [Mozilla's CA certificate
store](https://curl.se/docs/caextract.html), as extracted by `curl`.
When on OTP 24 or older, the lib will initialize using only the latter.

The trusted authorities' certificates are loaded when the application
starts and made available to the API through
[`persistent_term`](https://erlang.org/doc/man/persistent_term.html)[^2]. After that, they can
be explicitly overridden through the API.

### How to use

#### Erlang

##### 1\. Import as a dependency

rebar.config

``` erlang
{deps, [
    % [...]
    {tls_certificate_check, "~> 1.25"}
]}.
```

your\_application.app.src

``` erlang
{applications, [
    kernel,
    stdlib,
    % [...]
    tls_certificate_check
]}
```

##### 2\. Make your connections safer

``` erlang
Host = "example.com",
Options = tls_certificate_check:options(Host),
ssl:connect(Host, 443, Options, 5000)
```

#### Elixir

##### 1\. Import as a dependency

mix.exs

``` elixir
  defp deps do
    [
      # [...]
      {:tls_certificate_check, "~> 1.25"}
    ]
  end
```

##### 2\. Make your connections safer

``` elixir
host = "example.com"
options = :tls_certificate_check.options(host)
host |> String.to_charlist() |> :ssl.connect(443, options, 5000)
```

### Advanced Use

#### Overriding Trusted CAs

##### Erlang

```erlang
Path = certifi:cacertfile(),
tls_certificate_check:override_trusted_authorities({file, Path})
```

##### Elixir

```elixir
path = CAStore.file_path()
:tls_certificate_check.override_trusted_authorities({:file, path})
```

### API Reference

The API reference can be found on
[HexDocs](https://hexdocs.pm/tls_certificate_check/).

### Tested setup

  - Erlang/OTP 22 or newer
  - rebar3

### License

MIT License

Copyright (c) 2020-2024 Guilherme Andrade

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

[^1]: the use of OTP-trusted CAs can be controlled through the `use_otp_trusted_CAs` boolean
option within application env config.

[^2]: the persistent term key is derived from the CA store's own contents and existing keys
are not erased until the app terminates gracefully - this minimizes the risk of an impactful
global garbage collection.
