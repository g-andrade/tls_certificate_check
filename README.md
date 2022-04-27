# tls\_certificate\_check

[![](https://img.shields.io/hexpm/v/tls_certificate_check.svg?style=flat)](https://hex.pm/packages/tls_certificate_check)
[![](https://github.com/g-andrade/tls_certificate_check/workflows/build/badge.svg)](https://github.com/g-andrade/tls_certificate_check/actions?query=workflow%3Abuild)

`tls_certificate_check` is a library for Erlang/OTP and Elixir intended
on easing the establishement of [more
secure](https://wiki.mozilla.org/index.php?title=CA/IncludedCertificates&redirect=no)
HTTPS connections in ordinary setups.

Other kinds of TLS/SSL connections may also benefit from it.

It wraps [Mozilla's CA certificate
store](https://curl.se/docs/caextract.html), as extracted by `curl`,
together with
[ssl\_verify\_fun](https://github.com/deadtrickster/ssl_verify_fun.erl)
plus all the the boilerplate code required for validating [misordered
certificate chains](https://github.com/elixir-mint/mint/issues/95).

The trusted authorities' certificates are hardcoded in PEM format,
decoded when the application starts and made available to the API
through
[`persistent_term`](https://erlang.org/doc/man/persistent_term.html).

### Usage - Erlang

##### 1\. Import as a dependency

rebar.config

``` erlang
{deps,
 [% [...]
  {tls_certificate_check, "~> 1.14"}
  ]}.
```

your\_application.app.src

``` erlang
  {applications,
   [kernel,
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

### Usage - Elixir

##### 1\. Import as a dependency

mix.exs

``` elixir
  defp deps do
    [
      # [...]
      {:tls_certificate_check, "~> 1.14"}
    ]
  end
```

##### 2\. Make your connections safer

``` elixir
host = "example.com"
options = :tls_certificate_check.options(host)
:ssl.connect(host, 443, options, 5000)
```

### API Reference

The API reference can be found on
[HexDocs](https://hexdocs.pm/tls_certificate_check/).

### Tested setup

  - Erlang/OTP 22 or newer
  - rebar3

### License

MIT License

Copyright (c) 2020-2022 Guilherme Andrade

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
