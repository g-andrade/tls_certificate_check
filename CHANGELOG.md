# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2021-05-30

### Changed

- module with bundled CAs to latest as of 2021/05/25, 03:12 UTC
(source: https://curl.se/ca/cacert.pem)

### Removed

- [certificate authority] global chambersign root - 2008
- [certificate authority] chambers of commerce root - 2008

## [1.5.0] - 2021-05-13

### Added

- OTP 24 to CI targets

### Removed

- compatibility with OTP 21

## [1.4.0] - 2021-04-16

### Added

- [certificate authority] globalsign root e46
- [certificate authority] AC RAIZ FNMT-RCM SERVIDORES SEGUROS
- [certificate authority] globalsign root r46

### Changed

- module with bundled CAs to latest as of 2021/04/13, 03:12 UTC
(source: https://curl.se/ca/cacert.pem)

### Removed

- [certificate authority] geotrust primary certification authority - g2
- [certificate authority] verisign universal root certification authority
- [certificate authority] Staat der Nederlanden Root CA - G3

## [1.3.0] - 2021-04-02

### Added

- `tls_certificate_check:trusted_authorities/0` to API

### Changed

- list of authoritative certificates, from hardcoded to one that's generated on application boot
  and stored on `persistent_term`
- set of trusted public keys, from hardcoded to one that's generated on application boot
  and stored on `persistent_term`

### Removed

- compatibility with OTP 19
- compatibility with OTP 20
- compatibility with OTP 21.0 and 21.1
- priv/cacerts.pem

### Fixed

- unwarranted and risky hardcoding of record values

## [1.2.0] - 2021-03-12

### Added

- elements for easily updating bundled CAs
- [certificate authority] NAVER Global Root Certification Authority

### Changed

- module with bundled CAs to latest as of 2021/01/19, 04:12 UTC
(source: https://curl.se/ca/cacert.pem)

### Removed

- [dependency] `certifi`
- [dependency] `parse_trans`
- [certificate authority] thawte primary root ca - g2
- [certificate authority] geotrust global ca
- [certificate authority] geotrust primary certification authority
- [certificate authority] verisign class 3 public primary certification authority - g4
- [certificate authority] geotrust primary certification authority - g3
- [certificate authority] thawte primary root ca
- [certificate authority] thawte primary root ca - g3
- [certificate authority] verisign class 3 public primary certification authority - g5
- [certificate authority] geotrust universal ca
- [certificate authority] geotrust universal ca 2

### Fixed

- misuse of `tls_certificate_` namespace (all modules start with `tls_certificate_check` now)

## [1.1.1] - 2020-12-08

### Fixed

- compilation errors on OTP 20.1+ when on top of macOS Big Sur

## [1.1.0] - 2020-12-05

### Changed

- CA bundles, based on the latest mkcert.org full CA list as of Nov 13, 2020

## [1.0.2] - 2020-10-16

### Fixed

- misdetection of Mix as being rebar 2 and the erronous compilation warning that followed it

## [1.0.1] - 2020-05-21

### Fixed

- missing links to source code in application metadata

## [1.0.0] - 2020-05-21

### Added

- `:options` function to API, for easily securing connections
