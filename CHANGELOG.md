# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.14.0] - 2022-04-27

### Added

- [certificate authority] d-trust ev root ca 1 2020
- [certificate authority] d-trust br root ca 1 2020
- [certificate authority] Telia Root CA v2

### Changed

- module with bundled CAs to latest as of 2022/04/26, 03:12 UTC
(source: https://curl.se/ca/cacert.pem)

## [1.13.0] - 2022-03-18

### Changed

- module with bundled CAs to latest as of 2022/03/18, 12:30 UTC
(source: https://curl.se/ca/cacert.pem)

### Removed

- [certificate authority] ec-acc

## [1.12.0] - 2022-02-02

### Added

- [certificate authority] vtrus ecc root ca
- [certificate authority] isrg root x2
- [certificate authority] vtrus root ca
- [certificate authority] HiPKI Root CA - G1
- [certificate authority] Autoridad de Certificacion Firmaprofesional CIF A62634068

### Changed

- module with bundled CAs to latest as of 2022/02/01, 04:12 UTC
(source: https://curl.se/ca/cacert.pem)
- [certificate authority] gts root r4
- [certificate authority] gts root r3
- [certificate authority] gts root r1
- [certificate authority] gts root r2
- [certificate authority] GlobalSign ECC Root CA - R4

### Removed

- [certificate authority] GlobalSign Root CA - R2
- [certificate authority] cybertrust global root

## [1.11.0] - 2021-10-28

### Added

- [certificate authority] HARICA TLS ECC Root CA 2021
- [certificate authority] HARICA TLS RSA Root CA 2021
- [certificate authority] TunTrust Root CA

### Changed

- module with bundled CAs to latest as of 2021/10/26, 03:12 UTC
(source: https://curl.se/ca/cacert.pem)

## [1.10.0] - 2021-10-01

### Changed

- module with bundled CAs to latest as of 2021/09/30, 21:42 UTC
(source: https://curl.se/ca/cacert.pem)

### Removed

- [certificate authority] dst root ca x3

## [1.9.0] - 2021-09-03

### Added

- test coverage of certificates yet-to-be valid
- test coverage of misordered certificate chains

### Changed

- **partial chain validation to prepare for
[DST Root CA X3 expiration](https://blog.voltone.net/post/30)**
- documentation from edoc to ExDoc

### Removed

- dependency on badssl.com for important test cases

## [1.8.0] - 2021-08-31

### Added

- automated PR-based update of bundled CAs through GHA

### Changed

- app description to tentatively improve it

## [1.7.0] - 2021-07-08

### Added

- [certificate authority] certum ec-384 ca
- [certificate authority] globaltrust 2020
- [certificate authority] certum trusted root ca
- [certificate authority] anf secure server root ca

### Changed

- module with bundled CAs to latest as of 2021/07/05, 21:35 UTC
(source: https://curl.se/ca/cacert.pem)

### Removed

- [certificate authority] sonera class2 ca
- [certificate authority] trustis fps root ca
- [certificate authority] quovadis root certification authority

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
