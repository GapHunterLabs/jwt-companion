<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# JWT Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- JWT decode/verify tool window: paste or type a token, see header and
  payload claims in two independently scrollable panels — never a
  fixed-height table that becomes unreadable once a token has more than
  a couple of claims.
- Signature verification for `HS256` (shared secret) and `RS256`
  (public key/certificate PEM), using only the JDK's own
  `javax.crypto`/`java.security` APIs — no bundled crypto library.
- `iat`/`exp`/`nbf` claims rendered as human-readable UTC dates, with a
  VALID/EXPIRING_SOON/EXPIRED/NOT_YET_VALID indicator.
- Nothing typed into the tool window (token, secret, key) is persisted
  between sessions — in-memory only.

[Unreleased]: https://github.com/GapHunterLabs/jwt-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/jwt-companion/commits/0.1.0
