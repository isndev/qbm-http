# Changelog

All notable changes to the qbm-http module are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the module tracks the qb framework's
[Semantic Versioning](https://semver.org/). Framework-wide policy is in the qb
[VERSIONING](../../qb/VERSIONING.md) document.

## [Unreleased]

Tracks changes on the development branch not yet part of a tagged release.

## [2.0.0]

Aligns qbm-http with the qb 2.0 framework and hardens the HTTP/2, HTTP/3, WebSocket, and parsing paths.

### Changed

- Time handling migrated to the canonical chrono model: cookie `max_age`, CORS max-age, and rate-limit
  windows are `qb::duration`; the HTTP date API uses `qb::wall_time`; JWT leeway and expiry remain
  `std::chrono::seconds` (RFC NumericDate). The retired `qb::Timestamp` / `qb::Duration` types are gone.
- HTTP/3 build integration: `QBM_HTTP_HAS_HTTP3` is defined PUBLIC so consumers can gate on it.
- Percent-decoding deduplicated into `qb::http::utility`.
- Builds clean under `-Wall -Wextra`.

### Fixed

- HTTP/2: stream use-after-free in handler-throw containment; iterator invalidation during push-promise
  creation; trailer deduplication via a populated initial-frame header set; removed a dead
  `associated_push_promises` field.
- HTTP/1.1: throwing routing/response handlers are contained in the server session.
- Rate-limit client-id extractor made type-safe.

### Security

- HPACK: reject Huffman padding longer than 7 bits (RFC 7541 §5.2).
- Multipart: enforce part-count and total-size limits.
- WebSocket: bound message reassembly by default (denial-of-service hardening).
- HTTP/3: contain exceptions in nghttp3 callbacks and fail closed on RNG error; bound the client
  pending-request queue.
- Reject control characters in quoted header-attribute values.

[Unreleased]: https://github.com/isndev/qbm-http/compare/main...HEAD
