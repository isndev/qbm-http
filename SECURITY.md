<!-- Verified-against: qbm-http @ qb 3.0.0 (C++20 default, C++23 supported) -->
# Security policy

qbm-http is a module of the qb actor framework. Vulnerability reporting and disclosure follow the
framework's process — see the qb [SECURITY policy](https://github.com/isndev/qb/blob/main/SECURITY.md). **Do not report security issues
through public GitHub issues, pull requests, or discussions.**

## Supported versions

Security fixes target the module version that ships with the supported qb framework release (the `2.6.x`
line). See the framework policy for details.

## Module attack surface

When reporting, identify the affected component. qbm-http parses untrusted network input across several
layers, each a relevant surface:

- HTTP/1.1 request parsing (the vendored llhttp parser and the framing layer).
- HTTP/2: HPACK decoding, stream and flow-control state, push-promise handling.
- HTTP/3 over QUIC (when built with `QBM_HTTP_HAS_HTTP3`): the nghttp3 callbacks and request queue.
- WebSocket framing, masking, and message reassembly.
- Multipart and form body parsing.
- Header attribute parsing and value handling.

The module enforces bounds against denial of service (multipart part-count and total-size limits, WebSocket
reassembly limits, an HTTP/3 pending-request queue bound) and rejects malformed input (HPACK Huffman
padding, control characters in quoted header values). Report any case where these bounds can be bypassed or
where untrusted input reaches an unsafe path.

TLS-dependent features (HTTPS, WebSocket — all of it, even plaintext `ws://`, HTTP/2, HTTP/3, JWT, auth)
require an SSL-enabled build (`QB_HAS_SSL`); review your build configuration as part of your threat model.
