<!-- Verified-against: qb 3.0.0 (C++20 default, C++23 supported) -->

# Support

How to get help with qbm-http, and what to expect.

qbm-http is a module of the [qb actor framework](https://github.com/isndev/qb). Anything about the
framework itself — the actor model, the event loop, coroutines, building or installing qb — belongs
in the qb repository. This page covers the module.

## Where to ask

| Channel | Use it for |
|---|---|
| **[qb Discussions](https://github.com/isndev/qb/discussions)** | Questions, design help, "how do I…". One place for the whole framework, modules included. |
| **Issues in this repository** | Reproducible bugs and concrete feature requests **in qbm-http**. |
| **Security advisory** | Vulnerabilities — privately, per [SECURITY.md](./SECURITY.md). Never in a public issue. |

Before opening an issue, please:

1. Read the [module documentation](./readme/README.md) and check [CHANGELOG.md](./CHANGELOG.md) — 3.0
   is a major release and some of what changed is source-breaking.
2. Search existing issues, here and in [qb](https://github.com/isndev/qb/issues).
3. Prepare a minimal reproduction and your environment: OS, compiler and version, qb version, build
   flags. If the report involves TLS, HTTP/2 or HTTP/3, say which OpenSSL / nghttp2 / ngtcp2 versions the build found.

If you are not sure whether a defect is in the module or in the framework, file it here. Moving an
issue between repositories is cheap; a report nobody files is not.

## Scope of support

qbm-http is open-source software maintained on a best-effort basis, on the same terms as qb: building
on the supported toolchains, the documented APIs, and confirmed defects. It does not include
guaranteed response times, private consulting, or debugging application code that does not involve a
module defect.

The module is **not configurable standalone** — it calls CMake functions that only qb provides. Build
it from the qb-dev superproject, or install it from there and consume the installed package. See
[README.md](./README.md) for both routes.

## Self-service resources

- [Module documentation](./readme/README.md)
- [`llm/`](./llm/) — the agent-facing reference: a mental model plus the deterministic public API
- [qb documentation](https://github.com/isndev/qb/tree/main/readme) and its
  [FAQ](https://github.com/isndev/qb/blob/main/readme/7_reference/faq.md)
- [Examples](https://github.com/isndev/qb-examples)
