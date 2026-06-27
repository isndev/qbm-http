#
# qb - C++ Actor Framework
# Copyright (c) 2011-2026 qb - isndev (cpp.actor). All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#         limitations under the License.
#

# -----------------------------------------------------------------------------
# qbm-http test suite — tiered (unit / system / benchmark), per docs/tests-audit/_spec-qbm-http.md.
#
# Targets: qbm-http-test-<tier>-<name> via qb_register_module_test(TIER LABELS REQUIRES).
# REQUIRES gating decomposes the legacy single if(QB_HAS_SSL) bucket into its three real reasons:
#   - pure-logic http2 units: NO ssl (were accidentally gated).
#   - ws units/system: REQUIRES ssl — CRYPTO-LINK only (ws/ws.h #errors without qb::io::crypto for
#     Sec-WebSocket-Accept); they run plaintext ws://, not TLS.
#   - crypto/TLS: REQUIRES ssl for real (auth/jwt link; http2/https/ws TLS handshake at runtime).
#   - all system/* loopback tests: REQUIRES live (bind a loopback port).
# http3 stays behind QBM_HTTP_HAS_HTTP3.
#
# NOTE: 16 legacy monoliths remain registered FLAT in the "SPLIT-PENDING" block below; the split
# waves dissolve each into its tiered targets and remove it here. Keeps the build green meanwhile.
# -----------------------------------------------------------------------------

# qhttp_test(<tier> <name> <relpath> [REQUIRES...] [LABELS extra...]) helper.
# INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} (the tests/ dir) so the test files' `"../<hdr>.h"` module
# includes — authored relative to tests/ — keep resolving to qbm/http/<hdr>.h after the move into
# the unit/system/ subtrees. (Canonicalising those to <http/...> angle includes is a later cleanup.)
function(qhttp_test TIER NAME RELPATH)
    cmake_parse_arguments(T "" "" "REQUIRES;EXTRA_LABELS" ${ARGN})
    qb_register_module_test(
        MODULE_NAME http TIER ${TIER} TEST_NAME ${NAME}
        SOURCES ${RELPATH}
        INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}
        LABELS module:qbm-http tier:${TIER} ${T_EXTRA_LABELS}
        REQUIRES ${T_REQUIRES})
endfunction()

# =============================================================================
# UNIT — pure logic (no loop, no socket). Local FS + link-time crypto still unit.
# =============================================================================
# --- utility / uri / message / cookie ---
qhttp_test(unit utility-codec  unit/utility/utility-codec.cpp  EXTRA_LABELS utility)
qhttp_test(unit utility-split  unit/utility/utility-split.cpp  EXTRA_LABELS utility)
qhttp_test(unit utility-chars  unit/utility/utility-chars.cpp  EXTRA_LABELS utility)
qhttp_test(unit uri-parse      unit/uri/uri-parse.cpp          EXTRA_LABELS uri)
qhttp_test(unit http1-serialize-limits unit/http1/http1-serialize-limits.cpp EXTRA_LABELS http1)
qhttp_test(unit http1-parse-limits     unit/http1/http1-parse-limits.cpp     EXTRA_LABELS http1)
qhttp_test(unit http1-serialization unit/http1/http1-serialization.cpp EXTRA_LABELS http1)
qhttp_test(unit http1-protocol-framing unit/http1/http1-protocol-framing.cpp EXTRA_LABELS http1)
qhttp_test(unit validation-rules     unit/validation/validation-rules.cpp     EXTRA_LABELS validation)
qhttp_test(unit validation-schema    unit/validation/validation-schema.cpp    EXTRA_LABELS validation)
qhttp_test(unit validation-parameter unit/validation/validation-parameter.cpp EXTRA_LABELS validation)
qhttp_test(unit validation-sanitizer unit/validation/validation-sanitizer.cpp EXTRA_LABELS validation)
qhttp_test(unit validation-result    unit/validation/validation-result.cpp    EXTRA_LABELS validation)
qhttp_test(unit validation-request   unit/validation/validation-request.cpp   EXTRA_LABELS validation)
qhttp_test(unit validation-parameter-types unit/validation/validation-parameter-types.cpp EXTRA_LABELS validation)
qhttp_test(unit validation-request-params  unit/validation/validation-request-params.cpp  EXTRA_LABELS validation)
qhttp_test(unit validation-schema-policy unit/validation/validation-schema-policy.cpp EXTRA_LABELS validation)
qhttp_test(unit validation-error-type    unit/validation/validation-error-type.cpp    EXTRA_LABELS validation)
qhttp_test(unit body-codec       unit/message/body-codec.cpp)
qhttp_test(unit headers-utility  unit/message/headers-utility.cpp)
qhttp_test(unit message-types    unit/message/message-types.cpp)
qhttp_test(unit response-accessors unit/message/response-accessors.cpp)
qhttp_test(unit cookie           unit/cookie/cookie.cpp)
qhttp_test(unit multipart-security unit/security/multipart-security.cpp EXTRA_LABELS security)
qhttp_test(unit range-parser    unit/http1/range-parser.cpp    EXTRA_LABELS http1)
qhttp_test(unit date-parsing     unit/http-date/date-parsing.cpp)
qhttp_test(unit date-convenience unit/http-date/date-convenience.cpp)

# --- routing (router-* focused primitives + context) ---
qhttp_test(unit context-slots               unit/routing/context-slots.cpp            EXTRA_LABELS routing)
qhttp_test(unit router-methods-api          unit/routing/router-methods-api.cpp       EXTRA_LABELS routing)
qhttp_test(unit router-match                unit/routing/router-match.cpp             EXTRA_LABELS routing)
qhttp_test(unit router-async-dispatch       unit/routing/router-async-dispatch.cpp    EXTRA_LABELS routing)
qhttp_test(unit router-error-handling       unit/routing/router-error-handling.cpp    EXTRA_LABELS routing)
qhttp_test(unit router-middleware-chain     unit/routing/router-middleware-chain.cpp  EXTRA_LABELS routing)
qhttp_test(unit router-controller           unit/routing/router-controller.cpp        EXTRA_LABELS routing)
qhttp_test(unit router-group                unit/routing/router-group.cpp             EXTRA_LABELS routing)
qhttp_test(unit router-pipeline-integration unit/routing/router-pipeline-integration.cpp EXTRA_LABELS routing)
# routing-* : four concern-split files dissolved from the legacy test-router.cpp monolith
qhttp_test(unit routing-match      unit/routing/routing-match.cpp      EXTRA_LABELS routing)
qhttp_test(unit routing-methods    unit/routing/routing-methods.cpp    EXTRA_LABELS routing)
qhttp_test(unit routing-middleware unit/routing/routing-middleware.cpp EXTRA_LABELS routing)
qhttp_test(unit routing-compile    unit/routing/routing-compile.cpp    EXTRA_LABELS routing)
qhttp_test(unit path-parameters    unit/routing/path-parameters.cpp    EXTRA_LABELS routing)
qhttp_test(unit handler-node       unit/routing/handler-node.cpp       EXTRA_LABELS routing)
qhttp_test(unit handler-node-extra unit/routing/handler-node-extra.cpp EXTRA_LABELS routing)

# --- middleware (pure) ---
qhttp_test(unit middleware-conditional      unit/middleware/middleware-conditional.cpp      EXTRA_LABELS middleware)
qhttp_test(unit middleware-transform        unit/middleware/middleware-transform.cpp        EXTRA_LABELS middleware)
qhttp_test(unit middleware-timing           unit/middleware/middleware-timing.cpp           EXTRA_LABELS middleware)
qhttp_test(unit middleware-logging          unit/middleware/middleware-logging.cpp          EXTRA_LABELS middleware)
qhttp_test(unit middleware-security-headers unit/middleware/middleware-security-headers.cpp EXTRA_LABELS middleware)
qhttp_test(unit middleware-compression      unit/middleware/middleware-compression.cpp      EXTRA_LABELS middleware)
qhttp_test(unit middleware-cors             unit/middleware/middleware-cors.cpp             EXTRA_LABELS middleware)
qhttp_test(unit middleware-recaptcha        unit/middleware/middleware-recaptcha.cpp        EXTRA_LABELS middleware)
qhttp_test(unit middleware-error-handling   unit/middleware/middleware-error-handling.cpp   EXTRA_LABELS middleware)
qhttp_test(unit middleware-validator        unit/middleware/middleware-validator.cpp        EXTRA_LABELS middleware)
qhttp_test(unit middleware-static-files     unit/middleware/middleware-static-files.cpp     EXTRA_LABELS middleware)
qhttp_test(unit middleware-rate-limit        unit/middleware/middleware-rate-limit.cpp        EXTRA_LABELS middleware)
qhttp_test(unit middleware-rate-limit-window unit/middleware/middleware-rate-limit-window.cpp EXTRA_LABELS middleware slow)
# crypto-link (OpenSSL HMAC/SHA at link)
qhttp_test(unit middleware-auth unit/middleware/middleware-auth.cpp REQUIRES ssl EXTRA_LABELS middleware ssl)
qhttp_test(unit middleware-jwt  unit/middleware/middleware-jwt.cpp  REQUIRES ssl EXTRA_LABELS middleware ssl)
qhttp_test(unit auth-manager    unit/auth/auth-manager.cpp          REQUIRES ssl EXTRA_LABELS auth ssl)
qhttp_test(unit options-algorithm unit/auth/options-algorithm.cpp    REQUIRES ssl EXTRA_LABELS auth ssl)

# --- http2 pure-logic (UN-GATED from the legacy SSL bucket) ---
qhttp_test(unit http2-frame-layer      unit/http2/http2-frame-layer.cpp      EXTRA_LABELS http2)
qhttp_test(unit http2-server-protocol  unit/http2/http2-server-protocol.cpp  EXTRA_LABELS http2)
qhttp_test(unit http2-client-protocol  unit/http2/http2-client-protocol.cpp  EXTRA_LABELS http2)
qhttp_test(unit hpack-codec            unit/http2/hpack-codec.cpp            EXTRA_LABELS http2)
qhttp_test(unit hpack-encoder-strategy unit/http2/hpack-encoder-strategy.cpp EXTRA_LABELS http2)
qhttp_test(unit http2-header-validation unit/http2/http2-header-validation.cpp EXTRA_LABELS http2)
qhttp_test(unit http2-protocol-state    unit/http2/http2-protocol-state.cpp    EXTRA_LABELS http2)
qhttp_test(unit http2-client-validation unit/http2/http2-client-validation.cpp EXTRA_LABELS http2)
qhttp_test(unit http2-stream-state      unit/http2/http2-stream-state.cpp      EXTRA_LABELS http2)
qhttp_test(unit http2-protocol-coverage unit/http2/http2-protocol-coverage.cpp EXTRA_LABELS http2)
qhttp_test(unit http2-protocol-roundtrip unit/http2/http2-protocol-roundtrip.cpp EXTRA_LABELS http2)
# ws units (crypto-link ssl: ws.h #errors without qb::io::crypto; pure-logic, no socket)
qhttp_test(unit ws-close-frame-negative   unit/ws/ws-close-frame-negative.cpp   REQUIRES ssl EXTRA_LABELS ws)
qhttp_test(unit ws-frame-encode-validation unit/ws/ws-frame-encode-validation.cpp REQUIRES ssl EXTRA_LABELS ws)
qhttp_test(unit ws-key-crypto             unit/ws/ws-key-crypto.cpp             REQUIRES ssl EXTRA_LABELS ws)

# =============================================================================
# SYSTEM — in-process loopback client+server (REQUIRES live). Local TLS = +ssl.
# =============================================================================
qhttp_test(system http1-client         system/http1/http1-client.cpp         REQUIRES live EXTRA_LABELS http1)
qhttp_test(system http1-loopback-basic system/http1/http1-loopback-basic.cpp REQUIRES live EXTRA_LABELS http1)
qhttp_test(system http1-loopback system/http1/http1-loopback.cpp REQUIRES ssl live EXTRA_LABELS http1)
qhttp_test(system router-e2e-advanced  system/routing/router-e2e-advanced.cpp REQUIRES live EXTRA_LABELS http1 routing)
qhttp_test(system http2-client         system/http2/http2-client.cpp         REQUIRES ssl live EXTRA_LABELS http2 ssl)
qhttp_test(system http2-client-coro system/http2/http2-client-coro.cpp REQUIRES ssl live EXTRA_LABELS http2 coro ssl)
qhttp_test(system make-server-factory  system/server/make-server-factory.cpp REQUIRES ssl live EXTRA_LABELS http1 http2 ssl)
qhttp_test(system middleware-pipeline-system system/middleware/middleware-pipeline-system.cpp REQUIRES live EXTRA_LABELS middleware)
qhttp_test(system middleware-auth-jwt-system system/middleware/middleware-auth-jwt-system.cpp REQUIRES ssl live EXTRA_LABELS middleware ssl)
qhttp_test(system coro-client-http1    system/coro/coro-client-http1.cpp     REQUIRES live EXTRA_LABELS http1 coro)
qhttp_test(system coro-server-http1    system/coro/coro-server-http1.cpp     REQUIRES live EXTRA_LABELS http1 coro)
qhttp_test(system coro-gateway-e2e     system/coro/coro-gateway-e2e.cpp      REQUIRES live EXTRA_LABELS http1 coro)
# ws system — crypto-link ssl + live (plaintext ws:// but ws.h needs crypto to link)
qhttp_test(system ws-client-echo   system/ws/ws-client-echo.cpp   REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system ws-robustness    system/ws/ws-robustness.cpp    REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system ws-coro-client   system/ws/ws-coro-client.cpp   REQUIRES ssl live EXTRA_LABELS ws coro)
qhttp_test(system ws-coro-server   system/ws/ws-coro-server.cpp   REQUIRES ssl live EXTRA_LABELS ws coro)
qhttp_test(system ws-coro-handoff  system/ws/ws-coro-handoff.cpp  REQUIRES ssl live EXTRA_LABELS ws coro)
qhttp_test(system ws-framing-edge  system/ws/ws-framing-edge.cpp  REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system ws-lifecycle             system/ws/ws-lifecycle.cpp             REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system ws-handshake-security    system/ws/ws-handshake-security.cpp    REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system ws-coro-handshake-negative system/ws/ws-coro-handshake-negative.cpp REQUIRES ssl live EXTRA_LABELS ws coro)
qhttp_test(system ws-client-hardening      system/ws/ws-client-hardening.cpp      REQUIRES ssl live EXTRA_LABELS ws)

# =============================================================================
# SPLIT-PENDING — legacy monoliths still flat; dissolved + removed by the split waves.
# Registered transitionally with the REQUIRES they currently need to BUILD (SSL-on).
# =============================================================================

# =============================================================================
# HTTP/3 — gated on QBM_HTTP_HAS_HTTP3 (ngtcp2). Still a SPLIT-PENDING monolith.
# =============================================================================
if(QBM_HTTP_HAS_HTTP3)
    qhttp_test(unit   http3-validation unit/http3/http3-validation.cpp EXTRA_LABELS http3)
    qhttp_test(system http3-loopback   system/http3/http3-loopback.cpp REQUIRES quic ssl live EXTRA_LABELS http3 quic ssl)
    qhttp_test(system http3-interop    system/http3/http3-interop.cpp  REQUIRES quic ssl live EXTRA_LABELS http3 interop)
endif()

# SSL resources are copied by qb_setup_test_resources() (qb/CMakeLists.txt); tests find them in CWD.
qb_status_message("Configured qbm-http tests (tiered backbone: unit/system + 16 split-pending monoliths)")


# -----------------------------------------------------------------------------
# Benchmarks — google-benchmark harnesses (qbm-http-bench-<name>). REQUIRES gates as for tests.
# -----------------------------------------------------------------------------
function(qhttp_bench NAME RELPATH)
    cmake_parse_arguments(B "" "" "REQUIRES;EXTRA_LABELS" ${ARGN})
    qb_register_module_benchmark(
        MODULE_NAME http BENCH_NAME ${NAME}
        SOURCES ${RELPATH}
        INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}
        LABELS module:qbm-http bench ${B_EXTRA_LABELS}
        REQUIRES ${B_REQUIRES})
endfunction()

qhttp_bench(route-match      benchmark/routing/route-match.bench.cpp     EXTRA_LABELS routing)
qhttp_bench(http1-parser     benchmark/http1/http1-parser.bench.cpp      EXTRA_LABELS http1)
qhttp_bench(http1-serialize  benchmark/http1/http1-serialize.bench.cpp   EXTRA_LABELS http1)
qhttp_bench(hpack            benchmark/http2/hpack.bench.cpp             EXTRA_LABELS http2)
qhttp_bench(frame-codec      benchmark/http2/frame-codec.bench.cpp       EXTRA_LABELS http2)
qhttp_bench(cors             benchmark/middleware/cors.bench.cpp         EXTRA_LABELS middleware)
qhttp_bench(body-codec       benchmark/message/body-codec.bench.cpp      EXTRA_LABELS message)
qhttp_bench(uri-parse        benchmark/uri/uri-parse.bench.cpp           EXTRA_LABELS uri)
qhttp_bench(ws-throughput    benchmark/ws/ws-throughput.bench.cpp        REQUIRES ssl         EXTRA_LABELS ws)
qhttp_bench(auth-verify      benchmark/middleware/auth-verify.bench.cpp  REQUIRES ssl         EXTRA_LABELS middleware ssl)
qhttp_bench(compression      benchmark/middleware/compression.bench.cpp  REQUIRES compression EXTRA_LABELS middleware)
if(QBM_HTTP_HAS_HTTP3)
    qhttp_bench(http3-field-block benchmark/http3/field-block.bench.cpp  EXTRA_LABELS http3)
endif()
