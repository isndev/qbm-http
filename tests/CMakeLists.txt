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
qhttp_test(unit body-codec       unit/message/body-codec.cpp)
qhttp_test(unit headers-utility  unit/message/headers-utility.cpp)
qhttp_test(unit cookie           unit/cookie/cookie.cpp)
qhttp_test(unit multipart-security unit/security/multipart-security.cpp EXTRA_LABELS security)
qhttp_test(unit date-parsing     unit/http-date/date-parsing.cpp)

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
# crypto-link (OpenSSL HMAC/SHA at link)
qhttp_test(unit middleware-auth unit/middleware/middleware-auth.cpp REQUIRES ssl EXTRA_LABELS middleware ssl)
qhttp_test(unit middleware-jwt  unit/middleware/middleware-jwt.cpp  REQUIRES ssl EXTRA_LABELS middleware ssl)
qhttp_test(unit auth-manager    unit/auth/auth-manager.cpp          REQUIRES ssl EXTRA_LABELS auth ssl)

# --- http2 pure-logic (UN-GATED from the legacy SSL bucket) ---
qhttp_test(unit http2-frame-layer      unit/http2/http2-frame-layer.cpp      EXTRA_LABELS http2)
qhttp_test(unit http2-server-protocol  unit/http2/http2-server-protocol.cpp  EXTRA_LABELS http2)
qhttp_test(unit http2-client-protocol  unit/http2/http2-client-protocol.cpp  EXTRA_LABELS http2)
qhttp_test(unit hpack-codec            unit/http2/hpack-codec.cpp            EXTRA_LABELS http2)
qhttp_test(unit hpack-encoder-strategy unit/http2/hpack-encoder-strategy.cpp EXTRA_LABELS http2)

# =============================================================================
# SYSTEM — in-process loopback client+server (REQUIRES live). Local TLS = +ssl.
# =============================================================================
qhttp_test(system http1-client         system/http1/http1-client.cpp         REQUIRES live EXTRA_LABELS http1)
qhttp_test(system http1-loopback-basic system/http1/http1-loopback-basic.cpp REQUIRES live EXTRA_LABELS http1)
qhttp_test(system router-e2e-advanced  system/routing/router-e2e-advanced.cpp REQUIRES live EXTRA_LABELS http1 routing)
qhttp_test(system http2-client         system/http2/http2-client.cpp         REQUIRES ssl live EXTRA_LABELS http2 ssl)
qhttp_test(system make-server-factory  system/server/make-server-factory.cpp REQUIRES ssl live EXTRA_LABELS http1 http2 ssl)
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

# =============================================================================
# SPLIT-PENDING — legacy monoliths still flat; dissolved + removed by the split waves.
# Registered transitionally with the REQUIRES they currently need to BUILD (SSL-on).
# =============================================================================
qhttp_test(unit   _pending-utility           test-utility.cpp)
qhttp_test(unit   _pending-uri-only          test-uri-only.cpp)
qhttp_test(unit   _pending-dos-protection    test-dos-protection.cpp)
qhttp_test(unit   _pending-validation        test-validation.cpp)
qhttp_test(unit   _pending-router            test-router.cpp            EXTRA_LABELS routing)
qhttp_test(unit   _pending-middleware-rate-limit test-middleware-rate_limit.cpp EXTRA_LABELS middleware)
qhttp_test(unit   _pending-http2-header-validator test-http2-header-validator.cpp EXTRA_LABELS http2)
qhttp_test(unit   _pending-coro-http2-client test-coro-http2-client.cpp REQUIRES ssl EXTRA_LABELS http2 ssl)
qhttp_test(system _pending-session-http      test-session-http.cpp      REQUIRES ssl live EXTRA_LABELS http1 ssl)
qhttp_test(system _pending-integration-middleware test-integration-middleware.cpp REQUIRES ssl live EXTRA_LABELS middleware ssl)
qhttp_test(system _pending-ws-security       test-ws-security.cpp       REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system _pending-ws-coro-negative  test-ws-coro-negative.cpp  REQUIRES ssl live EXTRA_LABELS ws coro)
qhttp_test(system _pending-ws-api-hardening  test-ws-api-hardening.cpp  REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system _pending-ws-session        test-ws-session.cpp        REQUIRES ssl live EXTRA_LABELS ws)
qhttp_test(system _pending-ws-stress         test-ws-stress.cpp         REQUIRES ssl live EXTRA_LABELS ws)

# =============================================================================
# HTTP/3 — gated on QBM_HTTP_HAS_HTTP3 (ngtcp2). Still a SPLIT-PENDING monolith.
# =============================================================================
if(QBM_HTTP_HAS_HTTP3)
    qhttp_test(system _pending-http3-client test-http3-client.cpp REQUIRES quic ssl live EXTRA_LABELS http3 quic ssl)
endif()

# SSL resources are copied by qb_setup_test_resources() (qb/CMakeLists.txt); tests find them in CWD.
qb_status_message("Configured qbm-http tests (tiered backbone: unit/system + 16 split-pending monoliths)")
