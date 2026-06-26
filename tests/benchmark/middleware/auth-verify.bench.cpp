/**
 * @file qbm/http/tests/benchmark/middleware/auth-verify.bench.cpp
 * @brief google-benchmark harness for per-request JWT verification.
 *
 * Auth-gated routes pay a JWT verification cost on EVERY request:
 * `qb::http::auth::Manager::verify_token()` base64url-decodes the token, parses
 * the payload JSON, recomputes/checks the signature (HMAC or asymmetric), and
 * validates the time/issuer/audience claims. That verify is the dominant
 * per-request crypto cost of the auth middleware, so these benchmarks isolate it
 * across the four production signing families: HMAC HS256 / HS384 / HS512 and
 * RSA (RS256). Token MINTING is hoisted entirely out of the timed loop — only
 * the verify is measured.
 *
 * Fixtures reuse the seed suite's material so the benchmark exercises the same
 * code the tests pin:
 *   - the shared `make_user()` / `hmac_options()` from shared/auth_test_helpers.h
 *     (the exact User claim set verified in tests/unit/auth/auth-manager.cpp);
 *   - the deterministic embedded RSA PEM key pair from
 *     tests/unit/middleware/middleware-auth.cpp (kRsaPrivateKeyPem /
 *     kRsaPublicKeyPem), so the asymmetric path needs no per-run keygen.
 *
 * REQUIRES ssl: JWT HMAC/RSA verification goes through qb/io/crypto_jwt.h, which
 * `#error`s without OpenSSL (the integrator gates this target on `ssl`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * @ingroup Http
 */

#include <string>

#include <benchmark/benchmark.h>

#include "../auth.h"                       // qb::http::auth::{Manager, Options, User}
#include "shared/auth_test_helpers.h"      // make_user, hmac_options (resolves via tests/ include dir)

namespace {

using qb::http::auth::Manager;
using qb::http::auth::Options;
using qb::http::auth::User;

using qb::http::test::hmac_options;
using qb::http::test::make_user;

// ---------------------------------------------------------------------------
// Deterministic embedded RSA PEM pair — byte-exact from
// tests/unit/middleware/middleware-auth.cpp (kRsaPrivateKeyPem/kRsaPublicKeyPem).
// Reused so the asymmetric path needs no per-run keygen. This is a throwaway test
// fixture key, not a real credential.
// ---------------------------------------------------------------------------
// NOSONAR  pragma: allowlist secret  (test-only RSA key, never used outside tests)
const char *kRsaPrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
                                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9XQ6VOHmUCz/d\n"
                                "b5jFqL/5ogkA7Zz6Kt2SR0eWa3lOLMimTcHGMNrkkeXt0vvHBKDiB5Rh8Jg40mar\n"
                                "CJudCO2ngIxh90toXSiZmtQzZwWHgxH3oqQFYw7kVKssVHuXusC+HC40V333kijR\n"
                                "l2xHX+ckFrzMCJu5zeBOTs+D+2w0EfaEmXTF1XRjsaxjXHA4VMzRjymo+XO73Csi\n"
                                "TSfqPfg2z+P3hz9owqamBc9SuJk5Ke1bv0Rzgauy1Po4B8bWJU0rk3KT2XUuAfJl\n"
                                "bumWwHWjM7G5ubhHyIADU7onHAYCucsZkoSqaKMe6K1ZCXTBYQYB9jcSVfhG/eFe\n"
                                "d0fKRA1/AgMBAAECggEAWHDMXUwdmFOytcinuPVKCByyCNFxRfPcPTP2Tt4OL0FC\n"
                                "S024qUhrC2LK2Qr3lalnPHnexulYJv25frsL9slTOa6TojOd7/XGfwstfX5pujMw\n"
                                "opA++9cafvC+a3tfp+tMlt3RhJeyWPzV/KG0rBcx/Ix0C/UfSiXJ07kCOXmlPSGy\n"
                                "H5AJNax1v/RMT1aP4fDUj8VhN9y58GoM+kkKuvrl/hMVdXSpIXtrGR9jDHBQXVjb\n"
                                "MybxAH5FvR1SY0d8rC6cq6Z7kuX9T/mqZYDxqxhxxyj9+tw0lrFyQtUcZ1mAdWKL\n"
                                "VjCAh0W28BCaEM/OmsTxjxfg+OZ5g+aa5Wc26sGw+QKBgQDwoBUHs4/zz93SInp6\n"
                                "S8EBp/T8qDoeUomxvgOPfi9cjOdUpMGm0z8JSca1Y4gIfjPXAjEwR+xK6ok0F7hL\n"
                                "i+XQUSfTJ91itPirRcILQijxahSkvt2BjbD2F+aRqzyRg+3hjLbUEySYNG/WkZNs\n"
                                "HqLFSQ4bC8TPUOH2OvjcOb9nZwKBgQDJdnu2hyTvR6vsDe6gJ4syGhnDk5sbpGlm\n"
                                "ZAyILw4vmMD9r6IGR++xnNf0ZTcOpgRJ2FFtntZIU/K8/gICV19XkNCA8g3X3mRN\n"
                                "CiTvqOBBrkTsrBbk04rYWy3NHGO8nciy5D05r6ox6uo7mIVbUYoqSmKdtwIEIxeX\n"
                                "jUbfzabSKQKBgC3ugNUtg4cI4NDh3/tERp1oUC2Cd0Wef8Y7/TYA4k2KYAYaRRTx\n"
                                "MhE10gaB70+ft4mNU5JhyEsspfAZrwZMuBuhwjZeX7Yd0XHwKPA5OtOKalJgVKwM\n"
                                "PgFb4plf1Hn6cwgg8i1dUhjzuX194GQ9HNkH7vdesbzZNajo7OQs6cp1AoGAFzDE\n"
                                "XOaBoemmKK4R4e2rYEEQ5ip/mFb8qwSpTKPeBiyXSpyFEiQFu3RKh59/DvidVcLI\n"
                                "3M2D7R98ubSjlpFoMDRDTBSQ82BuO1AHoG7YIbdlx7inif+v4+fbBdlWwceH6s/L\n"
                                "HHDULprUC7gq4bApL2UQpQcD/GXtuUxR9EFACsECgYBufXuFy2L7KP5Wh8wk9Ref\n"
                                "M9b9wQF7Lo9gySj6sBSuBOmMLOli0uLnhoiZ1U3dIkOC3tFwMOIhC5sQiB75nnCJ\n"
                                "/SzObI1PFJ0pUYKeHi0rVltHvZQ4tKvJd0l10qI5C/ND+QJoXs74RHElwUM3UdgT\n"
                                "Wr7IeElg/Hj/Xu9vfiTVnw==\n"
                                "-----END PRIVATE KEY-----";

const char *kRsaPublicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvV0OlTh5lAs/3W+Yxai/\n"
                               "+aIJAO2c+irdkkdHlmt5TizIpk3BxjDa5JHl7dL7xwSg4geUYfCYONJmqwibnQjt\n"
                               "p4CMYfdLaF0omZrUM2cFh4MR96KkBWMO5FSrLFR7l7rAvhwuNFd995Io0ZdsR1/n\n"
                               "JBa8zAibuc3gTk7Pg/tsNBH2hJl0xdV0Y7GsY1xwOFTM0Y8pqPlzu9wrIk0n6j34\n"
                               "Ns/j94c/aMKmpgXPUriZOSntW79Ec4GrstT6OAfG1iVNK5Nyk9l1LgHyZW7plsB1\n"
                               "ozOxubm4R8iAA1O6JxwGArnLGZKEqmijHuitWQl0wWEGAfY3ElX4Rv3hXndHykQN\n"
                               "fwIDAQAB\n"
                               "-----END PUBLIC KEY-----";

// HMAC options pre-loaded with the chosen SHA family.
Options
hmac_opts(Options::Algorithm algo) {
    Options opts = hmac_options();
    opts.algorithm(algo);
    return opts;
}

// ---------------------------------------------------------------------------
// HMAC verify (HS256 / HS384 / HS512). The signing algorithm is state.range(0).
// ---------------------------------------------------------------------------
void
BM_Auth_VerifyHmac(benchmark::State &state) {
    const auto algo = static_cast<Options::Algorithm>(state.range(0));

    // SETUP (out of loop): build the verifier and mint ONE token to verify.
    const Manager     verifier(hmac_opts(algo));
    const std::string token = Manager(hmac_opts(algo)).generate_token(make_user());

    // Correctness gate: a broken verify must not report a number.
    {
        auto out = verifier.verify_token(token);
        if (!out.has_value() || out->id != "user-42") {
            state.SkipWithError("HMAC verify failed in setup");
            return;
        }
    }

    for (auto _ : state) {
        auto out = verifier.verify_token(token);
        benchmark::DoNotOptimize(out);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(token.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// RSA verify (RS256) — the asymmetric per-request cost.
// ---------------------------------------------------------------------------
void
BM_Auth_VerifyRsa(benchmark::State &state) {
    // SETUP (out of loop): sign with the private PEM, verify with the public PEM.
    Options sign_opts;
    sign_opts.algorithm(Options::Algorithm::RSA_SHA256).private_key(kRsaPrivateKeyPem).secret_key("");
    const std::string token = Manager(sign_opts).generate_token(make_user());

    Options verify_opts;
    verify_opts.algorithm(Options::Algorithm::RSA_SHA256).public_key(kRsaPublicKeyPem).secret_key("");
    const Manager verifier(verify_opts);

    {
        if (token.empty()) {
            state.SkipWithError("RSA token mint failed in setup");
            return;
        }
        auto out = verifier.verify_token(token);
        if (!out.has_value() || out->id != "user-42") {
            state.SkipWithError("RSA verify failed in setup");
            return;
        }
    }

    for (auto _ : state) {
        auto out = verifier.verify_token(token);
        benchmark::DoNotOptimize(out);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(token.size()));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

BENCHMARK(BM_Auth_VerifyHmac)
    ->Arg(static_cast<int>(Options::Algorithm::HMAC_SHA256))
    ->Arg(static_cast<int>(Options::Algorithm::HMAC_SHA384))
    ->Arg(static_cast<int>(Options::Algorithm::HMAC_SHA512))
    ->ArgNames({"algo"})
    ->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Auth_VerifyRsa)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
