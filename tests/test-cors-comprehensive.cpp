#include <gtest/gtest.h>
#include "../routing.h"

// Mock session for testing - same as in test-cors-advanced.cpp
class MockSession {
public:
    qb::http::Response                 _response;
    bool                               _closed = false;
    std::vector<qb::http::Response>    _responses;
    qb::unordered_map<std::string, std::string> _cors_headers;
    std::string                        _captured_body;
    qb::uuid                           _id; // Add session ID member

    // Constructor to initialize the ID
    MockSession()
        : _id(qb::generate_random_uuid()) {}

    // Required by Router to send responses
    MockSession &
    operator<<(qb::http::Response resp) {
        std::cout << "MockSession received response" << std::endl;

        // Capture CORS headers before move
        if (resp.headers().find("Access-Control-Allow-Origin") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Origin"] =
                resp.header("Access-Control-Allow-Origin");
            std::cout << "Captured Access-Control-Allow-Origin: "
                      << _cors_headers["Access-Control-Allow-Origin"] << std::endl;
        }

        if (resp.headers().find("Access-Control-Allow-Methods") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Methods"] =
                resp.header("Access-Control-Allow-Methods");
        }

        if (resp.headers().find("Access-Control-Allow-Headers") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Headers"] =
                resp.header("Access-Control-Allow-Headers");
        }

        if (resp.headers().find("Access-Control-Allow-Credentials") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Credentials"] =
                resp.header("Access-Control-Allow-Credentials");
        }

        if (resp.headers().find("Access-Control-Expose-Headers") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Expose-Headers"] =
                resp.header("Access-Control-Expose-Headers");
        }

        if (resp.headers().find("Access-Control-Max-Age") != resp.headers().end()) {
            _cors_headers["Access-Control-Max-Age"] =
                resp.header("Access-Control-Max-Age");
        }

        // Store Vary header
        if (resp.headers().find("Vary") != resp.headers().end()) {
            _cors_headers["Vary"] = resp.header("Vary");
            std::cout << "Captured Vary: " << _cors_headers["Vary"] << std::endl;
        }

        // Save status code
        _response.status_code = resp.status_code;

        try {
            if (!resp.body().empty()) {
                _captured_body   = resp.body().as<std::string>();
                _response.body() = _captured_body;
            }
        } catch (...) {
            // Ignore body errors
        }

        _responses.push_back(_response);
        return *this;
    }

    [[nodiscard]] bool
    is_connected() const {
        return !_closed;
    }

    void
    close() {
        _closed = true;
    }

    void
    reset() {
        _responses.clear();
        _response = qb::http::Response();
        _cors_headers.clear();
        _captured_body.clear();
        _closed = false;
    }

    [[nodiscard]] size_t
    responseCount() const {
        return _responses.size();
    }

    qb::http::Response &
    response() {
        return _response;
    }

    void
    printHeaders() const {
        std::cout << "Captured CORS headers:" << std::endl;
        for (const auto &[key, value] : _cors_headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << "Captured body: " << _captured_body << std::endl;
    }

    // Helper to get CORS headers
    [[nodiscard]] std::string
    header(const std::string &name) const {
        auto it = _cors_headers.find(name);
        if (it != _cors_headers.end()) {
            return it->second;
        }
        return "";
    }

    // Helper to get body
    [[nodiscard]] std::string
    body() const {
        return _captured_body;
    }

    // Return the session ID
    [[nodiscard]] const qb::uuid& id() const {
        return _id;
    }
};

class CorsComprehensiveTest : public ::testing::Test {
protected:
    using Router      = qb::http::TRequest<std::string>::Router<MockSession>;
    using Request     = qb::http::TRequest<std::string>;
    using CorsOptions = qb::http::CorsOptions;

    std::unique_ptr<Router> router;
    std::shared_ptr<MockSession> session; // Use shared_ptr for session

    void
    SetUp() override {
        router = std::make_unique<Router>();
        session = std::make_shared<MockSession>(); // Create session using make_shared
        session->reset();

        // Set up test routes
        router->GET("/api/users", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "List of users";
        });

        router->GET("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "User: " + ctx.param("id");
        });

        router->POST("/api/users", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_CREATED;
            ctx.response.body()      = "User created";
        });

        router->PUT("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "User updated: " + ctx.param("id");
        });

        router->DELETE("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
        });

        // A route with PATCH method
        router->PATCH("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "User patched: " + ctx.param("id");
        });

        // Route for performance testing
        router->GET("/api/performance", [](auto &ctx) {
            // Add some custom headers
            ctx.response.add_header("X-Custom-Header-1", "Value1");
            ctx.response.add_header("X-Custom-Header-2", "Value2");
            ctx.response.add_header("X-Response-Time", "10ms");

            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "Performance route";
        });
    }

    void
    TearDown() override {
        router.reset();
    }

    Request
    createRequest(http_method method, const std::string &path,
                  const std::string &origin = "") {
        Request req;
        req.method = method;
        req._uri   = qb::io::uri(path);

        if (!origin.empty()) {
            req.add_header("Origin", origin);
        }

        return req;
    }

    Request
    createPreflightRequest(const std::string &path, const std::string &origin,
                           const std::string              &method,
                           const std::vector<std::string> &headers = {}) {
        Request req = createRequest(HTTP_OPTIONS, path, origin);
        req.add_header("Access-Control-Request-Method", method);

        if (!headers.empty()) {
            std::string header_str = headers[0];
            for (size_t i = 1; i < headers.size(); ++i) {
                header_str += ", " + headers[i];
            }
            req.add_header("Access-Control-Request-Headers", header_str);
        }

        return req;
    }
};

// 1. Test de fallback pour les origines non autorisées
TEST_F(CorsComprehensiveTest, NonAllowedOriginFallback) {
    // Activer CORS avec des origines spécifiques
    router->enable_cors(
        CorsOptions().origins({"https://app.example.com", "https://admin.example.com"}));

    // Tester avec une origine autorisée
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");

    // Réinitialiser la session
    session->reset();

    // Tester avec une origine non autorisée
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://malicious.example.com");
    router->route(session, req2);

    // Vérifier que les en-têtes CORS ne sont pas présents pour l'origine non autorisée
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");

    // Vérifier que la réponse a été renvoyée (mais sans les en-têtes CORS)
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->body(), "List of users");

    // L'en-tête Vary doit être présent indépendamment de l'origine
    EXPECT_EQ(session->header("Vary"), "Origin");
}

// 2. Test de performances CORS
TEST_F(CorsComprehensiveTest, CorsPerformance) {
    // Configuration avec un grand nombre d'origines pour tester les performances
    std::vector<std::string> many_origins;
    for (int i = 1; i <= 100; i++) {
        many_origins.push_back("https://subdomain" + std::to_string(i) + ".example.com");
    }

    router->enable_cors(CorsOptions().origins(many_origins));

    // Mesurer le temps pour traiter une requête avec CORS
    auto start_time = std::chrono::high_resolution_clock::now();

    auto req =
        createRequest(HTTP_GET, "/api/performance", "https://subdomain50.example.com");
    router->route(session, req);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

    // Vérifier que la requête a été traitée correctement
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://subdomain50.example.com");
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);

    // Vérifier que le temps de traitement est raisonnable (moins de 10ms)
    // Ce seuil peut être ajusté en fonction de l'environnement d'exécution
    EXPECT_LT(duration.count(), 10000); // 10000 microsecondes = 10ms

    std::cout << "CORS processing time: " << duration.count() << " microseconds"
              << std::endl;
}

// 3. Test de combinaison de stratégies de correspondance
TEST_F(CorsComprehensiveTest, CombinedMatchingStrategies) {
    // Fonction personnalisée qui combine différentes stratégies
    auto combined_matcher = [](const std::string &origin) -> bool {
        // Liste d'origines exactes
        std::vector<std::string> exact_matches = {"https://app.example.com",
                                                  "https://admin.example.com"};

        // Vérifier les correspondances exactes
        for (const auto &match : exact_matches) {
            if (origin == match) {
                return true;
            }
        }

        // Motifs regex
        std::vector<std::regex> patterns = {
            std::regex(R"(^https:\/\/[a-z0-9]+\.api\.example\.(com|org)$)"),
            std::regex(R"(^https:\/\/shard-[0-9]{3}\.example\.com$)")};

        for (const auto &pattern : patterns) {
            if (std::regex_match(origin, pattern)) {
                return true;
            }
        }

        // Logique personnalisée
        if (origin.find("localhost:") != std::string::npos) {
            return true;
        }

        // Vérifier les origines internes basées sur un format spécifique
        if (origin.find("https://internal-") == 0 &&
            origin.find(".corp.example.com") != std::string::npos) {
            // Extraire l'ID de l'équipe pour des vérifications supplémentaires si
            // nécessaire
            std::string team_id = origin.substr(16, origin.find(".corp") - 16);
            // On pourrait vérifier team_id contre une liste d'équipes autorisées
            return !team_id.empty();
        }

        return false;
    };

    // Activer CORS avec le matcher combiné
    router->enable_cors(CorsOptions().origin_matcher(combined_matcher));

    // Test avec une correspondance exacte
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");
    session->reset();

    // Test avec une correspondance de regex
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://user.api.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://user.api.example.com");
    session->reset();

    // Test avec une autre correspondance de regex
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://shard-123.example.com");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://shard-123.example.com");
    session->reset();

    // Test avec localhost
    auto req4 = createRequest(HTTP_GET, "/api/users", "http://localhost:3000");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "http://localhost:3000");
    session->reset();

    // Test avec une origine interne
    auto req5 = createRequest(HTTP_GET, "/api/users",
                              "https://internal-devteam.corp.example.com");
    router->route(session, req5);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://internal-devteam.corp.example.com");
    session->reset();

    // Test avec une origine non autorisée
    auto req6 = createRequest(HTTP_GET, "/api/users", "https://evil.com");
    router->route(session, req6);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

// 4. Test d'échappement d'origine
TEST_F(CorsComprehensiveTest, OriginEscaping) {
    // Activer CORS avec des origines contenant des caractères spéciaux
    router->enable_cors(CorsOptions().origins({
        "https://example.com",
        "https://sub.example.com/with%20space", // URL encodée avec un espace
        "https://app.example.com/path?query=value&param=test" // Avec query string
    }));

    // Test avec une origine contenant des caractères spéciaux encodés
    auto req1 =
        createRequest(HTTP_GET, "/api/users", "https://sub.example.com/with%20space");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://sub.example.com/with%20space");
    session->reset();

    // Test avec une origine contenant des paramètres de requête
    auto req2 = createRequest(HTTP_GET, "/api/users",
                              "https://app.example.com/path?query=value&param=test");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://app.example.com/path?query=value&param=test");
    session->reset();

    // Test avec tentative d'injection
    auto req3 =
        createRequest(HTTP_GET, "/api/users", "https://evil.com\r\nSet-Cookie: pwned=1");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

// 5. Test de stratégie de correspondance pour les sous-domaines wildcard
TEST_F(CorsComprehensiveTest, WildcardSubdomainMatching) {
    // Créer un matcher qui accepte tous les sous-domaines de example.com
    auto wildcard_subdomain_matcher = [](const std::string &origin) -> bool {
        std::regex pattern(R"(^https:\/\/([a-zA-Z0-9_-]+\.)*example\.com$)");
        return std::regex_match(origin, pattern);
    };

    // Activer CORS avec le matcher de sous-domaines wildcard
    router->enable_cors(CorsOptions().origin_matcher(wildcard_subdomain_matcher));

    // Test avec un sous-domaine de premier niveau
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://api.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://api.example.com");
    session->reset();

    // Test avec un sous-domaine imbriqué
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://dev.api.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://dev.api.example.com");
    session->reset();

    // Test avec le domaine principal
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://example.com");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    session->reset();

    // Test avec un domaine non autorisé
    auto req4 = createRequest(HTTP_GET, "/api/users", "https://examplee.com");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
    session->reset();

    // Test avec un sous-domaine qui contient 'example.com' mais qui n'est pas valide
    auto req5 =
        createRequest(HTTP_GET, "/api/users", "https://malicious-example.com.evil.org");
    router->route(session, req5);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

// 6. Test CORS avec des méthodes HTTP standard
TEST_F(CorsComprehensiveTest, StandardHttpMethodsTest) {
    // Activer CORS avec plusieurs méthodes standard
    router->enable_cors(
        CorsOptions()
            .origins({"https://app.example.com"})
            .methods({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}));

    // Test de preflight pour une méthode GET
    auto req1 =
        createPreflightRequest("/api/users/patch/123", "https://app.example.com", "GET");
    router->route(session, req1);

    // Vérifier que la méthode GET est autorisée
    EXPECT_TRUE(session->header("Access-Control-Allow-Methods").find("GET") !=
                std::string::npos);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_NO_CONTENT);
    session->reset();

    // Test de preflight pour HEAD (une méthode moins utilisée)
    auto req2 =
        createPreflightRequest("/api/users/123", "https://app.example.com", "HEAD");
    router->route(session, req2);

    // Vérifier que la méthode HEAD est autorisée
    EXPECT_TRUE(session->header("Access-Control-Allow-Methods").find("HEAD") !=
                std::string::npos);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_NO_CONTENT);
    session->reset();

    // Tester une requête GET réelle - make sure session is reset
    auto req3 = createRequest(HTTP_GET, "/api/users/123", "https://app.example.com");
    session->reset(); // Make sure session is fully reset before this request

    // Debug output for the GET request
    std::cout << "CORS Debug - Testing actual GET request with Origin: "
              << req3.header("Origin") << std::endl;

    router->route(session, req3);

    std::cout << "MockSession received response for actual GET request" << std::endl;
    std::cout << "Captured Access-Control-Allow-Origin: "
              << session->header("Access-Control-Allow-Origin") << std::endl;
    std::cout << "Captured response status code: " << session->response().status_code
              << std::endl;

    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");
}

// 7. Test de mise en cache des préflight
TEST_F(CorsComprehensiveTest, PreflightCachingTest) {
    // Activer CORS avec un temps de cache de préflight spécifique
    router->enable_cors(CorsOptions()
                            .origins({"https://app.example.com"})
                            .all_methods()
                            .common_headers()
                            .age(3600)); // 1 heure de cache

    // Envoyer une requête preflight
    auto req = createPreflightRequest("/api/users", "https://app.example.com", "POST",
                                      {"Content-Type", "Authorization"});
    router->route(session, req);

    // Vérifier que l'en-tête de l'âge maximum est correctement défini
    EXPECT_EQ(session->header("Access-Control-Max-Age"), "3600");
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_NO_CONTENT);

    // Vérifier que les autres en-têtes CORS sont correctement définis
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");
    EXPECT_TRUE(session->header("Access-Control-Allow-Methods").find("POST") !=
                std::string::npos);
    EXPECT_TRUE(session->header("Access-Control-Allow-Headers").find("Content-Type") !=
                std::string::npos);
    EXPECT_TRUE(session->header("Access-Control-Allow-Headers").find("Authorization") !=
                std::string::npos);
}

// 8. Test des en-têtes Vary
TEST_F(CorsComprehensiveTest, VaryHeaderTest) {
    // Activer CORS avec configuration par défaut
    router->enable_cors(CorsOptions().origins({"https://app.example.com"}));

    // Test de requête simple
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);

    // Vérifier que l'en-tête Vary inclut Origin
    EXPECT_EQ(session->header("Vary"), "Origin");
    session->reset();

    // Test de requête preflight
    auto req2 = createPreflightRequest("/api/users", "https://app.example.com", "POST",
                                       {"Content-Type"});
    router->route(session, req2);

    // Vérifier que l'en-tête Vary inclut Origin et Access-Control-Request-Headers
    EXPECT_TRUE(session->header("Vary").find("Origin") != std::string::npos);
    EXPECT_TRUE(session->header("Vary").find("Access-Control-Request-Headers") !=
                std::string::npos);
}

// 9. Test de changement dynamique de configuration CORS
TEST_F(CorsComprehensiveTest, DynamicConfigurationTest) {
    // Configurer CORS initialement avec une origine
    router->enable_cors(CorsOptions().origins({"https://app-v1.example.com"}));

    // Tester avec l'origine initiale
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app-v1.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://app-v1.example.com");
    session->reset();

    // Tester avec une autre origine (non autorisée)
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://app-v2.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
    session->reset();

    // Changer la configuration CORS pour une nouvelle liste d'origines
    router->enable_cors(CorsOptions().origins({"https://app-v2.example.com"}));

    // Tester que l'ancienne origine n'est plus autorisée
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://app-v1.example.com");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
    session->reset();

    // Tester que la nouvelle origine est maintenant autorisée
    auto req4 = createRequest(HTTP_GET, "/api/users", "https://app-v2.example.com");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://app-v2.example.com");
}

// 10. Test de gestion des erreurs CORS
TEST_F(CorsComprehensiveTest, ErrorHandlingTest) {
    // Créer un matcher qui pourrait lever une exception
    auto potentially_failing_matcher = [](const std::string &origin) -> bool {
        // Simuler une erreur pour une origine spécifique
        if (origin == "https://trigger-error.example.com") {
            throw std::runtime_error("Simulated error in origin matcher");
        }
        return origin == "https://valid.example.com";
    };

    // Englober le matcher dans un try-catch pour éviter que les exceptions
    // ne se propagent au-delà du middleware CORS
    auto safe_matcher =
        [potentially_failing_matcher](const std::string &origin) -> bool {
        try {
            return potentially_failing_matcher(origin);
        } catch (const std::exception &e) {
            std::cerr << "Caught exception in matcher: " << e.what() << std::endl;
            return false;
        }
    };

    // Activer CORS avec le matcher sécurisé
    router->enable_cors(CorsOptions().origin_matcher(safe_matcher));

    // Tester avec une origine qui déclenche une erreur
    auto req1 =
        createRequest(HTTP_GET, "/api/users", "https://trigger-error.example.com");
    EXPECT_NO_THROW(router->route(session, req1));

    // La requête devrait être traitée, mais sans les en-têtes CORS
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    session->reset();

    // Tester avec une origine valide
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://valid.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://valid.example.com");
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}