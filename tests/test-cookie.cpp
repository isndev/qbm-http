#include <gtest/gtest.h>
#include "../http.h"

using namespace qb::http;

// Helper function to get a future time point
std::chrono::system_clock::time_point getFutureTime(int seconds_from_now) {
    return std::chrono::system_clock::now() + std::chrono::seconds(seconds_from_now);
}

//////////////////////////////////////////////////
// Cookie Class Tests
//////////////////////////////////////////////////

class CookieTest : public ::testing::Test {
protected:
    void SetUp() override {
    }
};

TEST_F(CookieTest, BasicConstructionAndGetters) {
    Cookie cookie("name", "value");

    EXPECT_EQ("name", cookie.name());
    EXPECT_EQ("value", cookie.value());
    EXPECT_EQ("/", cookie.path()); // Default path is "/"
    EXPECT_EQ("", cookie.domain()); // Default domain is empty
    EXPECT_FALSE(cookie.secure()); // Default secure is false
    EXPECT_FALSE(cookie.http_only()); // Default http_only is false
    EXPECT_FALSE(cookie.same_site().has_value()); // Default same_site is not set
}

TEST_F(CookieTest, Attributes) {
    Cookie cookie("test", "value");

    // Test fluent interface for setting attributes
    cookie.value("new_value")
            .path("/test")
            .domain("example.com")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax);

    EXPECT_EQ("new_value", cookie.value());
    EXPECT_EQ("/test", cookie.path());
    EXPECT_EQ("example.com", cookie.domain());
    EXPECT_TRUE(cookie.secure());
    EXPECT_TRUE(cookie.http_only());
    EXPECT_TRUE(cookie.same_site().has_value());
    EXPECT_EQ(SameSite::Lax, cookie.same_site().value());
}

TEST_F(CookieTest, Expiration) {
    Cookie cookie("test", "value");

    // Initially, no expiration
    EXPECT_FALSE(cookie.expires().has_value());
    EXPECT_FALSE(cookie.max_age().has_value());

    // Set expiration using time point
    auto future_time = getFutureTime(3600); // 1 hour from now
    cookie.expires(future_time);
    EXPECT_TRUE(cookie.expires().has_value());

    // Set max-age
    cookie.max_age(1800); // 30 minutes
    EXPECT_TRUE(cookie.max_age().has_value());
    EXPECT_EQ(1800, cookie.max_age().value());

    // Test expires_in helper
    Cookie another_cookie("test2", "value2");
    another_cookie.expires_in(7200); // 2 hours
    EXPECT_TRUE(another_cookie.expires().has_value());
}

TEST_F(CookieTest, ToHeader) {
    Cookie cookie("test", "value");

    // Basic cookie
    EXPECT_EQ("test=value; Path=/", cookie.to_header());

    // Add domain
    cookie.domain("example.com");
    EXPECT_EQ("test=value; Domain=example.com; Path=/", cookie.to_header());

    // Add security flags
    cookie.secure(true).http_only(true);
    EXPECT_EQ("test=value; Domain=example.com; Path=/; Secure; HttpOnly",
              cookie.to_header());

    // Add SameSite
    cookie.same_site(SameSite::Strict);
    EXPECT_EQ("test=value; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict",
              cookie.to_header());

    // Add Max-Age
    cookie.max_age(3600);
    EXPECT_EQ("test=value; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict",
              cookie.to_header());

    // Test different SameSite values
    cookie.same_site(SameSite::Lax);
    EXPECT_EQ("test=value; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax",
              cookie.to_header());

    cookie.same_site(SameSite::None);
    EXPECT_EQ("test=value; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None",
              cookie.to_header());
}

// Test spécifique pour SameSite::NOT_SET
TEST_F(CookieTest, SameSiteNotSet) {
    Cookie cookie("test", "value");

    // Par défaut, same_site ne devrait pas être défini
    EXPECT_FALSE(cookie.same_site().has_value());

    // Définir puis réinitialiser
    cookie.same_site(SameSite::Lax);
    EXPECT_TRUE(cookie.same_site().has_value());
    cookie.same_site(SameSite::NOT_SET);
    EXPECT_FALSE(cookie.same_site().has_value());

    // Vérifier que l'attribut n'apparaît pas dans l'en-tête
    EXPECT_EQ("test=value; Path=/", cookie.to_header());
}

// Test pour vérifier le comportement avec des caractères spéciaux
TEST_F(CookieTest, SpecialCharacters) {
    Cookie cookie("test", "value with spaces and !@#$%^&*()");

    std::string header = cookie.to_header();
    auto result = parse_set_cookie(header);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ("value with spaces and !@#$%^&*()", result->value());
}

// Test pour vérifier la priorité entre Max-Age et Expires
TEST_F(CookieTest, MaxAgeAndExpires) {
    Cookie cookie("test", "value");

    // Définir une expiration dans le passé
    auto past = std::chrono::system_clock::now() - std::chrono::hours(24);
    cookie.expires(past);

    // Mais définir max-age dans le futur
    cookie.max_age(3600);

    // Les deux attributs doivent apparaître dans l'en-tête
    std::string header = cookie.to_header();
    EXPECT_TRUE(header.find("Max-Age=3600") != std::string::npos);
    EXPECT_TRUE(header.find("Expires=") != std::string::npos);
}

// Test pour vérifier SameSite=None avec Secure (bonne pratique)
TEST_F(CookieTest, SameSiteNoneRequiresSecure) {
    Cookie cookie("test", "value");
    cookie.same_site(SameSite::None);

    // Bonnes pratiques: SameSite=None devrait toujours avoir Secure=true
    cookie.secure(true);

    std::string header = cookie.to_header();
    EXPECT_TRUE(header.find("SameSite=None") != std::string::npos);
    EXPECT_TRUE(header.find("Secure") != std::string::npos);
}

// Test pour les valeurs vides
TEST_F(CookieTest, EmptyValues) {
    Cookie cookie("test", "");
    EXPECT_EQ("", cookie.value());

    std::string header = cookie.to_header();
    EXPECT_EQ("test=; Path=/", header);

    auto result = parse_set_cookie(header);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ("", result->value());
}

// Test pour les domaines avec point initial
TEST_F(CookieTest, DomainWithLeadingDot) {
    Cookie cookie("test", "value");
    cookie.domain(".example.com");

    // Vérifier que le domaine est bien enregistré
    EXPECT_EQ(".example.com", cookie.domain());

    // Vérifier que le domaine est correctement inclus dans l'en-tête
    std::string header = cookie.to_header();
    EXPECT_TRUE(header.find("Domain=.example.com") != std::string::npos);
}

// Test pour la méthode serialize()
TEST_F(CookieTest, Serialize) {
    Cookie cookie("test", "value");

    // serialize() ne doit retourner que name=value, sans les attributs
    EXPECT_EQ("test=value", cookie.serialize());

    // Avec des caractères spéciaux
    Cookie cookie2("test2", "value with spaces");
    EXPECT_EQ("test2=value with spaces", cookie2.serialize());
}

// Test pour les limites de taille
TEST_F(CookieTest, SizeLimits) {
    // Créer un cookie avec un nom à la limite
    std::string long_name(1024, 'a'); // COOKIE_NAME_MAX = 1024
    Cookie cookie(long_name, "value");
    EXPECT_EQ(long_name, cookie.name());

    // Valeur longue mais dans les limites
    std::string long_value(1024, 'b'); // Moins que COOKIE_VALUE_MAX
    cookie.value(long_value);
    EXPECT_EQ(long_value, cookie.value());

    // Le cookie devrait être correctement formé
    std::string header = cookie.to_header();
    EXPECT_TRUE(header.find(long_name + "=" + long_value) == 0);
}

//////////////////////////////////////////////////
// Cookie Parsing Tests
//////////////////////////////////////////////////

TEST_F(CookieTest, ParseSimpleCookies) {
    // Basic cookie
    {
        auto result = parse_set_cookie("test=value; Path=/; Domain=example.com");
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ("test", result->name());
        EXPECT_EQ("value", result->value());
        EXPECT_EQ("/", result->path());
        EXPECT_EQ("example.com", result->domain());
    }

    // Cookie with SameSite
    {
        auto result = parse_set_cookie("test=value; SameSite=Lax");
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ("test", result->name());
        EXPECT_EQ("value", result->value());
        ASSERT_TRUE(result->same_site().has_value());
        EXPECT_EQ(SameSite::Lax, result->same_site().value());
    }

    // Invalid cookie
    {
        auto result = parse_set_cookie("");
        EXPECT_FALSE(result.has_value());
    }

    // Quoted values
    {
        auto result = parse_set_cookie("test=\"quoted value\"; Path=/");
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ("test", result->name());
        EXPECT_EQ("quoted value", result->value());
    }

    // Empty cookie string
    {
        auto cookies = parse_cookies(std::string(""), false);
        EXPECT_EQ(0, cookies.size());
    }
}

TEST_F(CookieTest, ParseMultipleCookies) {
    // Single cookie
    {
        auto cookies = parse_cookies(std::string("name=value"), false);
        ASSERT_EQ(1, cookies.size());
        EXPECT_EQ("value", cookies["name"]);
    }

    // Multiple cookies
    {
        auto cookies = parse_cookies(std::string("name1=value1; name2=value2; name3=value3"), false);
        ASSERT_EQ(3, cookies.size());
        EXPECT_EQ("value1", cookies["name1"]);
        EXPECT_EQ("value2", cookies["name2"]);
        EXPECT_EQ("value3", cookies["name3"]);
    }

    // Quoted values
    {
        auto cookies = parse_cookies(std::string("name=\"quoted value\"; another=123"), false);
        ASSERT_EQ(2, cookies.size());
        EXPECT_EQ("quoted value", cookies["name"]);
        EXPECT_EQ("123", cookies["another"]);
    }
}

//////////////////////////////////////////////////
// CookieJar Tests
//////////////////////////////////////////////////

class CookieJarTest : public ::testing::Test {
protected:
    CookieJar jar;

    void SetUp() override {
        // Initialize with some cookies
        jar.add("test1", "value1");
        jar.add("test2", "value2");
    }
};

TEST_F(CookieJarTest, AddAndRetrieve) {
    EXPECT_EQ(2, jar.size());
    EXPECT_TRUE(jar.has("test1"));
    EXPECT_TRUE(jar.has("test2"));

    const Cookie *cookie1 = jar.get("test1");
    ASSERT_NE(nullptr, cookie1);
    EXPECT_EQ("test1", cookie1->name());
    EXPECT_EQ("value1", cookie1->value());

    const Cookie *cookie2 = jar.get("test2");
    ASSERT_NE(nullptr, cookie2);
    EXPECT_EQ("test2", cookie2->name());
    EXPECT_EQ("value2", cookie2->value());

    // Test case insensitivity
    EXPECT_TRUE(jar.has("TEST1"));
    const Cookie *cookie_case = jar.get("TEST1");
    ASSERT_NE(nullptr, cookie_case);
    EXPECT_EQ("test1", cookie_case->name()); // Original name is preserved

    // Non-existent cookie
    EXPECT_FALSE(jar.has("nonexistent"));
    EXPECT_EQ(nullptr, jar.get("nonexistent"));
}

TEST_F(CookieJarTest, ModifyCookies) {
    // Add a new cookie
    jar.add("test3", "value3");
    EXPECT_EQ(3, jar.size());
    EXPECT_TRUE(jar.has("test3"));

    // Remove a cookie
    EXPECT_TRUE(jar.remove("test2"));
    EXPECT_EQ(2, jar.size());
    EXPECT_FALSE(jar.has("test2"));

    // Try to remove a non-existent cookie
    EXPECT_FALSE(jar.remove("nonexistent"));

    // Modify a cookie through the returned pointer
    Cookie *cookie1 = jar.get("test1");
    ASSERT_NE(nullptr, cookie1);
    cookie1->value("modified_value");

    // Verify the change persisted
    const Cookie *cookie1_again = jar.get("test1");
    EXPECT_EQ("modified_value", cookie1_again->value());

    // Replace a cookie
    Cookie new_cookie("test1", "replaced_value");
    jar.add(new_cookie);
    EXPECT_EQ(2, jar.size()); // Size shouldn't change
    EXPECT_EQ("replaced_value", jar.get("test1")->value());

    // Clear all cookies
    jar.clear();
    EXPECT_EQ(0, jar.size());
    EXPECT_TRUE(jar.empty());
}

//////////////////////////////////////////////////
// Integration Tests with HTTP Messages
//////////////////////////////////////////////////

TEST(CookieIntegration, RequestParsing) {
    // Create a request with a Cookie header
    Request request;
    request.add_header("Cookie", "name1=value1; name2=value2");

    // Parse the cookies
    request.parse_cookie_header();

    // Verify cookies were parsed
    EXPECT_TRUE(request.has_cookie("name1"));
    EXPECT_TRUE(request.has_cookie("name2"));
    EXPECT_EQ("value1", request.cookie_value("name1"));
    EXPECT_EQ("value2", request.cookie_value("name2"));

    // Test default value for non-existent cookie
    EXPECT_EQ("default", request.cookie_value("nonexistent", "default"));

    // Test case insensitivity
    EXPECT_TRUE(request.has_cookie("NAME1"));
    EXPECT_EQ("value1", request.cookie_value("NAME1"));
}

TEST(CookieIntegration, ResponseCookies) {
    Response response;

    // Add a cookie
    response.add_cookie("test1", "value1");
    EXPECT_TRUE(response.has_cookie("test1"));
    EXPECT_TRUE(response.has_header("Set-Cookie"));

    // Add another cookie
    auto &cookie = response.add_cookie("test2", "value2");
    cookie.domain("example.com").secure(true).http_only(true);

    // Verify we have two cookies
    EXPECT_EQ(2, response.cookies().size());

    // Verify cookie objects
    auto cookie1 = response.cookie("test1");
    ASSERT_NE(nullptr, cookie1);
    EXPECT_EQ("value1", cookie1->value());

    auto cookie2 = response.cookie("test2");
    ASSERT_NE(nullptr, cookie2);
    EXPECT_EQ("value2", cookie2->value());
    EXPECT_EQ("example.com", cookie2->domain());
    EXPECT_TRUE(cookie2->secure());
    EXPECT_TRUE(cookie2->http_only());

    // Modify and update
    cookie2->value("modified");
    response.update_cookie_header("test2");

    // Verify the modification
    cookie2 = response.cookie("test2");
    EXPECT_EQ("modified", cookie2->value());

    // Check for header
    bool found_header = false;
    for (const auto &header: response.headers()["Set-Cookie"]) {
        if (header.find("test2=modified") == 0) {
            found_header = true;
            break;
        }
    }
    EXPECT_TRUE(found_header);
}

TEST(CookieIntegration, ResponseRemoveCookie) {
    Response response;

    // Add a cookie
    response.add_cookie("test1", "value1");

    // Remove it
    response.remove_cookie("test1");

    // Get the cookie - it should exist but be expired
    auto cookie = response.cookie("test1");
    ASSERT_NE(nullptr, cookie);
    EXPECT_EQ("", cookie->value());
    EXPECT_TRUE(cookie->max_age().has_value());
    EXPECT_EQ(0, cookie->max_age().value());
}

// Test pour update_cookie_headers()
TEST(CookieIntegration, UpdateAllCookieHeaders) {
    Response response;

    // Ajouter plusieurs cookies
    response.add_cookie("test1", "value1");
    response.add_cookie("test2", "value2");

    // Modifier directement sans mettre à jour les en-têtes
    Cookie *cookie = response.cookie("test1");
    cookie->value("modified");

    // L'en-tête ne devrait pas être mis à jour
    bool found_modified = false;
    for (const auto &header: response.headers()["Set-Cookie"]) {
        if (header.find("test1=modified") == 0) {
            found_modified = true;
            break;
        }
    }
    EXPECT_FALSE(found_modified);

    // Mettre à jour tous les en-têtes
    response.update_cookie_headers();

    // Maintenant l'en-tête devrait être mis à jour
    found_modified = false;
    for (const auto &header: response.headers()["Set-Cookie"]) {
        if (header.find("test1=modified") == 0) {
            found_modified = true;
            break;
        }
    }
    EXPECT_TRUE(found_modified);
}

// Test pour remove_cookie avec domaine et chemin spécifiques
TEST(CookieIntegration, RemoveCookieWithDomainAndPath) {
    Response response;

    // Ajouter un cookie avec domaine et chemin
    auto &cookie = response.add_cookie("test", "value");
    cookie.domain("example.com").path("/admin");

    // Supprimer avec le même domaine et chemin
    response.remove_cookie("test", "example.com", "/admin");

    // Vérifier que le cookie a été correctement supprimé/expiré
    auto removed = response.cookie("test");
    ASSERT_NE(nullptr, removed);
    EXPECT_EQ("", removed->value());
    EXPECT_EQ("example.com", removed->domain());
    EXPECT_EQ("/admin", removed->path());
    EXPECT_TRUE(removed->max_age().has_value());
    EXPECT_EQ(0, removed->max_age().value());
}

//////////////////////////////////////////////////
// Max-Age Parsing Tests (std::from_chars performance fix)
//////////////////////////////////////////////////

TEST_F(CookieTest, MaxAgeParsingValidValues) {
    // Test valid positive Max-Age values
    {
        auto result = parse_set_cookie("test=value; Max-Age=3600");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(3600, result->max_age().value());
    }

    // Test Max-Age = 0 (delete cookie)
    {
        auto result = parse_set_cookie("test=value; Max-Age=0");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(0, result->max_age().value());
    }

    // Test large Max-Age value
    {
        auto result = parse_set_cookie("test=value; Max-Age=31536000"); // 1 year
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(31536000, result->max_age().value());
    }

    // Test negative Max-Age (should be parsed but treated as delete)
    {
        auto result = parse_set_cookie("test=value; Max-Age=-1");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(-1, result->max_age().value());
    }
}

TEST_F(CookieTest, MaxAgeParsingInvalidValues) {
    // Test invalid Max-Age (non-numeric) - should be ignored
    {
        auto result = parse_set_cookie("test=value; Max-Age=invalid");
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->max_age().has_value());
    }

    // Test empty Max-Age - should be ignored
    {
        auto result = parse_set_cookie("test=value; Max-Age=");
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->max_age().has_value());
    }

    // Test Max-Age with trailing garbage - should be ignored
    {
        auto result = parse_set_cookie("test=value; Max-Age=123abc");
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->max_age().has_value());
    }

    // Test Max-Age with leading whitespace in value
    {
        auto result = parse_set_cookie("test=value; Max-Age= 456");
        ASSERT_TRUE(result.has_value());
        // Note: Some implementations of std::from_chars may skip leading whitespace
        // The important thing is that the cookie is valid and max_age is either
        // set (if parsed) or not set (if parsing failed)
        // Either behavior is acceptable for this edge case
        if (result->max_age().has_value()) {
            EXPECT_EQ(456, result->max_age().value());
        }
        // If not set, that's also acceptable
    }
}

TEST_F(CookieTest, MaxAgeParsingEdgeCases) {
    // Test Max-Age with very large number (near int limit)
    {
        auto result = parse_set_cookie("test=value; Max-Age=2147483647"); // INT_MAX
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(2147483647, result->max_age().value());
    }

    // Test Max-Age at int min
    {
        auto result = parse_set_cookie("test=value; Max-Age=-2147483648"); // INT_MIN
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(-2147483648, result->max_age().value());
    }

    // Test Max-Age combined with Expires (both should be present)
    {
        auto result = parse_set_cookie("test=value; Max-Age=3600; Expires=Wed, 21 Oct 2025 07:28:00 GMT");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(3600, result->max_age().value());
        EXPECT_TRUE(result->expires().has_value());
    }
}

TEST_F(CookieTest, MaxAgeCaseInsensitive) {
    // Test case variations of Max-Age (should all work)
    {
        auto result = parse_set_cookie("test=value; max-age=3600");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(3600, result->max_age().value());
    }

    {
        auto result = parse_set_cookie("test=value; MAX-AGE=3600");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(3600, result->max_age().value());
    }

    {
        auto result = parse_set_cookie("test=value; Max-age=3600");
        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(result->max_age().has_value());
        EXPECT_EQ(3600, result->max_age().value());
    }
}

//////////////////////////////////////////////////
// Cookie::to_header() Optimization Tests
//////////////////////////////////////////////////

TEST_F(CookieTest, ToHeaderOptimizationBasic) {
    Cookie cookie("test", "value");

    std::string header = cookie.to_header();

    // Basic format verification
    EXPECT_EQ("test=value; Path=/", header);
}

TEST_F(CookieTest, ToHeaderOptimizationWithAllAttributes) {
    Cookie cookie("session", "abc123");
    cookie.domain(".example.com")
          .path("/api")
          .max_age(7200)
          .secure(true)
          .http_only(true)
          .same_site(SameSite::Strict);

    std::string header = cookie.to_header();

    // Verify all attributes are present
    EXPECT_NE(header.find("session=abc123"), std::string::npos);
    EXPECT_NE(header.find("Domain=.example.com"), std::string::npos);
    EXPECT_NE(header.find("Path=/api"), std::string::npos);
    EXPECT_NE(header.find("Max-Age=7200"), std::string::npos);
    EXPECT_NE(header.find("Secure"), std::string::npos);
    EXPECT_NE(header.find("HttpOnly"), std::string::npos);
    EXPECT_NE(header.find("SameSite=Strict"), std::string::npos);

    // Verify format starts with name=value
    EXPECT_EQ(header.find("session="), 0); // Starts with session=
    EXPECT_NE(header.find("; Max-Age="), std::string::npos); // Has semicolon before Max-Age
}

TEST_F(CookieTest, ToHeaderOptimizationLargeCookie) {
    // Test with large name and value (common scenario)
    std::string large_name(256, 'n');
    std::string large_value(4096, 'v');

    Cookie cookie(large_name, large_value);
    cookie.domain(".subdomain.example.com")
          .path("/very/long/path/segment")
          .max_age(86400);

    std::string header = cookie.to_header();

    // Verify the cookie is correctly formatted even with large content
    EXPECT_NE(header.find(large_name + "=" + large_value), std::string::npos);
    EXPECT_NE(header.find("Domain=.subdomain.example.com"), std::string::npos);
    EXPECT_NE(header.find("Path=/very/long/path/segment"), std::string::npos);
    EXPECT_NE(header.find("Max-Age=86400"), std::string::npos);

    // Verify no buffer overflow or truncation issues
    EXPECT_EQ(header.substr(0, large_name.length()), large_name);
}

TEST_F(CookieTest, ToHeaderOptimizationNoAttributes) {
    // Minimal cookie with only name and value
    Cookie cookie("minimal", "data");

    std::string header = cookie.to_header();

    // Should only have name=value and default Path=/
    EXPECT_EQ("minimal=data; Path=/", header);
}

TEST_F(CookieTest, ToHeaderOptimizationOnlyExpires) {
    Cookie cookie("expiring", "soon");
    auto future = std::chrono::system_clock::now() + std::chrono::hours(24);
    cookie.expires(future);

    std::string header = cookie.to_header();

    // Should include Expires
    EXPECT_NE(header.find("Expires="), std::string::npos);
    EXPECT_NE(header.find("expiring=soon"), std::string::npos);
}

TEST_F(CookieTest, ToHeaderOptimizationOnlyMaxAge) {
    Cookie cookie("temp", "data");
    cookie.max_age(1800); // 30 minutes

    std::string header = cookie.to_header();

    EXPECT_EQ("temp=data; Max-Age=1800; Path=/", header);
}

TEST_F(CookieTest, ToHeaderOptimizationSameSiteVariations) {
    // Test SameSite=None
    {
        Cookie cookie("s1", "v1");
        cookie.same_site(SameSite::None);
        EXPECT_EQ("s1=v1; Path=/; SameSite=None", cookie.to_header());
    }

    // Test SameSite=Lax
    {
        Cookie cookie("s2", "v2");
        cookie.same_site(SameSite::Lax);
        EXPECT_EQ("s2=v2; Path=/; SameSite=Lax", cookie.to_header());
    }

    // Test SameSite=Strict
    {
        Cookie cookie("s3", "v3");
        cookie.same_site(SameSite::Strict);
        EXPECT_EQ("s3=v3; Path=/; SameSite=Strict", cookie.to_header());
    }
}

TEST_F(CookieTest, ToHeaderOptimizationAttributeOrdering) {
    // Verify consistent attribute ordering
    Cookie cookie("ordered", "test");
    cookie.max_age(3600)
          .domain("example.com")
          .path("/secure")
          .secure(true)
          .http_only(true)
          .same_site(SameSite::Lax);

    std::string header = cookie.to_header();

    // Expected order: name=value; Max-Age; Domain; Path; Secure; HttpOnly; SameSite
    size_t pos_max_age = header.find("Max-Age");
    size_t pos_domain = header.find("Domain");
    size_t pos_path = header.find("Path");
    size_t pos_secure = header.find("Secure");
    size_t pos_http_only = header.find("HttpOnly");
    size_t pos_same_site = header.find("SameSite");

    // Verify ordering
    EXPECT_LT(pos_max_age, pos_domain);
    EXPECT_LT(pos_domain, pos_path);
    EXPECT_LT(pos_path, pos_secure);
    EXPECT_LT(pos_secure, pos_http_only);
    EXPECT_LT(pos_http_only, pos_same_site);
}

TEST_F(CookieTest, ToHeaderOptimizationWithEmptyPath) {
    // Test that empty path is handled correctly
    Cookie cookie("empty_path", "value");
    cookie.path("");

    std::string header = cookie.to_header();

    // Empty path should not be included in header (implementation skips empty)
    // Path defaults to "/" in constructor, so setting it to empty is different
    EXPECT_EQ(header.find("Path="), std::string::npos);
}

TEST_F(CookieTest, ToHeaderOptimizationSpecialCharactersInValue) {
    // Test special characters that might need escaping (implementation dependent)
    Cookie cookie("special", "value with spaces!@#$%");

    std::string header = cookie.to_header();

    // Verify basic structure is maintained
    EXPECT_EQ(header.substr(0, 8), "special=");
    EXPECT_NE(header.find("Path=/"), std::string::npos);
}

//////////////////////////////////////////////////
// Round-trip Tests (parse -> to_header -> parse)
//////////////////////////////////////////////////

TEST_F(CookieTest, MaxAgeRoundTrip) {
    // Set-Cookie -> parse -> to_header -> parse
    std::string original = "session=abc123; Max-Age=3600; Path=/; Secure";

    auto parsed = parse_set_cookie(original);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(3600, parsed->max_age().value());

    // Serialize and re-parse
    std::string serialized = parsed->to_header();
    auto reparsed = parse_set_cookie(serialized);

    ASSERT_TRUE(reparsed.has_value());
    EXPECT_EQ("session", reparsed->name());
    EXPECT_EQ("abc123", reparsed->value());
    // Max-Age should survive round-trip
    EXPECT_TRUE(reparsed->max_age().has_value());
    EXPECT_EQ(3600, reparsed->max_age().value());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
