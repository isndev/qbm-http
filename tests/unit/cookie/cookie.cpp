#include <gtest/gtest.h>
#include <chrono>
#include "../date.h" // qb::http::date::format_http_date (expiry ground-truth asserts)
#include "../http.h"

using namespace qb::http;

// Helper function to get a future time point
std::chrono::system_clock::time_point
getFutureTime(int seconds_from_now) {
    return std::chrono::system_clock::now() + std::chrono::seconds(seconds_from_now);
}

//////////////////////////////////////////////////
// Cookie Class Tests
//////////////////////////////////////////////////

class CookieTest : public ::testing::Test {
protected:
    void
    SetUp() override {}
};

TEST_F(CookieTest, BasicConstructionAndGetters) {
    Cookie cookie("name", "value");

    EXPECT_EQ("name", cookie.name());
    EXPECT_EQ("value", cookie.value());
    EXPECT_EQ("/", cookie.path());                // Default path is "/"
    EXPECT_EQ("", cookie.domain());               // Default domain is empty
    EXPECT_FALSE(cookie.secure());                // Default secure is false
    EXPECT_FALSE(cookie.http_only());             // Default http_only is false
    EXPECT_FALSE(cookie.same_site().has_value()); // Default same_site is not set
}

TEST_F(CookieTest, Attributes) {
    Cookie cookie("test", "value");

    // Test fluent interface for setting attributes
    cookie.value("new_value").path("/test").domain("example.com").secure(true).http_only(true).same_site(SameSite::Lax);

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

    // Set expiration using time point: expires(tp) stores the exact value, so
    // assert the computed time, not just that an optional became engaged.
    auto future_time = getFutureTime(3600); // 1 hour from now
    cookie.expires(future_time);
    ASSERT_TRUE(cookie.expires().has_value());
    EXPECT_EQ(cookie.expires().value(), future_time);

    // Set max-age
    cookie.max_age(std::chrono::seconds(1800)); // 30 minutes
    EXPECT_TRUE(cookie.max_age().has_value());
    EXPECT_EQ(1800, cookie.max_age().value());

    // expires_in(ttl) computes now()+ttl: assert the result lands in a tight
    // window around the expected instant (allow 5s of test-execution slack).
    const auto before = std::chrono::system_clock::now();
    Cookie     another_cookie("test2", "value2");
    another_cookie.expires_in(std::chrono::seconds(7200)); // 2 hours
    ASSERT_TRUE(another_cookie.expires().has_value());
    const auto expected_lo = before + std::chrono::seconds(7200);
    const auto expected_hi = std::chrono::system_clock::now() + std::chrono::seconds(7200);
    EXPECT_GE(another_cookie.expires().value(), expected_lo);
    EXPECT_LE(another_cookie.expires().value(), expected_hi);
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
    EXPECT_EQ("test=value; Domain=example.com; Path=/; Secure; HttpOnly", cookie.to_header());

    // Add SameSite
    cookie.same_site(SameSite::Strict);
    EXPECT_EQ("test=value; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict", cookie.to_header());

    // Add Max-Age
    cookie.max_age(std::chrono::seconds(3600));
    EXPECT_EQ("test=value; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict", cookie.to_header());

    // Test different SameSite values
    cookie.same_site(SameSite::Lax);
    EXPECT_EQ("test=value; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax", cookie.to_header());

    cookie.same_site(SameSite::None);
    EXPECT_EQ("test=value; Max-Age=3600; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None", cookie.to_header());
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
    auto        result = parse_set_cookie(header);

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
    cookie.max_age(std::chrono::seconds(3600));

    // Both attributes must appear, and the serialization is fully deterministic:
    // assert the exact ordered header (Expires precedes Max-Age precedes Path).
    std::string       header           = cookie.to_header();
    const std::string expected_expires = "Expires=" + qb::http::date::format_http_date(past);
    EXPECT_EQ(header, "test=value; " + expected_expires + "; Max-Age=3600; Path=/");
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
    Cookie      cookie(long_name, "value");
    EXPECT_EQ(long_name, cookie.name());

    // Valeur longue mais dans les limites
    std::string long_value(1024, 'b'); // Moins que COOKIE_VALUE_MAX
    cookie.value(long_value);
    EXPECT_EQ(long_value, cookie.value());

    // Le cookie devrait être correctement formé
    std::string header = cookie.to_header();
    EXPECT_TRUE(header.find(long_name + "=" + long_value) == 0);
}

TEST_F(CookieTest, ParseCookiesValueAtLimitSucceeds) {
    // A value of exactly COOKIE_VALUE_MAX - 1 bytes is accepted by the tokenizer
    // (the limit check rejects only on reaching COOKIE_VALUE_MAX).
    std::string at_limit_value(COOKIE_VALUE_MAX - 1, 'v');
    auto        cookies = parse_cookies(std::string("big=" + at_limit_value), false);
    ASSERT_EQ(cookies.size(), 1u);
    EXPECT_EQ(cookies["big"], at_limit_value);
}

TEST_F(CookieTest, ParseCookiesExactlyLimitValueIsAccepted) {
    // Ground truth (cookie.cpp:187): the guard is `length() >= COOKIE_VALUE_MAX`
    // checked BEFORE pushing, so the longest accepted value is exactly
    // COOKIE_VALUE_MAX bytes (the check passes for lengths 0..MAX-1, then the
    // MAX-th char is pushed). A value of exactly COOKIE_VALUE_MAX is therefore
    // ACCEPTED verbatim, not rejected. COOKIE_VALUE_MAX is the max stored length.
    std::string at_max_value(COOKIE_VALUE_MAX, 'v');
    auto        cookies = parse_cookies(std::string("big=" + at_max_value), false);
    ASSERT_EQ(cookies.size(), 1u);
    EXPECT_EQ(cookies["big"].size(), static_cast<std::size_t>(COOKIE_VALUE_MAX));
    EXPECT_EQ(cookies["big"], at_max_value);
}

TEST_F(CookieTest, ParseCookiesOverLimitValueIsRejected) {
    // The FIRST rejected length is COOKIE_VALUE_MAX + 1: on the (MAX+1)-th value
    // char the guard `length() >= COOKIE_VALUE_MAX` (cookie.cpp:187) trips and
    // throws, keeping memory bounded against a malicious oversized Cookie header.
    std::string over_limit_value(COOKIE_VALUE_MAX + 1, 'v');
    EXPECT_THROW((void) parse_cookies(std::string("big=" + over_limit_value), false), std::runtime_error);
}

TEST_F(CookieTest, ParseCookiesExactlyLimitNameIsAccepted) {
    // Same boundary semantics as the value guard (cookie.cpp:164): the check is
    // `length() >= COOKIE_NAME_MAX` before pushing, so a name of exactly
    // COOKIE_NAME_MAX bytes is the longest accepted, not a rejection.
    std::string at_max_name(COOKIE_NAME_MAX, 'n');
    auto        cookies = parse_cookies(std::string(at_max_name + "=v"), false);
    ASSERT_EQ(cookies.size(), 1u);
    EXPECT_EQ(cookies[at_max_name], "v");
}

TEST_F(CookieTest, ParseCookiesOverLimitNameIsRejected) {
    // The FIRST rejected name length is COOKIE_NAME_MAX + 1: the (MAX+1)-th name
    // char trips the guard `length() >= COOKIE_NAME_MAX` (cookie.cpp:164).
    std::string over_limit_name(COOKIE_NAME_MAX + 1, 'n');
    EXPECT_THROW((void) parse_cookies(std::string(over_limit_name + "=v"), false), std::runtime_error);
}

TEST_F(CookieTest, HostPrefixCookieNameIsPreservedAndRoundTrips) {
    // RFC 6265bis __Host-/__Secure- prefixes are part of the cookie name; the
    // parser carries them verbatim (no stripping, no enforcement here).
    auto result = parse_set_cookie("__Host-session=abc123; Path=/; Secure");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->name(), "__Host-session");
    EXPECT_EQ(result->value(), "abc123");
    EXPECT_EQ(result->path(), "/");
    EXPECT_TRUE(result->secure());

    // The prefix survives serialization byte-for-byte.
    EXPECT_EQ(result->to_header().substr(0, 22), "__Host-session=abc123;");
}

TEST_F(CookieTest, SecurePrefixCookieNameIsPreserved) {
    auto result = parse_set_cookie("__Secure-id=42; Secure; HttpOnly");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->name(), "__Secure-id");
    EXPECT_EQ(result->value(), "42");
    EXPECT_TRUE(result->secure());
    EXPECT_TRUE(result->http_only());
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

    // Quoted-pair escapes inside quoted values
    {
        auto cookies = parse_cookies(std::string(R"(name="a\"b\\c"; another=123)"), false);
        ASSERT_EQ(2, cookies.size());
        EXPECT_EQ("a\"b\\c", cookies["name"]);
        EXPECT_EQ("123", cookies["another"]);
    }
}

TEST_F(CookieTest, ParseCookiesRejectMalformedQuotedValues) {
    EXPECT_THROW((void) parse_cookies(std::string(R"(name="unterminated)"), false), std::runtime_error);
    EXPECT_THROW((void) parse_cookies(std::string(R"(name="value"junk; another=123)"), false), std::runtime_error);
    EXPECT_THROW((void) parse_cookies(std::string("name=\"bad\nvalue\""), false), std::runtime_error);
}

//////////////////////////////////////////////////
// CookieJar Tests
//////////////////////////////////////////////////

class CookieJarTest : public ::testing::Test {
protected:
    CookieJar jar;

    void
    SetUp() override {
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

TEST_F(CookieJarTest, AddByNameAndValuePreservesCookieName) {
    Cookie &cookie = jar.add("session_id", "abc123");

    EXPECT_EQ(cookie.name(), "session_id");
    EXPECT_EQ(cookie.value(), "abc123");

    const Cookie *stored_cookie = jar.get("session_id");
    ASSERT_NE(nullptr, stored_cookie);
    EXPECT_EQ(stored_cookie->name(), "session_id");
    EXPECT_EQ(stored_cookie->value(), "abc123");
}

TEST_F(CookieJarTest, AddByNameAndValueReplacesExistingCookie) {
    Cookie &cookie = jar.add("test1", "replacement");

    EXPECT_EQ(jar.size(), 2u);
    EXPECT_EQ(cookie.name(), "test1");
    EXPECT_EQ(cookie.value(), "replacement");
    ASSERT_NE(jar.get("test1"), nullptr);
    EXPECT_EQ(jar.get("test1")->value(), "replacement");
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
    EXPECT_EQ("default", request.cookie_value_or("nonexistent", "default"));

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
    for (const auto &header : response.headers()["Set-Cookie"]) {
        if (header.find("test2=modified") == 0) {
            found_header = true;
            break;
        }
    }
    EXPECT_TRUE(found_header);
}

TEST(CookieIntegration, ResponseReplacingCookieKeepsSetCookieHeadersInSync) {
    Response response;

    response.add_cookie("sid", "old");
    response.add_cookie("sid", "new");

    ASSERT_TRUE(response.has_header("Set-Cookie"));
    const auto &headers = response.headers().at("Set-Cookie");
    ASSERT_EQ(headers.size(), 1u);
    EXPECT_NE(headers.front().find("sid=new"), std::string::npos);
    EXPECT_EQ(headers.front().find("sid=old"), std::string::npos);
    ASSERT_NE(response.cookie("sid"), nullptr);
    EXPECT_EQ(response.cookie("sid")->value(), "new");
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
    for (const auto &header : response.headers()["Set-Cookie"]) {
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
    for (const auto &header : response.headers()["Set-Cookie"]) {
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

    // Test Max-Age with leading whitespace in value. parse_set_cookie applies
    // utility::trim_http_whitespace to the attribute value before from_chars
    // (cookie.cpp:323), so the leading space is stripped and "456" parses fully.
    // Pin the deterministic qb behavior rather than accept-either.
    {
        auto result = parse_set_cookie("test=value; Max-Age= 456");
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->max_age().has_value());
        EXPECT_EQ(456, result->max_age().value());
    }

    // Internal whitespace, however, leaves trailing bytes that from_chars cannot
    // consume (ptr != end), so the Max-Age is silently dropped.
    {
        auto result = parse_set_cookie("test=value; Max-Age=4 56");
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->max_age().has_value());
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
    cookie.domain(".example.com").path("/api").max_age(std::chrono::seconds(7200)).secure(true).http_only(true).same_site(SameSite::Strict);

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
    EXPECT_EQ(header.find("session="), 0);                   // Starts with session=
    EXPECT_NE(header.find("; Max-Age="), std::string::npos); // Has semicolon before Max-Age
}

TEST_F(CookieTest, ToHeaderOptimizationLargeCookie) {
    // Test with large name and value (common scenario)
    std::string large_name(256, 'n');
    std::string large_value(4096, 'v');

    Cookie cookie(large_name, large_value);
    cookie.domain(".subdomain.example.com").path("/very/long/path/segment").max_age(std::chrono::seconds(86400));

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
    auto   future = std::chrono::system_clock::now() + std::chrono::hours(24);
    cookie.expires(future);

    std::string header = cookie.to_header();

    // The Expires attribute must serialize the exact computed time_point via the
    // canonical RFC 1123 formatter, not merely "be present".
    const std::string expected_expires = "Expires=" + qb::http::date::format_http_date(future);
    EXPECT_NE(header.find(expected_expires), std::string::npos);
    EXPECT_NE(header.find("expiring=soon"), std::string::npos);
    // Exact full header for this single-attribute cookie.
    EXPECT_EQ(header, "expiring=soon; " + expected_expires + "; Path=/");
}

TEST_F(CookieTest, ToHeaderOptimizationOnlyMaxAge) {
    Cookie cookie("temp", "data");
    cookie.max_age(std::chrono::seconds(1800)); // 30 minutes

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
    cookie.max_age(std::chrono::seconds(3600)).domain("example.com").path("/secure").secure(true).http_only(true).same_site(SameSite::Lax);

    std::string header = cookie.to_header();

    // Expected order: name=value; Max-Age; Domain; Path; Secure; HttpOnly; SameSite
    size_t pos_max_age   = header.find("Max-Age");
    size_t pos_domain    = header.find("Domain");
    size_t pos_path      = header.find("Path");
    size_t pos_secure    = header.find("Secure");
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

TEST_F(CookieTest, ToHeaderRejectsSetCookieAttributeInjection) {
    EXPECT_THROW((void) Cookie("bad;name", "value").to_header(), std::runtime_error);
    EXPECT_THROW((void) Cookie("name", "value; HttpOnly").to_header(), std::runtime_error);

    Cookie bad_domain("name", "value");
    bad_domain.domain("example.com; Secure");
    EXPECT_THROW((void) bad_domain.to_header(), std::runtime_error);

    Cookie bad_path("name", "value");
    bad_path.path("/; Secure");
    EXPECT_THROW((void) bad_path.to_header(), std::runtime_error);
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
    auto        reparsed   = parse_set_cookie(serialized);

    ASSERT_TRUE(reparsed.has_value());
    EXPECT_EQ("session", reparsed->name());
    EXPECT_EQ("abc123", reparsed->value());
    // Max-Age should survive round-trip
    EXPECT_TRUE(reparsed->max_age().has_value());
    EXPECT_EQ(3600, reparsed->max_age().value());
}

//////////////////////////////////////////////////
// Coverage Wave-2: parse_cookies / parse_set_cookie edge branches
//////////////////////////////////////////////////

// parse_cookies with set_cookie_header=true exercises is_cookie_attribute's
// Set-Cookie attribute filtering (cookie.cpp:81-90). Known attributes (Path,
// Domain, Secure, ...) must be dropped, real name=value pairs kept.
TEST_F(CookieTest, ParseCookiesSetCookieHeaderFiltersKnownAttributes) {
    auto cookies = parse_cookies(std::string("sid=xyz; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"), true);
    // Only the real cookie pair survives; every attribute name is filtered.
    EXPECT_EQ(1u, cookies.size());
    ASSERT_TRUE(cookies.find("sid") != cookies.end());
    EXPECT_EQ("xyz", cookies["sid"]);
    EXPECT_TRUE(cookies.find("Path") == cookies.end());
    EXPECT_TRUE(cookies.find("Domain") == cookies.end());
    EXPECT_TRUE(cookies.find("Secure") == cookies.end());
    EXPECT_TRUE(cookies.find("SameSite") == cookies.end());
}

// is_cookie_attribute's legacy/empty branch (cookie.cpp:77-80): a name that
// begins with '$' (RFC 2109 legacy) is treated as an attribute and dropped.
TEST_F(CookieTest, ParseCookiesDropsDollarPrefixedLegacyAttributes) {
    // $Version / $Path are legacy attributes; "real" must survive in both modes.
    auto cookies = parse_cookies(std::string("$Version=1; real=ok; $Path=/"), true);
    EXPECT_TRUE(cookies.find("$Version") == cookies.end());
    EXPECT_TRUE(cookies.find("$Path") == cookies.end());
    ASSERT_TRUE(cookies.find("real") != cookies.end());
    EXPECT_EQ("ok", cookies["real"]);
}

// parse_cookies enforces the 16KB DoS guard (cookie.cpp:125-127).
TEST_F(CookieTest, ParseCookiesRejectsOver16KBHeader) {
    std::string huge = "a=" + std::string(16 * 1024 + 1, 'x');
    EXPECT_THROW((void) parse_cookies(huge, false), std::runtime_error);
}

// Separator (';'/',') encountered in NAME state with a buffered name but no '='
// emits an empty-value cookie (cookie.cpp:151-160). e.g. "flag; k=v".
TEST_F(CookieTest, ParseCookiesNameWithoutEqualsBeforeSeparatorYieldsEmptyValue) {
    auto cookies = parse_cookies(std::string("flag; k=v"), false);
    ASSERT_TRUE(cookies.find("flag") != cookies.end());
    EXPECT_EQ("", cookies["flag"]); // empty value emitted for the bare name
    ASSERT_TRUE(cookies.find("k") != cookies.end());
    EXPECT_EQ("v", cookies["k"]);
}

// In set_cookie_header mode, a bare attribute name before a separator is
// recognised and dropped rather than emitted (cookie.cpp:155 false branch).
TEST_F(CookieTest, ParseCookiesBareAttributeNameBeforeSeparatorIsDropped) {
    auto cookies = parse_cookies(std::string("Secure; real=v"), true);
    EXPECT_TRUE(cookies.find("Secure") == cookies.end());
    ASSERT_TRUE(cookies.find("real") != cookies.end());
    EXPECT_EQ("v", cookies["real"]);
}

// Quoted value exceeding COOKIE_VALUE_MAX via a plain quoted char throws
// (cookie.cpp:215-218).
TEST_F(CookieTest, ParseCookiesQuotedValueOverMaxPlainCharRejected) {
    // Open quote, then COOKIE_VALUE_MAX+1 plain chars => length check trips.
    std::string header = "big=\"" + std::string(COOKIE_VALUE_MAX + 1, 'a') + "\"";
    EXPECT_THROW((void) parse_cookies(header, false), std::runtime_error);
}

// Quoted value exceeding COOKIE_VALUE_MAX via an escaped char throws
// (cookie.cpp:194-197). Fill to the limit with plain chars, then an escape.
TEST_F(CookieTest, ParseCookiesQuotedValueOverMaxEscapedCharRejected) {
    // COOKIE_VALUE_MAX plain chars bring length to the limit, then "\\q" appends
    // an escaped char while at capacity => the escaped-branch length check trips.
    std::string header = "big=\"" + std::string(COOKIE_VALUE_MAX, 'a') + "\\q\"";
    EXPECT_THROW((void) parse_cookies(header, false), std::runtime_error);
}

// parse_set_cookie with no ';' separator: the whole header is the cookie-pair
// and the attribute string stays empty (cookie.cpp:280-283).
TEST_F(CookieTest, ParseSetCookieNoSemicolonWholeHeaderIsPair) {
    auto result = parse_set_cookie("only=pair");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ("only", result->name());
    EXPECT_EQ("pair", result->value());
    EXPECT_FALSE(result->secure());
    EXPECT_FALSE(result->same_site().has_value());
}

// parse_set_cookie returns nullopt when the cookie-pair has no '=' or an empty
// name (cookie.cpp:292-295).
TEST_F(CookieTest, ParseSetCookieInvalidPairReturnsNullopt) {
    EXPECT_FALSE(parse_set_cookie("novalue; Path=/").has_value());   // no '='
    EXPECT_FALSE(parse_set_cookie("=emptyname; Path=/").has_value()); // eq_pos == 0
}

// Quoted attribute value is unquoted (cookie.cpp:325-327): Path="/x" -> /x.
TEST_F(CookieTest, ParseSetCookieUnquotesAttributeValue) {
    auto result = parse_set_cookie("test=value; Path=\"/quoted/path\"; Domain=\"ex.com\"");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ("/quoted/path", result->path());
    EXPECT_EQ("ex.com", result->domain());
}

// parse_set_cookie SameSite=Strict and SameSite=None branches
// (cookie.cpp:360-366); the Lax branch is already covered elsewhere.
TEST_F(CookieTest, ParseSetCookieSameSiteStrictAndNone) {
    {
        auto result = parse_set_cookie("test=value; SameSite=Strict");
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->same_site().has_value());
        EXPECT_EQ(SameSite::Strict, result->same_site().value());
    }
    {
        auto result = parse_set_cookie("test=value; SameSite=None");
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->same_site().has_value());
        EXPECT_EQ(SameSite::None, result->same_site().value());
    }
}
