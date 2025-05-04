# `qbm-http`: Cookie Management

(`qbm/http/cookie.h`, `qbm/http/cookie.cpp`)

The HTTP module provides comprehensive support for managing HTTP cookies according to RFC 6265.

## `qb::http::Cookie` Class

Represents a single HTTP cookie with all its attributes.

*   **Constructor:** `Cookie(name_string, value_string)`
*   **Attributes (Setters return `Cookie&` for chaining):**
    *   `name()` / `value()`: Getters.
    *   `value(string)`: Set value.
    *   `path(string)`: Set Path attribute (default: "/").
    *   `domain(string)`: Set Domain attribute.
    *   `expires(time_point)`: Set Expires attribute using `std::chrono::system_clock::time_point`.
    *   `expires_in(seconds)`: Convenience to set Expires relative to now.
    *   `max_age(seconds)`: Set Max-Age attribute.
    *   `secure(bool)`: Set Secure flag.
    *   `http_only(bool)`: Set HttpOnly flag.
    *   `same_site(qb::http::SameSite)`: Set SameSite attribute (`None`, `Lax`, `Strict`). Use `SameSite::NOT_SET` or omit to not include the attribute.
*   **Serialization:**
    *   `to_header()`: Generates the full `Set-Cookie` header string value.
    *   `serialize()`: Generates only the `name=value` part (for `Cookie` request header).

```cpp
#include <qb/http.h>
#include <chrono>

// Create a session cookie
qb::http::Cookie session_cookie("sessionID", "abc123xyz");
session_cookie.path("/")
              .http_only(true)
              .secure(true) // Important for SameSite=None
              .same_site(qb::http::SameSite::Lax);

// Create a persistent tracking cookie
qb::http::Cookie tracking_cookie("tracker", "trk_987");
tracking_cookie.domain(".example.com")
                 .path("/")
                 .max_age(30 * 24 * 3600); // 30 days

// Format for Set-Cookie header
std::string header_value = session_cookie.to_header();
// -> "sessionID=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Lax"
```

## `qb::http::CookieJar` Class

Manages a collection of `Cookie` objects, typically representing the cookies associated with a request or response.

*   **Storage:** Uses `qb::icase_unordered_map<Cookie>` internally (case-insensitive name lookup).
*   **Adding Cookies:**
    *   `add(const Cookie&)` / `add(Cookie&&)`: Adds or replaces a cookie object.
    *   `add(name_string, value_string)`: Creates and adds a basic cookie, returning a reference.
*   **Accessing Cookies:**
    *   `get(name_string)`: Returns `const Cookie*` or `Cookie*` (nullptr if not found).
    *   `has(name_string)`: Checks existence.
    *   `all()`: Returns `const qb::icase_unordered_map<Cookie>&`.
*   **Removing Cookies:** `remove(name_string)`.
*   **Other:** `clear()`, `size()`, `empty()`.

## Parsing Cookies

### From Request (`Cookie` Header)

*   **Function:** `qb::http::parse_cookies(header_string_or_view, false)`.
*   **Input:** The value of the `Cookie` header (e.g., "name1=value1; name2=value2").
*   **Output:** `qb::icase_unordered_map<std::string>` mapping cookie names to values.
*   **Integration:** `qb::http::Request::parse_cookie_header()` performs this automatically and stores the result in its internal `CookieJar`. Access via `request.cookie("name")` or `request.cookie_value("name")`.

```cpp
// Assume req is a qb::http::Request object
req.add_header("Cookie", "user=alice; theme=dark");
req.parse_cookie_header();

std::string user = req.cookie_value("user"); // -> "alice"
const qb::http::Cookie* theme_cookie = req.cookie("theme");
if (theme_cookie) {
    std::cout << "Theme: " << theme_cookie->value(); // -> "dark"
}
```

### From Response (`Set-Cookie` Header)

*   **Function:** `qb::http::parse_set_cookie(header_string_or_view)`.
*   **Input:** The value of a *single* `Set-Cookie` header (e.g., "session=abc; Path=/; HttpOnly").
*   **Output:** `std::optional<qb::http::Cookie>` containing the parsed cookie and its attributes.
*   **Integration:** `qb::http::Response::parse_set_cookie_headers()` performs this automatically for all `Set-Cookie` headers and stores the results in its internal `CookieJar`. Access via `response.cookie("name")`.

```cpp
// Assume res is a qb::http::Response object
res.add_header("Set-Cookie", "user=bob; Max-Age=3600");
res.add_header("Set-Cookie", "pref=light; Path=/settings");
res.parse_set_cookie_headers();

const qb::http::Cookie* user_cookie = res.cookie("user");
if (user_cookie) {
    std::cout << "User max-age: " << user_cookie->max_age().value_or(0) << std::endl; // -> 3600
}

const qb::http::Cookie* pref_cookie = res.cookie("pref");
if (pref_cookie) {
    std::cout << "Pref path: " << pref_cookie->path() << std::endl; // -> "/settings"
}
```

## Setting Cookies in Responses

Use the methods on the `qb::http::Response` object:

```cpp
qb::http::Response response;

// Add a simple cookie
response.add_cookie("simple", "data");

// Add a cookie with attributes
auto& complex_cookie = response.add_cookie("complex", "more_data");
complex_cookie.path("/app")
              .secure(true)
              .http_only(true)
              .expires_in(7 * 24 * 3600); // Expires in 7 days

// Remove a cookie by setting an expired one
response.remove_cookie("old_cookie", ".example.com", "/");

// When the response is sent (e.g., via session << response),
// appropriate Set-Cookie headers will be generated.
```

*   `add_cookie` automatically adds the corresponding `Set-Cookie` header.
*   If you get a mutable `Cookie*` via `response.cookie("name")` and modify its attributes, you **must** call `response.update_cookie_header("name")` afterwards to update the `Set-Cookie` header in the response.
*   `response.update_cookie_headers()` updates all `Set-Cookie` headers based on the current state of the `CookieJar`.

**(See also:** `test-cookie.cpp`**)** 