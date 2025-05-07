# `qbm-http`: Request & Response

These are the core classes for representing HTTP messages.

## `qb::http::Request` / `TRequest<String>`

(`qbm/http/request.h`, `qbm/http/message_base.h`)

Represents an HTTP request. It inherits from `MessageBase` (for common features like headers and body).

*   **Template:** `TRequest<String>` where `String` is `std::string` (default, mutable) or `std::string_view` (read-only).
*   **Key Members:**
    *   `method`: `qb::http::method` (enum like `HTTP_GET`, `HTTP_POST`).
    *   `_uri`: `qb::io::uri` object containing the full URI.
    *   `_headers`: `qb::http::headers_map` (case-insensitive map of `string` -> `vector<String>`).
    *   `body()`: Accessor for the `qb::http::Body` object.
    *   `_cookies`: `qb::http::CookieJar` (parsed from `Cookie` header).
*   **Accessing URI Parts:**
    *   `uri()`: Get the `qb::io::uri` object.
    *   `path()`: Get the path part (e.g., `/users/123`).
    *   `query("key")`: Get the value of a query parameter.
    *   `queries()`: Get the map of all query parameters.
*   **Accessing Headers:**
    *   `header("Header-Name")`: Get the first value of a header (case-insensitive).
    *   `headers()`: Get the underlying map for full access.
    *   `has_header("Header-Name")`: Check for header existence.
    *   `add_header("Name", "Value")`, `set_header("Name", "Value")`, `remove_header("Name")`.
*   **Accessing Body:**
    *   `body()`: Get the `Body` object.
    *   `body().as<T>()`: Convert body to `std::string`, `std::string_view`, `qb::json`, `qb::http::Multipart`, etc.
    *   `body().raw()`: Access the underlying `qb::allocator::pipe<char>`.
*   **Accessing Cookies:**
    *   `parse_cookie_header()`: Parses the `Cookie` header (called automatically by server protocol).
    *   `cookie("name")`: Get `const Cookie*`.
    *   `cookie_value("name")`: Get cookie value string.
    *   `has_cookie("name")`.
    *   `cookies()`: Get the `CookieJar`.

## `qb::http::Response` / `TResponse<String>`

(`qbm/http/response.h`, `qbm/http/message_base.h`)

Represents an HTTP response. Inherits from `MessageBase` (for common features like headers and body).

*   **Template:** `TResponse<String>` where `String` is `std::string` (default) or `std::string_view`.
*   **Key Members:**
    *   `status_code`: `qb::http::status` (enum like `HTTP_STATUS_OK`).
    *   `status`: `String` holding the reason phrase (optional, defaults to standard phrase for `status_code`).
    *   `_headers`: `qb::http::headers_map`.
    *   `body()`: Accessor for the `qb::http::Body` object.
    *   `_cookies`: `qb::http::CookieJar` for *setting* response cookies via `Set-Cookie` headers.
*   **Setting Status:** Directly assign to `status_code`.
*   **Setting Headers:** `add_header()`, `set_header()`, `remove_header()`. Common headers like `Content-Type`, `Content-Length`, `Server` are often set automatically or via helpers.
*   **Setting Body:**
    *   `response.body() = "Some text";`
    *   `response.body() = my_json_object;`
    *   `response.body() = my_multipart_object;`
*   **Setting Cookies:**
    *   `add_cookie("name", "value")`: Adds a basic cookie.
    *   `add_cookie(Cookie object)`: Adds a cookie with specific attributes (path, domain, expiry, etc.).
    *   `remove_cookie("name")`: Adds an expired cookie to instruct the browser to remove it.
    *   `cookies()`: Get the `CookieJar`.
    *   `update_cookie_header("name")` / `update_cookie_headers()`: Updates `Set-Cookie` headers if `Cookie` objects were modified directly.

## `qb::http::Body`

(`qbm/http/body.h`, `qbm/http/body.cpp`)

Manages the message body content efficiently.

*   **Storage:** Uses `qb::allocator::pipe<char>` internally.
*   **Assignment:** `operator=` overloads for `std::string`, `std::string_view`, `std::vector<char>`, `qb::json`, `Multipart` (uses move semantics where possible).
*   **Appending:** `operator<<` to append data.
*   **Access:**
    *   `as<T>()`: Convert to `std::string`, `std::string_view`, `qb::json`, `Multipart`, `MultipartView`. Throws on failure (e.g., parsing invalid JSON).
    *   `raw()`: Get the underlying `pipe<char>`.
    *   `size()`, `empty()`, `begin()`, `end()`.
*   **Compression (Optional - requires Zlib):**
    *   `compress(encoding)`: Compresses the body in-place.
    *   `uncompress(encoding)`: Decompresses the body in-place.
    *   Static helpers `get_compressor_from_header` / `get_decompressor_from_header`.

## `qb::http::Headers` / `THeaders<String>`

(`qbm/http/headers.h`, `qbm/http/headers.cpp`)

Manages HTTP headers. This class is inherited by `MessageBase`.

*   **Storage:** `qb::icase_unordered_map<std::vector<String>>`.
*   **Case-Insensitive:** Header names are treated case-insensitively.
*   **Multiple Values:** Supports multiple values for the same header name (stored in the `std::vector`).
*   **Access:** `header("name", index, default)` gets a specific value, `headers()` gets the map.
*   **Manipulation:** `add_header`, `set_header`, `remove_header`.
*   **Attribute Parsing:** `attributes("header_name")` parses structured header values like `Content-Type: text/html; charset=utf-8` into a map (`{"charset": "utf-8"}`).
*   **Content-Type Helper:** Includes a nested `ContentType` class for easy parsing and access to MIME type and charset.
    *   `content_type()`: Returns a `ContentType` object parsed from the `Content-Type` header.
    *   `set_content_type("mime/type")`: Sets the `Content-Type` header and updates the internal `ContentType` object. 