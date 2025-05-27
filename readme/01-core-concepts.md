# 01: Core HTTP Concepts

This section provides an overview of the fundamental classes used to represent and manipulate HTTP messages within the `qb::http` module. These include requests, responses, message bodies, headers, and URIs.

## HTTP Messages: Request and Response

The `qb::http` module defines two primary classes for representing HTTP messages: `qb::http::Request` and `qb::http::Response`. These classes serve as containers for all information related to an HTTP exchange, supporting both HTTP/1.1 and HTTP/2 semantics where appropriate (e.g., HTTP/2 pseudo-headers are handled correctly during parsing and serialization for HTTP/2 contexts).

Both `Request` and `Response` inherit from a common base (`internal::MessageBase`) which provides shared functionalities like HTTP version management, header storage, and body handling.

### `qb::http::Request`

Represents an incoming or outgoing HTTP request. Key properties include:

-   **HTTP Method**: (`qb::http::Method`) The HTTP method of the request (e.g., `GET`, `POST`, `PUT`). Accessed via `request.method()`.
-   **URI**: (`qb::io::uri`) The Uniform Resource Identifier specifying the target resource. Accessed via `request.uri()`. This object provides detailed access to all parts of the URI (scheme, host, path, query parameters, fragment).
    -   For HTTP/2, the `:scheme`, `:authority` (or `Host` header), and `:path` pseudo-headers are used to construct this URI internally when parsing a request.
-   **HTTP Version**: (`major_version`, `minor_version`) Can be 1.1 for HTTP/1.1 or 2.0 for HTTP/2.
-   **Headers**: (`qb::http::Headers`) A collection of HTTP headers. For HTTP/2, this includes regular headers and is populated from HPACK decoded data. Pseudo-headers like `:method`, `:scheme`, `:path`, `:authority` are typically not stored here directly but are used to populate the respective `Request` members (method, URI components).
-   **Body**: (`qb::http::Body`) The message body content. See [Message Body](#http-message-body) section below.
-   **Cookies**: (`qb::http::CookieJar`) Parsed cookies from the `Cookie` header. Accessed via `request.cookies()` or `request.cookie("name")`. The `request.parse_cookie_header()` method must be called to populate this jar from the request headers.

```cpp
// Example: Creating and inspecting a Request object
#include <http/http.h>
#include <iostream>

qb::http::Request req(qb::http::method::POST, qb::io::uri("/submit_data?type=test"));
req.set_header("User-Agent", "QB-Client/1.0");
req.set_header("Content-Type", "application/json");
req.body() = R"({"key": "value"})";
req.add_cookie(qb::http::Cookie("session_id", "abc123xyz"));

std::cout << "Method: " << std::to_string(req.method()) << std::endl;
std::cout << "Path: " << req.uri().path() << std::endl;
std::cout << "Query 'type': " << req.query("type") << std::endl;
std::cout << "User-Agent: " << req.header("User-Agent") << std::endl;
std::cout << "Body: " << req.body().as<std::string>() << std::endl;
if (auto* cookie = req.cookie("session_id")) {
    std::cout << "Session ID Cookie: " << cookie->value() << std::endl;
}
```

### `qb::http::Response`

Represents an outgoing HTTP response. Key properties include:

-   **Status Code**: (`qb::http::Status`) The HTTP status code (e.g., `200 OK`, `404 Not Found`). Accessed via `response.status()`.
    -   For HTTP/2, this corresponds to the `:status` pseudo-header.
-   **HTTP Version**: (`major_version`, `minor_version`) Can be 1.1 or 2.0.
-   **Headers**: (`qb::http::Headers`) A collection of HTTP headers. For HTTP/2, this includes regular headers to be HPACK encoded. The `:status` pseudo-header is handled via `response.status()`.
-   **Body**: (`qb::http::Body`) The message body content. See [Message Body](#http-message-body) section below.
-   **Cookies**: (`qb::http::CookieJar`) Cookies to be sent to the client via `Set-Cookie` headers. Use `response.add_cookie()` to add cookies, which also automatically prepares the corresponding `Set-Cookie` header.

```cpp
// Example: Creating and populating a Response object
#include <http/http.h>
#include <iostream>

qb::http::Response res;
res.status() = qb::http::status::OK; // 200 OK
res.set_content_type("application/json; charset=utf-8");
res.body() = R"({"message": "Success!"})";
res.add_cookie(qb::http::Cookie("user_pref", "dark_mode").path("/").max_age(3600));

std::cout << "Status: " << res.status().code() << " " << std::string(res.status()) << std::endl;
std::cout << "Content-Type: " << res.header("Content-Type") << std::endl;
std::cout << "Body: " << res.body().as<std::string>() << std::endl;
// The Set-Cookie header is automatically managed by add_cookie
if (res.has_header("Set-Cookie")) {
    std::cout << "Set-Cookie Header: " << res.header("Set-Cookie") << std::endl;
}
```

## HTTP Message Body (`qb::http::Body`)

The `qb::http::Body` class represents the payload of an HTTP message. It is designed for efficiency and flexibility:

-   **Internal Storage**: Uses `qb::allocator::pipe<char>`, a dynamic buffer optimized for I/O operations, minimizing reallocations.
-   **Versatile Content**: Can hold text, JSON, binary data, multipart forms, etc.
-   **Fluent API**: Supports appending data using the `<<` operator and assignment from various types (`std::string`, `std::string_view`, `std::vector<char>`, `qb::json`, `qb::http::Multipart`, `qb::http::Form`).
-   **Type Conversion**: The `as<T>()` method allows converting the body content to common types like `std::string`, `std::string_view`, `qb::json`, `qb::http::Multipart`, or `qb::http::Form`. Parsing is performed during conversion.
-   **Compression**: If compiled with Zlib support (`QB_IO_WITH_ZLIB`), the body can be compressed (`body.compress("gzip")`) or decompressed (`body.uncompress("gzip")`).

```cpp
#include <http/http.h>
#include <iostream>

qb::http::Body body;

// Assigning content
body = "Hello, world!";
std::string text_content = body.as<std::string>(); // "Hello, world!"

qb::json json_payload = {{"key", "value"}, {"count", 42}};
body = json_payload;
qb::json parsed_json = body.as<qb::json>(); // Parses the body string back into JSON

// Appending content
body.clear();
body << "Part1" << " " << "Part2" << 123;
// body.as<std::string>() would be "Part1 Part2123"

// Raw access for direct manipulation or streaming
qb::allocator::pipe<char>& raw_pipe = body.raw();
raw_pipe.put("Direct data\0", 12); // Example of putting raw data
```

### Supported Body Types & Conversions

-   **Plain Text/Binary**: Assign from `std::string`, `std::string_view`, `const char*`, `std::vector<char>`. Convert using `as<std::string>()` or `as<std::string_view>()`.
-   **JSON**: Assign from `qb::json`. Convert using `as<qb::json>()`. Parses the body content (expected to be a JSON string).
-   **Form URL Encoded**: Assign from `qb::http::Form`. Serializes the form into `application/x-www-form-urlencoded` format. Convert using `as<qb::http::Form>()`. Parses the URL-encoded string into a `Form` object.
-   **Multipart**: Assign from `qb::http::Multipart`. Serializes the multipart data. Convert using `as<qb::http::Multipart>()`. Parses the multipart body string.

Refer to `body.h` and `body.cpp` for detailed template specializations for assignment and conversion. Further details on complex body types like Form and Multipart are in their respective documentation sections.

## HTTP Headers (`qb::http::THeaders`, `qb::http::Headers`)

HTTP headers are managed by the `qb::http::THeaders<StringType>` class template, from which `Request` and `Response` inherit. The common alias `qb::http::Headers` (for `std::string` values) is typically used.

Key features:

-   **Case-Insensitive Names**: Header names are handled case-insensitively (e.g., "Content-Type" is the same as "content-type").
-   **Multi-Value Support**: A single header name can have multiple values, stored as a `std::vector<StringType>`.
-   **Accessors**:
    -   `header(name, index = 0, default_value = {})`: Retrieves the value of a header. `index` is used for multi-value headers.
    -   `set_header(name, value)`: Sets a header, replacing any existing values for that name.
    -   `add_header(name, value)`: Adds a new value for a header. If the header already exists, the new value is appended to its list.
    -   `has_header(name)`: Checks for the existence of a header.
    -   `remove_header(name)`: Removes all occurrences of a header.
    -   `headers()`: Provides direct access to the underlying map (`qb::icase_unordered_map<std::vector<StringType>>`).
-   **Content-Type Helper**: `THeaders` includes a nested `ContentType` class and a `content_type()` method for convenient parsing and access to the MIME type and charset of the `Content-Type` header. `set_content_type(value)` updates both the raw header and the parsed `ContentType` object.

```cpp
#include <http/http.h>
#include <iostream>

qb::http::Request req;

// Setting headers
req.set_header("X-Request-ID", "12345");
req.add_header("Accept-Encoding", "gzip");
req.add_header("Accept-Encoding", "deflate"); // Adds a second value

// Getting headers
std::cout << "Request ID: " << req.header("X-Request-ID") << std::endl;
const auto& encodings = req.headers().at("accept-encoding"); // Access underlying map directly (case-insensitive key)
for (const auto& enc : encodings) {
    std::cout << "Accepts Encoding: " << enc << std::endl;
}

// Content-Type specific handling
req.set_content_type("application/json; charset=UTF-16");
std::cout << "MIME Type: " << req.content_type().type() << std::endl;   // "application/json"
std::cout << "Charset: " << req.content_type().charset() << std::endl; // "UTF-16"
```

## URI Handling (`qb::io::uri`)

Uniform Resource Identifiers (URIs) are managed by the `qb::io::uri` class. This class is part of the `qb-io` library but is fundamental to HTTP operations.

Key capabilities:

-   **Parsing**: Parses a URI string into its constituent components: scheme, user info, host (hostname, IPv4, or IPv6), port, path, query string, and fragment.
    -   In HTTP/2 server contexts, the URI for a request is typically reconstructed from the `:scheme`, `:authority` (or `Host` header), and `:path` pseudo-headers.
-   **Component Access**: Provides methods to access each part (e.g., `uri.scheme()`, `uri.host()`, `uri.path()`, `uri.query("param_name")`, `uri.fragment()`).
-   **Query Parameter Handling**: The `uri.queries()` method returns a map-like structure (`qb::icase_unordered_map<std::vector<std::string>>`) of decoded query parameters. `uri.query(name, index, default_value)` provides easy access to specific query values, supporting multi-value parameters.
-   **Normalization**: Path normalization utilities (e.g., resolving `.` and `..`).
-   **Encoding/Decoding**: Static methods `qb::io::uri::encode()` and `qb::io::uri::decode()` for percent-encoding and decoding URI components.

```cpp
#include <qb/io/uri.h>
#include <http/http.h>
#include <iostream>

qb::io::uri my_uri("https://john.doe:secret@example.com:8080/api/resource?search=term&page=2#section1");

std::cout << "Scheme: " << my_uri.scheme() << std::endl;       // "https"
std::cout << "Host: " << my_uri.host() << std::endl;         // "example.com"
std::cout << "Port: " << my_uri.port() << std::endl;         // "8080"
std::cout << "Path: " << my_uri.path() << std::endl;         // "/api/resource"
std::cout << "Search Query: " << my_uri.query("search") << std::endl; // "term"
std::cout << "Page Query: " << my_uri.query("page") << std::endl;   // "2"
std::cout << "Fragment: " << my_uri.fragment() << std::endl;   // "section1"

std::string original_path = "/path with spaces/";
std::string encoded_path = qb::io::uri::encode(original_path);
// encoded_path will be something like "/path%20with%20spaces/"
```

## HTTP Types (`qb::http::types.h`)

This header defines core enumerations and type aliases for HTTP methods and status codes, building upon the `llhttp` library's definitions. It is included via `<http/http.h>`.

-   **`qb::http::Method`**: A class wrapper around `enum class Method::Value` (which mirrors `::HTTP_DELETE`, `::HTTP_GET`, etc., from `llhttp.h`). It provides type safety, implicit conversions to string representations (e.g., `"GET"`), and comparison operators. Examples: `qb::http::method::GET`, `qb::http::method::POST`.

-   **`qb::http::Status`**: A class wrapper around `enum class Status::Value` (which mirrors `::HTTP_STATUS_OK`, `::HTTP_STATUS_NOT_FOUND`, etc.). Similar to `Method`, it offers type safety, string conversion (e.g., `"OK"`, `"Not Found"`), integer code access (`status.code()`), and comparisons. Examples: `qb::http::status::OK`, `qb::http::status::BAD_REQUEST`.

Constants like `qb::http::endl` (`"\r\n"`) and `qb::http::sep` (`' '`) are also available for constructing raw HTTP messages.

Understanding these core components is essential for working with the `qb::http` module, whether you are building client-side request logic or server-side handlers and middleware.

Next: [HTTP Message Body: Deep Dive](./02-body-deep-dive.md)

---
Return to [Index](./README.md) 