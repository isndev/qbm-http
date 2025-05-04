# `qbm-http`: Utilities

This document covers various utility functions and types provided by the `qbm-http` module.

## HTTP Date Handling (`qb::http::date`)

(`qbm/http/date.h`, `qbm/http/date.cpp`)

Provides functions for parsing and formatting dates according to HTTP standards (RFC 7231, RFC 6265).

*   **`format_http_date(timestamp_or_timepoint)`:** Formats a `qb::Timestamp` or `std::chrono::system_clock::time_point` into the preferred RFC 1123 format (e.g., "Sun, 06 Nov 1994 08:49:37 GMT").
*   **`format_cookie_date(timepoint)`:** Formats a time point specifically for the `Expires` attribute in `Set-Cookie` headers (currently same format as `format_http_date`).
*   **`parse_http_date(string_or_view)`:** Parses a date string in any of the three allowed HTTP formats (RFC 1123, RFC 850, asctime) and returns `std::optional<std::chrono::system_clock::time_point>`.
*   **`parse_cookie_date(string_or_view)`:** Parses a date string typically found in `Expires` attributes of cookies (currently uses `parse_http_date` logic).
*   **`now()`:** Returns the current time formatted as an HTTP date string.
*   **`to_time_point(qb::Timestamp)` / `to_timestamp(timepoint)`:** Convert between `qb::Timestamp` and `std::chrono::system_clock::time_point`.

```cpp
#include <qb/http.h>
#include <iostream>

auto now_tp = std::chrono::system_clock::now();
std::string http_date = qb::http::date::format_http_date(now_tp);
std::cout << "Current HTTP Date: " << http_date << std::endl;

auto parsed_tp = qb::http::date::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT");
if (parsed_tp) {
    std::cout << "Parsed successfully." << std::endl;
}
```

## String & Parsing Utilities (`qb::http::utility`)

(`qbm/http/utility.h`)

Contains helper functions for string manipulation and character checking according to HTTP specifications.

*   **Character Checks:** `is_char()`, `is_control()`, `is_special()`, `is_digit()`, `is_hex_digit()`, `is_http_whitespace()`.
*   **Case-Insensitive Comparison:** `iequals(string_a, string_b)`.
*   **String Splitting:**
    *   `split_string<String>(string_view, delimiters, reserve)`: Splits by any character in `delimiters`.
    *   `split_string<String>(string_view, predicate, reserve)`: Splits based on a custom predicate function.
    *   `split_string_by(string, boundary, reserve)`: Splits specifically by a boundary string (used in multipart).
*   **String Joining:** `join(vector_of_strings, delimiter)`.

## Header Utilities

(`qbm/http/headers.h`, `qbm/http/headers.cpp`)

*   **`parse_header_attributes(string_or_view)`:** Parses attributes from header values like `Content-Type` or `Content-Disposition` (e.g., `text/html; charset=utf-8`) into a `qb::icase_unordered_map<std::string>`.
*   **`accept_encoding()`:** Generates a suitable `Accept-Encoding` header value based on the available compression capabilities (requires Zlib).
*   **`content_encoding(accept_encoding_header)`:** Selects the best `Content-Encoding` to use based on the client's `Accept-Encoding` header (requires Zlib).

## Core Types (`qb::http::types`)

(`qbm/http/types.h`)

Defines fundamental enums and constants:

*   `http_method`: Enum for HTTP methods (GET, POST, etc.), aliased as `qb::http::method`.
*   `http_status`: Enum for HTTP status codes (OK, NOT_FOUND, etc.), aliased as `qb::http::status`.
*   `endl`: Constant `"\r\n"`.
*   `sep`: Constant `' '`.
*   `HTTP_METHOD_MAP`, `HTTP_STATUS_MAP`: X-Macros used internally for generating code related to methods and statuses.

## Other

*   **Date Class (`qb::http::Date`):** (`date.h`) Provides static methods `to_string` and `parse` wrapping the functions in the `qb::http::date` namespace for potential backward compatibility or alternative usage. 