# 02: HTTP Message Body: Deep Dive (`qb::http::Body`)

The [01: Core HTTP Concepts](./01-core-concepts.md) file introduced the `qb::http::Body` class. This section delves deeper into interacting with the HTTP message body, notably through its assignment operators (`operator=`), conversion methods (`as<T>()`), raw data access, and compression management.

The `Body` class is designed for flexibility and performance, utilizing `qb::allocator::pipe<char>` for efficient data storage.

## Content Assignment (`operator=`)

The `Body` class overloads `operator=` to allow easy assignment of various data types. The existing content of the body is generally cleared before assignment.

### Assigning from `std::string`

-   **`Body& operator=(std::string const& str)`**: Copies the string's content.
-   **`Body& operator=(std::string&& str) noexcept`**: Moves the string's content. The source string (`str`) is then cleared (`str.clear()`). This is the most efficient method for temporary `std::string`s or those no longer needed.

```cpp
#include <http/http.h> // Main include for Body, string, etc.
#include <iostream>    // For std::cout

qb::http::Body http_body;
std::string my_data = "Hello from std::string";

// Assignment by copy
http_body = my_data;
// my_data still contains "Hello from std::string"
std::cout << "Body after copy: " << http_body.as<std::string>() << std::endl;

// Assignment by move
std::string data_to_move = "This will be moved";
http_body = std::move(data_to_move);
// data_to_move is now empty (or in a valid but unspecified state)
std::cout << "Body after move: " << http_body.as<std::string>() << std::endl;
std::cout << "Original string after move: '" << data_to_move << "'" << std::endl; // Typically empty
```

### Assigning from `std::string_view`

-   **`Body& operator=(std::string_view const& str)`**: Copies the content of the `std::string_view`.
-   **`Body& operator=(std::string_view&& str) noexcept`**: Moves (copies) the content of the rvalue `std::string_view`. Since `std::string_view` does not own the data, this effectively results in a copy.

```cpp
#include <http/http.h> // Main include
#include <iostream>    // For std::cout

qb::http::Body http_body;
std::string_view sv_data = "Data from string_view";

// Assignment by copy (from lvalue const&)
http_body = sv_data;
std::cout << "Body from string_view: " << http_body.as<std::string>() << std::endl;

// Assignment from rvalue string_view
http_body = std::string_view("Literal as rvalue string_view");
std::cout << "Body from rvalue sv: " << http_body.as<std::string>() << std::endl;
```

### Assigning from `const char*` and String Literals

-   **`Body& operator=(char const* const& str)`**: Copies the C-string's content. Handles the case where `str` is `nullptr` (the body becomes empty).
-   **`Body& operator=(const char (&str)[N]) noexcept`**: Optimized for string literals, copies the content.

```cpp
#include <http/http.h> // Main include
#include <iostream>    // For std::cout

qb::http::Body http_body;

const char* c_string = "Data from C-string";
http_body = c_string;
std::cout << "Body from C-string: " << http_body.as<std::string>() << std::endl;

http_body = "Data from string literal";
std::cout << "Body from literal: " << http_body.as<std::string>() << std::endl;

http_body = nullptr; // Body will be empty
// EXPECT_TRUE(http_body.empty()); // Note: Removed gtest macro
```

### Assigning from `std::vector<char>`

-   **`Body& operator=(std::vector<char> const& vec)`**: Copies the vector's content.
-   **`Body& operator=(std::vector<char>&& vec) noexcept`**: Moves the vector's content. The source vector (`vec`) is then cleared (`vec.clear()`).

```cpp
#include <http/http.h> // Main include
#include <iostream>    // For std::cout
#include <vector>      // For std::vector

qb::http::Body http_body;
std::vector<char> char_vec = {'b', 'i', 'n', 'a', 'r', 'y'};

http_body = char_vec; // Copy
std::cout << "Body from vector copy: " << http_body.as<std::string>() << std::endl;

std::vector<char> vec_to_move = {'m', 'o', 'v', 'e', 'd'};
http_body = std::move(vec_to_move); // Move
std::cout << "Body from vector move: " << http_body.as<std::string>() << std::endl;
// EXPECT_TRUE(vec_to_move.empty()); // Note: Removed gtest macro
```

### Assigning from `qb::json`

-   **`Body& operator=(qb::json const& json_val)`**: Serializes the JSON object into a string (via `json_val.dump()`) and assigns it to the body.
-   **`Body& operator=(qb::json&& json_val) noexcept`**: Serializes the JSON object (semantically moved) into a string and assigns it.

```cpp
#include <http/http.h> // Main include for Body and qb::json
#include <iostream>    // For std::cout

qb::http::Body http_body;
qb::json my_json = {{"message", "Hello"}, {"value", 42}};

http_body = my_json; // Copy and serialization
// Body content: "{\"message\":\"Hello\",\"value\":42}"
std::cout << "Body from JSON: " << http_body.as<std::string>() << std::endl;
```

### Assigning from `qb::http::Form` (URL Encoded)

-   **`Body& operator=(Form const& form)`**: Serializes the `Form` object into an `application/x-www-form-urlencoded` string and assigns it.
-   **`Body& operator=(Form&& form) noexcept`**: Moves and serializes. The source `Form` is cleared (`form.clear()`).

```cpp
#include <http/http.h> // Main include for Body and Form
#include <iostream>    // For std::cout

qb::http::Body http_body;
qb::http::Form my_form;
my_form.add("user", "test_user");
my_form.add("email", "test@example.com");

http_body = my_form; // Copy and serialization
// Content: "user=test_user&email=test%40example.com" (order may vary)
std::cout << "Body from Form: " << http_body.as<std::string>() << std::endl;
```

### Assigning from `qb::http::Multipart`

-   **`Body& operator=(Multipart const& mp)`**: Serializes the multipart content (parts, headers, boundaries) and assigns it.

```cpp
#include <http/http.h> // Main include for Body and Multipart
#include <iostream>    // For std::cout

qb::http::Body http_body;
qb::http::Multipart multipart_data;
auto& part1 = multipart_data.create_part();
part1.set_header("Content-Disposition", "form-data; name=\"text_field\"");
part1.body = "Simple text";

http_body = multipart_data;
// The body now contains the full representation of the multipart message,
// including boundaries, part headers, and part bodies.
std::cout << "Multipart body string contains boundary: " 
          << (http_body.as<std::string>().find(multipart_data.boundary()) != std::string::npos)
          << std::endl;
```

## Content Conversion (`as<T>()`)

The `as<T>()` method allows converting and/or interpreting the raw body content into a specific type `T`. This often involves parsing the data.

-   **`as<std::string>() const`**: Returns a `std::string` copy of the body content.
-   **`as<std::string_view>() const`**: Returns a non-owning `std::string_view` of the body content. **Caution**: The `string_view` is valid only as long as the `Body` object is not modified or destroyed.
-   **`as<qb::json>() const`**: Attempts to parse the body content as a JSON string and returns a `qb::json` object. Throws `qb::json::parse_error` on failure.
-   **`as<Form>() const`**: Attempts to parse the body content as `application/x-www-form-urlencoded` data and returns a `qb::http::Form` object.
-   **`as<Multipart>() const`**: Attempts to parse the body content as a `multipart/form-data` message. The first line of the body is expected to be the boundary (e.g., `"--boundary_string\r\n"`). Throws `std::runtime_error` on parsing failure or if the boundary is not found.

```cpp
#include <http/http.h> // Main include for Body, qb::json, Form
#include <iostream>    // For std::cerr, std::cout

qb::http::Body body_json_str = R"({\"name\": \"QB\", \"version\": 1.0})";
try {
    qb::json parsed_obj = body_json_str.as<qb::json>();
    std::cout << "Parsed JSON version: " << parsed_obj["version"].get<double>() << std::endl;
} catch (const qb::json::parse_error& e) {
    std::cerr << "JSON parse error: " << e.what() << std::endl;
}

qb::http::Body body_form_str = "param1=value1&param2=another%20value";
qb::http::Form parsed_form = body_form_str.as<qb::http::Form>();
std::cout << "Parsed form param1: " << parsed_form.get_first("param1").value_or("") << std::endl;
```

## Raw Data Access (`raw()`)

For low-level control or streaming operations, you can directly access the internal `qb::allocator::pipe<char>` buffer:

-   **`qb::allocator::pipe<char> const& raw() const noexcept`**: Constant access.
-   **`qb::allocator::pipe<char>& raw() noexcept`**: Modifiable access.

This is useful if you need to read or write data in chunks or integrate with other I/O systems that operate on raw buffers. Remember that direct manipulation of the pipe might bypass some of `Body`'s managed features (like automatic size updates if you are not careful, though pipe itself manages its size).

## Streaming Operators (`operator<<`)

Just like with assignment, you can use `operator<<` to fluently append content to the body:

```cpp
#include <http/http.h> // For qb::http::Body
#include <iostream>    // For std::cout

qb::http::Body stream_body;
stream_body << "Chunk 1, " << 42 << ", more data.";
std::cout << "Streamed body: " << stream_body.as<std::string>() << std::endl;
// Output: Streamed body: Chunk 1, 42, more data.
```

## Compression and Decompression

If the library is compiled with Zlib support (`QB_IO_WITH_ZLIB` defined), the `Body` class offers methods for compressing and decompressing its content:

-   **`std::size_t compress(std::string const& encoding)`**: Compresses the body content using the specified encoding (e.g., `"gzip"`, `"deflate"`). The body content is replaced with the compressed data. Returns the size of the compressed data.
-   **`std::size_t uncompress(const std::string& encoding)`**: Decompresses the body content. The content is replaced with the decompressed data. Returns the size of the decompressed data.

These methods throw `std::runtime_error` if the encoding is unsupported or if an error occurs during (de)compression.

```cpp
#include <http/http.h> // For qb::http::Body
#include <iostream>    // For std::cout
// QB_IO_WITH_ZLIB should be handled by the build system for conditional compilation of Body::compress/uncompress

#ifdef QB_IO_WITH_ZLIB
qb::http::Body data_body = "A long text that will benefit from compression. A long text that will benefit from compression.";
size_t original_size = data_body.size();

size_t compressed_size = data_body.compress("gzip");
std::cout << "Original: " << original_size << ", Compressed (gzip): " << compressed_size << std::endl;
// data_body now contains gzipped data

size_t decompressed_size = data_body.uncompress("gzip");
std::cout << "Decompressed: " << decompressed_size << std::endl;
// data_body again contains the original text
// EXPECT_EQ(data_body.as<std::string>(), "A long text that will benefit from compression. A long text that will benefit from compression."); // Note: Removed gtest macro
#endif
```

The `Body` class is a fundamental and versatile component for managing HTTP message payloads in `qb::http`.

Previous: [01: Core HTTP Concepts](./01-core-concepts.md)
Next: [03: Routing Overview](./03-routing-overview.md)

---
Return to [Index](./README.md) 