# 15: HTTP Message Parsing

Internally, the `qb::http` module relies on a robust parsing mechanism to interpret raw byte streams from network connections into structured `qb::http::Request` and `qb::http::Response` objects. This process is handled by the `qb::http::Parser<MessageType>` template class, which is a wrapper around the high-performance `llhttp` library.

While application developers using the high-level routing system or HTTP client functions typically don't interact with the `Parser` directly, understanding its role can be beneficial for advanced use cases or when implementing custom protocols or transport layers.

## The `qb::http::Parser<MessageType>`

-   **Template Specialization**: The `Parser` is templated on `MessageType`, which can be either `qb::http::Request` for server-side parsing or `qb::http::Response` for client-side parsing.
-   **Underlying Engine**: It uses `llhttp` (a fork of Node.js's http-parser) for its speed and low-level control over the parsing process.
-   **Event-Driven Callbacks**: `llhttp` works by invoking a series of callbacks as it encounters different parts of an HTTP message (e.g., start of message, URL, header field, header value, body chunk, message complete).
-   **Stateful**: The `Parser` maintains state throughout the parsing of a single message. It needs to be `reset()` before parsing a new message.

### Key Callbacks and Their Roles (Simplified)

Within `qb::http::Parser`, static callback functions are defined and registered with `llhttp`. These callbacks populate the `MessageType` object (e.g., `msg`) being constructed:

-   **`on_url`**: When parsing a request, this callback receives the URL string and sets the method and URI on the `Request` object.
-   **`on_status`**: When parsing a response, this receives the status message (e.g., "OK", "Not Found") and sets the status code on the `Response` object.
-   **`on_header_field`**: Stores the name of the current header field being parsed.
-   **`on_header_value`**: Stores the value of the current header field, associating it with the previously stored name. It correctly handles multi-value headers by appending to a vector.
-   **`on_headers_complete`**: This is a crucial callback. It signifies that all headers have been parsed.
    -   The HTTP version (`major_version`, `minor_version`) is set on the message.
    -   If a `Content-Length` header is present, the parser might reserve space in the message body's internal buffer (`_data` pipe) for efficiency.
    -   It sets an `upgrade` flag if an `Upgrade` header is present.
    -   **Importantly, `llhttp` is often paused (`HPE_PAUSED`) at this point.** This allows the `qb::http` protocol handlers (like `qb::protocol::http_server`) to inspect the headers (e.g., to determine body length or type) before deciding how to proceed with parsing the body.
-   **`on_body`**: Called with chunks of the message body. The data is typically accumulated in an internal buffer (`_chunked` pipe).
-   **`on_message_complete`**: Signifies the end of the message.
    -   The accumulated body data from `_chunked` is moved into the final `msg.body().raw()`.
    -   The `Content-Type` of the message is parsed from the headers and set on the message object.
    -   This callback typically signals to the higher-level protocol handler that a complete message is ready.

### Integration with Protocol Handlers

The `qb::protocol::http_server` and `qb::protocol::http_client` classes (which are specializations of `qb::protocol::http_internal::base`) use an instance of `qb::http::Parser<MessageType>`.

1.  The protocol handler receives raw data from the transport (e.g., a TCP socket).
2.  It feeds this data into `parser.parse(buffer, size)`.
3.  If `parser.headers_completed()` becomes true and `parser.parse()` returned `HPE_PAUSED`, the protocol handler can inspect headers.
4.  The handler might call `parser.resume()` to continue parsing the body if necessary.
5.  The `getMessageSize()` method in the protocol handler often uses information from the parser (like `content_length` or chunked encoding state) to determine if a full HTTP message has been received in the input buffer.
6.  Once `on_message_complete` is triggered (and `parser.parse()` returns a specific code indicating completion), the protocol handler retrieves the fully formed `Request` or `Response` object using `parser.get_parsed_message()` and dispatches it (e.g., to the router or the client callback).

### Serialization

While parsing is about converting bytes to objects, the reverse process (serialization) is handled by `qb::allocator::pipe<char>::put<MessageType>()` specializations (see `http/http.cpp`). These format `Request` and `Response` objects back into the HTTP wire format.

-   `pipe << request_obj;` will serialize the request line, headers, and body.
-   `pipe << response_obj;` will serialize the status line, headers, and body.

This includes automatically adding a `Content-Length` header if not present and the body is non-empty.

## Summary

The `qb::http::Parser` provides the low-level machinery for transforming raw HTTP byte streams into usable `Request` and `Response` objects. Its integration with `llhttp` ensures efficient and standard-compliant parsing. While mostly an internal detail for users of the client functions or server router, its existence and basic operation explain how data flows from the network into the structured objects you interact with in your handlers and middleware.

Previous: [Asynchronous HTTP Client](./14-async-http-client.md)
Next: [Advanced Usage & Performance](./16-advanced-topics.md)

---
Return to [Index](./README.md) 