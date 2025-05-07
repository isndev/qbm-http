# `qbm-http`: Multipart/form-data Handling

(`qbm/http/multipart.h`, `qbm/http/multipart.cpp`)

The HTTP module provides support for parsing and creating `multipart/form-data` content, commonly used for file uploads and submitting complex forms.

## Concepts

*   **Multipart:** A format where the HTTP message body is divided into multiple distinct parts, each potentially having its own headers (like `Content-Disposition`, `Content-Type`) and body content.
*   **Boundary:** A unique string used to separate the different parts within the message body. The `Content-Type` header of a multipart request specifies this boundary (e.g., `Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXYZ`).
*   **Parts:** Each section between boundaries. A part typically represents a form field or an uploaded file.
    *   **Headers:** Each part can have headers, most importantly `Content-Disposition`, which usually contains the `name` of the form field and optionally the `filename` for file uploads.
    *   **Body:** The actual data for the form field or the content of the uploaded file.

## Parsing Multipart Requests (Server-Side)

The primary way to handle incoming multipart data is using the `Body::as<T>()` method.

*   **`Body::as<qb::http::Multipart>()`:** Parses the request body and returns a `qb::http::Multipart` object. This object contains a `std::vector` of `Multipart::Part` objects. Each `Part` uses `std::string` for its body, meaning the data for *all parts is copied* into the `Multipart` object during parsing.
*   **`Body::as<qb::http::MultipartView>()`:** Parses the request body and returns a `qb::http::MultipartView` object. Each `Part` in this view uses `std::string_view` for its body. This avoids copying the body data for each part, making it more efficient for large uploads, but the `string_view`s are only valid as long as the original request body buffer is valid.

```cpp
#include <http/http.h>
#include <fstream>

// Inside a route handler (e.g., POST /upload)
router.post("/upload", [](Context& ctx) {
    // Check Content-Type
    std::string content_type_header = ctx.request.header("Content-Type");
    if (content_type_header.find("multipart/form-data") == std::string::npos) {
        ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
        ctx.response.body() = "Expected multipart/form-data";
        ctx.complete();
        return;
    }

    try {
        // Parse the body (use MultipartView for potentially large files)
        auto multipart_view = ctx.request.body().as<qb::http::MultipartView>();

        std::string user_field;
        std::string uploaded_filename;

        for (const auto& part : multipart_view.parts()) {
            // Get Content-Disposition attributes
            auto disposition_attrs = part.attributes("Content-Disposition");
            std::string name = disposition_attrs.param("name");
            std::string filename = disposition_attrs.param("filename");

            if (!filename.empty()) {
                // It's a file part
                uploaded_filename = filename;
                std::cout << "Processing file: " << filename << " (Size: " << part.body.size() << ")\n";

                // --- Save the file (using string_view data) ---
                // Note: part.body is a string_view, valid only during this handler scope
                // unless the underlying request body buffer persists.
                // For saving, it's often safer to copy to a string or stream directly.
                std::ofstream ofs("./upload_" + filename, std::ios::binary);
                ofs.write(part.body.data(), part.body.size());
                // -----------------------------------------------

            } else if (!name.empty()) {
                // It's a form field
                std::cout << "Processing field: " << name << " = " << part.body << "\n";
                if (name == "user") {
                    user_field = std::string(part.body); // Copy if needed later
                }
            }
        }

        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Upload processed. User: " + user_field + ", Filename: " + uploaded_filename;
        ctx.complete();

    } catch (const std::exception& e) {
        // Handle parsing errors (e.g., invalid boundary, malformed data)
        ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
        ctx.response.body() = std::string("Failed to parse multipart data: ") + e.what();
        ctx.complete();
    }
});
```

## Creating Multipart Requests/Responses (Client/Server)

While less common for responses, you might create multipart content on the client or for specific server responses.

1.  **Create `qb::http::Multipart` Object:** Instantiate it. A boundary is generated automatically, or you can provide one.
2.  **Add Parts:** Use `multipart.create_part()` to get a reference to a new `Part`.
3.  **Set Part Headers:** Use `part.add_header()` or `part.headers()[...]`.
    *   Crucially set `Content-Disposition: form-data; name="field_name"` for fields.
    *   For files, use `Content-Disposition: form-data; name="field_name"; filename="your_file.txt"` and set an appropriate `Content-Type` header for the part.
4.  **Set Part Body:** Assign the data to `part.body`. For binary data, assign a `std::vector<char>` or use the `pipe<char>`. For text, assign a `std::string`.
5.  **Assign to Request/Response Body:** `request.body() = multipart;`
6.  **Set Main Content-Type Header:** Set the main request/response `Content-Type` header correctly, including the boundary: `request.add_header("Content-Type", "multipart/form-data; boundary=" + multipart.boundary());`

```cpp
#include <http/http.h>
#include <fstream>

// ... client code ...
qb::http::Request req("http://example.com/upload");
req.method = HTTP_POST;

// Create multipart object
qb::http::Multipart multipart_data;

// Add a text field part
auto& field_part = multipart_data.create_part();
field_part.add_header("Content-Disposition", "form-data; name=\"description\"");
field_part.body = "This is a test upload.";

// Add a file part
std::ifstream file_to_upload("my_image.jpg", std::ios::binary);
if (file_to_upload) {
    std::stringstream buffer;
    buffer << file_to_upload.rdbuf();
    std::string file_content = buffer.str();

    auto& file_part = multipart_data.create_part();
    file_part.add_header("Content-Disposition", "form-data; name=\"image_file\"; filename=\"my_image.jpg\"");
    file_part.add_header("Content-Type", "image/jpeg"); // Set appropriate MIME type
    file_part.body = std::move(file_content); // Move content into part body
}

// Set the multipart object as the request body
req.body() = multipart_data;

// *** Set the main Content-Type header with the boundary ***
req.add_header("Content-Type", "multipart/form-data; boundary=" + multipart_data.boundary());

// Send the request (sync or async)
// auto response = qb::http::POST(req);
// qb::http::POST(req, [](qb::http::async::Reply&& reply){ ... });
```

## Internal Parser (`MultipartParser`)

(`qbm/http/multipart.h` for `MultipartParser` class, `qbm/http/body.cpp` for `internal::MultipartReader`)

The `Body::as<Multipart>()` methods use `qb::http::internal::MultipartReader` (defined in `body.cpp`) which wraps the lower-level `qb::http::MultipartParser` (defined in `multipart.h`). This parser is a state machine that processes the input stream byte-by-byte and invokes callbacks (`onPartBegin`, `onHeaderField`, `onHeaderValue`, `onPartData`, `onPartEnd`, etc.) as different elements are encountered. Direct use of `MultipartParser` is generally not necessary unless building custom low-level parsing logic.

**(See also:** `test-http-multipart.cpp`**)** 