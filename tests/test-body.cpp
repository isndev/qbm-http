#include <gtest/gtest.h>
#include <qb/json.h>
#include "../http.h" // Should include body.h, multipart.h, etc.

// Conditional include for compression tests
#ifdef QB_HAS_COMPRESSION
#include <qb/io/compression.h>
#endif

using namespace qb::http;

// Helper function to create a simple multipart body
Multipart
create_simple_multipart() {
    Multipart mp;
    auto     &part1 = mp.create_part();
    part1.set_header("Content-Disposition", "form-data; name=\"text_field\"");
    part1.body = "Simple text";

    auto &part2 = mp.create_part();
    part2.set_header("Content-Disposition", "form-data; name=\"file_field\"; filename=\"test.txt\"");
    part2.set_header("Content-Type", "text/plain");
    part2.body = "Content of the file.";
    return mp;
}

// Helper function to create a simple Form
Form
create_simple_form() {
    Form form;
    form.add("name", "test_user");
    form.add("email", "test@example.com");
    form.add("param", "value1");
    form.add("param", "value2");
    return form;
}

class BodyTest : public ::testing::Test {
protected:
    Body body;

    void
    SetUp() override {
        // Common setup for tests, if any
    }
};

TEST_F(BodyTest, DefaultConstruction) {
    EXPECT_TRUE(body.empty());
    EXPECT_EQ(0, body.size());
}

TEST_F(BodyTest, Clear) {
    body << "some data";
    ASSERT_FALSE(body.empty());
    ASSERT_GT(body.size(), 0);
    body.clear();
    EXPECT_TRUE(body.empty());
    EXPECT_EQ(0, body.size());
}

TEST(HttpMessageReset, RequestResetClearsBodyAndMessageState) {
    Request request{method::POST, qb::io::uri{"/submit"}};
    request.set_header("Content-Type", "text/plain");
    request.body() = "stale request body";
    request.cookies().add("sid", "abc");
    request.major_version = 3;
    request.minor_version = 0;
    request.upgrade       = true;
    request.stream_id     = 123;
    request.keep_alive    = true;

    request.reset();

    EXPECT_EQ(request.method(), method::GET);
    EXPECT_NE(request.uri().path(), "/submit");
    EXPECT_TRUE(request.body().empty());
    EXPECT_FALSE(request.has_header("Content-Type"));
    EXPECT_EQ(request.content_type().type(), Headers::default_content_type);
    EXPECT_FALSE(request.has_cookie("sid"));
    EXPECT_EQ(request.major_version, 1);
    EXPECT_EQ(request.minor_version, 1);
    EXPECT_FALSE(request.upgrade);
    EXPECT_EQ(request.stream_id, 0u);
    EXPECT_FALSE(request.keep_alive);
}

TEST(HttpMessageReset, ResponseResetClearsBodyAndMessageState) {
    Response response{status::CREATED};
    response.set_header("Content-Type", "application/json");
    response.body() = R"({"stale":true})";
    response.add_cookie("sid", "abc");
    response.major_version = 3;
    response.minor_version = 0;
    response.upgrade       = true;
    response.stream_id     = 123;
    response.keep_alive    = true;

    response.reset();

    EXPECT_EQ(response.status(), status::OK);
    EXPECT_TRUE(response.body().empty());
    EXPECT_FALSE(response.has_header("Content-Type"));
    EXPECT_FALSE(response.has_header("Set-Cookie"));
    EXPECT_EQ(response.content_type().type(), Headers::default_content_type);
    EXPECT_FALSE(response.has_cookie("sid"));
    EXPECT_EQ(response.major_version, 1);
    EXPECT_EQ(response.minor_version, 1);
    EXPECT_FALSE(response.upgrade);
    EXPECT_EQ(response.stream_id, 0u);
    EXPECT_FALSE(response.keep_alive);
}

TEST_F(BodyTest, AppendOperator) {
    body << "Hello, " << "World!" << 123;
    EXPECT_EQ("Hello, World!123", body.as<std::string>());
}

TEST_F(BodyTest, ChunkSerializationPreservesInternalZeroHexDigits) {
    const std::string payload(16, 'x');

    qb::allocator::pipe<char> out;
    out << Chunk(payload.data(), payload.size());

    const std::string wire{out.begin(), out.size()};
    EXPECT_EQ(wire.substr(0, 4), "10\r\n");
    EXPECT_TRUE(wire.ends_with("\r\n"));
}

TEST_F(BodyTest, AssignString) {
    std::string s_val = "Test String";
    body              = s_val;
    EXPECT_EQ(s_val, body.as<std::string>());

    std::string s_val_move = "Test String Move";
    body                   = std::move(s_val_move);
    EXPECT_EQ("Test String Move", body.as<std::string>());
    // s_val_move is in a valid but unspecified state, typically empty after move for strings
}

TEST_F(BodyTest, AssignStringView) {
    std::string_view sv_val = "Test StringView";
    body                    = sv_val; // This will call the const& generic operator=
    EXPECT_EQ(sv_val, body.as<std::string_view>());

    body = std::string_view("Test StringView Move"); // rvalue
    EXPECT_EQ("Test StringView Move", body.as<std::string_view>());
}

TEST_F(BodyTest, AssignCString) {
    const char *c_str = "Test C-String";
    body              = c_str;
    EXPECT_EQ(c_str, body.as<std::string>());
}

TEST_F(BodyTest, AssignVectorChar) {
    std::vector<char> vec = {'t', 'e', 's', 't'};
    body                  = vec;
    EXPECT_EQ("test", body.as<std::string>());

    std::vector<char> vec_move = {'m', 'o', 'v', 'e'};
    body                       = std::move(vec_move);
    EXPECT_EQ("move", body.as<std::string>());
    EXPECT_TRUE(vec_move.empty()); // Vector is cleared after move
}

TEST_F(BodyTest, AsString) {
    body << "Conve" << "rt me";
    std::string s = body.as<std::string>();
    EXPECT_EQ("Convert me", s);
}

TEST_F(BodyTest, AsStringView) {
    body << "View" << " me";
    std::string_view sv = body.as<std::string_view>();
    EXPECT_EQ("View me", sv);
}

TEST_F(BodyTest, RawAccess) {
    body << "Raw Data";
    EXPECT_EQ("Raw Data", std::string(body.raw().begin(), body.raw().end()));
    const Body &const_body = body;
    EXPECT_EQ("Raw Data", std::string(const_body.raw().begin(), const_body.raw().end()));
}

TEST_F(BodyTest, Iterators) {
    std::string data = "Iterator Test";
    body             = data;
    std::string iterated_data;
    for (char c : body) {
        iterated_data += c;
    }
    EXPECT_EQ(data, iterated_data);

    const Body  const_body = data;
    std::string const_iterated_data;
    for (char c : const_body) {
        const_iterated_data += c;
    }
    EXPECT_EQ(data, const_iterated_data);
}

TEST_F(BodyTest, JsonAssignmentAndConversion) {
    qb::json j_val = {{"key", "value"}, {"number", 123}};
    body           = j_val;

    qb::json j_parsed = body.as<qb::json>();
    EXPECT_EQ(j_val.dump(), j_parsed.dump());

    qb::json j_val_move = {{"moved", true}};
    body                = std::move(j_val_move);
    j_parsed            = body.as<qb::json>();
    EXPECT_EQ(qb::json({{"moved", true}}).dump(), j_parsed.dump());
}

// Regression: assigning a json body serializes through qb::allocator::pipe::put<json>,
// which previously narrowed numbers (get<int>/get<unsigned int>/get<float>) so a
// 64-bit integer came out as a wrong 32-bit value (e.g. an epoch-ms timestamp went
// negative) and doubles lost precision. Verify full 64-bit / double fidelity by
// parsing the serialized body back.
TEST_F(BodyTest, JsonSerializationPreserves64BitAndDouble) {
    qb::json j;
    j["i64"]   = 1782214248072LL;        // > 2^31
    j["neg64"] = -5000000000LL;          // < -2^31
    j["u64"]   = 9000000000ULL;          // > 2^32
    j["dbl"]   = 0.1;                     // not representable as float
    j["dmax"]  = 1.7976931348623157e308; // double max
    j["small"] = 7;
    j["str"]   = "hello";

    body = j;
    const qb::json parsed = qb::json::parse(body.as<std::string>());

    EXPECT_EQ(parsed["i64"].get<std::int64_t>(), 1782214248072LL);
    EXPECT_EQ(parsed["neg64"].get<std::int64_t>(), -5000000000LL);
    EXPECT_EQ(parsed["u64"].get<std::uint64_t>(), 9000000000ULL);
    EXPECT_DOUBLE_EQ(parsed["dbl"].get<double>(), 0.1);
    EXPECT_DOUBLE_EQ(parsed["dmax"].get<double>(), 1.7976931348623157e308);
    EXPECT_EQ(parsed["small"].get<int>(), 7);
    EXPECT_EQ(parsed["str"].get<std::string>(), "hello");
}

TEST_F(BodyTest, FormAssignmentAndConversion) {
    Form original_form = create_simple_form();
    body               = original_form;

    // Check serialization (this is a basic check, assumes url_encode works)
    std::string encoded_form = body.as<std::string>();
    EXPECT_NE(encoded_form.find("name=test_user"), std::string::npos);
    EXPECT_NE(encoded_form.find("email=test%40example.com"), std::string::npos); // @ is %40
    EXPECT_NE(encoded_form.find("param=value1"), std::string::npos);
    EXPECT_NE(encoded_form.find("param=value2"), std::string::npos);

    Form parsed_form = body.as<Form>();
    EXPECT_EQ(original_form.fields().size(), parsed_form.fields().size());
    EXPECT_EQ("test_user", parsed_form.get_first("name").value_or(""));
    EXPECT_EQ("test@example.com", parsed_form.get_first("email").value_or(""));
    auto params = parsed_form.get("param");
    ASSERT_EQ(2, params.size());
    EXPECT_TRUE((params[0] == "value1" && params[1] == "value2") || (params[0] == "value2" && params[1] == "value1"));

    Form form_to_move = create_simple_form();
    form_to_move.add("extra", "move_val");
    size_t original_size = form_to_move.fields().size();

    body = std::move(form_to_move);
    EXPECT_TRUE(form_to_move.empty()); // Ensure moved form is empty

    Form parsed_moved_form = body.as<Form>();
    EXPECT_EQ(original_size, parsed_moved_form.fields().size());
    EXPECT_EQ("move_val", parsed_moved_form.get_first("extra").value_or(""));
}

// Concept honesty: Form has no `pipe<char>::put<Form>` serializer, only
// `operator=<Form>`. It must therefore be excluded from `is_body_appendable`
// so that `body << form` / `Body{form}` are rejected cleanly at the concept
// gate (instead of hard-erroring deep inside `pipe::put`). Assignment is the
// only supported path and must keep round-tripping.
template <typename T>
concept BodyLeftShiftable = requires(Body b, T v) { b << v; };

TEST_F(BodyTest, FormIsAssignmentOnlyNotAppendable) {
    // Form is not advertised as appendable...
    static_assert(!Body::is_body_appendable_v<Form>, "Form must not be appendable: no pipe::put<Form> exists");
    // ...so `body << form` does not compile, while genuinely-appendable
    // types (with a matching pipe::put<>) still do.
    static_assert(!BodyLeftShiftable<Form>, "`body << form` must be rejected at the concept gate");
    static_assert(BodyLeftShiftable<std::string>, "string remains appendable");
    static_assert(BodyLeftShiftable<Chunk>, "Chunk remains appendable");
    static_assert(BodyLeftShiftable<Multipart>, "Multipart remains appendable");
    static_assert(BodyLeftShiftable<qb::json>, "json remains appendable");

    // The documented path — assignment — works and round-trips.
    Form form = create_simple_form();
    body      = form;
    Form parsed = body.as<Form>();
    EXPECT_EQ(form.fields().size(), parsed.fields().size());
    EXPECT_EQ("test_user", parsed.get_first("name").value_or(""));
}

TEST_F(BodyTest, MultipartAssignmentAndConversion) {
    Multipart original_mp = create_simple_multipart();
    body                  = original_mp;

    // Basic check: The body should contain the boundary.
    std::string body_str = body.as<std::string>();
    EXPECT_NE(body_str.find(original_mp.boundary()), std::string::npos);

    Multipart parsed_mp = body.as<Multipart>();
    EXPECT_EQ(original_mp.boundary(), parsed_mp.boundary()); // Boundary might change if not set from body
    ASSERT_EQ(original_mp.parts().size(), parsed_mp.parts().size());

    // Compare parts (basic comparison)
    for (size_t i = 0; i < original_mp.parts().size(); ++i) {
        EXPECT_EQ(original_mp.parts()[i].body, parsed_mp.parts()[i].body);
        // Header comparison can be more detailed if needed
        EXPECT_EQ(original_mp.parts()[i].headers().size(), parsed_mp.parts()[i].headers().size());
    }
}

TEST_F(BodyTest, MultipartConversionPreservesPartDataAcrossMultipleParserCallbacks) {
    const std::string boundary       = "Boundary123";
    const std::string tricky_payload = "alpha\r\n--Boundary123Xbeta\r\n--Boundary123Ygamma";

    body = "--" + boundary
           + "\r\n"
             "Content-Disposition: form-data; name=\"file\"\r\n"
             "\r\n"
           + tricky_payload + "\r\n--" + boundary + "--";

    Multipart parsed_mp = body.as<Multipart>();
    ASSERT_EQ(parsed_mp.parts().size(), 1u);
    EXPECT_EQ(parsed_mp.parts()[0].body, tricky_payload);
}

#ifdef QB_HAS_COMPRESSION
TEST_F(BodyTest, CompressionAndDecompression) {
    std::string original_data = "This is some data to compress. Repeat: This is some data to compress.";
    body                      = original_data;

    // Test GZIP
    std::size_t compressed_size_gzip = body.compress("gzip");
    EXPECT_GT(original_data.size(), compressed_size_gzip); // Expect compression
    EXPECT_NE(original_data, body.as<std::string>());      // Body is now compressed

    std::size_t decompressed_size_gzip = body.uncompress("gzip");
    EXPECT_EQ(original_data.size(), decompressed_size_gzip);
    EXPECT_EQ(original_data, body.as<std::string>()); // Body is back to original

    // Test Deflate
    body                                = original_data; // Reset body
    std::size_t compressed_size_deflate = body.compress("deflate");
    EXPECT_GT(original_data.size(), compressed_size_deflate);
    EXPECT_NE(original_data, body.as<std::string>());

    std::size_t decompressed_size_deflate = body.uncompress("deflate");
    EXPECT_EQ(original_data.size(), decompressed_size_deflate);
    EXPECT_EQ(original_data, body.as<std::string>());

    // Test with empty body
    body.clear();
    EXPECT_EQ(0, body.compress("gzip"));
    EXPECT_EQ(0, body.uncompress("gzip"));

    // Test with empty encoding (should do nothing)
    body = original_data;
    EXPECT_EQ(original_data.size(), body.compress(""));
    EXPECT_EQ(original_data, body.as<std::string>());
    EXPECT_EQ(original_data.size(), body.uncompress(""));
    EXPECT_EQ(original_data, body.as<std::string>());

    // Test unsupported encoding for compress (get_compressor_from_header throws)
    body = original_data;
    EXPECT_THROW(body.compress("unsupported_encoding"), std::runtime_error);

    // Test unsupported encoding for decompress (get_decompressor_from_header throws)
    // First, we need to "fake" a compressed body with an unknown encoding
    // This is tricky as the decompressor is chosen based on encoding string.
    // If get_decompressor_from_header throws, uncompress will throw.
    body = "fake compressed data"; // Not actually compressed with "unsupported"
    EXPECT_THROW(body.uncompress("unsupported_encoding"), std::runtime_error);

    // Test identity encoding
    body = original_data;
    EXPECT_EQ(original_data.size(), body.compress("identity"));
    EXPECT_EQ(original_data, body.as<std::string>());
    // For uncompress, "identity" is not a compression type, so get_decompressor throws
    // We'd need qb::compression::builtin::make_decompressor("identity") to return something for it to be testable here
    // Or, if "identity" is meant to be a pass-through, the current behavior of throwing is expected
    // Given the current implementation of get_decompressor_from_header, "identity" will lead to "Unsupported encoding type"
    // because make_decompressor("identity") will return nullptr.
    EXPECT_THROW(body.uncompress("identity"), std::runtime_error);
}

TEST_F(BodyTest, MultipleCompressionsDecompressions) {
    std::string original_data = "Data for multiple compressions.";
    body                      = original_data;

    body.compress("gzip");
    // Trying to compress again without decompressing might lead to issues
    // or just attempt to re-compress already compressed data.
    // The current API does not prevent this.
    // Let's assume we always decompress before another compress or operation.

    body.uncompress("gzip");
    EXPECT_EQ(original_data, body.as<std::string>());

    body.compress("deflate");
    body.uncompress("deflate");
    EXPECT_EQ(original_data, body.as<std::string>());
}
#endif // QB_HAS_COMPRESSION

TEST_F(BodyTest, FormParsingEdgeCases) {
    // Empty key
    body       = "=value";
    Form form1 = body.as<Form>();
    EXPECT_TRUE(form1.empty()); // Empty keys are typically ignored or treated as error

    // Empty value
    body       = "key=";
    Form form2 = body.as<Form>();
    EXPECT_FALSE(form2.empty());
    ASSERT_TRUE(form2.get_first("key").has_value());
    EXPECT_EQ("", form2.get_first("key").value());

    // Key only, no '='
    body       = "keyonly";
    Form form3 = body.as<Form>();
    EXPECT_FALSE(form3.empty());
    ASSERT_TRUE(form3.get_first("keyonly").has_value());
    EXPECT_EQ("", form3.get_first("keyonly").value());

    // Multiple empty values and keys
    body       = "key1=value1&=nokey&key2=";
    Form form4 = body.as<Form>();
    EXPECT_EQ(2, form4.fields().size()); // =nokey should be ignored
    EXPECT_EQ("value1", form4.get_first("key1").value_or("WRONG"));
    EXPECT_EQ("", form4.get_first("key2").value_or("WRONG"));

    // Empty body
    body       = "";
    Form form5 = body.as<Form>();
    EXPECT_TRUE(form5.empty());

    // Just an ampersand
    body       = "&";
    Form form6 = body.as<Form>();
    EXPECT_TRUE(form6.empty());

    // Leading and trailing ampersands
    body       = "&key1=value1&key2=value2&";
    Form form7 = body.as<Form>();
    EXPECT_EQ(2, form7.fields().size());
    EXPECT_EQ("value1", form7.get_first("key1").value_or("WRONG"));
    EXPECT_EQ("value2", form7.get_first("key2").value_or("WRONG"));

    // Only key-value pairs without ampersand
    body = "key1=value1key2=value2"; // This is not standard, behavior might depend on parser strictness
    // Current parser would treat "value1key2=value2" as value for key1
    Form form8 = body.as<Form>();
    EXPECT_EQ(1, form8.fields().size());
    EXPECT_EQ("value1key2=value2", form8.get_first("key1").value_or(""));
}

TEST_F(BodyTest, MultipartDetailedComparisonAndBoundaryInBody) {
    Multipart original_mp = create_simple_multipart();
    // Manually construct the body string with the boundary
    std::string boundary_str     = original_mp.boundary();
    std::string raw_body_content = "--" + boundary_str + "\r\n";
    raw_body_content += "Content-Disposition: form-data; name=\"text_field\"\r\n";
    raw_body_content += "\r\n";
    raw_body_content += "Simple text\r\n";
    raw_body_content += "--" + boundary_str + "\r\n";
    raw_body_content += "Content-Disposition: form-data; name=\"file_field\"; filename=\"test.txt\"\r\n";
    raw_body_content += "Content-Type: text/plain\r\n";
    raw_body_content += "\r\n";
    raw_body_content += "Content of the file.\r\n";
    raw_body_content += "--" + boundary_str + "--\r\n";

    body = raw_body_content;

    Multipart parsed_mp = body.as<Multipart>();
    EXPECT_EQ(boundary_str, parsed_mp.boundary());
    ASSERT_EQ(original_mp.parts().size(), parsed_mp.parts().size());

    for (size_t i = 0; i < original_mp.parts().size(); ++i) {
        const auto &original_part = original_mp.parts()[i];
        const auto &parsed_part   = parsed_mp.parts()[i];
        EXPECT_EQ(original_part.body, parsed_part.body);
        ASSERT_EQ(original_part.headers().size(), parsed_part.headers().size());
        for (const auto &header_pair : original_part.headers()) {
            EXPECT_TRUE(parsed_part.has_header(header_pair.first));
            EXPECT_EQ(original_part.header(header_pair.first), parsed_part.header(header_pair.first));
        }
    }
}

TEST_F(BodyTest, JsonErrorConditions) {
    body = "not a valid json";
    EXPECT_THROW((void) body.as<qb::json>(), qb::json::parse_error);

    body = "{\"key\": \"value\","; // Incomplete JSON
    EXPECT_THROW((void) body.as<qb::json>(), qb::json::parse_error);

    body = ""; // Empty body
    EXPECT_THROW((void) body.as<qb::json>(), qb::json::parse_error);
}

TEST_F(BodyTest, SelfAssignment) {
    body = "initial data";
    body = body; // Test self-assignment (copy)
    EXPECT_EQ("initial data", body.as<std::string>());

    Body  body2    = "other data";
    Body &body_ref = body2;
    body2          = body_ref; // Test self-assignment (copy) via reference
    EXPECT_EQ("other data", body2.as<std::string>());

    // Test self-move assignment
    // body = std::move(body); // This is problematic and usually indicates a bug in user code.
    // The standard library containers have specific behavior for self-move.
    // For qb::allocator::pipe, the behavior might depend on its specific
    // move assignment operator implementation.
    // A common outcome is that the object is left in a valid but unspecified state.
    // It's generally not a useful test unless specific guarantees are made.

    // No specific test for self-move for now as default implementation should handle it,
    // and direct self-move is often undefined behavior or leads to an unspecified state.
    // The existing move assignment test `body = std::move(s_val_move);` already tests the move mechanics.
}

TEST_F(BodyTest, ExplicitBodyConstructorsAndAssignments) {
    // Copy constructor
    Body b1 = "initial data for b1";
    Body b2 = b1;
    EXPECT_EQ("initial data for b1", b1.as<std::string>());
    EXPECT_EQ("initial data for b1", b2.as<std::string>());
    EXPECT_NE(b1.raw().begin(), b2.raw().begin()); // Should be a deep copy

    // Move constructor
    Body b3 = std::move(b1);
    EXPECT_EQ("initial data for b1", b3.as<std::string>());
    // b1 is now in a valid but unspecified state (likely empty for pipe allocator)
    EXPECT_TRUE(b1.empty() || b1.raw().begin() == nullptr);

    // Copy assignment
    Body b4 = "initial data for b4";
    Body b5 = "will be overwritten";
    b5      = b4;
    EXPECT_EQ("initial data for b4", b4.as<std::string>());
    EXPECT_EQ("initial data for b4", b5.as<std::string>());
    EXPECT_NE(b4.raw().begin(), b5.raw().begin());

    // Move assignment
    Body b6 = "will be moved";
    b5      = std::move(b6);
    EXPECT_EQ("will be moved", b5.as<std::string>());
    EXPECT_TRUE(b6.empty() || b6.raw().begin() == nullptr);

    // Variadic Args Constructor
    Body b7("Hello", " ", "World", 123);
    EXPECT_EQ("Hello World123", b7.as<std::string>());
}

TEST_F(BodyTest, BodyWithEmbeddedNulls) {
    std::string data_with_nulls = "Hello\0World";
    data_with_nulls.resize(11); // Ensure size includes the null
    body = data_with_nulls;

    EXPECT_EQ(11, body.size());
    EXPECT_FALSE(body.empty());

    std::string s_out = body.as<std::string>();
    EXPECT_EQ(11, s_out.size());
    EXPECT_EQ(data_with_nulls, s_out);

    std::string_view sv_out = body.as<std::string_view>();
    EXPECT_EQ(11, sv_out.size());
    EXPECT_EQ(data_with_nulls, sv_out);

    // Check direct raw access
    qb::allocator::pipe<char> const &raw_pipe = body.raw();
    EXPECT_EQ(11, raw_pipe.size());
    EXPECT_EQ(0, memcmp(raw_pipe.begin(), data_with_nulls.data(), 11));
}

TEST_F(BodyTest, FormEncodingDecodingComplexValues) {
    Form form;
    form.add("spaced key", "spaced value");
    form.add("plus+key", "plus+value");
    form.add("percent%key", "percent%value");
    form.add("ampersand&key", "ampersand&value");
    form.add("equals=key", "equals=value");
    form.add("unicode✓key", "unicode✓value"); // Requires UTF-8 aware URI encoding

    body                     = form;
    std::string encoded_body = body.as<std::string>();

    // Basic checks for encoding (exact encoding depends on qb::io::uri::encode)
    EXPECT_NE(encoded_body.find("spaced+key=spaced+value"), std::string::npos);
    EXPECT_NE(encoded_body.find("plus%2Bkey=plus%2Bvalue"), std::string::npos);
    EXPECT_NE(encoded_body.find("percent%25key=percent%25value"), std::string::npos);
    EXPECT_NE(encoded_body.find("ampersand%26key=ampersand%26value"), std::string::npos);
    EXPECT_NE(encoded_body.find("equals%3Dkey=equals%3Dvalue"), std::string::npos);
    EXPECT_NE(encoded_body.find("unicode%E2%9C%93key=unicode%E2%9C%93value"), std::string::npos);
    // ✓ is E2 9C 93 in UTF-8

    Form parsed_form = body.as<Form>();
    EXPECT_EQ("spaced value", parsed_form.get_first("spaced key").value_or(""));
    EXPECT_EQ("plus+value", parsed_form.get_first("plus+key").value_or(""));
    EXPECT_EQ("percent%value", parsed_form.get_first("percent%key").value_or(""));
    EXPECT_EQ("ampersand&value", parsed_form.get_first("ampersand&key").value_or(""));
    EXPECT_EQ("equals=value", parsed_form.get_first("equals=key").value_or(""));
    EXPECT_EQ("unicode✓value", parsed_form.get_first("unicode✓key").value_or(""));
}

// Note: `MultipartView` (zero-copy `std::string_view`-backed multipart)
// has been retired alongside `RequestView`/`ResponseView`. The owning
// `Multipart` is tested above and is the only supported variant.

#ifdef QB_HAS_COMPRESSION
TEST_F(BodyTest, CompressionWithChunkedEncoding) {
    std::string original_data = "Test data for chunked encoding considerations.";
    body                      = original_data;

    // get_compressor_from_header should ignore "chunked"
    EXPECT_NO_THROW(body.compress("gzip, chunked"));
    EXPECT_NE(original_data, body.as<std::string>()); // Should be gzipped
    body.uncompress("gzip");                          // Decompress with just gzip
    EXPECT_EQ(original_data, body.as<std::string>());

    body = original_data;
    EXPECT_NO_THROW(body.compress("deflate, chunked"));
    EXPECT_NE(original_data, body.as<std::string>()); // Should be deflated
    body.uncompress("deflate");
    EXPECT_EQ(original_data, body.as<std::string>());

    body = original_data;
    EXPECT_NO_THROW(body.compress("chunked, gzip")); // Order shouldn't matter for compressor
    EXPECT_NE(original_data, body.as<std::string>());
    body.uncompress("gzip");
    EXPECT_EQ(original_data, body.as<std::string>());

    // Test uncompress with "chunked"
    // get_decompressor_from_header expects "chunked" to be last if present, or throws
    body = original_data;
    body.compress("gzip"); // Compress it first
    // Valid: chunked is last (and effectively ignored by get_decompressor for choosing algorithm)
    EXPECT_NO_THROW(body.uncompress("gzip, chunked"));
    EXPECT_EQ(original_data, body.as<std::string>());

    body = original_data;
    body.compress("gzip");
    // Invalid: chunked is not last
    EXPECT_THROW(body.uncompress("chunked, gzip"), std::runtime_error);
    // Body remains compressed as uncompress threw before modification
    body.uncompress("gzip"); // cleanup
    EXPECT_EQ(original_data, body.as<std::string>());
}

TEST_F(BodyTest, DecompressionMultipleEncodingsError) {
    body = "some data";
    // get_decompressor_from_header throws if multiple actual compression algorithms are found
    EXPECT_THROW(body.uncompress("gzip, deflate"), std::runtime_error);
    EXPECT_THROW(body.uncompress("deflate, gzip"), std::runtime_error);
}
#endif // QB_HAS_COMPRESSION

TEST(BodyTryAs, StringConversionAlwaysSucceeds) {
    qb::http::Body b;
    b           = std::string("hello");
    auto result = b.try_as<std::string>();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "hello");
}

TEST(BodyTryAs, ValidJsonParses) {
    qb::http::Body b;
    b           = std::string(R"({"k":42})");
    auto result = b.try_as<qb::json>();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)["k"].get<int>(), 42);
}

TEST(BodyTryAs, MalformedJsonReturnsNulloptInsteadOfThrowing) {
    qb::http::Body b;
    b = std::string("{not valid json");
    EXPECT_NO_THROW({
        auto result = b.try_as<qb::json>();
        EXPECT_FALSE(result.has_value());
    });
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
