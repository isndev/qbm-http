#include <gtest/gtest.h>

#include "../headers.h"

TEST(HeadersUtility, AcceptEncodingDoesNotAdvertiseChunked) {
    const std::string advertised = qb::http::accept_encoding();
    EXPECT_EQ(advertised.find("chunked"), std::string::npos);
}

TEST(HeadersUtility, ContentEncodingRespectsQZero) {
    const std::string first_supported = qb::http::content_encoding("*");
    if (first_supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    const std::string header = first_supported + ";q=0";
    EXPECT_TRUE(qb::http::content_encoding(header).empty());
}

TEST(HeadersUtility, WildcardDoesNotReenableExplicitlyDisabledEncoding) {
    const std::string first_supported = qb::http::content_encoding("*");
    if (first_supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    const std::string header = first_supported + ";q=0, *;q=1";
    const std::string selected = qb::http::content_encoding(header);

    EXPECT_TRUE(selected.empty() || selected != first_supported);
}
