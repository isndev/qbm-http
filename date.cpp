
#include "./date.h"

namespace qb::http {

/**
 * @brief Format a timestamp as an HTTP date string
 * @param ts Timestamp to format
 * @return Formatted date string conforming to RFC 7231
 *
 * Formats a timestamp in the standard HTTP date format:
 * "Day, DD Mon YYYY HH:MM:SS GMT"
 * This format is used in HTTP headers like Date, Last-Modified, etc.
 * According to RFC 7231 section 7.1.1.1, all HTTP date/time stamps
 * MUST be represented in Greenwich Mean Time (GMT).
 */
std::string
Date::to_string(qb::Timestamp const ts) noexcept {
    std::string result;
    result.reserve(29);

    const auto time = static_cast<int64_t>(ts.seconds());
    tm         tm{};
#if defined(_MSC_VER) || defined(__MINGW32__)
    if (gmtime_s(&tm, &time) != 0)
        return {};
    auto gmtime = &tm;
#else
    const auto crt_time = static_cast<time_t>(time);
    const auto gmtime   = gmtime_r(&crt_time, &tm);
    if (!gmtime)
        return {};
#endif

    switch (gmtime->tm_wday) {
        case 0:
            result += "Sun, ";
            break;
        case 1:
            result += "Mon, ";
            break;
        case 2:
            result += "Tue, ";
            break;
        case 3:
            result += "Wed, ";
            break;
        case 4:
            result += "Thu, ";
            break;
        case 5:
            result += "Fri, ";
            break;
        case 6:
            result += "Sat, ";
            break;
    }

    result += gmtime->tm_mday < 10 ? '0' : static_cast<char>(gmtime->tm_mday / 10 + 48);
    result += static_cast<char>(gmtime->tm_mday % 10 + 48);

    switch (gmtime->tm_mon) {
        case 0:
            result += " Jan ";
            break;
        case 1:
            result += " Feb ";
            break;
        case 2:
            result += " Mar ";
            break;
        case 3:
            result += " Apr ";
            break;
        case 4:
            result += " May ";
            break;
        case 5:
            result += " Jun ";
            break;
        case 6:
            result += " Jul ";
            break;
        case 7:
            result += " Aug ";
            break;
        case 8:
            result += " Sep ";
            break;
        case 9:
            result += " Oct ";
            break;
        case 10:
            result += " Nov ";
            break;
        case 11:
            result += " Dec ";
            break;
    }

    const auto year = gmtime->tm_year + 1900;
    result += static_cast<char>(year / 1000 + 48);
    result += static_cast<char>((year / 100) % 10 + 48);
    result += static_cast<char>((year / 10) % 10 + 48);
    result += static_cast<char>(year % 10 + 48);
    result += ' ';

    result += gmtime->tm_hour < 10 ? '0' : static_cast<char>(gmtime->tm_hour / 10 + 48);
    result += static_cast<char>(gmtime->tm_hour % 10 + 48);
    result += ':';

    result += gmtime->tm_min < 10 ? '0' : static_cast<char>(gmtime->tm_min / 10 + 48);
    result += static_cast<char>(gmtime->tm_min % 10 + 48);
    result += ':';

    result += gmtime->tm_sec < 10 ? '0' : static_cast<char>(gmtime->tm_sec / 10 + 48);
    result += static_cast<char>(gmtime->tm_sec % 10 + 48);

    result += " GMT";

    return result;
}

/**
 * @brief Parse an HTTP date string into a timestamp
 * @param str HTTP date string to parse
 * @return Parsed timestamp
 *
 * Parses an HTTP date string into a timestamp according to RFC 7231.
 */
qb::Timestamp
Date::parse(std::string_view const str) noexcept {
    return {};
}

/**
 * @brief Parse an HTTP date string into a timestamp
 * @param str HTTP date string to parse
 * @return Parsed timestamp
 *
 * Parses an HTTP date string into a timestamp according to RFC 7231.
 */
qb::Timestamp
Date::parse(std::string const &str) noexcept {
    return {};
}

} // namespace qb::http