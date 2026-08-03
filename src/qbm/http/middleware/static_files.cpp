/**
 * @file qbm/http/middleware/static_files.cpp
 * @brief Out-of-line definitions for the static-file serving middleware.
 *
 * Houses the non-template helper bodies declared in `static_files.h`: the
 * `StaticFilesOptions` constructor and the `qb::http::internal` filesystem,
 * MIME, ETag, range-parsing and directory-listing helpers. The
 * `StaticFilesMiddleware` class template and the `static_files_middleware`
 * factory template remain header-only by design.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./static_files.h"

namespace qb::http {

StaticFilesOptions::StaticFilesOptions(std::filesystem::path root_dir)
    : root_directory(std::move(root_dir)) {
    // Pre-populate with common MIME types
    mime_types[".html"]  = "text/html; charset=utf-8";
    mime_types[".htm"]   = "text/html; charset=utf-8";
    mime_types[".css"]   = "text/css; charset=utf-8";
    mime_types[".js"]    = "application/javascript; charset=utf-8";
    mime_types[".json"]  = "application/json; charset=utf-8";
    mime_types[".xml"]   = "application/xml; charset=utf-8";
    mime_types[".txt"]   = "text/plain; charset=utf-8";
    mime_types[".jpg"]   = "image/jpeg";
    mime_types[".jpeg"]  = "image/jpeg";
    mime_types[".png"]   = "image/png";
    mime_types[".gif"]   = "image/gif";
    mime_types[".svg"]   = "image/svg+xml";
    mime_types[".ico"]   = "image/x-icon";
    mime_types[".woff"]  = "font/woff";
    mime_types[".woff2"] = "font/woff2";
    mime_types[".ttf"]   = "font/ttf";
    mime_types[".eot"]   = "application/vnd.ms-fontobject";
    mime_types[".otf"]   = "font/otf";
    mime_types[".pdf"]   = "application/pdf";
    mime_types[".zip"]   = "application/zip";
    mime_types[".gz"]    = "application/gzip";
    mime_types[".tar"]   = "application/x-tar";
    mime_types[".mp4"]   = "video/mp4";
    mime_types[".webm"]  = "video/webm";
    mime_types[".mp3"]   = "audio/mpeg";
    mime_types[".ogg"]   = "audio/ogg";
    mime_types[".wav"]   = "audio/wav";
}

namespace internal {

bool
if_none_match_contains(std::string_view if_none_match, std::string_view current_etag) noexcept {
    if_none_match = trim_optional_whitespace(if_none_match);
    if (if_none_match == "*") {
        return true;
    }

    current_etag = trim_optional_whitespace(current_etag);
    if (current_etag.size() > 2 && current_etag.substr(0, 2) == "W/") {
        current_etag.remove_prefix(2);
    }

    while (!if_none_match.empty()) {
        const auto comma_pos = if_none_match.find(',');
        auto candidate = trim_optional_whitespace(comma_pos == std::string_view::npos ? if_none_match : if_none_match.substr(0, comma_pos));

        if (candidate == "*") {
            return true;
        }

        if (candidate.size() > 2 && candidate.substr(0, 2) == "W/") {
            candidate.remove_prefix(2);
        }

        if (candidate == current_etag) {
            return true;
        }

        if (comma_pos == std::string_view::npos) {
            break;
        }
        if_none_match.remove_prefix(comma_pos + 1);
    }

    return false;
}

std::filesystem::path
sanitize_and_resolve_path(const std::filesystem::path &base_path, std::string_view original_relative_path_sv) {
    // base_path is assumed to be canonical already from StaticFilesMiddleware constructor
    const std::filesystem::path &canonical_base_path = base_path;

    // (1) URL-decode path bytes. A literal '+' is valid in a URI path
    // and must not be interpreted as a space.
    std::string decoded = qb::http::utility::decode_path_component(original_relative_path_sv);

    // (2) A NUL byte inside a path is never legitimate for static-file
    // serving. Reject immediately rather than relying on OS-specific
    // APIs to notice the truncation.
    if (decoded.find('\0') != std::string::npos) {
        return {};
    }

    std::string_view decoded_view{decoded};

    const size_t     first_char_pos    = decoded_view.find_first_not_of('/');
    std::string_view path_to_append_sv = (first_char_pos == std::string_view::npos) ? std::string_view{} : decoded_view.substr(first_char_pos);

    std::filesystem::path relative_candidate{path_to_append_sv};

    // (3) After stripping the leading slashes the path must be relative.
    // If the platform interprets the remainder as absolute (e.g. a
    // Windows drive letter sneaked in via encoding) we refuse.
    if (relative_candidate.is_absolute()) {
        return {};
    }

    std::filesystem::path relative_part = relative_candidate.lexically_normal();

    std::filesystem::path combined_path;
    if (relative_part.empty() || relative_part == std::filesystem::path(".")) {
        combined_path = canonical_base_path; // Accessing the root itself
    } else {
        combined_path = canonical_base_path / relative_part;
    }

    // (4) Resolve symlinks, `.` and `..` against the real filesystem.
    std::error_code       ec_canonical;
    std::filesystem::path fully_resolved_path = std::filesystem::weakly_canonical(combined_path, ec_canonical);

    if (ec_canonical) {
        return {};
    }

    // (5) Prefix check with separator boundary.
    const std::string resolved_str = fully_resolved_path.string();
    const std::string base_str     = canonical_base_path.string();

    if (std::string_view(resolved_str).starts_with(base_str)) {
        if (resolved_str.length() == base_str.length()) {
            return fully_resolved_path; // base itself
        }
        if (resolved_str.length() > base_str.length() && resolved_str[base_str.length()] == std::filesystem::path::preferred_separator) {
            return fully_resolved_path;
        }
    }

    return {}; // Path escapes the base directory.
}

std::string
get_mime_type_for_file(const std::filesystem::path &file_path, const StaticFilesOptions &opts) {
    std::string ext = file_path.extension().string();
    if (!ext.empty()) {
        // Locale-independent ASCII lowercasing: file extensions are
        // ASCII by contract, we explicitly avoid std::tolower whose
        // behaviour varies with the current C locale (F52).
        for (char &c : ext) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') {
                c = static_cast<char>(uc | 0x20);
            }
        }
        auto it = opts.mime_types.find(ext);
        if (it != opts.mime_types.end()) {
            return it->second;
        }
    }
    return opts.default_mime_type;
}

std::optional<std::pair<long long, long long>>
parse_byte_range(std::string_view range_header_value, long long total_file_size) noexcept {
    if (total_file_size <= 0) {
        return std::nullopt;
    }

    constexpr std::string_view prefix = "bytes=";
    if (!range_header_value.starts_with(prefix)) {
        return std::nullopt;
    }
    const std::string_view range_spec = range_header_value.substr(prefix.size());
    if (range_spec.empty()) {
        return std::nullopt;
    }

    // Multi-range is not supported and must be rejected, not silently
    // interpreted as the first range only.
    if (range_spec.find(',') != std::string_view::npos) {
        return std::nullopt;
    }

    const auto dash_pos = range_spec.find('-');
    if (dash_pos == std::string_view::npos) {
        return std::nullopt;
    }

    // Strictly parse a non-negative decimal integer (digits only, no
    // sign, no whitespace, no leading zeroes tolerated).
    const auto parse_u64 = [](std::string_view token) -> std::optional<long long> {
        if (token.empty()) {
            return std::nullopt;
        }
        long long value = 0;
        for (char c : token) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
            const long long digit = c - '0';
            // Overflow guard: LLONG_MAX / 10 - 1 to leave headroom.
            if (value > (std::numeric_limits<long long>::max() - digit) / 10) {
                return std::nullopt;
            }
            value = value * 10 + digit;
        }
        return value;
    };

    const std::string_view start_tok = range_spec.substr(0, dash_pos);
    const std::string_view end_tok   = range_spec.substr(dash_pos + 1);

    if (!start_tok.empty() && !end_tok.empty()) {
        const auto start_opt = parse_u64(start_tok);
        const auto end_opt   = parse_u64(end_tok);
        if (!start_opt || !end_opt)
            return std::nullopt;
        long long start = *start_opt;
        long long end   = *end_opt;
        if (start > end || start >= total_file_size)
            return std::nullopt;
        end = std::min(end, total_file_size - 1);
        return std::make_pair(start, (end - start) + 1);
    }

    if (!start_tok.empty()) {
        const auto start_opt = parse_u64(start_tok);
        if (!start_opt)
            return std::nullopt;
        long long start = *start_opt;
        if (start >= total_file_size)
            return std::nullopt;
        return std::make_pair(start, total_file_size - start);
    }

    const auto suffix_opt = parse_u64(end_tok);
    if (!suffix_opt)
        return std::nullopt;

    const long long suffix = *suffix_opt;
    if (suffix <= 0)
        return std::nullopt;
    if (suffix >= total_file_size) {
        return std::make_pair(0LL, total_file_size);
    }
    return std::make_pair(total_file_size - suffix, suffix);
}

std::string
generate_directory_listing_html(const std::filesystem::path &directory_path,
                                std::string_view             request_uri_path, // The original URI path for link construction
                                const StaticFilesOptions    &opts) {
    std::ostringstream html;

    std::string dir_display_name_str = directory_path.filename().string();
    // If filename is empty (e.g. path was "/foo/") or "." (e.g. path was "/foo/."), try parent's filename.
    if ((dir_display_name_str.empty() || dir_display_name_str == ".") && directory_path.has_parent_path()) {
        // For a path like "/base/subdir/." or "/base/subdir/", parent_path is "/base/subdir", filename is "subdir"
        // For a path like "/base/.", parent_path is "/base", filename is "base"
        // For root like "/.", parent_path is "/", filename is "" or "/" depending on system.
        // We need to be careful if directory_path itself is the root_directory.
        std::filesystem::path parent_of_current_dir = directory_path.parent_path();
        if (directory_path.lexically_normal() == opts.root_directory.lexically_normal()
            || (parent_of_current_dir.empty() || parent_of_current_dir == directory_path)) {
            // at root
            // If it's the root directory of the static files, display a generic name or root indicator
            dir_display_name_str = opts.root_directory.filename().string(); // or simply "/" or "Root"
            if (dir_display_name_str.empty() || dir_display_name_str == ".")
                dir_display_name_str = "/";
        } else {
            dir_display_name_str = parent_of_current_dir.filename().string();
        }
    }
    if (dir_display_name_str.empty() && request_uri_path.length() > 1) {
        // Fallback for root if path was "/"
        dir_display_name_str = "/";
    }

    html << "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
         << "<title>Index of " << utility::escape_html(dir_display_name_str) << "</title>\n"
         << "<style>body{font-family: sans-serif;} table{border-collapse: collapse; width:80%; margin: 20px auto;} th,td{border:1px solid "
            "#ddd; padding:8px; text-align:left;} th{background-color:#f2f2f2;} a{text-decoration:none; color:#007bff;} "
            "a:hover{text-decoration:underline;}</style>\n"
         << "</head>\n<body>\n"
         << "<h1>Index of " << utility::escape_html(dir_display_name_str) << "</h1>\n"
         << "<table>\n<tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>\n";

    // Normalize request_uri_path: ensure it ends with a slash for correct relative links
    std::string base_link_path = std::string(request_uri_path);
    if (base_link_path.empty() || base_link_path.back() != '/') {
        base_link_path += '/';
    }

    // Parent directory link, if not at the root_directory of the options
    if (directory_path != opts.root_directory && directory_path.has_parent_path()) {
        html << "<tr><td><a href=\"../\">../</a></td><td>-</td><td>-</td></tr>\n";
    }

    std::error_code ec;
    for (const auto &entry : std::filesystem::directory_iterator(directory_path, ec)) {
        if (ec)
            continue; // Skip entries we can't iterate

        std::string file_name = entry.path().filename().string();
        std::string link_name = utility::escape_html(file_name);
        if (entry.is_directory(ec)) {
            link_name += "/";
        }
        if (ec)
            continue;

        html << "<tr><td><a href=\"" << base_link_path << utility::uri_encode_component(file_name) << (entry.is_directory(ec) ? "/\"" : "\"")
             << ">" << link_name << "</a></td>";

        if (entry.is_regular_file(ec)) {
            html << "<td>" << std::filesystem::file_size(entry, ec) << "</td>";
        } else {
            html << "<td>-</td>";
        }
        if (ec) {
            html << "<td>-</td>";
        } // Reset if error during size or type check for this entry

        auto last_write = std::filesystem::last_write_time(entry, ec);
        if (!ec) {
            // Convert file_time_type to system_clock::time_point for to_string
            auto sctp_for_to_string = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                last_write - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
            html << "<td>" << qb::http::date::to_string(sctp_for_to_string) << "</td>";
        } else {
            html << "<td>-</td>";
        }
        html << "</tr>\n";
    }
    if (ec) {
        // Error during iteration itself
        html << "<tr><td colspan=\"3\">Error reading directory contents.</td></tr>\n";
    }

    html << "</table>\n</body>\n</html>";
    return html.str();
}

} // namespace internal
} // namespace qb::http
