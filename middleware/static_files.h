/**
 * @file qbm/http/middleware/static_files.h
 * @brief Defines the StaticFilesMiddleware class for serving static files.
 *
 * This file contains the definition of the StaticFilesMiddleware class,
 * which is used to serve static files from a given directory.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <iostream> // Added for logging
#include <memory>
#include <string>
#include <vector>
#include <filesystem> // Requires C++17
#include <fstream>
#include <sstream>
#include <system_error> // For std::error_code
#include <chrono>
#include <optional>

#include <qb/system/container/unordered_map.h>
#include "../routing/middleware.h"
#include "../request.h"
#include "../response.h"
#include "../types.h" // For qb::http::status
#include "../utility.h" // For string utilities if needed

namespace qb::http {
    /**
     * @brief Configuration options for the StaticFilesMiddleware.
     */
    class StaticFilesOptions {
    public:
        std::filesystem::path root_directory;
        bool serve_index_file = true;
        std::string index_file_name = "index.html";
        std::string default_mime_type = "application/octet-stream";
        std::string path_prefix_to_strip; // e.g., "/static"
        qb::unordered_map<std::string, std::string> mime_types;
        bool set_cache_control_header = true;
        std::string cache_control_value = "public, max-age=3600"; // Default 1 hour
        bool enable_etags = true;
        bool enable_last_modified = true;
        bool enable_range_requests = true; // New option for Range Requests
        bool enable_directory_listing = false; // New option for Directory Listing (default false for security)

        StaticFilesOptions(std::filesystem::path root_dir)
            : root_directory(std::move(root_dir)) {
            // Pre-populate with common MIME types
            mime_types[".html"] = "text/html; charset=utf-8";
            mime_types[".htm"] = "text/html; charset=utf-8";
            mime_types[".css"] = "text/css; charset=utf-8";
            mime_types[".js"] = "application/javascript; charset=utf-8";
            mime_types[".json"] = "application/json; charset=utf-8";
            mime_types[".xml"] = "application/xml; charset=utf-8";
            mime_types[".txt"] = "text/plain; charset=utf-8";
            mime_types[".jpg"] = "image/jpeg";
            mime_types[".jpeg"] = "image/jpeg";
            mime_types[".png"] = "image/png";
            mime_types[".gif"] = "image/gif";
            mime_types[".svg"] = "image/svg+xml";
            mime_types[".ico"] = "image/x-icon";
            mime_types[".woff"] = "font/woff";
            mime_types[".woff2"] = "font/woff2";
            mime_types[".ttf"] = "font/ttf";
            mime_types[".eot"] = "application/vnd.ms-fontobject";
            mime_types[".otf"] = "font/otf";
            mime_types[".pdf"] = "application/pdf";
            mime_types[".zip"] = "application/zip";
            mime_types[".gz"] = "application/gzip";
            mime_types[".tar"] = "application/x-tar";
            mime_types[".mp4"] = "video/mp4";
            mime_types[".webm"] = "video/webm";
            mime_types[".mp3"] = "audio/mpeg";
            mime_types[".ogg"] = "audio/ogg";
            mime_types[".wav"] = "audio/wav";
        }

        StaticFilesOptions &with_root_directory(std::filesystem::path root_dir) {
            this->root_directory = std::move(root_dir);
            return *this;
        }

        StaticFilesOptions &with_serve_index_file(bool serve) {
            this->serve_index_file = serve;
            return *this;
        }

        StaticFilesOptions &with_index_file_name(std::string name) {
            this->index_file_name = std::move(name);
            return *this;
        }

        StaticFilesOptions &with_default_mime_type(std::string type) {
            this->default_mime_type = std::move(type);
            return *this;
        }

        StaticFilesOptions &with_path_prefix_to_strip(std::string prefix) {
            this->path_prefix_to_strip = std::move(prefix);
            return *this;
        }

        StaticFilesOptions &add_mime_type(const std::string &extension, const std::string &mime_type_value) {
            mime_types[extension] = mime_type_value;
            return *this;
        }

        StaticFilesOptions &with_cache_control(bool enabled, std::string value = "public, max-age=3600") {
            set_cache_control_header = enabled;
            if (enabled) {
                cache_control_value = std::move(value);
            }
            return *this;
        }

        StaticFilesOptions &with_etags(bool enabled) {
            enable_etags = enabled;
            return *this;
        }

        StaticFilesOptions &with_last_modified(bool enabled) {
            enable_last_modified = enabled;
            return *this;
        }

        StaticFilesOptions &with_range_requests(bool enabled) {
            enable_range_requests = enabled;
            return *this;
        }

        StaticFilesOptions &with_directory_listing(bool enabled) {
            enable_directory_listing = enabled;
            return *this;
        }
    };

    namespace internal {
        // Helper to normalize a path and prevent directory traversal.
        // Returns an empty path if traversal is detected or path is invalid.
        inline std::filesystem::path
        sanitize_and_resolve_path(const std::filesystem::path &base_path, std::string_view original_relative_path_sv) {
            // base_path is assumed to be canonical already from StaticFilesMiddleware constructor
            const std::filesystem::path &canonical_base_path = base_path;

            size_t first_char_pos = original_relative_path_sv.find_first_not_of('/');
            std::string_view path_to_append_sv = (first_char_pos == std::string_view::npos)
                                                     ? std::string_view{}
                                                     : original_relative_path_sv.substr(first_char_pos);

            std::filesystem::path relative_part = std::filesystem::path(path_to_append_sv).lexically_normal();

            std::filesystem::path combined_path;
            if (relative_part.empty() || relative_part == std::filesystem::path(".")) {
                combined_path = canonical_base_path; // Accessing the root itself
            } else {
                combined_path = canonical_base_path / relative_part;
            }

            std::error_code ec_canonical;
            std::filesystem::path fully_resolved_path = std::filesystem::weakly_canonical(combined_path, ec_canonical);

            if (ec_canonical) {
                return {};
            }

            // Security check: Ensure the *fully resolved* path is still within or equal to the *canonical_base_path*.
            // Convert both to strings for a robust prefix check that handles symlink differences in parent paths.
            std::string resolved_str = fully_resolved_path.string();
            std::string base_str = canonical_base_path.string();

            if (resolved_str.rfind(base_str, 0) == 0) {
                // Check if resolved_str starts with base_str
                // Further check: if base_str is "/a/b" and resolved_str is "/a/b_c", it's not a subdirectory match.
                // The resolved path must be base_str itself or base_str + "/" + something_else.
                if (resolved_str.length() == base_str.length()) {
                    return fully_resolved_path; // It's the base directory itself
                }
                if (resolved_str.length() > base_str.length() && resolved_str[base_str.length()] ==
                    std::filesystem::path::preferred_separator) {
                    return fully_resolved_path; // It's a subdirectory or file within base
                }
            }

            return {}; // Path is outside the base directory.
        }

        inline std::string get_mime_type_for_file(const std::filesystem::path &file_path,
                                                  const StaticFilesOptions &opts) {
            std::string ext = file_path.extension().string();
            if (!ext.empty()) {
                // Convert extension to lowercase for case-insensitive map lookup
                // std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                // Using a loop for wider compatibility if ::tolower isn't suitable for all char types directly
                for (char &c: ext) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                auto it = opts.mime_types.find(ext);
                if (it != opts.mime_types.end()) {
                    return it->second;
                }
            }
            return opts.default_mime_type;
        }

        // Helper to parse a single byte range from the Range header
        // Supports: "bytes=start-end", "bytes=start-", "bytes=-suffixLength"
        // Returns {start_offset, length_to_read}, or nullopt if invalid/unsupported
        inline std::optional<std::pair<long long, long long> >
        parse_byte_range(std::string_view range_header_value, long long total_file_size) {
            if (range_header_value.rfind("bytes=", 0) != 0) {
                // Must start with "bytes="
                return std::nullopt;
            }
            std::string_view range_spec = range_header_value.substr(6); // Skip "bytes="

            size_t dash_pos = range_spec.find('-');
            if (dash_pos == std::string_view::npos) {
                return std::nullopt; // Invalid format
            }

            long long start = -1, end = -1;

            // Parse start part (before dash)
            std::string start_str(range_spec.substr(0, dash_pos));
            if (!start_str.empty()) {
                try {
                    size_t parsed_chars_start = 0;
                    start = std::stoll(start_str, &parsed_chars_start);
                    if (parsed_chars_start != start_str.length()) return std::nullopt;
                    // Ensure all of start_str was number
                } catch (const std::out_of_range &) { return std::nullopt; }
                catch (const std::invalid_argument &) { return std::nullopt; }
            }

            // Parse end part (after dash)
            std::string end_str(range_spec.substr(dash_pos + 1));
            if (!end_str.empty()) {
                try {
                    size_t parsed_chars_end = 0;
                    end = std::stoll(end_str, &parsed_chars_end);
                    if (parsed_chars_end != end_str.length()) return std::nullopt; // Ensure all of end_str was number
                } catch (const std::out_of_range &) { return std::nullopt; }
                catch (const std::invalid_argument &) { return std::nullopt; }
            }

            if (start != -1 && end != -1) {
                // bytes=start-end
                if (start > end || start >= total_file_size) return std::nullopt;
                end = std::min(end, total_file_size - 1);
                return std::make_pair(start, (end - start) + 1);
            } else if (start != -1) {
                // bytes=start-
                if (start >= total_file_size) return std::nullopt;
                return std::make_pair(start, total_file_size - start);
            } else if (end != -1) {
                // bytes=-suffixLength (end here means suffix length)
                if (end == 0 || end > total_file_size) return std::nullopt;
                return std::make_pair(total_file_size - end, end);
            } else {
                return std::nullopt; // Invalid like "bytes=-"
            }
        }

        // Helper to generate HTML for directory listing
        inline std::string generate_directory_listing_html(
            const std::filesystem::path &directory_path,
            std::string_view request_uri_path, // The original URI path for link construction
            const StaticFilesOptions &opts
        ) {
            std::ostringstream html;

            std::string dir_display_name_str = directory_path.filename().string();
            // If filename is empty (e.g. path was "/foo/") or "." (e.g. path was "/foo/."), try parent's filename.
            if ((dir_display_name_str.empty() || dir_display_name_str == ".") && directory_path.has_parent_path()) {
                // For a path like "/base/subdir/." or "/base/subdir/", parent_path is "/base/subdir", filename is "subdir"
                // For a path like "/base/.", parent_path is "/base", filename is "base"
                // For root like "/.", parent_path is "/", filename is "" or "/" depending on system.
                // We need to be careful if directory_path itself is the root_directory.
                std::filesystem::path parent_of_current_dir = directory_path.parent_path();
                if (directory_path.lexically_normal() == opts.root_directory.lexically_normal() ||
                    (parent_of_current_dir.empty() || parent_of_current_dir == directory_path)) {
                    // at root
                    // If it's the root directory of the static files, display a generic name or root indicator
                    dir_display_name_str = opts.root_directory.filename().string(); // or simply "/" or "Root"
                    if (dir_display_name_str.empty() || dir_display_name_str == ".") dir_display_name_str = "/";
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
                    <<
                    "<style>body{font-family: sans-serif;} table{border-collapse: collapse; width:80%; margin: 20px auto;} th,td{border:1px solid #ddd; padding:8px; text-align:left;} th{background-color:#f2f2f2;} a{text-decoration:none; color:#007bff;} a:hover{text-decoration:underline;}</style>\n"
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
            for (const auto &entry: std::filesystem::directory_iterator(directory_path, ec)) {
                if (ec) continue; // Skip entries we can't iterate

                std::string file_name = entry.path().filename().string();
                std::string link_name = utility::escape_html(file_name);
                if (entry.is_directory(ec)) {
                    link_name += "/";
                }
                if (ec) continue;

                html << "<tr><td><a href=\"" << base_link_path << utility::uri_encode_component(file_name)
                        << (entry.is_directory(ec) ? "/\"" : "\"") << ">" << link_name << "</a></td>";

                if (entry.is_regular_file(ec)) {
                    html << "<td>" << std::filesystem::file_size(entry, ec) << "</td>";
                } else {
                    html << "<td>-</td>";
                }
                if (ec) { html << "<td>-</td>"; } // Reset if error during size or type check for this entry

                auto last_write = std::filesystem::last_write_time(entry, ec);
                if (!ec) {
                    // Convert file_time_type to system_clock::time_point for to_string
                    auto sctp_for_to_string = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        last_write - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
                    );
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

    /**
     * @brief Middleware for serving static files from the filesystem.
     *
     * @tparam SessionType The type of the session object.
     */
    template<typename SessionType>
    class StaticFilesMiddleware : public IMiddleware<SessionType> {
    public:
        using ContextPtr = std::shared_ptr<Context<SessionType> >;

        explicit StaticFilesMiddleware(StaticFilesOptions options, std::string name = "StaticFilesMiddleware")
            : _options(std::move(options)), _name(std::move(name)) {
            if (_options.root_directory.empty()) {
                throw std::invalid_argument("StaticFilesOptions::root_directory cannot be empty.");
            }
            std::error_code ec;
            if (!std::filesystem::exists(_options.root_directory, ec) || !std::filesystem::is_directory(
                    _options.root_directory, ec)) {
                if (ec) {
                    throw std::runtime_error(
                        "Error checking StaticFilesOptions::root_directory: " + _options.root_directory.string() + " - "
                        + ec.message());
                } else {
                    throw std::runtime_error(
                        "StaticFilesOptions::root_directory does not exist or is not a directory: " + _options.
                        root_directory.string());
                }
            }
            // Normalize AND canonicalize root_directory to ensure consistent path comparisons and operations.
            _options.root_directory = std::filesystem::canonical(_options.root_directory, ec);
            if (ec) {
                throw std::runtime_error(
                    "Failed to get canonical path for root_directory: " + _options.root_directory.string() + " - " + ec.
                    message());
            }
        }

        void process(ContextPtr ctx) override {
            std::string_view request_path_sv = ctx->request().uri().path();
            std::filesystem::path target_file_abs;

            // Optimization: Handle HEAD requests early if possible, or ensure body is not sent.
            bool is_head_request = ctx->request().method() == qb::http::method::HEAD;

            std::string_view effective_request_path_sv = request_path_sv;

            if (!_options.path_prefix_to_strip.empty()) {
                if (request_path_sv.rfind(_options.path_prefix_to_strip, 0) == 0) {
                    effective_request_path_sv.remove_prefix(_options.path_prefix_to_strip.length());
                } else {
                    ctx->complete(AsyncTaskResult::CONTINUE); // Let other handlers try
                    return;
                }
            }

            target_file_abs = internal::sanitize_and_resolve_path(
                _options.root_directory,
                effective_request_path_sv
            );

            if (target_file_abs.empty()) {
                // Path traversal or invalid path detected by sanitize_and_resolve_path
                send_error_response(ctx, qb::http::status::FORBIDDEN, "Forbidden");
                return;
            }

            // Check existence and type
            std::error_code ec_exists, ec_is_dir, ec_is_reg, ec_idx_exists, ec_idx_is_reg;

            bool path_exists = std::filesystem::exists(target_file_abs, ec_exists);

            if (ec_exists) {
                // Error during exists check
                send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR, "Error accessing file system.");
                return;
            }
            if (!path_exists) {
                // File or directory does not exist
                send_error_response(ctx, qb::http::status::NOT_FOUND, "File not found");
                return;
            }

            bool is_dir = std::filesystem::is_directory(target_file_abs, ec_is_dir);

            if (ec_is_dir) {
                // Error during is_directory check
                send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR,
                                    "Error accessing file system attributes.");
                return;
            }

            bool is_regular = false;
            if (!is_dir) {
                // Only check is_regular_file if not a directory
                is_regular = std::filesystem::is_regular_file(target_file_abs, ec_is_reg);
                if (ec_is_reg) {
                    send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR,
                                        "Error accessing file system attributes.");
                    return;
                }
            }

            if (is_dir) {
                // Explicitly a directory, try to serve index or list
                if (_options.serve_index_file && !_options.index_file_name.empty()) {
                    std::filesystem::path index_file_path = target_file_abs / _options.index_file_name;

                    bool index_exists = std::filesystem::exists(index_file_path, ec_idx_exists);

                    bool index_is_reg = false;
                    if (!ec_idx_exists && index_exists) {
                        index_is_reg = std::filesystem::is_regular_file(index_file_path, ec_idx_is_reg);
                    }

                    if (!ec_idx_exists && index_exists && !ec_idx_is_reg && index_is_reg) {
                        target_file_abs = index_file_path; // Now target the index file
                        is_dir = false; // Treat as if we're serving a file now
                        is_regular = true; // The index file is regular
                    }
                }

                if (is_dir) {
                    // Still a directory (index not found/served or not enabled)
                    if (_options.enable_directory_listing) {
                        std::string listing_html = internal::generate_directory_listing_html(
                            target_file_abs, request_path_sv, _options);
                        ctx->response().status() = qb::http::status::OK;
                        ctx->response().set_header("Content-Type", "text/html; charset=utf-8");
                        ctx->response().set_header("Content-Length", std::to_string(listing_html.length()));
                        if (_options.set_cache_control_header) {
                            // Apply cache control for directory listing too
                            ctx->response().set_header("Cache-Control", _options.cache_control_value);
                            // Or a different policy for listings?
                        }
                        if (is_head_request) {
                            ctx->response().body().clear();
                        } else {
                            ctx->response().body() = listing_html;
                        }
                        ctx->complete(AsyncTaskResult::COMPLETE);
                        return;
                    } else if (is_dir) {
                        // serve_index_file was false or index not found, AND directory listing disabled
                        send_error_response(ctx, qb::http::status::FORBIDDEN, "Directory listing not allowed.");
                        return;
                    }
                }
            }

            // At this point, target_file_abs refers to a regular file (either originally, or an index file)
            // and is_dir is false.
            if (!is_regular) {
                // Should not happen if logic above is correct and it's not a dir
                send_error_response(ctx, qb::http::status::NOT_FOUND, "Requested resource is not a regular file.");
                return;
            }

            // ETag and Last-Modified handling
            std::string etag_value;
            std::filesystem::file_time_type last_modified_time;

            if (_options.enable_etags || _options.enable_last_modified) {
                std::error_code file_stat_ec;
                auto file_size_for_cond = std::filesystem::file_size(target_file_abs, file_stat_ec);
                if (file_stat_ec) {
                    send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR,
                                        "Error getting file metadata for cache headers");
                    return;
                }
                last_modified_time = std::filesystem::last_write_time(target_file_abs, file_stat_ec);
                if (file_stat_ec) {
                    send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR,
                                        "Error getting file last write time for cache headers");
                    return;
                }

                if (_options.enable_etags) {
                    // Simple ETag: combination of size and last modified time (as seconds since epoch)
                    auto last_modified_sys_tp_for_etag = std::chrono::time_point_cast<
                        std::chrono::system_clock::duration>(
                        last_modified_time - std::filesystem::file_time_type::clock::now() +
                        std::chrono::system_clock::now()
                    );
                    auto last_modified_epoch_sec = std::chrono::duration_cast<std::chrono::seconds>(
                        last_modified_sys_tp_for_etag.time_since_epoch()).count();
                    etag_value = "\"" + std::to_string(file_size_for_cond) + "-" + std::to_string(
                                     last_modified_epoch_sec) + "\"";
                    ctx->response().set_header("ETag", etag_value);

                    std::string_view if_none_match_sv = ctx->request().header("If-None-Match");
                    if (!if_none_match_sv.empty()) {
                        // Basic check, more robust parsing might be needed for multiple ETags or weak ETags
                        // Example: split by comma for lists of ETags
                        if (if_none_match_sv.find(etag_value) != std::string_view::npos) {
                            // Check if our ETag is in the list
                            send_not_modified_response(ctx);
                            return;
                        }
                    }
                }

                if (_options.enable_last_modified) {
                    // Convert file_time_type to system_clock::time_point for to_string and comparison
                    auto last_modified_sys_tp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        last_modified_time - std::filesystem::file_time_type::clock::now() +
                        std::chrono::system_clock::now()
                    );
                    std::string last_modified_str = qb::http::date::to_string(last_modified_sys_tp);
                    // Uses your existing date formatter
                    ctx->response().set_header("Last-Modified", last_modified_str);

                    std::string_view if_modified_since_sv = ctx->request().header("If-Modified-Since");
                    if (!if_modified_since_sv.empty()) {
                        auto if_modified_since_tp_opt = qb::http::date::parse_http_date(if_modified_since_sv);
                        if (if_modified_since_tp_opt) {
                            // Precision of last_modified_time from filesystem might be higher than HTTP date.
                            // Truncate last_modified_time (as system_clock::time_point) to seconds for comparison.
                            auto last_modified_sec_precision = std::chrono::time_point_cast<std::chrono::seconds>(
                                last_modified_sys_tp);
                            auto if_modified_since_sec_precision = std::chrono::time_point_cast<std::chrono::seconds>(
                                *if_modified_since_tp_opt);

                            if (last_modified_sec_precision <= if_modified_since_sec_precision) {
                                send_not_modified_response(ctx);
                                return;
                            }
                        }
                    }
                }
            }

            if (_options.enable_range_requests) {
                ctx->response().set_header("Accept-Ranges", "bytes");
            }

            std::ifstream file_stream(target_file_abs, std::ios::binary | std::ios::ate);
            if (!file_stream.is_open()) {
                send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR, "Could not open file");
                return;
            }

            long long full_file_size = static_cast<long long>(file_stream.tellg());
            file_stream.seekg(0, std::ios::beg);

            long long offset = 0;
            long long length_to_read = full_file_size;
            bool is_range_request = false;
            bool should_send_416 = false;

            std::string_view range_header_sv = ctx->request().header("Range");

            if (_options.enable_range_requests) {
                // Range requests ARE enabled
                ctx->response().set_header("Accept-Ranges", "bytes");
                if (!range_header_sv.empty() && !is_head_request) {
                    auto parsed_range_opt = internal::parse_byte_range(range_header_sv, full_file_size);
                    if (parsed_range_opt) {
                        offset = parsed_range_opt->first;
                        length_to_read = parsed_range_opt->second;
                        is_range_request = true;
                        ctx->response().status() = qb::http::status::PARTIAL_CONTENT;
                        std::string content_range_val = "bytes " + std::to_string(offset) + "-" +
                                                        std::to_string(offset + length_to_read - 1) + "/" +
                                                        std::to_string(full_file_size);
                        ctx->response().set_header("Content-Range", content_range_val);
                    } else {
                        // Range header present and unparseable/unsatisfiable
                        should_send_416 = true;
                    }
                } // else (no range header or HEAD request) -> is_range_request remains false, serve full file.
            } else {
                // Range requests are DISABLED.
                // Ensure is_range_request is false, and no range-specific headers are set.
                is_range_request = false; // Explicitly ensure it's false
                should_send_416 = false; // No 416 if ranges are disabled
                ctx->response().headers().erase("Accept-Ranges");
                ctx->response().headers().erase("Content-Range");
            }

            if (should_send_416) {
                // This implies range requests were enabled and an issue occurred
                send_range_not_satisfiable_response(ctx, full_file_size);
                return;
            }

            // If it's not a (successful) range request, serve the full file with 200 OK.
            if (!is_range_request) {
                offset = 0;
                length_to_read = full_file_size;
                ctx->response().status() = qb::http::status::OK;
            }

            std::string mime_type = internal::get_mime_type_for_file(target_file_abs, _options);

            if (!is_range_request) {
                // For full requests or if range processing was skipped/failed to become a range request
                ctx->response().status() = qb::http::status::OK;
            }
            // Content-Type is always needed, for 200 or 206
            ctx->response().set_header("Content-Type", mime_type);
            ctx->response().set_header("Content-Length", std::to_string(length_to_read));
            // Length of actual data being sent

            if (_options.set_cache_control_header && !_options.cache_control_value.empty()) {
                ctx->response().set_header("Cache-Control", _options.cache_control_value);
            }

            // Only set Accept-Ranges if range requests are enabled.
            if (_options.enable_range_requests) {
                ctx->response().set_header("Accept-Ranges", "bytes");
            }

            if (is_head_request) {
                ctx->response().body().clear(); // Ensure body is empty for HEAD
                ctx->complete(AsyncTaskResult::COMPLETE);
                return;
            }

            // Seek to the correct offset if it's a range request
            if (is_range_request) {
                file_stream.seekg(offset, std::ios::beg);
                if (file_stream.fail()) {
                    send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR,
                                        "Error seeking in file for range request");
                    return;
                }
            }

            // Efficiently read file to response body's underlying pipe
            auto &response_body_pipe = ctx->response().body().raw();
            response_body_pipe.clear(); // Ensure it's empty

            if (length_to_read > 0) {
                response_body_pipe.allocate_back(static_cast<size_t>(length_to_read));
                // Read exactly length_to_read bytes
                if (!file_stream.read(response_body_pipe.begin(), length_to_read)) {
                    // Error reading file or read less than expected (should not happen if size checks were correct)
                    response_body_pipe.clear();
                    send_error_response(ctx, qb::http::status::INTERNAL_SERVER_ERROR,
                                        "Error reading file content for range/full");
                    return;
                }
            }

            ctx->complete(AsyncTaskResult::COMPLETE);
        }

        std::string name() const override {
            return _name;
        }

        void cancel() override {
            // No specific cancellation for synchronous file I/O
        }

    private:
        StaticFilesOptions _options;
        std::string _name;

        void send_error_response(ContextPtr ctx, qb::http::status status, const std::string &message) {
            ctx->response().status() = status;
            ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
            // For HEAD requests with errors, body should still be set for consistency,
            // but it won't be sent by the underlying transport.
            // Or, one might choose to clear it if is_head_request.
            // The current qb::http::Server logic likely handles not sending body for HEAD.
            ctx->response().body() = message;
            ctx->complete(AsyncTaskResult::COMPLETE);
        }

        void send_not_modified_response(ContextPtr ctx) {
            ctx->response().status() = qb::http::status::NOT_MODIFIED;
            // Key headers for 304: Date, ETag (if used), Cache-Control, Expires, Vary.
            // Content-* headers should be omitted.
            // The ETag and Last-Modified headers would have already been set by the calling logic.
            // Cache-Control would also have been set if applicable.
            // Ensure Content-Type, Content-Length, etc. are cleared or not sent for 304.
            // The qb::http::Response class or server layer should handle this distinction.
            // For safety, we can clear them here from the perspective of the middleware's responsibility.
            ctx->response().headers().erase("Content-Type");
            ctx->response().headers().erase("Content-Length");
            // Add other headers that should be removed for 304?
            // Transfer-Encoding, Content-Encoding?
            // For now, these two are the most critical.
            ctx->response().body().clear();
            ctx->complete(AsyncTaskResult::COMPLETE);
        }

        void send_range_not_satisfiable_response(ContextPtr ctx, long long total_file_size) {
            ctx->response().status() = qb::http::status::RANGE_NOT_SATISFIABLE;
            ctx->response().set_header("Content-Range", "bytes */" + std::to_string(total_file_size));
            // According to RFC 7231, a 416 response SHOULD NOT include other representation metadata.
            // Content-Type is often omitted or kept minimal.
            ctx->response().headers().erase("Content-Type"); // Remove if previously set
            ctx->response().headers().erase("ETag");
            ctx->response().headers().erase("Last-Modified");
            ctx->response().body().clear();
            ctx->complete(AsyncTaskResult::COMPLETE);
        }
    };


    /**
     * @brief Factory function to create a StaticFilesMiddleware instance.
     * @tparam SessionType The session type.
     * @param options Configuration options for serving static files.
     * @param name Optional name for the middleware.
     * @return A shared pointer to the created StaticFilesMiddleware.
     */
    template<typename SessionType>
    std::shared_ptr<StaticFilesMiddleware<SessionType> >
    static_files_middleware(
        StaticFilesOptions options,
        const std::string &name = "StaticFilesMiddleware"
    ) {
        return std::make_shared<StaticFilesMiddleware<SessionType> >(std::move(options), name);
    }
} // namespace qb::http 
