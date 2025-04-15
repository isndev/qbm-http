#include "./cors_options.h"

namespace qb::http {

void
CorsOptions::ensure_patterns_compiled() const {
    if (_match_strategy == OriginMatchStrategy::Regex && !_patterns_compiled) {
        _regex_patterns.clear();
        for (const auto &pattern : _origins) {
            _regex_patterns.emplace_back(pattern);
        }
        _patterns_compiled = true;
    }
}

CorsOptions::CorsOptions() {
    _origins = {"*"}; // By default, allow all origins
}

CorsOptions::CorsOptions(std::vector<std::string> origins)
    : _origins(std::move(origins)) {}

CorsOptions &
CorsOptions::origins(std::vector<std::string> origins) {
    _origins           = std::move(origins);
    _patterns_compiled = false; // Reset compiled patterns
    return *this;
}

CorsOptions &
CorsOptions::origin_patterns(std::vector<std::string> patterns) {
    _origins           = std::move(patterns);
    _match_strategy    = OriginMatchStrategy::Regex;
    _patterns_compiled = false;
    return *this;
}

CorsOptions &
CorsOptions::origin_matcher(std::function<bool(const std::string &)> matcher) {
    _origin_matcher = std::move(matcher);
    _match_strategy = OriginMatchStrategy::Function;
    return *this;
}

CorsOptions &
CorsOptions::methods(std::vector<std::string> methods) {
    _methods = std::move(methods);
    return *this;
}

CorsOptions &
CorsOptions::all_methods() {
    _methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};
    return *this;
}

CorsOptions &
CorsOptions::headers(std::vector<std::string> headers) {
    _headers = std::move(headers);
    return *this;
}

CorsOptions &
CorsOptions::common_headers() {
    _headers = {"Content-Type",     "Authorization", "Accept",      "Origin",
                "X-Requested-With", "X-Auth-Token",  "X-CSRF-Token"};
    return *this;
}

CorsOptions &
CorsOptions::expose(std::vector<std::string> headers) {
    _expose_headers = std::move(headers);
    return *this;
}

CorsOptions &
CorsOptions::credentials(AllowCredentials allow) {
    _credentials = allow;
    return *this;
}

CorsOptions &
CorsOptions::age(int age) {
    _max_age = age;
    return *this;
}

CorsOptions
CorsOptions::permissive() {
    return CorsOptions().all_methods().common_headers().credentials(
        AllowCredentials::Yes);
}

CorsOptions
CorsOptions::secure(const std::vector<std::string> &allowed_origins) {
    return CorsOptions(allowed_origins)
        .methods({"GET", "POST", "PUT", "DELETE"})
        .headers({"Content-Type", "Authorization"})
        .credentials(AllowCredentials::Yes);
}

const std::vector<std::string> &
CorsOptions::origins() const {
    return _origins;
}

bool
CorsOptions::allow_all_origins() const {
    return !_origins.empty() && _origins[0] == "*";
}

bool
CorsOptions::is_origin_allowed(const std::string &origin) const {
    if (origin.empty())
        return false;

    // If using a custom function strategy, use it regardless of allow_all_origins
    if (_match_strategy == OriginMatchStrategy::Function) {
        return _origin_matcher && _origin_matcher(origin);
    }

    // If using wildcard origins without a custom function, allow all
    if (allow_all_origins())
        return true;

    switch (_match_strategy) {
        case OriginMatchStrategy::Exact:
            for (const auto &allowed_origin : _origins) {
                if (origin == allowed_origin) {
                    return true;
                }
            }
            return false;

        case OriginMatchStrategy::Regex:
            ensure_patterns_compiled();
            for (const auto &pattern : _regex_patterns) {
                if (std::regex_match(origin, pattern)) {
                    return true;
                }
            }
            return false;

        default:
            return false;
    }
}

const std::vector<std::string> &
CorsOptions::allowed_methods() const {
    return _methods;
}

const std::vector<std::string> &
CorsOptions::allowed_headers() const {
    return _headers;
}

const std::vector<std::string> &
CorsOptions::exposed_headers() const {
    return _expose_headers;
}

CorsOptions::AllowCredentials
CorsOptions::allow_credentials() const {
    return _credentials;
}

int
CorsOptions::max_age() const {
    return _max_age;
}

CorsOptions::OriginMatchStrategy
CorsOptions::match_strategy() const {
    return _match_strategy;
}

} // namespace qb::http