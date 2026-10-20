/**
 * @file qbm/http/detail/redirect.h
 * @brief Internal URI resolution for opt-in HTTP redirects.
 *
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#pragma once

#include <optional>
#include <string_view>

#include <qb/io/uri.h>

namespace qb::http {
class Request;
class Response;
} // namespace qb::http

namespace qb::http::detail {

/**
 * @brief Resolve a Location against an absolute HTTP(S) base, preserving encoded component bytes.
 * @return An owning URI, or nullopt for an invalid reference or an unsupported destination.
 * @note Userinfo, scoped IP literals and IPvFuture are refused. An absent Location fragment inherits
 *       the base fragment. Origin, downgrade and method policy belong to the redirect chain.
 *       Allocation failures from this resolver's temporary strings can propagate.
 */
[[nodiscard]] std::optional<qb::io::uri> resolve_redirect_location(const qb::io::uri &base, std::string_view location);

/** @brief Apply redirect method, body and origin policy to the logical request. */
[[nodiscard]] bool prepare_redirect(Request &request, const Response &response, bool allow_cross_origin);

} // namespace qb::http::detail
