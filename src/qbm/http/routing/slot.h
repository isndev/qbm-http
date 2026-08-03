/**
 * @file qbm/http/routing/slot.h
 * @brief Strongly-typed compile-time keys for `Context` custom-data slots.
 *
 * The legacy `Context::set<T>(const std::string&, T)` / `Context::get<T>(const std::string&)`
 * API stores values as `std::any` keyed by a runtime string. It works but is footgunny:
 *
 *   - Nothing forbids `ctx->set<int>("user-id", 42)` on one site and
 *     `ctx->get<std::size_t>("user-id")` on another: the second call just
 *     silently returns `std::nullopt` at run-time.
 *   - Reads always go through `std::any_cast`, paying a type-id compare.
 *   - Key strings are untyped: nothing in the handler signature tells you
 *     what each middleware produced into the context.
 *
 * `qb::http::Slot<T>` fixes all three by encoding the value type *and* the
 * slot name at compile-time. Slots are meant to be declared once, shared
 * between the middleware that produces a value and the handler that reads
 * it, typically as `inline constexpr` globals in a shared header.
 *
 * Example:
 * @code
 * // Shared header
 * struct AuthenticatedUser { std::string id; std::string email; };
 * inline constexpr qb::http::Slot<AuthenticatedUser> kAuthUser{"auth.user"};
 *
 * // Middleware (producer)
 * void auth_middleware(auto ctx) {
 *     AuthenticatedUser u = verify_token(ctx->request());
 *     ctx->set(kAuthUser, std::move(u));       // type-checked
 *     ctx->complete(AsyncTaskResult::CONTINUE);
 * }
 *
 * // Handler (consumer)
 * void profile_handler(auto ctx) {
 *     if (const auto* user = ctx->get_if(kAuthUser)) {
 *         ctx->response().body() = user->email;   // no any_cast
 *     }
 * }
 * @endcode
 *
 * The underlying storage is the same `CustomDataMap` as the string-keyed API,
 * so mixing `ctx->set(kAuthUser, x)` and `ctx->set<AuthenticatedUser>("auth.user", x)`
 * is valid and round-trips correctly. Typed slots can therefore be introduced
 * incrementally without breaking any existing call site.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>
#include <string_view>

namespace qb::http {

/**
 * @brief Strongly-typed compile-time key for `Context` custom-data slots.
 *
 * A `Slot<T>` pairs a compile-time identifier (`name`) with the value type
 * (`T`) stored under it. See the file-level documentation for usage and
 * motivation.
 *
 * Slots are intended to be declared as `inline constexpr` globals:
 * @code
 * inline constexpr qb::http::Slot<User> kAuthUser{"auth.user"};
 * @endcode
 *
 * Two slots with the same `name` but different `T` are **different** C++
 * types, so the compiler prevents accidental cross-typing. They are *not*
 * however prevented from aliasing the same underlying map entry &mdash;
 * that is a conscious choice since we must allow interop with the legacy
 * string-keyed API and also the typed sugar for `ctx->get<T>("k")`.
 *
 * @tparam T The type of the value stored under this slot.
 */
template <typename T>
struct Slot {
    using value_type = T;

    /// Identifier used as the key in `Context::CustomDataMap`. Lifetime
    /// must outlive every `Context` that uses this slot &mdash; which is
    /// trivially the case when the slot is an `inline constexpr` global
    /// initialised from a string literal.
    std::string_view name;

    consteval explicit Slot(std::string_view n) noexcept
        : name(n) {}
    consteval explicit Slot(const char *n) noexcept
        : name(n) {}

    /// Explicit access to the slot's value type &mdash; useful for
    /// template deduction in third-party code without pulling in `Slot`
    /// itself.
    [[nodiscard]] constexpr std::string_view
    key() const noexcept {
        return name;
    }
};

namespace detail {
/// Converts a slot's `string_view` identifier into a `std::string`
/// suitable for lookup in the legacy string-keyed `CustomDataMap`.
/// Short names (the common case) remain on-stack thanks to SSO.
[[nodiscard]] inline std::string
slot_key_to_string(std::string_view name) {
    return std::string(name);
}
} // namespace detail

} // namespace qb::http
