#pragma once

#include <functional>
#include <optional>
#include <string>
#include <qb/io/crypto.h>
#include "options.h"
#include "user.h"

namespace qb {
namespace http {
namespace auth {

/**
 * @brief Class for managing authentication and authorization
 *
 * This class provides methods for generating, validating, and verifying 
 * authentication tokens, as well as extracting user information.
 */
class Manager {
private:
    Options _options;

    /**
     * @brief Generate a JWT payload
     * @param user User for which to generate the token
     * @return The payload in JSON format
     */
    std::string generate_token_payload(const User &user) const;

public:
    /**
     * @brief Constructor with authentication options
     * @param options Authentication options
     */
    explicit Manager(const Options &options = Options())
        : _options(options) {}

    /**
     * @brief Generate a token for a user
     * @param user User for which to generate the token
     * @return The generated token
     */
    std::string generate_token(const User &user) const;

    /**
     * @brief Extract token from authentication header
     * @param auth_header Authentication header
     * @return The extracted token, or an empty string if the format is incorrect
     */
    std::string extract_token_from_header(const std::string &auth_header) const;

    /**
     * @brief Verify and extract information from a token
     * @param token Token to verify
     * @return User information extracted, or nullopt if the token is invalid
     */
    std::optional<User> verify_token(const std::string &token) const;

    /**
     * @brief Get the current authentication options
     * @return Reference to the authentication options
     */
    const Options &get_options() const {
        return _options;
    }

    /**
     * @brief Update the authentication options
     * @param options New authentication options
     */
    void set_options(const Options &options) {
        _options = options;
    }
};

// Type alias for backward compatibility
using AuthManager = Manager;

} // namespace auth
} // namespace http
} // namespace qb