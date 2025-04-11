
#pragma once

#include <qb/io/uri.h>
#include "headers.h"
#include "body.h"

namespace qb::http {

namespace internal {

/**
 * @brief Base class for HTTP messages
 * @tparam String String type (std::string or std::string_view)
 * 
 * Common base class for both Request and Response message types.
 */
template <typename String>
struct MessageBase
    : public THeaders<String>
    , Body {
    using string_type = String;

    uint16_t major_version;
    uint16_t minor_version;

    bool upgrade{};

    /**
     * @brief Default constructor
     * 
     * Initializes a message with HTTP/1.1
     */
    MessageBase() noexcept
        : major_version(1)
        , minor_version(1) {
        reset();
    }

    /**
     * @brief Copy constructor
     * @param other Message to copy from
     * 
     * Creates a deep copy of another message including all headers and body content.
     * This ensures each message instance maintains its own independent data.
     */
    MessageBase(MessageBase const &) = default;
    
    /**
     * @brief Constructor with headers and body
     * @param headers Headers map
     * @param body Message body
     */
    MessageBase(qb::icase_unordered_map<std::vector<String>> headers, Body body)
        : THeaders<String>(std::move(headers))
        , Body(std::move(body))
        , major_version(1)
        , minor_version(1) {}
    
    /**
     * @brief Move constructor
     * @param other Message to move from
     * 
     * Efficiently transfers ownership of resources from the source message
     * to this message without copying data.
     */
    MessageBase(MessageBase &&) noexcept = default;
    
    /**
     * @brief Copy assignment operator
     * @param other Message to copy from
     * @return Reference to this message
     * 
     * Creates a deep copy of the source message including all headers
     * and body content.
     */
    MessageBase &operator=(MessageBase const &) = default;
    
    /**
     * @brief Move assignment operator
     * @param other Message to move from
     * @return Reference to this message
     * 
     * Efficiently transfers ownership of resources from the source message
     * to this message without copying data, and releases any previous
     * resources held by this message.
     */
    MessageBase &operator=(MessageBase &&) noexcept = default;

    /**
     * @brief Reset the message state
     * 
     * Clears all headers while preserving body content.
     */
    void
    reset() {
        this->_headers.clear();
    };

public:
    /**
     * @brief Get the body object
     * @return Reference to the body
     */
    [[nodiscard]] inline Body &
    body() {
        return static_cast<Body &>(*this);
    }

    /**
     * @brief Get the body object (const)
     * @return Const reference to the body
     */
    [[nodiscard]] inline Body const &
    body() const {
        return static_cast<Body const &>(*this);
    }
};

} // namespace internal

}
