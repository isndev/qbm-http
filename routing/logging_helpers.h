#pragma once

#include <vector>
#include <string>
#include <sstream> // For ostringstream
#include <iomanip> // For std::hex

// Ensure types used by utility functions are defined first
// Forward declarations might not be enough if an enum class value is needed for a default argument, or for sizeof, etc.
// However, to_string_for_log just takes them by value/reference.
// Let's try including the full headers that define these types before the utility namespace.

// For qb::http::RequestProcessingStage
#include "./async_types.h" 
// For qb::http::MiddlewareResult
#include "../middleware/middleware_interface.h" 

// Extern declaration for the global log vector
// This MUST be in the global namespace or correctly declared to be found by the linker
extern std::vector<std::string> adv_test_mw_middleware_execution_log;

namespace qb {
namespace http {
// Forward declare enums if their full definitions are in other headers that might create circular dependencies
// enum class RequestProcessingStage; // Definition is now in async_types.h
// class MiddlewareResult; // Definition is in middleware_interface.h

namespace utility {
    inline std::string pointer_to_string_for_log(const void* p) {
        if (!p) return "nullptr";
        std::ostringstream oss;
        oss << std::hex << reinterpret_cast<uintptr_t>(p);
        return oss.str();
    }

    inline std::string to_string_for_log(qb::http::RequestProcessingStage stage) {
        // This might need the full definition of RequestProcessingStage if not just casting.
        // For now, relying on previous simplification.
        return "StageAsInt_" + std::to_string(static_cast<int>(stage));
    }

    inline std::string to_string_for_log(qb::http::MiddlewareResult result) {
        // This relies on your manual change to result.action()
        return "ResultAsInt_" + std::to_string(static_cast<int>(result.action()));
    }

    inline std::string bool_to_string(bool b) {
        return b ? "true" : "false";
    }

} // namespace utility
} // namespace http
} // namespace qb 