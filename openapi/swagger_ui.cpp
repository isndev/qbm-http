#include <unordered_map>
#include <string>
#include <utility>
#include <sstream>

namespace qb {
namespace http {
namespace openapi {
namespace ui {

/**
 * @brief Get a map of Swagger UI static files
 * 
 * In a real implementation, this would contain actual Swagger UI files.
 * For this example, we're providing stubs that indicate how it would work.
 * 
 * @return Map of file paths to (content, mime type) pairs
 */
std::unordered_map<std::string, std::pair<std::string, std::string>> getSwaggerUIFiles() {
    std::unordered_map<std::string, std::pair<std::string, std::string>> files;
    
    // In a real implementation, these would be actual file contents embedded in the binary
    // For example, using tools like incbin (https://github.com/graphitemaster/incbin)
    
    // Add mock Swagger UI files (in a real implementation, these would be the actual files)
    files["/swagger-ui.css"] = {
        "/* Mock Swagger UI CSS */",
        "text/css"
    };
    
    files["/swagger-ui-bundle.js"] = {
        "/* Mock Swagger UI bundle JS */\nconsole.log('Swagger UI Bundle loaded');",
        "application/javascript"
    };
    
    files["/swagger-ui-standalone-preset.js"] = {
        "/* Mock Swagger UI standalone preset JS */\nconsole.log('Swagger UI Preset loaded');",
        "application/javascript"
    };
    
    files["/favicon-32x32.png"] = {
        "Mock PNG data",
        "image/png"
    };
    
    // Add additional files if needed (syntax-highlighter, other assets, etc.)
    
    return files;
}

/**
 * @brief How to implement this with real Swagger UI files
 * 
 * 1. Download latest Swagger UI from the [official repository](https://github.com/swagger-api/swagger-ui/tree/master/dist)
 * 2. Use a tool like incbin or xxd to convert each file to a C++ array:
 *    
 *    #include "incbin.h"
 *    INCBIN(SwaggerUICss, "path/to/swagger-ui.css");
 *    INCBIN(SwaggerUIBundle, "path/to/swagger-ui-bundle.js");
 *    // etc...
 * 
 * 3. Modify getSwaggerUIFiles() to use these embedded files:
 *    
 *    files["/swagger-ui.css"] = {
 *        std::string(reinterpret_cast<const char*>(gSwaggerUICssData), gSwaggerUICssSize),
 *        "text/css"
 *    };
 *    // etc...
 */

} // namespace ui
} // namespace openapi
} // namespace http
} // namespace qb 