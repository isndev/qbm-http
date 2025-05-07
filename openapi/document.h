#pragma once

#include <qb/json.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <regex>
#include "../routing/router.h"

namespace qb {
namespace http {
namespace openapi {

/**
 * @brief OpenAPI document generator
 * 
 * Generates OpenAPI/Swagger documentation from HTTP routes.
 */
class DocumentGenerator {
public:
    /**
     * @brief Constructor with basic API info
     * @param title API title
     * @param version API version
     * @param description API description
     */
    DocumentGenerator(
        const std::string& title = "API Documentation",
        const std::string& version = "1.0.0",
        const std::string& description = ""
    );
    
    /**
     * @brief Set API title
     * @param title API title
     * @return Reference to this generator
     */
    DocumentGenerator& setTitle(const std::string& title);
    
    /**
     * @brief Set API version
     * @param version API version
     * @return Reference to this generator
     */
    DocumentGenerator& setVersion(const std::string& version);
    
    /**
     * @brief Set API description
     * @param description API description
     * @return Reference to this generator
     */
    DocumentGenerator& setDescription(const std::string& description);
    
    /**
     * @brief Set API contact information
     * @param name Contact name
     * @param email Contact email
     * @param url Contact URL
     * @return Reference to this generator
     */
    DocumentGenerator& setContact(const std::string& name, const std::string& email, const std::string& url);
    
    /**
     * @brief Set API license information
     * @param name License name
     * @param url License URL
     * @return Reference to this generator
     */
    DocumentGenerator& setLicense(const std::string& name, const std::string& url);
    
    /**
     * @brief Add a server to the API
     * @param url Server URL
     * @param description Server description
     * @return Reference to this generator
     */
    DocumentGenerator& addServer(const std::string& url, const std::string& description = "");
    
    /**
     * @brief Add Bearer JWT authentication
     * @param name Security scheme name
     * @param scheme Authentication scheme type
     * @param bearerFormat Bearer format (e.g., JWT)
     * @return Reference to this generator
     */
    DocumentGenerator& addBearerAuth(
        const std::string& name = "bearerAuth", 
        const std::string& scheme = "bearer", 
        const std::string& bearerFormat = "JWT"
    );
    
    /**
     * @brief Add API key authentication
     * @param name Security scheme name
     * @param in Location of the API key (header, query, cookie)
     * @param paramName Name of the parameter
     * @return Reference to this generator
     */
    DocumentGenerator& addApiKeyAuth(
        const std::string& name, 
        const std::string& in, 
        const std::string& paramName
    );
    
    /**
     * @brief Process a router to extract routes
     * @param router Router to process
     * @return Reference to this generator
     */
    template <typename Session, typename String>
    DocumentGenerator& processRouter(const Router<Session, String>& router);
    
    /**
     * @brief Add API tag
     * @param name Tag name
     * @param description Tag description
     * @return Reference to this generator
     */
    DocumentGenerator& addTag(const std::string& name, const std::string& description = "");
    
    /**
     * @brief Add a custom path specification
     * @param path Path to add
     * @param pathSpec Path specification
     * @return Reference to this generator
     */
    DocumentGenerator& addPathSpecification(const std::string& path, const qb::json& pathSpec);
    
    /**
     * @brief Add a schema definition to the components section
     * @param name Schema name
     * @param schema Schema definition
     * @return Reference to this generator
     */
    DocumentGenerator& addSchemaDefinition(const std::string& name, const qb::json& schema);
    
    /**
     * @brief Generate OpenAPI document as JSON object
     * @return JSON object containing the OpenAPI document
     */
    qb::json generateDocument() const;
    
    /**
     * @brief Generate OpenAPI document as JSON string
     * @param pretty Whether to pretty-print the JSON
     * @return JSON string
     */
    std::string generateJson(bool pretty = true) const;
    
    /**
     * @brief Process a route group
     * @param group Route group to process
     * @param parentPrefix Parent path prefix
     */
    template <typename Session, typename String>
    void processRouteGroup(
        const typename Router<Session, String>::RouteGroup& group, 
        const std::string& parentPrefix = ""
    );
    
    /**
     * @brief Process a route controller
     * @param controller Controller to process
     * @param parentPrefix Parent path prefix
     */
    template <typename Session, typename String>
    void processController(
        const typename Router<Session, String>::Controller& controller, 
        const std::string& parentPrefix = ""
    );
    
    /**
     * @brief Process a route
     * @param method HTTP method
     * @param route Route to process
     * @param fullPath Optional full path override
     */
    template <typename Session, typename String>
    void processRoute(
        http_method method,
        const std::unique_ptr<typename Router<Session, String>::IRoute>& route,
        const std::string& fullPath = ""
    );
    
    /**
     * @brief Process a route without accessing internal members
     * @param method HTTP method
     * @param path Route path
     * @param summary Route summary
     * @param description Route description
     * @param tags Route tags
     * @param requestBody Request body schema
     * @param responses Response schemas
     * @param parameters Additional parameters
     * @return Reference to this generator
     */
    DocumentGenerator& processSimpleRoute(
        http_method method,
        const std::string& path,
        const std::string& summary = "",
        const std::string& description = "",
        const std::vector<std::string>& tags = {},
        const qb::json& requestBody = qb::json::object(),
        const qb::json& responses = qb::json::object(),
        const qb::json& parameters = qb::json::array()
    );
    
    /**
     * @brief Extract security requirements from a middleware chain
     * @param middlewareChain Middleware chain to process
     * @return Security requirements object
     */
    template <typename Session, typename String>
    qb::json extractSecurityRequirements(
        const std::shared_ptr<MiddlewareChain<Session, String>>& middlewareChain
    ) const;
    
private:
    qb::json _info;               ///< API info object
    qb::json _servers;            ///< API servers array
    qb::json _paths;              ///< API paths object
    qb::json _components;         ///< API components object
    qb::json _tags;               ///< API tags array
    
    /**
     * @brief Initialize the OpenAPI document structure
     */
    void initialize();
    
    /**
     * @brief Normalize a path for OpenAPI compatibility
     * @param path Path to normalize
     * @return Normalized path
     */
    std::string normalizePath(const std::string& path) const;
    
    /**
     * @brief Extract path parameters from a path
     * @param path Path to extract from
     * @return Array of path parameter objects
     */
    qb::json extractPathParameters(const std::string& path) const;
    
    /**
     * @brief Convert HTTP method enum to string
     * @param method HTTP method
     * @return Method as string
     */
    std::string methodToString(http_method method) const;
};

} // namespace openapi
} // namespace http
} // namespace qb

// Include the implementation for template methods
#include "document.tpp" 