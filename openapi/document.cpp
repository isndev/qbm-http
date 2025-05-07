#include "document.h"
#include <regex>
#include <sstream>

namespace qb {
namespace http {
namespace openapi {

DocumentGenerator::DocumentGenerator(
    const std::string& title,
    const std::string& version,
    const std::string& description
) {
    initialize();
    
    // Initialiser les informations de l'API
    setTitle(title);
    setVersion(version);
    if (!description.empty()) {
        setDescription(description);
    }
}

void DocumentGenerator::initialize() {
    // Initialiser les structures de données
    _info = qb::json::object();
    _servers = qb::json::array();
    _paths = qb::json::object();
    _components = qb::json::object();
    _tags = qb::json::array();
}

DocumentGenerator& DocumentGenerator::setTitle(const std::string& title) {
    _info["title"] = title;
    return *this;
}

DocumentGenerator& DocumentGenerator::setVersion(const std::string& version) {
    _info["version"] = version;
    return *this;
}

DocumentGenerator& DocumentGenerator::setDescription(const std::string& description) {
    _info["description"] = description;
    return *this;
}

DocumentGenerator& DocumentGenerator::setContact(
    const std::string& name,
    const std::string& email,
    const std::string& url
) {
    qb::json contact = qb::json::object();
    
    if (!name.empty()) {
        contact["name"] = name;
    }
    
    if (!email.empty()) {
        contact["email"] = email;
    }
    
    if (!url.empty()) {
        contact["url"] = url;
    }
    
    if (!contact.empty()) {
        _info["contact"] = contact;
    }
    
    return *this;
}

DocumentGenerator& DocumentGenerator::setLicense(
    const std::string& name,
    const std::string& url
) {
    qb::json license = qb::json::object();
    
    if (!name.empty()) {
        license["name"] = name;
    }
    
    if (!url.empty()) {
        license["url"] = url;
    }
    
    if (!license.empty()) {
        _info["license"] = license;
    }
    
    return *this;
}

DocumentGenerator& DocumentGenerator::addServer(
    const std::string& url,
    const std::string& description
) {
    if (_servers.empty()) {
        _servers = qb::json::array();
    }
    
    qb::json server = {{"url", url}};
    if (!description.empty()) {
        server["description"] = description;
    }
    
    _servers.push_back(server);
    return *this;
}

DocumentGenerator& DocumentGenerator::addBearerAuth(
    const std::string& name,
    const std::string& scheme,
    const std::string& bearerFormat
) {
    if (!_components.contains("securitySchemes")) {
        _components["securitySchemes"] = qb::json::object();
    }
    
    qb::json securityScheme = {
        {"type", "http"},
        {"scheme", scheme}
    };
    
    if (!bearerFormat.empty()) {
        securityScheme["bearerFormat"] = bearerFormat;
    }
    
    _components["securitySchemes"][name] = securityScheme;
    return *this;
}

DocumentGenerator& DocumentGenerator::addApiKeyAuth(
    const std::string& name,
    const std::string& in,
    const std::string& paramName
) {
    if (!_components.contains("securitySchemes")) {
        _components["securitySchemes"] = qb::json::object();
    }
    
    _components["securitySchemes"][name] = {
        {"type", "apiKey"},
        {"in", in},
        {"name", paramName}
    };
    
    return *this;
}

DocumentGenerator& DocumentGenerator::addTag(
    const std::string& name,
    const std::string& description
) {
    if (_tags.empty()) {
        _tags = qb::json::array();
    }
    
    qb::json tag = {{"name", name}};
    if (!description.empty()) {
        tag["description"] = description;
    }
    
    // Check if tag already exists
    bool exists = false;
    for (const auto& existingTag : _tags) {
        if (existingTag["name"] == name) {
            exists = true;
            break;
        }
    }
    
    if (!exists) {
        _tags.push_back(tag);
    }
    
    return *this;
}

DocumentGenerator& DocumentGenerator::addPathSpecification(
    const std::string& path,
    const qb::json& pathSpec
) {
    _paths[path] = pathSpec;
    return *this;
}

DocumentGenerator& DocumentGenerator::addSchemaDefinition(
    const std::string& name,
    const qb::json& schema
) {
    if (!_components.contains("schemas")) {
        _components["schemas"] = qb::json::object();
    }
    
    _components["schemas"][name] = schema;
    return *this;
}

qb::json DocumentGenerator::generateDocument() const {
    qb::json doc = {
        {"openapi", "3.0.0"},
        {"info", _info},
        {"paths", _paths}
    };
    
    // Add servers if present
    if (!_servers.empty()) {
        doc["servers"] = _servers;
    }
    
    // Add tags if present
    if (!_tags.empty()) {
        doc["tags"] = _tags;
    }
    
    // Add components if present
    if (!_components.empty()) {
        doc["components"] = _components;
    }
    
    return doc;
}

std::string DocumentGenerator::generateJson(bool pretty) const {
    qb::json doc = generateDocument();
    
    if (pretty) {
        return doc.dump(4);
    } else {
        return doc.dump();
    }
}

std::string DocumentGenerator::normalizePath(const std::string& path) const {
    if (path.empty()) {
        return "/";
    }
    
    std::string result = path;
    
    // Ensure path starts with '/'
    if (result[0] != '/') {
        result = "/" + result;
    }
    
    // Remove trailing slash if present (except for root path)
    if (result.length() > 1 && result.back() == '/') {
        result.pop_back();
    }
    
    return result;
}

qb::json DocumentGenerator::extractPathParameters(const std::string& path) const {
    qb::json params = qb::json::array();
    
    // Extract parameters using regex (colon format - :param)
    std::regex paramRegex(":([a-zA-Z0-9_]+)");
    std::string::const_iterator start = path.begin();
    std::string::const_iterator end = path.end();
    std::smatch matches;
    
    while (std::regex_search(start, end, matches, paramRegex)) {
        std::string paramName = matches[1].str();
        
        qb::json param = {
            {"name", paramName},
            {"in", "path"},
            {"required", true},
            {"schema", {
                {"type", "string"}
            }}
        };
        
        params.push_back(param);
        
        // Continue searching from where the last match ended
        start = matches[0].second;
    }
    
    return params;
}

std::string DocumentGenerator::methodToString(http_method method) const {
    switch (method) {
        case HTTP_GET:
            return "get";
        case HTTP_POST:
            return "post";
        case HTTP_PUT:
            return "put";
        case HTTP_DELETE:
            return "delete";
        case HTTP_PATCH:
            return "patch";
        case HTTP_HEAD:
            return "head";
        case HTTP_OPTIONS:
            return "options";
        default:
            return "get";  // Default to GET if unknown
    }
}

DocumentGenerator& DocumentGenerator::processSimpleRoute(
    http_method method,
    const std::string& path,
    const std::string& summary,
    const std::string& description,
    const std::vector<std::string>& tags,
    const qb::json& requestBody,
    const qb::json& responses,
    const qb::json& parameters
) {
    // Normalize the path
    std::string normalizedPath = normalizePath(path);
    
    // Extract path parameters and replace with OpenAPI format
    std::string openapiPath = normalizedPath;
    std::regex paramRegex(":([a-zA-Z0-9_]+)");
    openapiPath = std::regex_replace(openapiPath, paramRegex, "{$1}");
    
    // Get the method as string
    std::string methodStr = methodToString(method);
    
    // Create path item if it doesn't exist
    if (!_paths.contains(openapiPath)) {
        _paths[openapiPath] = qb::json::object();
    }
    
    // Create operation object
    qb::json operation = qb::json::object();
    
    // Add summary and description if available
    if (!summary.empty()) {
        operation["summary"] = summary;
    }
    
    if (!description.empty()) {
        operation["description"] = description;
    }
    
    // Always add tags as an array, even if empty
    operation["tags"] = qb::json::array();
    if (!tags.empty()) {
        for (const auto& tag : tags) {
            operation["tags"].push_back(tag);
        }
    }
    
    // Add request body if available
    if (!requestBody.is_null() && !requestBody.empty()) {
        operation["requestBody"] = requestBody;
    }
    
    // Add responses if available
    if (!responses.is_null() && !responses.empty()) {
        operation["responses"] = responses;
    } else {
        // Add default responses
        operation["responses"] = {
            {"200", {
                {"description", "Successful operation"}
            }}
        };
    }
    
    // Add parameters if available
    if (!parameters.is_null() && !parameters.empty()) {
        operation["parameters"] = parameters;
    }
    
    // Add path parameters
    qb::json pathParams = extractPathParameters(normalizedPath);
    if (!pathParams.empty()) {
        if (!operation.contains("parameters")) {
            operation["parameters"] = qb::json::array();
        }
        
        for (const auto& param : pathParams) {
            operation["parameters"].push_back(param);
        }
    }
    
    // Add the operation to the path
    _paths[openapiPath][methodStr] = operation;
    
    return *this;
}

} // namespace openapi
} // namespace http
} // namespace qb 