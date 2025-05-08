#pragma once

#include <algorithm>

namespace qb {
namespace http {
namespace openapi {

template <typename Session, typename String>
DocumentGenerator& DocumentGenerator::processRouter(const Router<Session, String>& router) {
    // Process direct routes in the router
    for (const auto& method : router.getRegisteredMethods()) {
        for (const auto& route : router.getRoutes(method)) {
            // Process the route with its own path
            std::string route_path = route->getPath();
            processRoute<Session, String>(method, route, route_path);
        }
    }
    
    // Process route groups
    for (const auto& group : router.getGroups()) {
        processRouteGroup<Session, String>(*group, "");
    }
    
    // Process controllers
    for (const auto& controller : router.getControllers()) {
        processController<Session, String>(*controller, "");
    }
    
    return *this;
}

template <typename Session, typename String>
void DocumentGenerator::processRouteGroup(
    const typename Router<Session, String>::RouteGroup& group,
    const std::string& parentPrefix
) {
    // Get the group prefix
    const std::string prefix = parentPrefix + group.getPrefix();
    
    // Get the group's metadata
    const auto& group_metadata = group.getMetadata();
    
    // If the group has a specific OpenAPI tag, add it to the tags list if not already there
    const std::string& tag = group.getOpenApiTag();
    std::vector<std::string> all_tags;
    
    if (!tag.empty()) {
        // Add the tag if it doesn't exist yet
        bool tag_exists = false;
        for (const auto& existing_tag : _tags) {
            if (existing_tag.contains("name") && existing_tag["name"] == tag) {
                tag_exists = true;
                break;
            }
        }
        
        if (!tag_exists) {
            addTag(tag);
        }
        
        // Add to group tags
        all_tags.push_back(tag);
    }
    
    // Add tags from group metadata
    for (const auto& metadata_tag : group_metadata.tags) {
        if (std::find(all_tags.begin(), all_tags.end(), metadata_tag) == all_tags.end()) {
            all_tags.push_back(metadata_tag);
            
            // Also add to global tags if not already there
            bool tag_exists = false;
            for (const auto& existing_tag : _tags) {
                if (existing_tag.contains("name") && existing_tag["name"] == metadata_tag) {
                    tag_exists = true;
                    break;
                }
            }
            
            if (!tag_exists) {
                addTag(metadata_tag);
            }
        }
    }
    
    // Process all routes in this group
    for (http_method method : {HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE, HTTP_PATCH, HTTP_HEAD, HTTP_OPTIONS}) {
        for (const auto& route : group.getRoutes(method)) {
            // Get the route's own metadata
            const auto& route_metadata = route->getMetadata();
            
            // Merge group metadata with route metadata (route takes precedence)
            std::string summary = !route_metadata.summary.empty() ? route_metadata.summary : group_metadata.summary;
            std::string description = !route_metadata.description.empty() ? route_metadata.description : group_metadata.description;
            
            // Combine tags from group and route
            std::vector<std::string> combined_tags = all_tags;
            for (const auto& route_tag : route_metadata.tags) {
                if (std::find(combined_tags.begin(), combined_tags.end(), route_tag) == combined_tags.end()) {
                    combined_tags.push_back(route_tag);
                }
            }
            
            // Process the route with the full path prefix and combined metadata
            processSimpleRoute(
                method, 
                prefix + route->getPath(),
                summary,
                description,
                combined_tags,
                !route_metadata.requestBody.empty() ? route_metadata.requestBody : group_metadata.requestBody,
                !route_metadata.responses.empty() ? route_metadata.responses : group_metadata.responses,
                !route_metadata.parameters.empty() ? route_metadata.parameters : group_metadata.parameters
            );
        }
    }
    
    // Process nested sub-groups
    for (const auto& subGroup : group.getSubGroups()) {
        processRouteGroup<Session, String>(*subGroup, prefix);
    }
}

template <typename Session, typename String>
void DocumentGenerator::processController(
    const typename Router<Session, String>::Controller& controller,
    const std::string& parentPrefix
) {
    // Get the base path from the controller
    const std::string basePath = parentPrefix + controller.base_path();
    
    // Get the controller's metadata
    const auto& controller_metadata = controller.getMetadata();
    
    // Collect all tags for the controller
    std::vector<std::string> all_tags;
    
    // If the controller has a specific OpenAPI tag, add it to the tags list if not already there
    const std::string& tag = controller.getOpenApiTag();
    if (!tag.empty()) {
        // Add the tag if it doesn't exist yet
        bool tag_exists = false;
        for (const auto& existing_tag : _tags) {
            if (existing_tag.contains("name") && existing_tag["name"] == tag) {
                tag_exists = true;
                break;
            }
        }
        
        if (!tag_exists) {
            addTag(tag);
        }
        
        // Add to the controller's tags
        all_tags.push_back(tag);
    }
    
    // Add tags from controller metadata
    for (const auto& metadata_tag : controller_metadata.tags) {
        if (std::find(all_tags.begin(), all_tags.end(), metadata_tag) == all_tags.end()) {
            all_tags.push_back(metadata_tag);
            
            // Also add to global tags if not already there
            bool tag_exists = false;
            for (const auto& existing_tag : _tags) {
                if (existing_tag.contains("name") && existing_tag["name"] == metadata_tag) {
                    tag_exists = true;
                    break;
                }
            }
            
            if (!tag_exists) {
                addTag(metadata_tag);
            }
        }
    }
    
    // Process all routes in this controller
    const auto& router = controller.router();
    for (http_method method : {HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE, HTTP_PATCH, HTTP_HEAD, HTTP_OPTIONS}) {
        for (const auto& route : router.getRoutes(method)) {
            // Get the route's own metadata
            const auto& route_metadata = route->getMetadata();
            
            // Route metadata takes precedence over controller metadata
            std::string summary = route_metadata.summary;
            if (summary.empty()) {
                summary = controller_metadata.summary;
            }
            
            std::string description = route_metadata.description;
            if (description.empty()) {
                description = controller_metadata.description;
            }
            
            // Combine tags from controller and route
            std::vector<std::string> combined_tags = all_tags;
            for (const auto& route_tag : route_metadata.tags) {
                if (std::find(combined_tags.begin(), combined_tags.end(), route_tag) == combined_tags.end()) {
                    combined_tags.push_back(route_tag);
                }
            }
            
            // Process the route with the full path prefix
            processSimpleRoute(
                method, 
                basePath + route->getPath(),
                summary,
                description,
                combined_tags,
                route_metadata.requestBody.empty() ? controller_metadata.requestBody : route_metadata.requestBody,
                route_metadata.responses.empty() ? controller_metadata.responses : route_metadata.responses,
                route_metadata.parameters.empty() ? controller_metadata.parameters : route_metadata.parameters
            );
        }
    }
}

template <typename Session, typename String>
void DocumentGenerator::processRoute(
    http_method method,
    const std::unique_ptr<typename Router<Session, String>::IRoute>& route,
    const std::string& fullPath
) {
    // Get the route path
    std::string path = fullPath.empty() ? route->getPath() : fullPath;
    
    // Get the route metadata
    const auto& metadata = route->getMetadata();
    
    // Process as a simple route
    processSimpleRoute(
        method, 
        path,
        metadata.summary,
        metadata.description,
        metadata.tags,
        metadata.requestBody,
        metadata.responses,
        metadata.parameters
    );
}

template <typename Session, typename String>
qb::json DocumentGenerator::extractSecurityRequirements(
    const std::shared_ptr<MiddlewareChain<Session, String>>& middlewareChain
) const {
    // TODO: Implement security requirements extraction from middleware
    (void)middlewareChain;
    return qb::json::array();
}

} // namespace openapi
} // namespace http
} // namespace qb 