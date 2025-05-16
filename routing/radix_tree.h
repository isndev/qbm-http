#pragma once

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <regex>
#include "./path_parameters.h"
#include "./logging_helpers.h" // For utility::pointer_to_string_for_log etc.

namespace qb::http {

// Forward declare Controller and IRoute to be used in RadixMatchResult
// This assumes they are defined in a way that allows forward declaration here.
// If they are complex templates, this might need adjustment or inclusion of their headers.
// For now, using void* and a type enum is safer if full types are problematic here.
// template <typename Session, typename String> class IRoute;
// template <typename Session, typename String> class Controller;

/**
 * @brief Structure to hold detailed results of a Radix tree match.
 */
struct RadixMatchResult {
    enum class TargetType { NONE, HANDLER, CONTROLLER };
    
    void* target_ptr = nullptr;         // Pointer to the matched entity (e.g., IRoute*, Controller*)
    TargetType type = TargetType::NONE;    // Type of the matched entity
    PathParameters params;              // Parameters extracted FROM THE MATCHED PATH SEGMENTS TO THIS NODE
    std::string matched_path_prefix;    // The path prefix string that led to this node (e.g. /users/:id)
    std::string remaining_path;         // The part of the input path remaining *after* this node's prefix was matched
    int priority = 0;                   // Priority of the matched route/entity
    std::string full_debug_matched_path; // For debugging: the full path Radix thinks it matched to get to target_ptr
};

/**
 * @brief Radix tree node for efficient route matching
 *
 * This class implements a radix tree (also known as a patricia trie) for
 * efficiently matching URL paths. It provides significantly faster matching
 * than regex-based approaches, especially for large numbers of routes.
 */
class RadixNode {
public:
    /**
     * @struct Child
     * @brief Represents a child node in the radix tree.
     * Stores the path segment leading to this child, a pointer to the child RadixNode,
     * a flag indicating if this segment is a parameter, and the parameter name if applicable.
     */
    struct Child {
        std::string                segment;    // Static part of the segment, or empty for pure param like :id
        std::shared_ptr<RadixNode> node;
        bool                       is_param;   // True if this child represents a path parameter AFTER its static segment part
        std::string                param_name; // The name of the parameter (e.g., "id")
    };

    std::vector<Child> children;
    void*              entity_ptr = nullptr; // Can be IRoute* or Controller*
    RadixMatchResult::TargetType entity_type = RadixMatchResult::TargetType::NONE;
    int                priority    = 0;
    bool               is_endpoint = false; // True if a route/controller is registered *at* this node exactly
    
    RadixNode() = default;

    /**
     * @brief Inserts a path pattern into the radix tree node and its descendants.
     *
     * Recursively adds nodes to the tree based on the segments of the path.
     * If a segment corresponds to a parameter (e.g., ":id"), it's marked accordingly.
     *
     * @param path The path pattern to insert (e.g., "/users/:id/profile").
     * @param target Pointer to the handler function, controller, or object for this route.
     * @param prio Priority of this route (higher value means higher priority).
     * @param type_of_entity Type of the entity being inserted.
     */
    void insert(const std::string &path, void *target, int prio, RadixMatchResult::TargetType type_of_entity);

    /**
     * @brief Matches a URL path against this radix tree node and its descendants.
     *
     * Traverses the tree based on path segments. If a match is found,
     * it populates the `params` map with any extracted path parameters.
     *
     * @param path_to_match The URL path to match.
     * @param accumulated_params Accumulated path parameters as out-parameter.
     * @param current_path_build The current path being built.
     * @return An optional RadixMatchResult containing the match result.
     */
    std::optional<RadixMatchResult> match(const std::string &path_to_match, PathParameters& accumulated_params, const std::string& current_path_build) const;
};

/**
 * @brief Radix tree for efficient route matching.
 *
 * This class provides a high-level interface for a radix tree (Patricia trie)
 * specialized for HTTP route matching. It wraps a root RadixNode and offers
 * methods to insert routes and match incoming URL paths against the stored routes.
 * It handles path normalization (ensuring paths start with '/') internally.
 */
class RadixTree {
private:
    std::shared_ptr<RadixNode> _root; ///< The root node of the radix tree.

public:
    /**
     * @brief Default constructor. Initializes an empty RadixTree with a root node.
     */
    RadixTree()
        : _root(std::make_shared<RadixNode>()) {}

    /**
     * @brief Inserts a route into the tree.
     *
     * The path is normalized (prefixed with '/' if not already) before insertion.
     *
     * @param path The route path pattern (e.g., "/users/:id").
     * @param target Pointer to the handler, controller, or object for this route.
     * @param priority Priority of the route (higher value means higher priority).
     * @param type_of_entity Type of the entity being inserted.
     */
    void insert(const std::string &path, void *target, int priority, RadixMatchResult::TargetType type_of_entity);

    /**
     * @brief Matches an incoming URL path against the routes stored in the tree.
     *
     * The input path is normalized (prefixed with '/' if not already) before matching.
     * Extracted path parameters are stored in the `params` map.
     *
     * @param path The URL path to match.
     * @return An optional RadixMatchResult containing the match result.
     */
    std::optional<RadixMatchResult> match(const std::string &path) const;
    
    /**
     * @brief Extracts parameters from a path pattern by matching against an actual path
     * 
     * This is used when you have a pattern like "/users/:id" and a path like "/users/123"
     * and need to extract that id=123.
     * 
     * @param pattern The path pattern with parameter placeholders (e.g., "/users/:id")
     * @param actual_path The actual path to match against (e.g., "/users/123")
     * @return An optional RadixMatchResult containing the parameters (if matched)
     */
    static std::optional<RadixMatchResult> extract_params_from_path_pattern(
        const std::string& pattern, std::string_view actual_path) {
        
        if (pattern.empty() || actual_path.empty()) {
            return std::nullopt;
        }
        
        // Normalize paths to start with /
        std::string normalized_pattern = pattern;
        if (normalized_pattern[0] != '/') {
            normalized_pattern = '/' + normalized_pattern;
        }
        
        std::string normalized_path(actual_path);
        if (normalized_path[0] != '/') {
            normalized_path = '/' + normalized_path;
        }
        
        // Convert pattern to regex
        std::string regex_pattern = normalized_pattern;
        std::vector<std::string> param_names;
        
        // Replace parameter placeholders with regex capture groups
        // Handle both :param format and {param} format
        std::regex param_regex(":([^/]+)|\\{([^}]+)\\}");
        std::smatch matches;
        std::string::const_iterator start = regex_pattern.begin();
        std::string::const_iterator end = regex_pattern.end();
        
        // Find and process all parameters
        while (std::regex_search(start, end, matches, param_regex)) {
            // Parameter name is either in group 1 (:param) or group 2 ({param})
            std::string param_name = matches[1].matched ? matches[1].str() : matches[2].str();
            param_names.push_back(param_name);
            
            // Calculate position and length in the original string
            size_t match_pos = matches[0].first - regex_pattern.begin();
            size_t match_len = matches[0].length();
            
            // Replace with a capture group
            regex_pattern.replace(match_pos, match_len, "([^/]+)");
            
            // Update iterators
            start = regex_pattern.begin() + match_pos + 7; // Length of "([^/]+)"
            end = regex_pattern.end();
        }
        
        // Add anchors to match the entire string
        regex_pattern = "^" + regex_pattern + "$";
        
        // Create and try to match the regex
        try {
            std::regex full_regex(regex_pattern);
            std::smatch path_matches;
            
            if (std::regex_match(normalized_path, path_matches, full_regex)) {
                // Create result with parameters
                RadixMatchResult result;
                result.matched_path_prefix = normalized_pattern;
                
                // Extract parameters from captures
                for (size_t i = 0; i < param_names.size(); ++i) {
                    if (i + 1 < path_matches.size()) {
                        result.params[param_names[i]] = path_matches[i + 1].str();
                    }
                }
                
                return result;
            }
        } catch (const std::regex_error& e) {
            // Log regex error or handle it appropriately
        }
        
        return std::nullopt;
    }
};

} // namespace qb::http