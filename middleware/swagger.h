#pragma once

#include <string>
#include <unordered_map>
#include "./middleware_interface.h"
#include "../openapi/document.h"

namespace qb {
namespace http {
namespace openapi {

// Forward declaration for embedded Swagger UI files
namespace ui {
// This will be defined in swagger_ui.cpp
extern std::unordered_map<std::string, std::pair<std::string, std::string>> getSwaggerUIFiles();
}

/**
 * @brief Middleware for serving OpenAPI documentation with Swagger UI
 *
 * This middleware serves the OpenAPI specification and Swagger UI
 * for interactive API documentation.
 */
template <typename Session, typename String = std::string>
class SwaggerMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    
    /**
     * @brief Constructor
     * @param generator OpenAPI document generator
     * @param basePath Base path for serving the UI (default: /api-docs)
     * @param specPath Path for the OpenAPI JSON spec (default: /openapi.json)
     * @param name Middleware name
     */
    explicit SwaggerMiddleware(
        DocumentGenerator& generator,
        const std::string& basePath = "/api-docs",
        const std::string& specPath = "/openapi.json",
        std::string name = "SwaggerMiddleware"
    ) : _generator(generator), 
        _base_path(basePath), 
        _spec_path(specPath),
        _name(std::move(name)),
        _static_files(ui::getSwaggerUIFiles()) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        const std::string& path = ctx.path();
        
        // Serve OpenAPI JSON specification
        if (path == _base_path + _spec_path) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.add_header("Content-Type", "application/json");
            ctx.response.body() = _generator.generateJson(true);
            ctx.mark_handled();
            return MiddlewareResult::Stop();
        }
        
        // Serve Swagger UI index
        if (path == _base_path || path == _base_path + "/") {
            serveSwaggerUIIndex(ctx);
            return MiddlewareResult::Stop();
        }
        
        // Serve Swagger UI static assets
        if (path.find(_base_path + "/") == 0) {
            std::string assetPath = path.substr(_base_path.length());
            serveStaticAsset(ctx, assetPath);
            return MiddlewareResult::Stop();
        }
        
        // Not a Swagger UI path, continue middleware chain
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     * @return Middleware name
     */
    std::string name() const override {
        return _name;
    }
    
private:
    DocumentGenerator& _generator;
    std::string _base_path;
    std::string _spec_path;
    std::string _name;
    std::unordered_map<std::string, std::pair<std::string, std::string>> _static_files;
    
    /**
     * @brief Serve the Swagger UI index page
     * @param ctx Request context
     */
    void serveSwaggerUIIndex(Context& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.add_header("Content-Type", "text/html");
        
        // Generate HTML with correct paths to resources and spec
        std::string html = "<!DOCTYPE html>\n";
        html += "<html lang=\"en\">\n";
        html += "<head>\n";
        html += "  <meta charset=\"UTF-8\">\n";
        html += "  <title>API Documentation</title>\n";
        html += "  <link rel=\"stylesheet\" type=\"text/css\" href=\"" + _base_path + "/swagger-ui.css\">\n";
        html += "  <link rel=\"icon\" type=\"image/png\" href=\"" + _base_path + "/favicon-32x32.png\" sizes=\"32x32\">\n";
        html += "  <style>\n";
        html += "    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }\n";
        html += "    *, *:before, *:after { box-sizing: inherit; }\n";
        html += "    body { margin: 0; background: #fafafa; }\n";
        html += "  </style>\n";
        html += "</head>\n";
        html += "<body>\n";
        html += "  <div id=\"swagger-ui\"></div>\n";
        html += "  <script src=\"" + _base_path + "/swagger-ui-bundle.js\"></script>\n";
        html += "  <script src=\"" + _base_path + "/swagger-ui-standalone-preset.js\"></script>\n";
        html += "  <script>\n";
        html += "    window.onload = function() {\n";
        html += "      const ui = SwaggerUIBundle({\n";
        html += "        url: \"" + _base_path + _spec_path + "\",\n";
        html += "        dom_id: '#swagger-ui',\n";
        html += "        deepLinking: true,\n";
        html += "        presets: [\n";
        html += "          SwaggerUIBundle.presets.apis,\n";
        html += "          SwaggerUIStandalonePreset\n";
        html += "        ],\n";
        html += "        layout: \"StandaloneLayout\",\n";
        html += "        docExpansion: 'list',\n";
        html += "        defaultModelsExpandDepth: 1,\n";
        html += "        defaultModelExpandDepth: 1,\n";
        html += "        operationsSorter: 'alpha'\n";
        html += "      });\n";
        html += "      window.ui = ui;\n";
        html += "    }\n";
        html += "  </script>\n";
        html += "</body>\n";
        html += "</html>";
        
        ctx.response.body() = html;
        ctx.mark_handled();
    }
    
    /**
     * @brief Serve a static asset from the embedded files
     * @param ctx Request context
     * @param path Asset path
     */
    void serveStaticAsset(Context& ctx, const std::string& path) {
        auto it = _static_files.find(path);
        if (it != _static_files.end()) {
            // Found the file
            const auto& [content, mime_type] = it->second;
            
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.add_header("Content-Type", mime_type);
            
            // Add cache headers for static assets
            ctx.response.add_header("Cache-Control", "public, max-age=86400"); // 1 day
            
            ctx.response.body() = content;
        } else {
            // File not found
            ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
            ctx.response.body() = "Not Found";
        }
        
        ctx.mark_handled();
    }
};

/**
 * @brief Create a Swagger UI middleware
 * @param generator OpenAPI document generator
 * @param basePath Base path for the UI
 * @param specPath Path for the OpenAPI JSON spec
 * @return Swagger middleware adapter
 */
template <typename Session, typename String = std::string>
auto swagger_middleware(
    DocumentGenerator& generator,
    const std::string& basePath = "/api-docs",
    const std::string& specPath = "/openapi.json"
) {
    auto middleware = std::make_shared<SwaggerMiddleware<Session, String>>(
        generator, basePath, specPath
    );
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace openapi
} // namespace http
} // namespace qb 