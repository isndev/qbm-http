#pragma once

#include "middleware_interface.h"
#include <memory>
#include <functional>
#include <string>

namespace qb::http {

/**
 * @brief Middleware for transforming requests/responses
 */
template <typename Session, typename String = std::string>
class TransformMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    using RequestTransformer = std::function<void(Request&)>;
    using ResponseTransformer = std::function<void(Response&)>;
    
    /**
     * @brief Constructor
     * @param request_transformer Request transformation function
     * @param response_transformer Response transformation function
     * @param name Middleware name
     */
    TransformMiddleware(
        RequestTransformer request_transformer = nullptr,
        ResponseTransformer response_transformer = nullptr,
        std::string name = "TransformMiddleware"
    ) : _request_transformer(std::move(request_transformer)),
        _response_transformer(std::move(response_transformer)),
        _name(std::move(name)) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        if (_request_transformer) {
            _request_transformer(ctx.request);
        }
        
        if (_response_transformer) {
            ctx.after_handling([this](Context& ctx) {
                _response_transformer(ctx.response);
            });
        }
        
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
private:
    RequestTransformer _request_transformer;
    ResponseTransformer _response_transformer;
    std::string _name;
};

/**
 * @brief Create a transformation middleware
 */
template <typename Session, typename String = std::string>
auto transform_middleware(
    typename TransformMiddleware<Session, String>::RequestTransformer request_transformer = nullptr,
    typename TransformMiddleware<Session, String>::ResponseTransformer response_transformer = nullptr,
    const std::string& name = "TransformMiddleware"
) {
    auto middleware = std::make_shared<TransformMiddleware<Session, String>>(
        std::move(request_transformer),
        std::move(response_transformer),
        name
    );
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 