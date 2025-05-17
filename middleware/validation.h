#pragma once

#include <memory>
#include <string>
#include <vector>
#include "../routing/middleware.h" 
#include "../validation/request_validator.h" // Updated include path
#include "../validation/error.h"  // Updated include path, provides qb::http::validation::Result
#include "../response.h"          
#include "../types.h"             
#include <qb/json.h>               

namespace qb::http { // Middleware stays in qb::http

template <typename SessionType>
class ValidationMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;

    explicit ValidationMiddleware(std::shared_ptr<qb::http::validation::RequestValidator> validator, // Use namespaced RequestValidator
                                std::string name = "ValidationMiddleware")
        : _validator(std::move(validator)), _name(std::move(name)) {
        if (!_validator) {
            throw std::invalid_argument("ValidationMiddleware: RequestValidator cannot be null.");
        }
    }

    void process(ContextPtr ctx) override {
        validation::Result validation_result; // Use namespaced Result
        // Pass ctx->path_parameters() which is const qb::http::PathParameters&
        // RequestValidator::validate takes const qb::http::PathParameters*
        bool is_valid = _validator->validate(ctx->request(), validation_result, &(ctx->path_parameters()));

        if (is_valid) {
            ctx->complete(AsyncTaskResult::CONTINUE);
        } else {
            ctx->response().status_code = HTTP_STATUS_BAD_REQUEST; 
            ctx->response().set_header("Content-Type", "application/json");
            
            qb::json error_body;
            error_body["message"] = "Validation failed.";
            qb::json errors_array = qb::json::array();
            for (const auto& err : validation_result.errors()) { // err is now validation::Error
                qb::json error_detail;
                error_detail["field"] = err.field_path;
                error_detail["rule"] = err.rule_violated;
                error_detail["message"] = err.message;
                if (err.offending_value.has_value()) {
                    error_detail["value"] = err.offending_value.value();
                }
                errors_array.push_back(error_detail);
            }
            error_body["errors"] = errors_array;
            ctx->response().body() = error_body.dump(2); 

            ctx->complete(AsyncTaskResult::COMPLETE); 
        }
    }

    std::string name() const override {
        return _name;
    }

    void cancel() override {}

private:
    std::shared_ptr<qb::http::validation::RequestValidator> _validator; // Use namespaced RequestValidator
    std::string _name;
};

template <typename SessionType>
std::shared_ptr<ValidationMiddleware<SessionType>> validation_middleware(
    std::shared_ptr<qb::http::validation::RequestValidator> validator, // Use namespaced RequestValidator
    const std::string& name = "ValidationMiddleware"
) {
    return std::make_shared<ValidationMiddleware<SessionType>>(std::move(validator), name);
}

} // namespace qb::http 