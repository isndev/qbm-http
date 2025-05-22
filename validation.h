/**
 * @file qbm/http/validation.h
 * @brief Main convenience header for the QB HTTP Validation system.
 *
 * This header serves as a single include point for all essential public components
 * of the qb-http validation module. By including this file, users gain access to core
 * validation elements such as error reporting (`validation::Error`, `validation::Result`),
 * validation rules (`validation::Rule`), schema validation (`validation::SchemaValidator`),
 * parameter validation (`validation::ParameterValidator`), data sanitization (`validation::Sanitizer`),
 * and request validation (`validation::RequestValidator`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

// This file is the primary entry point for users of the QB HTTP Validation system.
// It includes all necessary public headers for defining and using validation rules and validators.

#include "./validation/error.h"               // For Error and Result structures.
#include "./validation/rule.h"                  // For Rule class and predefined rules.
#include "./validation/schema_validator.h"      // For SchemaValidator.
#include "./validation/parameter_validator.h" // For ParameterValidator.
#include "./validation/sanitizer.h"           // For Sanitizer class and sanitization functions.
#include "./validation/request_validator.h"   // For RequestValidator.

// Note: The actual validation middleware (e.g., qb/http/middleware/validation.h)
// would typically use these components to perform validation as part of the request lifecycle.

/**
 * @namespace qb::http
 * @brief Main namespace for QB HTTP functionalities.
 *        The validation system components are defined within the nested `qb::http::validation` namespace.
 */
namespace qb::http {
    /**
     * @namespace qb::http::validation
     * @brief Contains all components for data validation and sanitization within HTTP requests and responses.
     * This includes structures for error reporting, rule definitions, various validators (schema, parameter, request),
     * and data sanitizers.
     */
    // For convenience, users might want to use a namespace alias in their own code:
    // namespace validation = qb::http::validation; 
} // namespace qb::http 
