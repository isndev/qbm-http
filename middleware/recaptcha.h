/**
 * @file recaptcha.h
 * @brief Middleware asynchrone pour vérifier les tokens Google reCAPTCHA
 *
 * Copyright (c) 2011-2025 qb - isndev (cpp.actor). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef QB_MODULE_HTTP_RECAPTCHA_MIDDLEWARE_H_
#define QB_MODULE_HTTP_RECAPTCHA_MIDDLEWARE_H_

#include <qb/json.h>
#include <string>
#include <functional>
#include <optional>
#include <chrono>
#include "../http.h"

namespace qb::http::middleware {

/**
 * @brief Options de configuration pour le middleware reCAPTCHA
 */
struct RecaptchaOptions {
    std::string secret_key;                        ///< Clé secrète Google reCAPTCHA
    float min_score = 0.5f;                        ///< Score minimum acceptable (0.0 à 1.0)
    std::string api_url = "https://www.google.com/recaptcha/api/siteverify"; ///< URL de l'API de vérification
    
    // Où chercher le token
    enum class TokenLocation {
        Header,  ///< Dans un header HTTP
        Body,    ///< Dans le corps de la requête
        Query    ///< Dans les paramètres de l'URL
    };
    
    TokenLocation token_location = TokenLocation::Body; ///< Emplacement du token
    std::string token_field_name = "g-recaptcha-response"; ///< Nom du champ contenant le token
    
    // Configuration fluide
    RecaptchaOptions& set_secret_key(const std::string& key) {
        secret_key = key;
        return *this;
    }
    
    RecaptchaOptions& set_min_score(float score) {
        min_score = score;
        return *this;
    }
    
    RecaptchaOptions& from_header(const std::string& header_name) {
        token_location = TokenLocation::Header;
        token_field_name = header_name;
        return *this;
    }
    
    RecaptchaOptions& from_body(const std::string& field_name) {
        token_location = TokenLocation::Body;
        token_field_name = field_name;
        return *this;
    }
    
    RecaptchaOptions& from_query(const std::string& param_name) {
        token_location = TokenLocation::Query;
        token_field_name = param_name;
        return *this;
    }
};

/**
 * @brief Résultat de la vérification reCAPTCHA
 */
struct RecaptchaResult {
    bool success = false;          ///< Vérification réussie ou échouée
    float score = 0.0f;           ///< Score reCAPTCHA (0.0 à 1.0)
    std::string action;           ///< Action associée au token
    std::string hostname;         ///< Hostname qui a généré le token
    std::string error_codes;      ///< Codes d'erreur éventuels
    std::chrono::system_clock::time_point challenge_ts; ///< Timestamp du challenge
};

/**
 * @brief Middleware asynchrone pour valider les tokens Google reCAPTCHA
 * 
 * Ce middleware intercepte les requêtes HTTP, extrait un token reCAPTCHA,
 * vérifie sa validité auprès de l'API Google, et rejette les requêtes
 * dont le score est insuffisant.
 * 
 * @tparam RouterType Type du routeur
 */
template <typename RouterType>
class RecaptchaMiddleware {
public:
    /**
     * @brief Constructeur avec options
     * @param options Options de configuration pour reCAPTCHA
     */
    explicit RecaptchaMiddleware(const RecaptchaOptions& options)
        : _options(options) {
        if (_options.secret_key.empty()) {
            throw std::invalid_argument("reCAPTCHA secret key is required");
        }
    }
    
    /**
     * @brief Opérateur de fonction pour utilisation comme middleware
     * @tparam ContextType Type du contexte de routage
     * @param ctx Contexte de la requête
     * @param next Fonction callback pour continuer la chaîne de middleware
     */
    template <typename ContextType, typename NextType>
    void operator()(ContextType& ctx, NextType next) const {
        // Extraction du token reCAPTCHA
        auto token = extract_token(ctx.request);
        
        if (!token) {
            // Token manquant, rejeter la requête
            ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
            ctx.response.body() = qb::json{
                {"error", "reCAPTCHA token is missing"}
            };
            ctx.session << ctx.response;
            next(false);
            return;
        }
        
        // Créer la requête vers l'API Google
        qb::http::Request req(_options.api_url);
        req.method = HTTP_POST;
        req.add_header("Content-Type", "application/x-www-form-urlencoded");
        
        // Construire le corps de la requête
        std::string body = "secret=" + _options.secret_key + "&response=" + *token;
        req.body() = body;
        
        // Envoyer la requête de manière asynchrone
        qb::http::POST(req, [ctx, next, this](qb::http::async::Reply&& reply) mutable {
            auto result = parse_recaptcha_response(reply.response);
            
            // Stocker le résultat dans le contexte pour utilisation ultérieure
            ctx.template set<RecaptchaResult>("recaptcha_result", result);
            
            if (!result.success || result.score < _options.min_score) {
                // Vérification échouée ou score trop bas
                ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
                ctx.response.body() = qb::json{
                    {"error", "reCAPTCHA verification failed"},
                    {"details", result.error_codes.empty() ? "Score too low" : result.error_codes}
                };
                ctx.session << ctx.response;
                next(false);
                return;
            }
            
            // Vérification réussie, continuer la chaîne de middleware
            next(true);
        });
    }
    
private:
    RecaptchaOptions _options;
    
    /**
     * @brief Extrait le token reCAPTCHA de la requête
     * @param request Requête HTTP
     * @return Token reCAPTCHA ou std::nullopt si non trouvé
     */
    template <typename RequestType>
    std::optional<std::string> extract_token(const RequestType& request) const {
        switch (_options.token_location) {
            case RecaptchaOptions::TokenLocation::Header:
                if (request.has_header(_options.token_field_name)) {
                    return request.header(_options.token_field_name);
                }
                break;
                
            case RecaptchaOptions::TokenLocation::Body:
                try {
                    if (request.has_body()) {
                        const auto& body = request.body();
                        if (body.is_json()) {
                            auto json = body.template as<qb::json::object>();
                            if (json.contains(_options.token_field_name)) {
                                return json[_options.token_field_name].template get<std::string>();
                            }
                        } else if (body.is_form()) {
                            auto form = body.template as<qb::http::Form>();
                            if (form.has(_options.token_field_name)) {
                                return form.get(_options.token_field_name);
                            }
                        }
                    }
                } catch (...) {
                    // Erreur de parsing, retourner nullopt
                }
                break;
                
            case RecaptchaOptions::TokenLocation::Query:
                if (request.uri().has_query_param(_options.token_field_name)) {
                    return request.uri().query_param(_options.token_field_name);
                }
                break;
        }
        
        return std::nullopt;
    }
    
    /**
     * @brief Parse la réponse de l'API reCAPTCHA
     * @param response Réponse HTTP de l'API Google
     * @return Résultat de la vérification
     */
    RecaptchaResult parse_recaptcha_response(const qb::http::Response& response) const {
        RecaptchaResult result;
        
        if (response.status_code != HTTP_STATUS_OK) {
            result.error_codes = "HTTP error: " + std::to_string(response.status_code);
            return result;
        }
        
        try {
            auto json = response.body().template as<qb::json::object>();
            
            // Extraire les champs de base
            result.success = json.value("success", false);
            
            // Si succès, extraire les informations supplémentaires
            if (result.success) {
                result.score = json.value("score", 0.0f);
                result.action = json.value("action", "");
                result.hostname = json.value("hostname", "");
                
                // Parser le timestamp
                if (json.contains("challenge_ts")) {
                    auto ts_str = json["challenge_ts"].get<std::string>();
                    // Simplification: supposer un format ISO 8601
                    // Dans une implémentation réelle, utilisez une bibliothèque de date/time
                    result.challenge_ts = std::chrono::system_clock::now();
                }
            }
            
            // Extraire les codes d'erreur éventuels
            if (json.contains("error-codes")) {
                const auto& errors = json["error-codes"];
                if (errors.is_array()) {
                    std::string error_concat;
                    for (const auto& err : errors.get<qb::json::array>()) {
                        if (!error_concat.empty()) error_concat += ", ";
                        error_concat += err.get<std::string>();
                    }
                    result.error_codes = error_concat;
                }
            }
            
        } catch (const std::exception& e) {
            result.success = false;
            result.error_codes = std::string("JSON parsing error: ") + e.what();
        }
        
        return result;
    }
};

/**
 * @brief Crée un middleware de vérification reCAPTCHA
 * @param options Options de configuration
 * @return Instance du middleware
 */
template <typename RouterType>
auto recaptcha(const RecaptchaOptions& options) {
    return RecaptchaMiddleware<RouterType>(options);
}

/**
 * @brief Crée un middleware de vérification reCAPTCHA avec la clé secrète
 * @param secret_key Clé secrète Google reCAPTCHA
 * @param min_score Score minimum acceptable (optionnel)
 * @return Instance du middleware
 */
template <typename RouterType>
auto recaptcha(const std::string& secret_key, float min_score = 0.5f) {
    RecaptchaOptions options;
    options.secret_key = secret_key;
    options.min_score = min_score;
    return RecaptchaMiddleware<RouterType>(options);
}

} // namespace qb::http::middleware

#endif // QB_MODULE_HTTP_RECAPTCHA_MIDDLEWARE_H_ 