#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <string>
#include <algorithm>

#include "middleware_interface.h"

namespace qb::http {

/**
 * @brief Chaîne de middlewares synchrones et asynchrones
 * 
 * Cette classe permet de combiner plusieurs middlewares en une séquence
 * d'exécution, gérant à la fois les middlewares synchrones et asynchrones.
 */
template <typename Session, typename String = std::string>
class MiddlewareChain : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    
    /**
     * @brief Constructeur par défaut
     */
    MiddlewareChain() = default;
    
    /**
     * @brief Constructeur avec liste de middlewares initiale
     * @param middlewares Liste de middlewares à ajouter
     */
    explicit MiddlewareChain(std::vector<MiddlewarePtr<Session, String>> middlewares)
        : _middlewares(std::move(middlewares)) {}
    
    /**
     * @brief Ajoute un middleware à la chaîne
     * @param middleware Middleware à ajouter
     * @return Référence à cette chaîne pour chaînage
     */
    MiddlewareChain& add(MiddlewarePtr<Session, String> middleware) {
        _middlewares.push_back(std::move(middleware));
        return *this;
    }
    
    /**
     * @brief Traiter une requête à travers la chaîne de middlewares
     * @param ctx Contexte de la requête
     * @param completion_callback Callback à appeler à la fin du traitement
     * @return Résultat du traitement
     */
    MiddlewareResult process(Context& ctx, CompletionCallback completion_callback = nullptr) override {
        if (_middlewares.empty()) {
            auto result = MiddlewareResult::Continue();
            if (completion_callback) completion_callback(result);
            return result;
        }
        
        // Créer un contexte de traitement pour suivre la progression dans la chaîne
        auto chain_context = std::make_shared<ChainExecutionContext>(
            ctx,
            _middlewares,
            0,
            completion_callback,
            _error_handler
        );
        
        // Démarrer l'exécution de la chaîne
        return process_next(*chain_context);
    }
    
    /**
     * @brief Définit un gestionnaire d'erreurs pour la chaîne
     * @param handler Fonction à appeler en cas d'erreur
     * @return Référence à cette chaîne pour chaînage
     */
    MiddlewareChain& on_error(std::function<void(Context&, const std::string&)> handler) {
        _error_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Récupère le nom de la chaîne
     */
    std::string name() const override {
        return "MiddlewareChain";
    }
    
private:
    // Liste des middlewares
    std::vector<MiddlewarePtr<Session, String>> _middlewares;
    
    // Gestionnaire d'erreurs optionnel
    std::function<void(Context&, const std::string&)> _error_handler;
    
    // Contexte d'exécution pour suivre l'état de la chaîne
    struct ChainExecutionContext {
        Context& ctx;
        const std::vector<MiddlewarePtr<Session, String>>& middlewares;
        size_t current_index;
        CompletionCallback final_callback;
        std::function<void(Context&, const std::string&)> error_handler;
        
        ChainExecutionContext(
            Context& c,
            const std::vector<MiddlewarePtr<Session, String>>& mw,
            size_t index,
            CompletionCallback callback,
            std::function<void(Context&, const std::string&)> eh
        ) : ctx(c), middlewares(mw), current_index(index), 
            final_callback(std::move(callback)), error_handler(std::move(eh)) {}
    };
    
    /**
     * @brief Traite le prochain middleware dans la chaîne
     * @param chain_ctx Contexte d'exécution de la chaîne
     * @return Résultat du traitement
     */
    MiddlewareResult process_next(ChainExecutionContext& chain_ctx) {
        // Si tous les middlewares ont été traités ou si le contexte est déjà géré
        if (chain_ctx.current_index >= chain_ctx.middlewares.size() || chain_ctx.ctx.is_handled()) {
            auto result = MiddlewareResult::Continue();
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(result);
            }
            return result;
        }
        
        // Récupérer le middleware actuel
        auto& middleware = chain_ctx.middlewares[chain_ctx.current_index];
        
        // Préparer le callback pour le middleware suivant
        auto next_callback = [chain_ctx_ptr = std::make_shared<ChainExecutionContext>(chain_ctx)](MiddlewareResult result) mutable {
            auto& chain_ctx = *chain_ctx_ptr;
            
            // Vérifier le résultat du middleware
            if (result.is_error()) {
                // Appeler le gestionnaire d'erreurs s'il existe
                if (chain_ctx.error_handler) {
                    chain_ctx.error_handler(chain_ctx.ctx, result.error_message());
                }
                
                // Transmettre l'erreur au callback final
                if (chain_ctx.final_callback) {
                    chain_ctx.final_callback(result);
                }
                return;
            }
            
            if (result.should_stop()) {
                // Middleware a demandé d'arrêter le traitement
                if (chain_ctx.final_callback) {
                    chain_ctx.final_callback(result);
                }
                return;
            }
            
            if (result.should_skip()) {
                // Middleware a demandé de sauter au handler final
                chain_ctx.current_index = chain_ctx.middlewares.size();
            } else {
                // Passer au middleware suivant
                chain_ctx.current_index++;
            }
            
            // Récursivement traiter le prochain middleware
            MiddlewareChain<Session, String>::process_next_static(chain_ctx);
        };
        
        // Exécuter le middleware actuel
        MiddlewareResult result = middleware->process(chain_ctx.ctx, next_callback);
        
        // Si le middleware est asynchrone, simplement retourner Async
        if (result.is_async()) {
            return MiddlewareResult::Async();
        }
        
        // Pour les middlewares synchrones, vérifier le résultat immédiatement
        if (result.is_error()) {
            if (chain_ctx.error_handler) {
                chain_ctx.error_handler(chain_ctx.ctx, result.error_message());
            }
            
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(result);
            }
            return result;
        }
        
        if (result.should_stop()) {
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(result);
            }
            return result;
        }
        
        if (result.should_skip()) {
            // Sauter au handler final
            auto final_result = MiddlewareResult::Skip();
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(final_result);
            }
            return final_result;
        }
        
        // Passer au middleware suivant
        chain_ctx.current_index++;
        return process_next(chain_ctx);
    }
    
    // Version statique pour être appelée depuis des lambdas capturant chain_ctx par valeur
    static void process_next_static(ChainExecutionContext& chain_ctx) {
        MiddlewareChain<Session, String> chain;
        chain.process_next(chain_ctx);
    }
};

/**
 * @brief Fonction d'aide pour créer une chaîne de middlewares
 */
template <typename Session, typename String = std::string>
auto make_middleware_chain(std::vector<MiddlewarePtr<Session, String>> middlewares = {}) {
    return std::make_shared<MiddlewareChain<Session, String>>(std::move(middlewares));
}

} // namespace qb::http 