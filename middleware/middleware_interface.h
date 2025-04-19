#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <optional>
#include <type_traits>

#include "../routing/context.h"

namespace qb::http {

/**
 * @brief Résultat d'un middleware indiquant comment la chaîne doit procéder
 */
enum class MiddlewareAction {
    CONTINUE,   ///< Continue vers le middleware suivant
    SKIP,       ///< Sauter le reste des middlewares et exécuter le handler final
    STOP,       ///< Arrêter le traitement (la réponse a été définie)
    ERROR       ///< Arrêter avec une erreur
};

/**
 * @brief Résultat d'exécution d'un middleware avec support asynchrone intégré
 */
class MiddlewareResult {
public:
    /**
     * @brief Constructeur pour un résultat synchrone
     * @param action Action à prendre pour la suite du traitement
     * @param error_message Message d'erreur optionnel (si action est ERROR)
     */
    explicit MiddlewareResult(MiddlewareAction action, 
                      std::string error_message = {})
        : _action(action), 
          _is_async(false), 
          _error_message(std::move(error_message)) {}
    
    /**
     * @brief Constructeur pour un résultat asynchrone
     * @param is_async Indique si le traitement est asynchrone
     */
    explicit MiddlewareResult(bool is_async = true)
        : _action(MiddlewareAction::CONTINUE), 
          _is_async(is_async) {}
    
    // Méthodes d'usine pour créer les différents types de résultats
    static MiddlewareResult Continue() { return MiddlewareResult(MiddlewareAction::CONTINUE); }
    static MiddlewareResult Skip() { return MiddlewareResult(MiddlewareAction::SKIP); }
    static MiddlewareResult Stop() { return MiddlewareResult(MiddlewareAction::STOP); }
    static MiddlewareResult Error(std::string message) { return MiddlewareResult(MiddlewareAction::ERROR, std::move(message)); }
    static MiddlewareResult Async() { return MiddlewareResult(true); }
    
    // Accesseurs
    bool is_async() const { return _is_async; }
    bool should_continue() const { return _action == MiddlewareAction::CONTINUE; }
    bool should_skip() const { return _action == MiddlewareAction::SKIP; }
    bool should_stop() const { return _action == MiddlewareAction::STOP || _action == MiddlewareAction::ERROR; }
    bool is_error() const { return _action == MiddlewareAction::ERROR; }
    MiddlewareAction action() const { return _action; }
    const std::string& error_message() const { return _error_message; }
    
private:
    MiddlewareAction _action;
    bool _is_async;
    std::string _error_message;
};

/**
 * @brief Interface pour les middlewares synchrones
 * 
 * Ce middleware traite de manière synchrone et retourne immédiatement un résultat.
 */
template <typename Session, typename String = std::string>
class ISyncMiddleware {
public:
    using Context = RouterContext<Session, String>;
    
    virtual ~ISyncMiddleware() = default;
    
    /**
     * @brief Traite une requête à travers ce middleware de manière synchrone
     * @param ctx Contexte de la requête
     * @return Résultat du middleware
     */
    virtual MiddlewareResult process(Context& ctx) = 0;
    
    /**
     * @brief Récupère le nom du middleware (pour logging/débogage)
     */
    virtual std::string name() const = 0;
};

/**
 * @brief Interface pour les middlewares asynchrones
 * 
 * Ce middleware peut retarder son traitement et appeler le callback
 * lorsqu'il est terminé.
 */
template <typename Session, typename String = std::string>
class IAsyncMiddleware {
public:
    using Context = RouterContext<Session, String>;
    using CompletionCallback = std::function<void(MiddlewareResult)>;
    
    virtual ~IAsyncMiddleware() = default;
    
    /**
     * @brief Traite une requête à travers ce middleware de manière asynchrone
     * @param ctx Contexte de la requête
     * @param callback Fonction à appeler lorsque le traitement est terminé
     */
    virtual void process_async(Context& ctx, CompletionCallback callback) = 0;
    
    /**
     * @brief Récupère le nom du middleware (pour logging/débogage)
     */
    virtual std::string name() const = 0;
};

/**
 * @brief Interface unifiée pour les middlewares
 * 
 * Cette interface combine les comportements synchrones et asynchrones.
 * Les classes peuvent implémenter une ou les deux méthodes selon leurs besoins.
 */
template <typename Session, typename String = std::string>
class IMiddleware {
public:
    using Context = RouterContext<Session, String>;
    using CompletionCallback = std::function<void(MiddlewareResult)>;
    
    virtual ~IMiddleware() = default;
    
    /**
     * @brief Traite une requête synchrone ou asynchrone selon le type de middleware
     * @param ctx Contexte de la requête
     * @param callback Fonction à appeler si le traitement est asynchrone
     * @return Résultat du middleware (ignoré si asynchrone)
     * 
     * Cette méthode doit être implémentée par toutes les classes dérivées.
     * Pour un middleware synchrone, elle doit retourner le résultat et ignorer le callback.
     * Pour un middleware asynchrone, elle doit retourner MiddlewareResult::Async() et 
     * appeler le callback plus tard.
     */
    virtual MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) = 0;
    
    /**
     * @brief Récupère le nom du middleware (pour logging/débogage)
     */
    virtual std::string name() const = 0;
};

// Type alias pour simplifier la création de middlewares partagés
template <typename Session, typename String = std::string>
using MiddlewarePtr = std::shared_ptr<IMiddleware<Session, String>>;

/**
 * @brief Adaptateur pour convertir un middleware synchrone en middleware unifié
 */
template <typename Session, typename String = std::string>
class SyncMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    
    explicit SyncMiddlewareAdapter(std::shared_ptr<ISyncMiddleware<Session, String>> middleware)
        : _middleware(std::move(middleware)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        auto result = _middleware->process(ctx);
        if (callback) callback(result);
        return result;
    }
    
    std::string name() const override {
        return _middleware->name();
    }
    
private:
    std::shared_ptr<ISyncMiddleware<Session, String>> _middleware;
};

/**
 * @brief Adaptateur pour convertir un middleware asynchrone en middleware unifié
 */
template <typename Session, typename String = std::string>
class AsyncMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    
    explicit AsyncMiddlewareAdapter(std::shared_ptr<IAsyncMiddleware<Session, String>> middleware)
        : _middleware(std::move(middleware)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (!callback) {
            throw std::runtime_error("Async middleware requires a callback");
        }
        
        _middleware->process_async(ctx, callback);
        return MiddlewareResult::Async();
    }
    
    std::string name() const override {
        return _middleware->name();
    }
    
private:
    std::shared_ptr<IAsyncMiddleware<Session, String>> _middleware;
};

/**
 * @brief Adaptateur pour utiliser une fonction lambda comme middleware synchrone
 */
template <typename Session, typename String = std::string>
class FunctionMiddleware : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    using SyncFunction = std::function<MiddlewareResult(Context&)>;
    using AsyncFunction = std::function<void(Context&, CompletionCallback)>;
    
    // Constructeur pour fonction synchrone
    explicit FunctionMiddleware(SyncFunction func, std::string name = "FunctionMiddleware")
        : _sync_func(std::move(func)), _name(std::move(name)) {}
    
    // Constructeur pour fonction asynchrone
    explicit FunctionMiddleware(AsyncFunction func, std::string name = "AsyncFunctionMiddleware")
        : _async_func(std::move(func)), _name(std::move(name)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (_sync_func) {
            auto result = _sync_func(ctx);
            if (callback) callback(result);
            return result;
        }
        
        if (_async_func) {
            if (!callback) {
                throw std::runtime_error("Async middleware requires a callback");
            }
            _async_func(ctx, callback);
            return MiddlewareResult::Async();
        }
        
        // No function defined
        auto error = MiddlewareResult::Error("No middleware function defined");
        if (callback) callback(error);
        return error;
    }
    
    std::string name() const override {
        return _name;
    }
    
private:
    SyncFunction _sync_func;
    AsyncFunction _async_func;
    std::string _name;
};

// Fonctions d'aide pour créer des middlewares basés sur des fonctions
template <typename Session, typename String = std::string, typename Func>
std::shared_ptr<IMiddleware<Session, String>> make_middleware(Func&& func, const std::string& name = "Middleware") {
    return std::make_shared<FunctionMiddleware<Session, String>>(std::forward<Func>(func), name);
}

// Adaptateur pour la compatibilité avec le système original de middleware
template <typename Session, typename String = std::string>
class LegacyMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    using LegacySyncMiddleware = std::function<bool(Context&)>;
    using LegacyAsyncMiddleware = std::function<void(Context&, std::function<void(bool)>)>;
    
    // Constructeur pour middleware synchrone hérité
    explicit LegacyMiddlewareAdapter(LegacySyncMiddleware func, std::string name = "LegacySyncMiddleware")
        : _sync_func(std::move(func)), _name(std::move(name)) {}
    
    // Constructeur pour middleware asynchrone hérité
    explicit LegacyMiddlewareAdapter(LegacyAsyncMiddleware func, std::string name = "LegacyAsyncMiddleware")
        : _async_func(std::move(func)), _name(std::move(name)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (_sync_func) {
            bool continue_processing = _sync_func(ctx);
            auto result = continue_processing ? MiddlewareResult::Continue() : MiddlewareResult::Stop();
            if (callback) callback(result);
            return result;
        }
        
        if (_async_func) {
            if (!callback) {
                throw std::runtime_error("Async middleware requires a callback");
            }
            
            _async_func(ctx, [callback](bool continue_processing) {
                auto result = continue_processing ? MiddlewareResult::Continue() : MiddlewareResult::Stop();
                callback(result);
            });
            
            return MiddlewareResult::Async();
        }
        
        // No function defined
        auto error = MiddlewareResult::Error("No middleware function defined");
        if (callback) callback(error);
        return error;
    }
    
    std::string name() const override {
        return _name;
    }
    
private:
    LegacySyncMiddleware _sync_func;
    LegacyAsyncMiddleware _async_func;
    std::string _name;
};

// Fonctions d'aide pour créer des middlewares compatibles avec l'ancien système
template <typename Session, typename String = std::string>
std::shared_ptr<IMiddleware<Session, String>> from_legacy_middleware(
    typename LegacyMiddlewareAdapter<Session, String>::LegacySyncMiddleware func, 
    const std::string& name = "LegacySyncMiddleware") {
    return std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(func), name);
}

template <typename Session, typename String = std::string>
std::shared_ptr<IMiddleware<Session, String>> from_legacy_middleware(
    typename LegacyMiddlewareAdapter<Session, String>::LegacyAsyncMiddleware func, 
    const std::string& name = "LegacyAsyncMiddleware") {
    return std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(func), name);
}

} // namespace qb::http 