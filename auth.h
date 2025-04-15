#ifndef QBM_HTTP_AUTH_H
#define QBM_HTTP_AUTH_H

#include <chrono>
#include <functional>
#include <optional>
#include <qb/io/crypto.h>
#include <string>
#include <unordered_map>
#include <vector>
#include "./routing.h"

namespace qb {
namespace http {

/**
 * @brief Structure pour stocker les informations d'un utilisateur authentifié
 *
 * Cette structure contient toutes les informations nécessaires sur un utilisateur
 * authentifié, y compris son identifiant, son nom, ses rôles et d'autres
 * métadonnées associées.
 */
struct AuthUser {
    std::string                                  id;
    std::string                                  username;
    std::vector<std::string>                     roles;
    qb::unordered_map<std::string, std::string> metadata;

    /**
     * @brief Vérifier si l'utilisateur a un rôle spécifique
     * @param role Le rôle à vérifier
     * @return true si l'utilisateur a le rôle, false sinon
     */
    bool
    has_role(const std::string &role) const {
        return std::find(roles.begin(), roles.end(), role) != roles.end();
    }

    /**
     * @brief Vérifier si l'utilisateur a l'un des rôles spécifiés
     * @param required_roles Les rôles à vérifier
     * @return true si l'utilisateur a au moins un des rôles, false sinon
     */
    bool
    has_any_role(const std::vector<std::string> &required_roles) const {
        for (const auto &role : required_roles) {
            if (has_role(role))
                return true;
        }
        return false;
    }

    /**
     * @brief Vérifier si l'utilisateur a tous les rôles spécifiés
     * @param required_roles Les rôles à vérifier
     * @return true si l'utilisateur a tous les rôles, false sinon
     */
    bool
    has_all_roles(const std::vector<std::string> &required_roles) const {
        for (const auto &role : required_roles) {
            if (!has_role(role))
                return false;
        }
        return true;
    }
};

/**
 * @brief Classe pour gérer les configurations d'authentification
 *
 * Cette classe contient toutes les options pour configurer le middleware
 * d'authentification, incluant les clés, les algorithmes, les durées de
 * validité des tokens, etc.
 */
class AuthOptions {
public:
    /**
     * @brief Algorithmes supportés pour l'authentification
     */
    enum class Algorithm {
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        RSA_SHA256,
        RSA_SHA384,
        RSA_SHA512,
        ECDSA_SHA256,
        ECDSA_SHA384,
        ECDSA_SHA512,
        ED25519
    };

private:
    std::vector<unsigned char> _secret_key;
    std::string                _public_key;
    std::string                _private_key;
    Algorithm                  _algorithm = Algorithm::HMAC_SHA256;
    std::chrono::seconds       _token_expiration{3600}; // 1 hour default
    std::string                _token_issuer;
    std::string                _token_audience;
    std::string                _auth_header_name               = "Authorization";
    std::string                _auth_scheme                    = "Bearer";
    bool                       _require_signature_verification = true;
    bool                       _verify_expiration              = true;
    bool                       _verify_not_before              = true;
    bool                       _verify_issuer                  = false;
    bool                       _verify_audience                = false;
    std::chrono::seconds       _clock_skew_tolerance =
        std::chrono::seconds(0); // Default: no tolerance

public:
    AuthOptions() = default;

    /**
     * @brief Définir la clé secrète pour les algorithmes HMAC
     * @param secret La clé secrète
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    secret_key(const std::string &secret) {
        _secret_key.assign(secret.begin(), secret.end());
        return *this;
    }

    /**
     * @brief Définir la clé secrète pour les algorithmes HMAC
     * @param secret La clé secrète en bytes
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    secret_key(const std::vector<unsigned char> &secret) {
        _secret_key = secret;
        return *this;
    }

    /**
     * @brief Définir la clé publique pour les algorithmes asymétriques
     * @param key La clé publique au format PEM
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    public_key(const std::string &key) {
        _public_key = key;
        return *this;
    }

    /**
     * @brief Définir la clé privée pour les algorithmes asymétriques
     * @param key La clé privée au format PEM
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    private_key(const std::string &key) {
        _private_key = key;
        return *this;
    }

    /**
     * @brief Définir l'algorithme à utiliser
     * @param alg L'algorithme à utiliser
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    algorithm(Algorithm alg) {
        _algorithm = alg;
        return *this;
    }

    /**
     * @brief Définir la durée de validité des tokens
     * @param seconds La durée en secondes
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    token_expiration(std::chrono::seconds seconds) {
        _token_expiration = seconds;
        return *this;
    }

    /**
     * @brief Définir l'émetteur des tokens
     * @param issuer L'émetteur
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    token_issuer(const std::string &issuer) {
        _token_issuer  = issuer;
        _verify_issuer = !issuer.empty();
        return *this;
    }

    /**
     * @brief Définir l'audience des tokens
     * @param audience L'audience
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    token_audience(const std::string &audience) {
        _token_audience  = audience;
        _verify_audience = !audience.empty();
        return *this;
    }

    /**
     * @brief Définir le nom de l'en-tête d'authentification
     * @param name Le nom de l'en-tête
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    auth_header_name(const std::string &name) {
        _auth_header_name = name;
        return *this;
    }

    /**
     * @brief Définir le schéma d'authentification
     * @param scheme Le schéma (ex: "Bearer")
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    auth_scheme(const std::string &scheme) {
        _auth_scheme = scheme;
        return *this;
    }

    /**
     * @brief Activer/désactiver la vérification de la signature
     * @param verify true pour activer, false pour désactiver
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    require_signature_verification(bool verify) {
        _require_signature_verification = verify;
        return *this;
    }

    /**
     * @brief Activer/désactiver la vérification de l'expiration
     * @param verify true pour activer, false pour désactiver
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    verify_expiration(bool verify) {
        _verify_expiration = verify;
        return *this;
    }

    /**
     * @brief Activer/désactiver la vérification de la date de début de validité
     * @param verify true pour activer, false pour désactiver
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    verify_not_before(bool verify) {
        _verify_not_before = verify;
        return *this;
    }

    /**
     * @brief Définir une tolérance pour les décalages d'horloge entre les serveurs
     * @param tolerance La tolérance en secondes
     * @return Référence à l'objet AuthOptions pour chaînage
     */
    AuthOptions &
    clock_skew_tolerance(std::chrono::seconds tolerance) {
        _clock_skew_tolerance = tolerance;
        return *this;
    }

    // Getters
    const std::vector<unsigned char> &
    get_secret_key() const {
        return _secret_key;
    }
    const std::string &
    get_public_key() const {
        return _public_key;
    }
    const std::string &
    get_private_key() const {
        return _private_key;
    }
    Algorithm
    get_algorithm() const {
        return _algorithm;
    }
    std::chrono::seconds
    get_token_expiration() const {
        return _token_expiration;
    }
    std::chrono::seconds
    get_clock_skew_tolerance() const {
        return _clock_skew_tolerance;
    }
    const std::string &
    get_token_issuer() const {
        return _token_issuer;
    }
    const std::string &
    get_token_audience() const {
        return _token_audience;
    }
    const std::string &
    get_auth_header_name() const {
        return _auth_header_name;
    }
    const std::string &
    get_auth_scheme() const {
        return _auth_scheme;
    }
    bool
    get_require_signature_verification() const {
        return _require_signature_verification;
    }
    bool
    get_verify_expiration() const {
        return _verify_expiration;
    }
    bool
    get_verify_not_before() const {
        return _verify_not_before;
    }
    bool
    get_verify_issuer() const {
        return _verify_issuer;
    }
    bool
    get_verify_audience() const {
        return _verify_audience;
    }
};

/**
 * @brief Classe pour gérer l'authentification et l'autorisation dans le router HTTP
 *
 * Cette classe fournit des méthodes pour générer, valider et vérifier des tokens
 * d'authentification, ainsi que des middlewares pour protéger les routes.
 */
class AuthManager {
private:
    AuthOptions _options;

    /**
     * @brief Générer un payload JWT
     * @param user L'utilisateur pour lequel générer le token
     * @return Le payload en format JSON
     */
    std::string generate_token_payload(const AuthUser &user) const;

    /**
     * @brief Extraire le token de l'en-tête d'authentification
     * @param auth_header L'en-tête d'authentification
     * @return Le token extrait, ou une chaîne vide si le format est incorrect
     */
    std::string extract_token_from_header(const std::string &auth_header) const;

public:
    /**
     * @brief Vérifier et extraire les informations d'un token
     * @param token Le token à vérifier
     * @return Les informations utilisateur extraites, ou nullopt si le token est
     * invalide
     */
    std::optional<AuthUser> verify_token(const std::string &token) const;

    /**
     * @brief Constructeur avec options d'authentification
     * @param options Les options d'authentification
     */
    explicit AuthManager(const AuthOptions &options = AuthOptions())
        : _options(options) {}

    /**
     * @brief Générer un token pour un utilisateur
     * @param user L'utilisateur pour lequel générer le token
     * @return Le token généré
     */
    std::string generate_token(const AuthUser &user) const;

    /**
     * @brief Middleware pour vérifier l'authentification
     * @return Une fonction middleware pour le router
     */
    template <typename Router>
    typename Router::middleware_handler
    authenticate() const {
        return [this](typename Router::Context &ctx) {
            const auto &auth_header =
                ctx.request.header(_options.get_auth_header_name());
            if (auth_header.empty()) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body()      = "Authentication required";
                ctx.session << ctx.response;
                ctx.handled = true;
                return false;
            }

            std::string token = extract_token_from_header(auth_header);
            if (token.empty()) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body()      = "Invalid authentication format";
                ctx.session << ctx.response;
                ctx.handled = true;
                return false;
            }

            auto user = verify_token(token);
            if (!user) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body()      = "Invalid or expired token";
                ctx.session << ctx.response;
                ctx.handled = true;
                return false;
            }

            // Stocker les informations utilisateur dans le contexte de la requête
            ctx.state["user"] = *user;

            return true;
        };
    }

    /**
     * @brief Middleware pour vérifier les rôles d'un utilisateur
     * @param roles Les rôles requis
     * @param require_all Si true, tous les rôles sont requis; sinon, au moins un
     * @return Une fonction middleware pour le router
     */
    template <typename Router>
    typename Router::middleware_handler
    authorize(const std::vector<std::string> &roles, bool require_all = false) const {
        return [this, roles, require_all](typename Router::Context &ctx) {
            // Vérifier d'abord que l'utilisateur est authentifié
            if (!ctx.state.contains("user")) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body()      = "Authentication required";
                ctx.session << ctx.response;
                ctx.handled = true;
                return false;
            }

            const auto &user = std::any_cast<AuthUser>(ctx.state["user"]);
            bool        authorized =
                require_all ? user.has_all_roles(roles) : user.has_any_role(roles);

            if (!authorized) {
                ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
                ctx.response.body()      = "Insufficient permissions";
                ctx.session << ctx.response;
                ctx.handled = true;
                return false;
            }

            return true;
        };
    }

    /**
     * @brief Obtenir les options d'authentification actuelles
     * @return Les options d'authentification
     */
    const AuthOptions &
    get_options() const {
        return _options;
    }

    /**
     * @brief Mettre à jour les options d'authentification
     * @param options Les nouvelles options
     */
    void
    set_options(const AuthOptions &options) {
        _options = options;
    }
};

} // namespace http
} // namespace qb

#endif // QBM_HTTP_AUTH_H