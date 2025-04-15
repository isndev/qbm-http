#include "router.h"
#include <chrono>
#include <iostream>

namespace qb::http {

// Ce fichier contiendrait l'implémentation des méthodes non-template.
// Cependant, Router est entièrement template, donc ce fichier resterait vide
// ou contiendrait uniquement des fonctions helpers non-template si elles étaient
// définies.

// Exemple de fonction helper non-template qui pourrait être définie ici:
std::string
format_timestamp(const std::chrono::system_clock::time_point &tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    char buf[100];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
    return std::string(buf);
}

} // namespace qb::http