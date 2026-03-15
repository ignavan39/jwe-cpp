/**
 * @file encrypt_payload.cpp
 * @brief CLI-утилита: зашифровать JSON-полезную нагрузку в JWE-токен
 *
 * Использование:
 * @code
 *   # Из JWK-файла
 *   ./jwe_encrypt --jwk public_key.json --payload '{"sub":"123","name":"Иван"}'
 *
 *   # Из JWKS URL (только HTTP)
 *   ./jwe_encrypt --jwks http://idp.example.com/.well-known/jwks.json \
 *                 --kid my-key-id \
 *                 --payload '{"sub":"123"}'
 *
 *   # Из stdin (payload)
 *   echo '{"sub":"456"}' | ./jwe_encrypt --jwk pub.json
 * @endcode
 *
 * Вывод: компактный JWE-токен в stdout, ошибки — в stderr.
 */

#include <jwe/jwe.hpp>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

// ─── Утилиты ───────────────────────────────────────────────────────────────

static void printUsage(const char* prog) {
    std::cerr
        << "\nИспользование:\n"
        << "  " << prog << " [--jwk <file>|--jwks <url>] [--kid <id>] [--payload <json>]\n\n"
        << "Опции:\n"
        << "  --jwk     <file>  Путь к файлу с публичным JWK (JSON)\n"
        << "  --jwks    <url>   URL JWKS-эндпоинта (только HTTP)\n"
        << "  --kid     <id>    kid для поиска ключа в JWKS (опционально)\n"
        << "  --payload <json>  JSON полезная нагрузка (если не указан — читается из stdin)\n"
        << "  --verbose         Вывод подробной информации\n"
        << "  --help            Показать эту справку\n\n"
        << "Примеры:\n"
        << "  " << prog << " --jwk pub.json --payload '{\"sub\":\"1\"}'\n"
        << "  echo '{\"sub\":\"1\"}' | " << prog << " --jwk pub.json\n\n";
}

static std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Не удаётся открыть файл: " + path);
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

static std::string readStdin() {
    return std::string(std::istreambuf_iterator<char>(std::cin),
                       std::istreambuf_iterator<char>());
}

// ─── Основная логика ───────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::string jwkFile, jwksUrl, kid, payload;
    bool verbose = false;

    // Разбор аргументов
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else if (arg == "--jwk" && i + 1 < argc) {
            jwkFile = argv[++i];
        } else if (arg == "--jwks" && i + 1 < argc) {
            jwksUrl = argv[++i];
        } else if (arg == "--kid" && i + 1 < argc) {
            kid = argv[++i];
        } else if (arg == "--payload" && i + 1 < argc) {
            payload = argv[++i];
        } else {
            std::cerr << "Неизвестный аргумент: " << arg << '\n';
            printUsage(argv[0]);
            return 1;
        }
    }

    // Валидация аргументов
    if (jwkFile.empty() && jwksUrl.empty()) {
        std::cerr << "Ошибка: укажите --jwk или --jwks\n";
        printUsage(argv[0]);
        return 1;
    }
    if (!jwkFile.empty() && !jwksUrl.empty()) {
        std::cerr << "Ошибка: нельзя одновременно указывать --jwk и --jwks\n";
        return 1;
    }

    // Читаем payload из stdin если не задан явно
    if (payload.empty()) {
        if (verbose) std::cerr << "[INFO] Читаем payload из stdin...\n";
        payload = readStdin();
    }

    if (payload.empty()) {
        std::cerr << "Ошибка: payload пустой\n";
        return 1;
    }

    try {
        jwe::JweBuilder builder;

        // Загрузка ключа
        if (!jwkFile.empty()) {
            if (verbose) std::cerr << "[INFO] Загружаем JWK из: " << jwkFile << '\n';
            std::string jwkContent = readFile(jwkFile);
            builder.setPublicKeyFromJwkString(jwkContent);
        } else {
            if (verbose) std::cerr << "[INFO] Загружаем JWKS из: " << jwksUrl << '\n';
            builder.setPublicKeyFromJwksUrl(jwksUrl, kid);
        }

        if (verbose) {
            std::cerr << "[INFO] Payload длина: " << payload.size() << " байт\n";
            std::cerr << "[INFO] Шифруем...\n";
        }

        // Шифрование
        auto token = builder.build(payload);

        if (verbose) {
            std::cerr << "[INFO] JWE Protected Header: " << token.protected_header << '\n';
            std::cerr << "[INFO] IV (base64url):        " << token.initialization_vector << '\n';
            std::cerr << "[INFO] Tag (base64url):       " << token.authentication_tag << '\n';
        }

        // Вывод компактного токена
        std::cout << token.compact() << '\n';
        return 0;

    } catch (const jwe::JweError& e) {
        std::cerr << "JWE ошибка: " << e.what() << '\n';
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << '\n';
        return 3;
    }
}
