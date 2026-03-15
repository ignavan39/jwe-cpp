/**
 * @file basic_usage.cpp
 * @brief Пример программного использования библиотеки jwe-cpp
 *
 * Демонстрирует полный сценарий из ТЗ:
 *  1. Подготовка plaintext (JSON с персональными данными)
 *  2-7. Построение JWE-токена через JweBuilder
 *
 * Компиляция:
 * @code
 *   cmake --build build
 *   ./build/examples/basic_usage
 * @endcode
 */

#include <jwe/jwe.hpp>
#include <iomanip>
#include <iostream>

// ─── Вспомогательная функция вывода ────────────────────────────────────────

static void printSeparator(const char* title = nullptr) {
    std::cout << "\n";
    if (title) {
        std::size_t len    = std::strlen(title);
        std::size_t dashes = (len < 46) ? (46 - len) : 0;
        std::cout << "\u250c\u2500 " << title << " ";
        for (std::size_t i = 0; i < dashes; ++i) std::cout << "\u2500";
        std::cout << "\u2510\n";
    } else {
        for (int i = 0; i < 55; ++i) std::cout << "\u2500";
        std::cout << "\n";
    }
}

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════╗\n"
              << "║          jwe-cpp :: Пример использования              ║\n"
              << "║   RFC 7516 · RSA-OAEP-256 · A256GCM · без зависимостей║\n"
              << "╚═══════════════════════════════════════════════════════╝\n";

    // ── Публичный ключ RSA (RFC 7517 Appendix A.1) ──────────────────────
    // Это тестовый ключ из официальной спецификации JWK.
    // В реальном проекте — заменить на ключ от сервис-провайдера.
    const char* jwkJson = R"({"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","kid":"2011-04-29","n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXMO_LRQMG8OAzToTMEMlFIJo2XAL_HWSK--jLj5Bx_V1dqzHK4ycJUYaSrGKUhPPNv8h0SCFP6OheMkFikhS0s5h0jMNBKGN4qbqr2qFAQiLt-Ts3G8aW8iRuoQKp9VoKkIUl5K2-LkLQ3IUJqz82CX9LVLaJ_3P3vmLwKINnO5r67Pq1reKcZFJMb0BIkUXMIVeH1_O8pTYnROL8yQKjP-Rp9MfN_r8xH6bKovzG6l9HHpOPBDJ6g6vPCHMM8YjBc_gpP2Qa0s6HpIg","e":"AQAB"})";

    // ── Шаг 1: Персональные данные (plaintext) ───────────────────────────
    const std::string plaintext = R"({
    "sub":   "user-42",
    "name":  "Иванова Мария Сергеевна",
    "email": "m.ivanova@example.ru",
    "phone": "+7 900 123-45-67",
    "iat":   1710000000
})";

    printSeparator("Шаг 1: Plaintext (персональные данные)");
    std::cout << plaintext << '\n';

    try {
        // ── Шаги 2-7: Построение JWE-токена ──────────────────────────────
        jwe::JweBuilder builder;
        builder.setPublicKeyFromJwkString(jwkJson);

        printSeparator("Шаги 2-7: Построение JWE");
        std::cout << "  Алгоритм ключа:   RSA-OAEP-256\n"
                  << "  Алгоритм данных:  A256GCM\n"
                  << "  Размер CEK:       " << jwe::kCekSize * 8 << " бит\n"
                  << "  Размер IV:        " << jwe::kIvSize  * 8 << " бит\n"
                  << "  Размер тега:      " << jwe::kTagSize * 8 << " бит\n";

        auto token = builder.build(plaintext);

        // ── Вывод компонентов токена ──────────────────────────────────────
        printSeparator("Компоненты JWE-токена");
        std::cout << "  Protected Header  : " << token.protected_header       << '\n'
                  << "  Encrypted Key     : " << token.encrypted_key.substr(0,32) << "…\n"
                  << "  Initialization IV : " << token.initialization_vector  << '\n'
                  << "  Ciphertext        : " << token.ciphertext.substr(0,32) << "…\n"
                  << "  Auth Tag          : " << token.authentication_tag     << '\n';

        // Декодируем заголовок для наглядности
        auto hdrBytes = jwe::base64url::decode(token.protected_header);
        std::string hdrStr(hdrBytes.begin(), hdrBytes.end());
        std::cout << "\n  Заголовок (декодирован): " << hdrStr << '\n';

        // ── Компактная сериализация ───────────────────────────────────────
        printSeparator("JWE Compact Serialization (RFC 7516 §7.1)");
        std::string compact = token.compact();
        // Выводим по частям для читаемости
        std::size_t part = 0;
        const char* partNames[] = {
            "Header          ",
            "Encrypted Key   ",
            "IV              ",
            "Ciphertext      ",
            "Authentication  "
        };
        std::size_t start = 0;
        for (std::size_t i = 0; i <= compact.size(); ++i) {
            if (i == compact.size() || compact[i] == '.') {
                std::string chunk = compact.substr(start, i - start);
                std::cout << "  " << partNames[part++] << ": "
                          << (chunk.size() > 40
                              ? chunk.substr(0,40) + "…(" + std::to_string(chunk.size()) + " chars)"
                              : chunk)
                          << '\n';
                start = i + 1;
            }
        }

        std::cout << "\n┌─ Полный токен ─────────────────────────────────────┐\n";
        // Печатаем по 72 символа в строке
        for (std::size_t i = 0; i < compact.size(); i += 72)
            std::cout << "│ " << compact.substr(i, 72) << '\n';
        std::cout << "└────────────────────────────────────────────────────┘\n";

        // ── Статистика ────────────────────────────────────────────────────
        printSeparator("Статистика");
        std::cout << "  Plaintext размер : " << plaintext.size() << " байт\n"
                  << "  Ciphertext размер: "
                  << jwe::base64url::decode(token.ciphertext).size() << " байт\n"
                  << "  Токен длина      : " << compact.size() << " символов\n";

        std::cout << "\n✓ JWE-токен успешно сформирован!\n\n";
        return 0;

    } catch (const jwe::JweError& e) {
        std::cerr << "\n✗ JWE ошибка: " << e.what() << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Ошибка: " << e.what() << '\n';
        return 2;
    }
}
