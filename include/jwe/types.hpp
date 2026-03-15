#pragma once

/**
 * @file types.hpp
 * @brief Базовые типы и константы для JWE-реализации
 *
 * RFC 7516 — JSON Web Encryption (JWE)
 * Алгоритм шифрования ключа : RSA-OAEP-256 (RFC 3447)
 * Алгоритм шифрования данных: AES-256-GCM  (NIST SP 800-38D)
 */

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace jwe {

// ─── Псевдонимы ────────────────────────────────────────────────────────────

using Bytes     = std::vector<uint8_t>;
using ByteSpan  = std::span<const uint8_t>;

// ─── Размеры ───────────────────────────────────────────────────────────────

inline constexpr std::size_t kCekSize   = 32;  ///< 256 бит — AES-256
inline constexpr std::size_t kIvSize    = 12;  ///< 96  бит — GCM Initialization Vector
inline constexpr std::size_t kTagSize   = 16;  ///< 128 бит — GCM Authentication Tag

// ─── Идентификаторы алгоритмов (RFC 7518) ──────────────────────────────────

inline constexpr std::string_view kAlgRsaOaep256 = "RSA-OAEP-256";
inline constexpr std::string_view kEncA256Gcm     = "A256GCM";

// ─── Структуры результата ──────────────────────────────────────────────────

/**
 * @brief Все пять частей компактного представления JWE.
 *
 * Итоговый токен: header.ek.iv.ciphertext.tag
 * (каждая часть — BASE64URL без паддинга)
 */
struct JweToken {
    std::string protected_header;  ///< BASE64URL(UTF-8({"alg":…,"enc":…}))
    std::string encrypted_key;     ///< BASE64URL(RSA-OAEP-256(CEK))
    std::string initialization_vector; ///< BASE64URL(IV)
    std::string ciphertext;        ///< BASE64URL(AES-256-GCM(plaintext))
    std::string authentication_tag;///< BASE64URL(GCM tag)

    /// Компактная сериализация RFC 7516 §7.1
    [[nodiscard]] std::string compact() const {
        return protected_header + '.' +
               encrypted_key   + '.' +
               initialization_vector + '.' +
               ciphertext      + '.' +
               authentication_tag;
    }
};

// ─── Публичный RSA-ключ (минимальный набор полей JWK) ──────────────────────

/**
 * @brief RSA публичный ключ в формате JWK.
 *
 * Поля n (modulus) и e (exponent) хранятся в BASE64URL-кодировке,
 * точно как в JWKS-ответе сервис-провайдера.
 */
struct RsaPublicKey {
    std::string kty; ///< Всегда "RSA"
    std::string n;   ///< BASE64URL(modulus)
    std::string e;   ///< BASE64URL(public exponent)
    std::string kid; ///< Идентификатор ключа (опционально)
    std::string use; ///< "enc" | "sig"
    std::string alg; ///< Ожидаем "RSA-OAEP-256"
};

// ─── Исключения ────────────────────────────────────────────────────────────

/// Базовый класс ошибок библиотеки
struct JweError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct CryptoError    : JweError { using JweError::JweError; };
struct EncodingError  : JweError { using JweError::JweError; };
struct KeyError       : JweError { using JweError::JweError; };
struct NetworkError   : JweError { using JweError::JweError; };
struct ParseError     : JweError { using JweError::JweError; };

} // namespace jwe
