#pragma once

/**
 * @file jwe_builder.hpp
 * @brief Основной класс для построения JWE-токенов (RFC 7516)
 *
 * Реализует все шаги ТЗ:
 *  1. Принимает plaintext (JSON с персональными данными)
 *  2. Формирует защищённый заголовок {"alg":"RSA-OAEP-256","enc":"A256GCM"}
 *  3. Генерирует случайный CEK (Content Encryption Key, 256 бит)
 *  4. Шифрует CEK публичным RSA-ключом (RSA-OAEP-256) → JWE Encrypted Key
 *  5. Генерирует случайный IV (96 бит) → JWE Initialization Vector
 *  6. AAD = ASCII(BASE64URL(JWE Protected Header))
 *  7. Шифрует plaintext: AES-256-GCM(CEK, IV, AAD) → ciphertext + tag
 *
 * Использование:
 * @code
 *   jwe::JweBuilder builder;
 *   builder.setPublicKeyFromJwkString(R"({"kty":"RSA","n":"…","e":"AQAB"})");
 *   auto token = builder.build(R"({"sub":"user123","name":"Иван"})");
 *   std::cout << token.compact() << '\n';
 * @endcode
 */

#include "aes_gcm.hpp"
#include "base64url.hpp"
#include "jwks_fetcher.hpp"
#include "rsa_oaep.hpp"
#include "types.hpp"

#include <optional>
#include <string>

namespace jwe {

class JweBuilder {
public:
    JweBuilder() = default;

    // ─── Настройка ключа ─────────────────────────────────────────────────

    /**
     * @brief Установить публичный ключ из JWK JSON-строки.
     * @param jwk  Строка вида {"kty":"RSA","n":"…","e":"AQAB"}
     */
    JweBuilder& setPublicKeyFromJwkString(std::string_view jwk) {
        key_ = keyFromJwkString(jwk);
        return *this;
    }

    /**
     * @brief Загрузить публичный ключ с JWKS URL.
     * @param url  URL JWKS-эндпоинта
     * @param kid  Опциональный kid
     */
    JweBuilder& setPublicKeyFromJwksUrl(std::string_view url,
                                        std::string_view kid = "") {
        key_ = fetchJwksKey(url, kid);
        return *this;
    }

    /**
     * @brief Установить публичный ключ напрямую.
     */
    JweBuilder& setPublicKey(RsaPublicKey key) {
        key_ = std::move(key);
        return *this;
    }

    // ─── Построение токена ───────────────────────────────────────────────

    /**
     * @brief Построить JWE Compact Serialization из plaintext.
     *
     * @param plaintext  Открытый текст (обычно JSON с персональными данными)
     * @return JweToken  Структура со всеми пятью компонентами токена
     * @throws KeyError     если ключ не задан
     * @throws CryptoError  при ошибках шифрования
     */
    [[nodiscard]] JweToken build(std::string_view plaintext) const {
        if (!key_) throw KeyError("JweBuilder: публичный ключ не задан");

        // ── Шаг 2: Защищённый заголовок ──────────────────────────────────
        //   {"alg":"RSA-OAEP-256","enc":"A256GCM"}
        //   Ключи в алфавитном порядке — для детерминированного BASE64URL
        const std::string headerJson =
            R"({"alg":"RSA-OAEP-256","enc":"A256GCM"})";
        const std::string protectedHeader = base64url::encode(headerJson);

        // ── Шаг 3: Генерация CEK (256 бит = 32 байта) ────────────────────
        Bytes cek = crypto::randomBytes(kCekSize);

        // ── Шаг 4: Шифрование CEK публичным RSA-OAEP-256 ─────────────────
        Bytes nBytes = base64url::decode(key_->n);
        Bytes eBytes = base64url::decode(key_->e);

        Bytes encryptedKey = crypto::rsaOaepEncrypt(
            ByteSpan{nBytes},
            ByteSpan{eBytes},
            ByteSpan{cek});

        // ── Шаг 5: Генерация IV (96 бит = 12 байт) ───────────────────────
        Bytes iv = crypto::randomBytes(kIvSize);

        // ── Шаг 6: AAD = ASCII(BASE64URL(JWE Protected Header)) ──────────
        //   В стандарте: AAD — это байты ASCII-строки protectedHeader
        Bytes aad(protectedHeader.begin(), protectedHeader.end());

        // ── Шаг 7: Шифрование plaintext — AES-256-GCM ─────────────────────
        Bytes pt(plaintext.begin(), plaintext.end());
        auto gcmResult = crypto::aes256_gcm_encrypt(
            ByteSpan{cek},
            ByteSpan{iv},
            ByteSpan{pt},
            ByteSpan{aad});

        // ── Сборка JweToken ───────────────────────────────────────────────
        JweToken token;
        token.protected_header       = protectedHeader;
        token.encrypted_key          = base64url::encode(ByteSpan{encryptedKey});
        token.initialization_vector  = base64url::encode(ByteSpan{iv});
        token.ciphertext             = base64url::encode(ByteSpan{gcmResult.ciphertext});
        token.authentication_tag     = base64url::encode(
            ByteSpan{gcmResult.tag.data(), gcmResult.tag.size()});

        return token;
    }

private:
    std::optional<RsaPublicKey> key_;
};

} // namespace jwe
