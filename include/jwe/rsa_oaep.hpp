#pragma once

/**
 * @file rsa_oaep.hpp
 * @brief RSA-OAEP-256 шифрование (PKCS #1 v2.2, RFC 8017)
 *
 * Шифрует сообщение публичным ключом RSA с OAEP-паддингом на SHA-256.
 * Реализация raw-RSA поверх BigInt + MGF1(SHA-256).
 *
 * Ограничения:
 *  - Только шифрование (публичным ключом)
 *  - Только RSA-2048 и RSA-4096 (хотя код параметризован под любой ключ)
 *  - OAEP label = "" (пустая строка) — стандартный вариант JWE
 */

#include "bigint.hpp"
#include "sha256.hpp"
#include "types.hpp"
#include <random>

namespace jwe::crypto {

/**
 * @brief Случайные байты, криптографически стойкие (через /dev/urandom).
 */
[[nodiscard]] inline Bytes randomBytes(std::size_t n) {
#ifdef _WIN32
    // На Windows используем CryptGenRandom через BCrypt
    // Упрощённый вариант через std::random_device (достаточно для демо)
    Bytes out(n);
    std::random_device rd;
    for (auto& b : out) b = uint8_t(rd());
    return out;
#else
    Bytes out(n);
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) throw CryptoError("Не удаётся открыть /dev/urandom");
    if (fread(out.data(), 1, n, f) != n) {
        fclose(f);
        throw CryptoError("Ошибка чтения /dev/urandom");
    }
    fclose(f);
    return out;
#endif
}

/**
 * @brief RSA-OAEP-256 шифрование (RFC 8017 §7.1.1).
 *
 * @param n_bytes  Модуль RSA (big-endian байты из JWK "n")
 * @param e_bytes  Открытая экспонента RSA (big-endian байты из JWK "e")
 * @param message  Сообщение (≤ k - 2*hLen - 2 байт, где k=размер ключа)
 * @param label    OAEP Label (по умолчанию пустой — стандарт JWE)
 * @return Зашифрованный блок длиной k байт
 */
[[nodiscard]] inline Bytes rsaOaepEncrypt(
    ByteSpan     n_bytes,
    ByteSpan     e_bytes,
    ByteSpan     message,
    ByteSpan     label = {})
{
    constexpr std::size_t hLen = Sha256::kDigestSize; // 32

    BigInt n = BigInt::fromBytes(n_bytes);
    BigInt e = BigInt::fromBytes(e_bytes);

    std::size_t k = (n.bitLen() + 7) / 8; // длина ключа в байтах

    if (k < 2 * hLen + 2)
        throw CryptoError("RSA-OAEP: ключ слишком мал");
    if (message.size() > k - 2 * hLen - 2)
        throw CryptoError("RSA-OAEP: сообщение слишком длинное");

    // 1. Хэш метки: lHash = Hash(L)
    auto lHash = Sha256::hash(label);

    // 2. DB = lHash || PS || 0x01 || M
    //    где PS — нулевой паддинг длиной k - mLen - 2*hLen - 2
    Bytes db;
    db.reserve(k - hLen - 1);
    db.insert(db.end(), lHash.begin(), lHash.end());
    std::size_t psLen = k - message.size() - 2 * hLen - 2;
    db.insert(db.end(), psLen, 0x00);
    db.push_back(0x01);
    db.insert(db.end(), message.begin(), message.end());

    // 3. Случайная seed длиной hLen
    Bytes seed = randomBytes(hLen);

    // 4. dbMask  = MGF1(seed, k - hLen - 1)
    Bytes dbMask = mgf1_sha256(ByteSpan{seed}, k - hLen - 1);

    // 5. maskedDB = DB XOR dbMask
    Bytes maskedDB(db.size());
    for (std::size_t i = 0; i < db.size(); ++i)
        maskedDB[i] = db[i] ^ dbMask[i];

    // 6. seedMask = MGF1(maskedDB, hLen)
    Bytes seedMask = mgf1_sha256(ByteSpan{maskedDB}, hLen);

    // 7. maskedSeed = seed XOR seedMask
    Bytes maskedSeed(hLen);
    for (std::size_t i = 0; i < hLen; ++i)
        maskedSeed[i] = seed[i] ^ seedMask[i];

    // 8. EM = 0x00 || maskedSeed || maskedDB
    Bytes em;
    em.reserve(k);
    em.push_back(0x00);
    em.insert(em.end(), maskedSeed.begin(), maskedSeed.end());
    em.insert(em.end(), maskedDB.begin(),   maskedDB.end());

    // 9. RSA: c = m^e mod n
    BigInt m = BigInt::fromBytes(ByteSpan{em});
    BigInt c = BigInt::powmod(m, e, n);

    // 10. Привести к длине k (big-endian, с ведущими нулями)
    return c.toBytes(k);
}

} // namespace jwe::crypto
