#pragma once

/**
 * @file aes_gcm.hpp
 * @brief AES-256 + GCM (Galois/Counter Mode) — реализация с нуля
 *
 * Стандарты:
 *  - AES: FIPS 197
 *  - GCM: NIST SP 800-38D
 *
 * Ограничения данной реализации:
 *  - Только 256-битный ключ (32 байта)
 *  - IV строго 96 бит (12 байт) — рекомендуемый размер для GCM
 *  - Тег аутентификации 128 бит (16 байт)
 */

#include "types.hpp"
#include <array>
#include <cstring>

namespace jwe::crypto {

// ─── AES-256 ───────────────────────────────────────────────────────────────

namespace detail {

// S-box (FIPS 197, Figure 7)
inline constexpr uint8_t kSBox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Rcon для ключевого расписания AES (FIPS 197, §A.3)
inline constexpr uint8_t kRcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

// Умножение в GF(2^8) по модулю 0x11b
inline constexpr uint8_t gf_mul(uint8_t a, uint8_t b) noexcept {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80);
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

} // namespace detail

// ─── AES-256 Block Cipher ──────────────────────────────────────────────────

class Aes256 {
public:
    static constexpr std::size_t kKeySize   = 32;
    static constexpr std::size_t kBlockSize = 16;
    static constexpr int         kRounds    = 14;

    using Block = std::array<uint8_t, kBlockSize>;

    explicit Aes256(ByteSpan key) {
        if (key.size() != kKeySize)
            throw CryptoError("AES-256: ожидается ключ 32 байта");
        keyExpansion(key);
    }

    /// Зашифровать один блок (ECB, in-place)
    void encryptBlock(Block& block) const noexcept {
        addRoundKey(block, 0);
        for (int r = 1; r < kRounds; ++r) {
            subBytes(block);
            shiftRows(block);
            mixColumns(block);
            addRoundKey(block, r);
        }
        subBytes(block);
        shiftRows(block);
        addRoundKey(block, kRounds);
    }

private:
    // Развёрнутые ключи: (kRounds+1) * 4 слова по 4 байта
    std::array<uint32_t, (kRounds + 1) * 4> rk_{};

    void keyExpansion(ByteSpan key) noexcept {
        for (int i = 0; i < 8; ++i)
            rk_[i] = (uint32_t(key[i*4])   << 24) | (uint32_t(key[i*4+1]) << 16) |
                     (uint32_t(key[i*4+2]) <<  8) |  uint32_t(key[i*4+3]);

        for (int i = 8; i < (kRounds + 1) * 4; ++i) {
            uint32_t t = rk_[i - 1];
            if (i % 8 == 0) {
                t = subWord(rotWord(t)) ^ (uint32_t(detail::kRcon[i/8]) << 24);
            } else if (i % 8 == 4) {
                t = subWord(t);
            }
            rk_[i] = rk_[i - 8] ^ t;
        }
    }

    static uint32_t rotWord(uint32_t w) noexcept {
        return (w << 8) | (w >> 24);
    }

    static uint32_t subWord(uint32_t w) noexcept {
        return (uint32_t(detail::kSBox[(w >> 24) & 0xff]) << 24) |
               (uint32_t(detail::kSBox[(w >> 16) & 0xff]) << 16) |
               (uint32_t(detail::kSBox[(w >>  8) & 0xff]) <<  8) |
                uint32_t(detail::kSBox[ w        & 0xff]);
    }

    void addRoundKey(Block& b, int round) const noexcept {
        for (int c = 0; c < 4; ++c) {
            uint32_t k = rk_[round * 4 + c];
            b[c*4+0] ^= uint8_t(k >> 24);
            b[c*4+1] ^= uint8_t(k >> 16);
            b[c*4+2] ^= uint8_t(k >>  8);
            b[c*4+3] ^= uint8_t(k);
        }
    }

    static void subBytes(Block& b) noexcept {
        for (auto& byte : b) byte = detail::kSBox[byte];
    }

    static void shiftRows(Block& b) noexcept {
        std::swap(b[1], b[13]); std::swap(b[1], b[9]); std::swap(b[1], b[5]);
        std::swap(b[2], b[10]); std::swap(b[6], b[14]);
        std::swap(b[15], b[11]); std::swap(b[11], b[7]); std::swap(b[7], b[3]);
    }

    static void mixColumns(Block& b) noexcept {
        using namespace detail;
        for (int c = 0; c < 4; ++c) {
            uint8_t s0 = b[c*4], s1 = b[c*4+1], s2 = b[c*4+2], s3 = b[c*4+3];
            b[c*4+0] = gf_mul(0x02,s0)^gf_mul(0x03,s1)^s2^s3;
            b[c*4+1] = s0^gf_mul(0x02,s1)^gf_mul(0x03,s2)^s3;
            b[c*4+2] = s0^s1^gf_mul(0x02,s2)^gf_mul(0x03,s3);
            b[c*4+3] = gf_mul(0x03,s0)^s1^s2^gf_mul(0x02,s3);
        }
    }
};

// ─── GCM (Galois/Counter Mode) ─────────────────────────────────────────────

/**
 * @brief Результат AES-256-GCM шифрования.
 */
struct GcmResult {
    Bytes ciphertext;
    std::array<uint8_t, kTagSize> tag;
};

namespace detail {

// Умножение в GF(2^128) по неприводимому многочлену x^128+x^7+x^2+x+1
// (NIST SP 800-38D, §6.3)
inline void gf128_mul(
    const std::array<uint8_t,16>& x,
    const std::array<uint8_t,16>& y,
    std::array<uint8_t,16>&       z) noexcept
{
    z.fill(0);
    std::array<uint8_t,16> v = y;

    for (int i = 0; i < 16; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            if (x[i] & (1 << bit)) {
                for (int j = 0; j < 16; ++j) z[j] ^= v[j];
            }
            bool lsb = v[15] & 1;
            // Сдвиг v вправо на 1 бит
            for (int j = 15; j > 0; --j) v[j] = uint8_t((v[j] >> 1) | (v[j-1] << 7));
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xe1; // редукция: x^128 = x^7+x^2+x+1 => 0xe1000...0
        }
    }
}

} // namespace detail

/**
 * @brief AES-256-GCM шифрование (NIST SP 800-38D).
 *
 * @param key         32-байтный ключ шифрования
 * @param iv          12-байтный вектор инициализации
 * @param plaintext   Открытый текст
 * @param aad         Additional Authenticated Data (не шифруется, но аутентифицируется)
 * @return GcmResult  { ciphertext, tag }
 * @throws CryptoError при некорректных параметрах
 */
[[nodiscard]] inline GcmResult aes256_gcm_encrypt(
    ByteSpan key,
    ByteSpan iv,
    ByteSpan plaintext,
    ByteSpan aad)
{
    if (key.size() != kCekSize)
        throw CryptoError("GCM: ключ должен быть 32 байта");
    if (iv.size() != kIvSize)
        throw CryptoError("GCM: IV должен быть 12 байт");

    Aes256 aes(key);

    // H = AES(key, 0^128)
    Aes256::Block H{};
    aes.encryptBlock(H);

    // Начальный счётчик J0 = IV || 0x00000001 (96-bit IV, NIST §7.1)
    Aes256::Block J0{};
    std::copy(iv.begin(), iv.end(), J0.begin());
    J0[15] = 0x01;

    // GCTR: шифрование текста
    GcmResult result;
    result.ciphertext.resize(plaintext.size());

    auto incr32 = [](Aes256::Block& cb) {
        for (int i = 15; i >= 12; --i)
            if (++cb[i] != 0) break;
    };

    Aes256::Block cb = J0;
    incr32(cb);

    for (std::size_t offset = 0; offset < plaintext.size(); offset += 16) {
        Aes256::Block ek = cb;
        aes.encryptBlock(ek);
        incr32(cb);
        std::size_t n = std::min<std::size_t>(16, plaintext.size() - offset);
        for (std::size_t j = 0; j < n; ++j)
            result.ciphertext[offset + j] = plaintext[offset + j] ^ ek[j];
    }

    // GHASH аутентификационный тег
    // S = GHASH(H, A, C) где A=aad, C=ciphertext
    // GHASH(H, X) = X_1*H^m + X_2*H^(m-1) + ... (в GF(2^128))

    // Копируем H (Block → array<uint8_t,16>) для использования в GHASH
    std::array<uint8_t, 16> Harr{};
    std::copy(H.begin(), H.end(), Harr.begin());

    auto ghash_update = [&](std::array<uint8_t,16>& tag_val,
                            ByteSpan data) {
        std::size_t full = data.size() / 16;
        for (std::size_t i = 0; i < full; ++i) {
            for (int j = 0; j < 16; ++j)
                tag_val[j] ^= data[i*16 + j];
            std::array<uint8_t,16> tmp{};
            detail::gf128_mul(tag_val, Harr, tmp);
            tag_val = tmp;
        }
        std::size_t rem = data.size() % 16;
        if (rem) {
            std::array<uint8_t,16> padded{};
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(full*16),
                      data.end(), padded.begin());
            for (int j = 0; j < 16; ++j) tag_val[j] ^= padded[j];
            std::array<uint8_t,16> tmp{};
            detail::gf128_mul(tag_val, Harr, tmp);
            tag_val = tmp;
        }
    };

    std::array<uint8_t,16> tag_val{};
    ghash_update(tag_val, aad);
    ghash_update(tag_val, ByteSpan{result.ciphertext});

    // Финальный блок длин (64-bit big-endian * 2)
    std::array<uint8_t,16> len_block{};
    uint64_t aad_bits = uint64_t(aad.size()) * 8;
    uint64_t ct_bits  = uint64_t(result.ciphertext.size()) * 8;
    for (int i = 7; i >= 0; --i) {
        len_block[i]     = uint8_t(aad_bits >> ((7-i)*8));
        len_block[8 + i] = uint8_t(ct_bits  >> ((7-i)*8));
    }
    for (int j = 0; j < 16; ++j) tag_val[j] ^= len_block[j];
    {
        std::array<uint8_t,16> tmp{};
        detail::gf128_mul(tag_val, Harr, tmp);
        tag_val = tmp;
    }

    // T = MSB_t(GCTR(J0, S))
    Aes256::Block ej0 = J0;
    aes.encryptBlock(ej0);
    for (int j = 0; j < 16; ++j) tag_val[j] ^= ej0[j];

    std::copy(tag_val.begin(), tag_val.end(), result.tag.begin());
    return result;
}

} // namespace jwe::crypto
