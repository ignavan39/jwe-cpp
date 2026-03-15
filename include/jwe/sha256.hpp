#pragma once

/**
 * @file sha256.hpp
 * @brief SHA-256 и HMAC-SHA-256 — реализация с нуля (FIPS 180-4)
 *
 * Используется внутри MGF1 (маскирующая функция OAEP) и OAEP-padding.
 */

#include "types.hpp"
#include <array>
#include <cstring>

namespace jwe::crypto {

// ─── SHA-256 ───────────────────────────────────────────────────────────────

namespace detail {

/// Константы K (FIPS 180-4, §4.2.2)
inline constexpr std::array<uint32_t, 64> kShaK = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline constexpr uint32_t rotr(uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32 - n));
}

} // namespace detail

/**
 * @brief Инкрементальный SHA-256 хэшер.
 *
 * Использование:
 * @code
 *   Sha256 h;
 *   h.update(data);
 *   auto digest = h.finalize();
 * @endcode
 */
class Sha256 {
public:
    static constexpr std::size_t kDigestSize  = 32;
    static constexpr std::size_t kBlockSize   = 64;

    using Digest = std::array<uint8_t, kDigestSize>;

    Sha256() noexcept { reset(); }

    void reset() noexcept {
        state_  = kInitState;
        count_  = 0;
        bufLen_ = 0;
    }

    void update(ByteSpan data) noexcept {
        for (auto byte : data) {
            buf_[bufLen_++] = byte;
            if (bufLen_ == kBlockSize) {
                processBlock();
                bufLen_ = 0;
            }
        }
        count_ += data.size() * 8;
    }

    void update(const Bytes& data) noexcept {
        update(ByteSpan{data});
    }

    void update(std::string_view sv) noexcept {
        update(ByteSpan{reinterpret_cast<const uint8_t*>(sv.data()), sv.size()});
    }

    [[nodiscard]] Digest finalize() noexcept {
        // Паддинг (FIPS 180-4 §5.1.1)
        buf_[bufLen_++] = 0x80;
        if (bufLen_ > 56) {
            while (bufLen_ < 64) buf_[bufLen_++] = 0;
            processBlock();
            bufLen_ = 0;
        }
        while (bufLen_ < 56) buf_[bufLen_++] = 0;

        // Длина в битах (big-endian 64-bit)
        for (std::size_t i = 0; i < 8; ++i)
            buf_[56 + i] = uint8_t(count_ >> ((7u - i) * 8u));
        processBlock();

        Digest out{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t j = 0; j < 4; ++j)
                out[i * 4u + j] = uint8_t(state_[i] >> ((3u - j) * 8u));
        return out;
    }

    /// Однопроходный хэш
    [[nodiscard]] static Digest hash(ByteSpan data) noexcept {
        Sha256 h; h.update(data); return h.finalize();
    }
    [[nodiscard]] static Digest hash(const Bytes& data) noexcept {
        return hash(ByteSpan{data});
    }
    [[nodiscard]] static Digest hash(std::string_view sv) noexcept {
        return hash(ByteSpan{reinterpret_cast<const uint8_t*>(sv.data()), sv.size()});
    }

private:
    static constexpr std::array<uint32_t, 8> kInitState = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    std::array<uint32_t, 8> state_{};
    std::array<uint8_t, 64> buf_{};
    uint64_t count_{0};
    std::size_t bufLen_{0};

    void processBlock() noexcept {
        using namespace detail;

        std::array<uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i)
            w[i] = (uint32_t(buf_[i*4u])   << 24) | (uint32_t(buf_[i*4u+1u]) << 16) |
                   (uint32_t(buf_[i*4u+2u]) <<  8) |  uint32_t(buf_[i*4u+3u]);
        for (std::size_t i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15u], 7) ^ rotr(w[i-15u], 18) ^ (w[i-15u] >> 3);
            uint32_t s1 = rotr(w[i- 2u],17) ^ rotr(w[i- 2u], 19) ^ (w[i- 2u] >> 10);
            w[i] = w[i-16u] + s0 + w[i-7u] + s1;
        }

        auto [a,b,c,d,e,f,g,h] = state_;
        for (std::size_t i = 0; i < 64; ++i) {
            uint32_t S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch  = (e & f) ^ (~e & g);
            uint32_t tmp1 = h + S1 + ch + kShaK[i] + w[i];
            uint32_t S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t tmp2 = S0 + maj;
            h = g; g = f; f = e; e = d + tmp1;
            d = c; c = b; b = a; a = tmp1 + tmp2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

// ─── HMAC-SHA-256 ──────────────────────────────────────────────────────────

/**
 * @brief HMAC-SHA-256 (RFC 2104).
 * @param key   Ключ произвольной длины.
 * @param data  Данные.
 * @return 32-байтный MAC.
 */
[[nodiscard]] inline Sha256::Digest hmac_sha256(ByteSpan key, ByteSpan data) noexcept {
    std::array<uint8_t, 64> k_ipad{}, k_opad{};

    Bytes kbuf(key.begin(), key.end());
    if (kbuf.size() > 64) {
        auto d = Sha256::hash(ByteSpan{kbuf});
        kbuf.assign(d.begin(), d.end());
    }
    kbuf.resize(64, 0);

    for (std::size_t i = 0; i < 64; ++i) {
        k_ipad[i] = kbuf[i] ^ 0x36u;
        k_opad[i] = kbuf[i] ^ 0x5Cu;
    }

    Sha256 inner;
    inner.update(ByteSpan{k_ipad});
    inner.update(data);
    auto inner_hash = inner.finalize();

    Sha256 outer;
    outer.update(ByteSpan{k_opad});
    outer.update(ByteSpan{inner_hash});
    return outer.finalize();
}

// ─── MGF1 (PKCS #1 v2.2 §B.2.1) ───────────────────────────────────────────

/**
 * @brief Маскирующая функция MGF1 на основе SHA-256.
 * @param seed   Зерно.
 * @param length Требуемая длина маски в байтах.
 * @return Маска заданной длины.
 */
[[nodiscard]] inline Bytes mgf1_sha256(ByteSpan seed, std::size_t length) {
    Bytes mask;
    mask.reserve(length);

    for (uint32_t counter = 0; mask.size() < length; ++counter) {
        std::array<uint8_t, 4> c_bytes = {
            uint8_t(counter >> 24), uint8_t(counter >> 16),
            uint8_t(counter >>  8), uint8_t(counter)
        };
        Sha256 h;
        h.update(seed);
        h.update(ByteSpan{c_bytes});
        auto d = h.finalize();
        for (auto b : d) {
            if (mask.size() < length) mask.push_back(b);
        }
    }
    return mask;
}

} // namespace jwe::crypto
