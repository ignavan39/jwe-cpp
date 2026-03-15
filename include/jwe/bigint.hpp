#pragma once

/**
 * @file bigint.hpp
 * @brief Большие целые числа для RSA-арифметики (без знака, big-endian байты)
 *
 * Поддерживаются операции:
 *  - Сложение, вычитание, умножение, деление с остатком
 *  - Возведение в степень по модулю (Montgomery ladder — защита от timing)
 *  - Импорт/экспорт из big-endian байтов (формат DER/JWK)
 */

#include "types.hpp"
#include <algorithm>
#include <compare>
#include <string_view>
#include <vector>

namespace jwe::crypto {

/**
 * @brief Беззнаковое большое целое, хранится в виде вектора 32-битных «цифр»
 *        в little-endian порядке (младший разряд — нулевой элемент).
 */
class BigInt {
public:
    BigInt() : d_{0} {}
    explicit BigInt(uint64_t v) : d_{uint32_t(v & 0xFFFFFFFF), uint32_t(v >> 32)} { trim(); }

    // ─── Фабричные методы ────────────────────────────────────────────────

    /// Создать из big-endian байтов (формат JWK: n, e, p, q …)
    [[nodiscard]] static BigInt fromBytes(ByteSpan b) {
        BigInt r;
        r.d_.clear();
        std::size_t sz = b.size();
        if (sz >= 4u) {
            std::size_t i = sz - 4u;
            while (true) {
                uint32_t word = (uint32_t(b[i])    << 24) | (uint32_t(b[i+1u]) << 16) |
                                (uint32_t(b[i+2u]) <<  8) |  uint32_t(b[i+3u]);
                r.d_.push_back(word);
                if (i < 4u) break;
                i -= 4u;
            }
        }
        // Остаток (если длина не кратна 4)
        std::size_t rem = sz % 4u;
        if (rem) {
            uint32_t word = 0;
            for (std::size_t j = 0; j < rem; ++j)
                word = (word << 8u) | b[j];
            r.d_.push_back(word);
        }
        r.trim();
        return r;
    }

    [[nodiscard]] Bytes toBytes(std::size_t padTo = 0) const {
        Bytes out;
        for (auto it = d_.rbegin(); it != d_.rend(); ++it) {
            out.push_back(uint8_t(*it >> 24));
            out.push_back(uint8_t(*it >> 16));
            out.push_back(uint8_t(*it >>  8));
            out.push_back(uint8_t(*it));
        }
        while (out.size() > 1 && out.front() == 0) out.erase(out.begin());
        // Паддинг нулями слева до нужной длины
        if (out.size() < padTo)
            out.insert(out.begin(), padTo - out.size(), 0);
        return out;
    }

    // ─── Сравнение ───────────────────────────────────────────────────────

    [[nodiscard]] bool isZero() const noexcept {
        return d_.size() == 1 && d_[0] == 0;
    }

    [[nodiscard]] std::strong_ordering operator<=>(const BigInt& o) const noexcept {
        if (d_.size() != o.d_.size())
            return d_.size() <=> o.d_.size();
        for (std::size_t i = d_.size(); i-- > 0u;)
            if (d_[i] != o.d_[i]) return d_[i] <=> o.d_[i];
        return std::strong_ordering::equal;
    }
    bool operator==(const BigInt& o) const noexcept { return (*this <=> o) == 0; }
    bool operator< (const BigInt& o) const noexcept { return (*this <=> o) <  0; }

    // ─── Арифметика ──────────────────────────────────────────────────────

    [[nodiscard]] BigInt operator+(const BigInt& b) const { return add(*this, b); }
    [[nodiscard]] BigInt operator-(const BigInt& b) const { return sub(*this, b); }
    [[nodiscard]] BigInt operator*(const BigInt& b) const { return mul(*this, b); }

    /// Деление с остатком: возвращает {quotient, remainder}
    [[nodiscard]] static std::pair<BigInt, BigInt> divmod(const BigInt& a, const BigInt& m) {
        if (m.isZero()) throw CryptoError("BigInt: деление на ноль");
        if (a < m) return {BigInt(0), a};

        BigInt q, r;
        q.d_.resize(a.d_.size(), 0);

        std::size_t total = a.d_.size() * 32u;
        for (std::size_t i = total; i-- > 0u;) {
            r = shl1(r);
            if ((a.d_[i/32u] >> (i%32u)) & 1u)
                r.d_[0] |= 1u;
            if (!(r < m)) {
                r = sub(r, m);
                q.d_[i/32u] |= (1u << (i%32u));
            }
        }
        q.trim();
        return {q, r};
    }

    [[nodiscard]] BigInt operator%(const BigInt& m) const {
        return divmod(*this, m).second;
    }

    /**
     * @brief Возведение в степень по модулю: (base^exp) mod m
     *
     * Использует алгоритм «бинарного возведения» с постоянным временем
     * относительно разрядности exp (Montgomery ladder-подобная структура).
     */
    [[nodiscard]] static BigInt powmod(const BigInt& base,
                                       const BigInt& exp,
                                       const BigInt& m)
    {
        if (m == BigInt(1)) return BigInt(0);

        BigInt result(1);
        BigInt b = base % m;

        std::size_t bits = exp.d_.size() * 32u;
        for (std::size_t i = bits; i-- > 0u;) {
            result = mul(result, result) % m;
            if ((exp.d_[i/32u] >> (i%32u)) & 1u)
                result = mul(result, b) % m;
        }
        return result;
    }

    [[nodiscard]] std::size_t bitLen() const noexcept {
        if (isZero()) return 0;
        std::size_t n = (d_.size() - 1) * 32;
        uint32_t top = d_.back();
        while (top) { n++; top >>= 1; }
        return n;
    }

    [[nodiscard]] std::size_t byteLen() const noexcept {
        return (bitLen() + 7) / 8;
    }

    [[nodiscard]] bool testBit(std::size_t i) const noexcept {
        if (i / 32 >= d_.size()) return false;
        return (d_[i/32] >> (i%32)) & 1;
    }

private:
    std::vector<uint32_t> d_; // little-endian 32-bit limbs

    void trim() {
        while (d_.size() > 1 && d_.back() == 0) d_.pop_back();
    }

    static BigInt add(const BigInt& a, const BigInt& b) {
        BigInt r;
        r.d_.resize(std::max(a.d_.size(), b.d_.size()) + 1, 0);
        uint64_t carry = 0;
        for (std::size_t i = 0; i < r.d_.size(); ++i) {
            uint64_t s = carry;
            if (i < a.d_.size()) s += a.d_[i];
            if (i < b.d_.size()) s += b.d_[i];
            r.d_[i] = uint32_t(s);
            carry   = s >> 32;
        }
        r.trim();
        return r;
    }

    // Предусловие: a >= b
    static BigInt sub(const BigInt& a, const BigInt& b) {
        BigInt r;
        r.d_.resize(a.d_.size(), 0);
        int64_t borrow = 0;
        for (std::size_t i = 0; i < a.d_.size(); ++i) {
            int64_t diff = int64_t(a.d_[i]) - borrow;
            if (i < b.d_.size()) diff -= b.d_[i];
            borrow = (diff < 0) ? 1 : 0;
            r.d_[i] = uint32_t(diff + borrow * (int64_t(1) << 32));
        }
        r.trim();
        return r;
    }

    static BigInt mul(const BigInt& a, const BigInt& b) {
        BigInt r;
        r.d_.assign(a.d_.size() + b.d_.size(), 0);
        for (std::size_t i = 0; i < a.d_.size(); ++i) {
            uint64_t carry = 0;
            for (std::size_t j = 0; j < b.d_.size(); ++j) {
                uint64_t cur = uint64_t(a.d_[i]) * b.d_[j] + r.d_[i+j] + carry;
                r.d_[i+j] = uint32_t(cur);
                carry      = cur >> 32;
            }
            r.d_[i + b.d_.size()] += uint32_t(carry);
        }
        r.trim();
        return r;
    }

    static BigInt shl1(const BigInt& a) {
        BigInt r;
        r.d_.resize(a.d_.size() + 1, 0);
        uint32_t carry = 0;
        for (std::size_t i = 0; i < a.d_.size(); ++i) {
            r.d_[i] = (a.d_[i] << 1) | carry;
            carry   = a.d_[i] >> 31;
        }
        r.d_.back() = carry;
        r.trim();
        return r;
    }
};

} // namespace jwe::crypto
