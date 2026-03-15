#pragma once

/**
 * @file base64url.hpp
 * @brief BASE64URL кодирование/декодирование без паддинга (RFC 4648 §5)
 *
 * Реализация не использует сторонних зависимостей.
 * Таблица символов: A-Z a-z 0-9 - _
 */

#include "types.hpp"
#include <string>
#include <string_view>

namespace jwe::base64url {

namespace detail {

/// Таблица кодирования (RFC 4648, таблица 2)
inline constexpr char kEncTable[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Таблица декодирования: 0xFF — недопустимый символ
// clang-format off
inline constexpr uint8_t kDecTable[256] = {
//  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x00
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x10
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 62  , 0xFF, 0xFF, // 0x20  '-'=62
    52  , 53  , 54  , 55  , 56  , 57  , 58  , 59  , 60  , 61  , 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x30  '0'-'9'
    0xFF, 0   , 1   , 2   , 3   , 4   , 5   , 6   , 7   , 8   , 9   , 10  , 11  , 12  , 13  , 14  , // 0x40  'A'-'O'
    15  , 16  , 17  , 18  , 19  , 20  , 21  , 22  , 23  , 24  , 25  , 0xFF, 0xFF, 0xFF, 0xFF, 63  , // 0x50  'P'-'Z','_'=63
    0xFF, 26  , 27  , 28  , 29  , 30  , 31  , 32  , 33  , 34  , 35  , 36  , 37  , 38  , 39  , 40  , // 0x60  'a'-'o'
    41  , 42  , 43  , 44  , 45  , 46  , 47  , 48  , 49  , 50  , 51  , 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x70  'p'-'z'
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x80
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x90
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0xA0
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0xB0
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0xC0
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0xD0
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0xE0
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  // 0xF0
};
// clang-format on

} // namespace detail

// ─── Кодирование ───────────────────────────────────────────────────────────

/**
 * @brief Кодирует произвольные байты в BASE64URL-строку без '=' паддинга.
 * @param data  Входные данные.
 * @return BASE64URL-строка.
 */
[[nodiscard]] inline std::string encode(ByteSpan data) {
    std::string out;
    out.reserve((data.size() * 4 + 2) / 3);

    std::size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t v = (uint32_t(data[i])     << 16) |
                     (uint32_t(data[i + 1]) <<  8) |
                      uint32_t(data[i + 2]);
        out += detail::kEncTable[(v >> 18) & 0x3F];
        out += detail::kEncTable[(v >> 12) & 0x3F];
        out += detail::kEncTable[(v >>  6) & 0x3F];
        out += detail::kEncTable[(v)       & 0x3F];
    }
    if (i + 1 == data.size()) {
        uint32_t v = uint32_t(data[i]) << 16;
        out += detail::kEncTable[(v >> 18) & 0x3F];
        out += detail::kEncTable[(v >> 12) & 0x3F];
    } else if (i + 2 == data.size()) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out += detail::kEncTable[(v >> 18) & 0x3F];
        out += detail::kEncTable[(v >> 12) & 0x3F];
        out += detail::kEncTable[(v >>  6) & 0x3F];
    }
    return out;
}

[[nodiscard]] inline std::string encode(const Bytes& data) {
    return encode(ByteSpan{data});
}

[[nodiscard]] inline std::string encode(std::string_view sv) {
    return encode(ByteSpan{
        reinterpret_cast<const uint8_t*>(sv.data()), sv.size()
    });
}

// ─── Декодирование ─────────────────────────────────────────────────────────

/**
 * @brief Декодирует BASE64URL-строку (с паддингом или без) в байты.
 * @param s  Входная BASE64URL-строка.
 * @return Декодированные байты.
 * @throws EncodingError при недопустимых символах.
 */
[[nodiscard]] inline Bytes decode(std::string_view s) {
    // Убираем паддинг '='
    while (!s.empty() && s.back() == '=') s.remove_suffix(1);

    Bytes out;
    out.reserve(s.size() * 3 / 4);

    auto get = [&](char c) -> uint8_t {
        auto v = detail::kDecTable[static_cast<uint8_t>(c)];
        if (v == 0xFF)
            throw EncodingError(
                std::string("base64url: недопустимый символ '") + c + "'");
        return v;
    };

    std::size_t i = 0;
    for (; i + 3 < s.size(); i += 4) {
        uint32_t v = (uint32_t(get(s[i]))     << 18) |
                     (uint32_t(get(s[i + 1])) << 12) |
                     (uint32_t(get(s[i + 2])) <<  6) |
                      uint32_t(get(s[i + 3]));
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >>  8));
        out.push_back(uint8_t(v));
    }

    const std::size_t rem = s.size() - i;
    if (rem == 2) {
        uint32_t v = (uint32_t(get(s[i])) << 18) | (uint32_t(get(s[i+1])) << 12);
        out.push_back(uint8_t(v >> 16));
    } else if (rem == 3) {
        uint32_t v = (uint32_t(get(s[i])) << 18) |
                     (uint32_t(get(s[i+1])) << 12) |
                     (uint32_t(get(s[i+2])) << 6);
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >>  8));
    } else if (rem == 1) {
        throw EncodingError("base64url: недопустимая длина строки");
    }
    return out;
}

} // namespace jwe::base64url
