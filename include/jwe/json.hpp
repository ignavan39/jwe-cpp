#pragma once

/**
 * @file json.hpp
 * @brief Минимальный JSON-парсер для работы с JWKS и JWE-заголовком
 *
 * Поддерживает:
 *  - Объекты { "key": value, … }
 *  - Массивы [ value, … ]
 *  - Строки, числа, булевы значения, null
 *
 * Не поддерживает: Unicode escape \uXXXX (только ASCII и UTF-8 literal),
 * вложенность глубже ~64 уровней.
 *
 * Достаточно для разбора JWKS-ответа по RFC 7517.
 */

#include "types.hpp"
#include <cmath>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace jwe::json {

// ─── Forward declarations ──────────────────────────────────────────────────

struct Value;
struct Object;   // forward-declared; defined after Value

using Null   = std::monostate;
using Bool   = bool;
using Number = double;
using String = std::string;
using Array  = std::vector<Value>;

// ValueVariant держит Object* через unique_ptr чтобы не требовать
// полного типа Object/Value на этапе объявления variant.
// Фактически: Null | Bool | Number | String | Array | Object (boxed)
using ValueVariant = std::variant<Null, Bool, Number, String, Array,
                                  std::unique_ptr<Object>>;

/**
 * @brief JSON-значение.
 *
 * Object хранится как unique_ptr<Object> внутри variant, чтобы разорвать
 * циклическую зависимость Value→Object→Value при неполных типах.
 * Это также обходит баг GCC 14 libstdc++ PR#114863 (tuple_like + std::map).
 */
struct Value {
    ValueVariant v;

    Value()            : v(Null{})          {}
    Value(Null n)      : v(n)               {}
    Value(Bool b)      : v(b)               {}
    Value(Number n)    : v(n)               {}
    Value(String s)    : v(std::move(s))    {}
    Value(Array a)     : v(std::move(a))    {}
    Value(std::unique_ptr<Object> o) : v(std::move(o)) {}

    // Copy constructor/assignment — нужны из-за unique_ptr
    Value(const Value& o);
    Value& operator=(const Value& o);
    Value(Value&&) noexcept = default;
    Value& operator=(Value&&) noexcept = default;
    ~Value() = default;

    [[nodiscard]] bool isNull()   const noexcept { return std::holds_alternative<Null>(v); }
    [[nodiscard]] bool isBool()   const noexcept { return std::holds_alternative<Bool>(v); }
    [[nodiscard]] bool isNumber() const noexcept { return std::holds_alternative<Number>(v); }
    [[nodiscard]] bool isString() const noexcept { return std::holds_alternative<String>(v); }
    [[nodiscard]] bool isArray()  const noexcept { return std::holds_alternative<Array>(v); }
    [[nodiscard]] bool isObject() const noexcept {
        return std::holds_alternative<std::unique_ptr<Object>>(v);
    }

    [[nodiscard]] const String& asString() const {
        if (!isString()) throw ParseError("JSON: ожидается строка");
        return std::get<String>(v);
    }
    [[nodiscard]] const Array& asArray() const {
        if (!isArray()) throw ParseError("JSON: ожидается массив");
        return std::get<Array>(v);
    }
    [[nodiscard]] const Object& asObject() const;

    [[nodiscard]] const Value& operator[](std::string_view key) const;
    [[nodiscard]] bool has(std::string_view key) const noexcept;
};

// ─── Object — после полного определения Value ────────────────────────────

/**
 * @brief JSON-объект: упорядоченный список пар ключ→значение.
 * Реализован как вектор пар (не std::map) чтобы обойти GCC 14 PR#114863.
 */
struct Object {
    std::vector<std::pair<std::string, Value>> entries;

    Value& operator[](std::string key) {
        for (auto& [k, val] : entries)
            if (k == key) return val;
        entries.emplace_back(std::move(key), Value{});
        return entries.back().second;
    }

    [[nodiscard]] const Value* find(std::string_view key) const noexcept {
        for (const auto& [k, val] : entries)
            if (k == key) return &val;
        return nullptr;
    }

    auto begin() const noexcept { return entries.begin(); }
    auto end()   const noexcept { return entries.end();   }
};

// ─── Определения методов Value, требующих полный тип Object ──────────────

inline Value::Value(const Value& o) : v(Null{}) {
    std::visit([this](const auto& alt) {
        using T = std::decay_t<decltype(alt)>;
        if constexpr (std::is_same_v<T, std::unique_ptr<Object>>) {
            v = std::make_unique<Object>(*alt);
        } else {
            v = alt;
        }
    }, o.v);
}

inline Value& Value::operator=(const Value& o) {
    if (this != &o) {
        std::visit([this](const auto& alt) {
            using T = std::decay_t<decltype(alt)>;
            if constexpr (std::is_same_v<T, std::unique_ptr<Object>>) {
                v = std::make_unique<Object>(*alt);
            } else {
                v = alt;
            }
        }, o.v);
    }
    return *this;
}

inline const Object& Value::asObject() const {
    if (!isObject()) throw ParseError("JSON: ожидается объект");
    return *std::get<std::unique_ptr<Object>>(v);
}

inline const Value& Value::operator[](std::string_view key) const {
    const Value* p = asObject().find(key);
    if (!p) throw ParseError(std::string("JSON: ключ не найден: ") + std::string(key));
    return *p;
}

inline bool Value::has(std::string_view key) const noexcept {
    if (!isObject()) return false;
    return std::get<std::unique_ptr<Object>>(v)->find(key) != nullptr;
}

// ─── Парсер ────────────────────────────────────────────────────────────────

class Parser {
public:
    explicit Parser(std::string_view src) : src_(src), pos_(0) {}

    [[nodiscard]] Value parse() {
        skipWs();
        auto v = parseValue();
        skipWs();
        if (pos_ != src_.size())
            throw ParseError("JSON: неожиданный символ в конце: " +
                             std::string(1, src_[pos_]));
        return v;
    }

private:
    std::string_view src_;
    std::size_t      pos_;

    char peek() const {
        if (pos_ >= src_.size()) throw ParseError("JSON: неожиданный конец");
        return src_[pos_];
    }

    char next() {
        char c = peek();
        ++pos_;
        return c;
    }

    void expect(char c) {
        if (next() != c)
            throw ParseError(std::string("JSON: ожидается '") + c + "'");
    }

    void skipWs() noexcept {
        while (pos_ < src_.size() &&
               (src_[pos_] == ' ' || src_[pos_] == '\t' ||
                src_[pos_] == '\n'|| src_[pos_] == '\r'))
            ++pos_;
    }

    Value parseValue() {
        skipWs();
        char c = peek();
        if (c == '"')  return parseString();
        if (c == '{')  return parseObject();
        if (c == '[')  return parseArray();
        if (c == 't')  { pos_+=4; return Value{true};  }
        if (c == 'f')  { pos_+=5; return Value{false}; }
        if (c == 'n')  { pos_+=4; return Value{};      }
        return parseNumber();
    }

    String parseString() {
        expect('"');
        std::string s;
        while (true) {
            char c = next();
            if (c == '"') break;
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case '"': s += '"'; break;
                    case '\\':s += '\\';break;
                    case '/': s += '/'; break;
                    case 'n': s += '\n';break;
                    case 'r': s += '\r';break;
                    case 't': s += '\t';break;
                    case 'b': s += '\b';break;
                    case 'f': s += '\f';break;
                    default:  s += e;   break;
                }
            } else {
                s += c;
            }
        }
        return s;
    }

    Value parseObject() {
        expect('{');
        auto obj = std::make_unique<Object>();
        skipWs();
        if (peek() == '}') { ++pos_; return Value{std::move(obj)}; }
        while (true) {
            skipWs();
            auto key = parseString();
            skipWs();
            expect(':');
            skipWs();
            auto val = parseValue();
            (*obj)[std::move(key)] = std::move(val);
            skipWs();
            char sep = peek();
            if (sep == '}') { ++pos_; break; }
            if (sep != ',') throw ParseError("JSON: ожидается ',' или '}'");
            ++pos_;
        }
        return Value{std::move(obj)};
    }

    Array parseArray() {
        expect('[');
        Array arr;
        skipWs();
        if (peek() == ']') { ++pos_; return arr; }
        while (true) {
            skipWs();
            arr.push_back(parseValue());
            skipWs();
            char sep = peek();
            if (sep == ']') { ++pos_; break; }
            if (sep != ',') throw ParseError("JSON: ожидается ',' или ']'");
            ++pos_;
        }
        return arr;
    }

    Number parseNumber() {
        std::size_t start = pos_;
        if (pos_ < src_.size() && src_[pos_] == '-') ++pos_;
        while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        if (pos_ < src_.size() && src_[pos_] == '.') {
            ++pos_;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        }
        if (pos_ < src_.size() && (src_[pos_] == 'e' || src_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < src_.size() && (src_[pos_] == '+' || src_[pos_] == '-')) ++pos_;
            while (pos_ < src_.size() && src_[pos_] >= '0' && src_[pos_] <= '9') ++pos_;
        }
        if (pos_ == start) throw ParseError("JSON: ожидается число");
        return std::stod(std::string(src_.substr(start, pos_ - start)));
    }
};

// ─── Публичный API ─────────────────────────────────────────────────────────

[[nodiscard]] inline Value parse(std::string_view src) {
    return Parser(src).parse();
}

// ─── Сериализация (для формирования JWE Protected Header) ──────────────────

[[nodiscard]] inline std::string serialize(const Value& v) {
    if (v.isNull())   return "null";
    if (v.isBool())   return std::get<Bool>(v.v) ? "true" : "false";
    if (v.isNumber()) {
        auto n = std::get<Number>(v.v);
        if (n == std::floor(n) && std::abs(n) < 1e15)
            return std::to_string(static_cast<long long>(n));
        return std::to_string(n);
    }
    if (v.isString()) {
        std::string s = "\"";
        for (char c : std::get<String>(v.v)) {
            if      (c == '"')  s += "\\\"";
            else if (c == '\\') s += "\\\\";
            else if (c == '\n') s += "\\n";
            else if (c == '\r') s += "\\r";
            else if (c == '\t') s += "\\t";
            else                s += c;
        }
        s += '"';
        return s;
    }
    if (v.isArray()) {
        std::string s = "[";
        bool first = true;
        for (const auto& el : std::get<Array>(v.v)) {
            if (!first) s += ',';
            s += serialize(el);
            first = false;
        }
        return s + "]";
    }
    // Object (stored as unique_ptr<Object>)
    std::string s = "{";
    bool first = true;
    for (const auto& entry : v.asObject().entries) {
        if (!first) s += ',';
        s += '"' + entry.first + "\":" + serialize(entry.second);
        first = false;
    }
    return s + "}";
}

} // namespace jwe::json
