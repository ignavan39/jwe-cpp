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
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace jwe::json {

// ─── Тип значения ─────────────────────────────────────────────────────────

struct Value;

using Null   = std::monostate;
using Bool   = bool;
using Number = double;
using String = std::string;
using Array  = std::vector<Value>;
using Object = std::map<std::string, Value, std::less<>>;

struct Value : std::variant<Null, Bool, Number, String, Array, Object> {
    using variant::variant;

    // ─── Аксессоры ────────────────────────────────────────────────────

    [[nodiscard]] bool isNull()   const noexcept { return std::holds_alternative<Null>(*this); }
    [[nodiscard]] bool isBool()   const noexcept { return std::holds_alternative<Bool>(*this); }
    [[nodiscard]] bool isNumber() const noexcept { return std::holds_alternative<Number>(*this); }
    [[nodiscard]] bool isString() const noexcept { return std::holds_alternative<String>(*this); }
    [[nodiscard]] bool isArray()  const noexcept { return std::holds_alternative<Array>(*this); }
    [[nodiscard]] bool isObject() const noexcept { return std::holds_alternative<Object>(*this); }

    [[nodiscard]] const String& asString() const {
        if (!isString()) throw ParseError("JSON: ожидается строка");
        return std::get<String>(*this);
    }

    [[nodiscard]] const Array& asArray() const {
        if (!isArray()) throw ParseError("JSON: ожидается массив");
        return std::get<Array>(*this);
    }

    [[nodiscard]] const Object& asObject() const {
        if (!isObject()) throw ParseError("JSON: ожидается объект");
        return std::get<Object>(*this);
    }

    [[nodiscard]] const Value& operator[](std::string_view key) const {
        const auto& obj = asObject();
        auto it = obj.find(key);
        if (it == obj.end())
            throw ParseError(std::string("JSON: ключ не найден: ") + std::string(key));
        return it->second;
    }

    [[nodiscard]] bool has(std::string_view key) const noexcept {
        if (!isObject()) return false;
        const auto& obj = std::get<Object>(*this);
        return obj.find(key) != obj.end();
    }
};

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

    Object parseObject() {
        expect('{');
        Object obj;
        skipWs();
        if (peek() == '}') { ++pos_; return obj; }
        while (true) {
            skipWs();
            auto key = parseString();
            skipWs();
            expect(':');
            skipWs();
            obj[key] = parseValue();
            skipWs();
            char sep = peek();
            if (sep == '}') { ++pos_; break; }
            if (sep != ',') throw ParseError("JSON: ожидается ',' или '}'");
            ++pos_;
        }
        return obj;
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
    if (v.isBool())   return std::get<Bool>(v) ? "true" : "false";
    if (v.isNumber()) {
        auto n = std::get<Number>(v);
        // Печатаем без экспоненциальной нотации для целых
        if (n == std::floor(n) && std::abs(n) < 1e15)
            return std::to_string(static_cast<long long>(n));
        return std::to_string(n);
    }
    if (v.isString()) {
        std::string s = "\"";
        for (char c : std::get<String>(v)) {
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
        for (const auto& el : std::get<Array>(v)) {
            if (!first) s += ',';
            s += serialize(el);
            first = false;
        }
        return s + "]";
    }
    // Object
    std::string s = "{";
    bool first = true;
    for (const auto& [k, val] : std::get<Object>(v)) {
        if (!first) s += ',';
        s += '"' + k + "\":" + serialize(val);
        first = false;
    }
    return s + "}";
}

} // namespace jwe::json
