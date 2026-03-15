#pragma once

/**
 * @file json.hpp
 * @brief Минимальный JSON-парсер для работы с JWKS и JWE-заголовком
 *
 * Намеренно не использует std::variant и std::map — оба ломаются
 * в GCC 14 / libstdc++ 14 из-за бага PR#114863 (tuple_like concept).
 * Реализован собственный tagged union без шаблонов.
 */

#include "types.hpp"
#include <cassert>
#include <cmath>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace jwe::json {

// ─── Forward declarations ──────────────────────────────────────────────────

class Value;

// ─── JSON Object — вектор пар (без std::map) ──────────────────────────────

class Object {
public:
    struct Entry { std::string key; Value* val; };

    Object()                          = default;
    Object(const Object&);
    Object(Object&&) noexcept         = default;
    Object& operator=(const Object&);
    Object& operator=(Object&&)       = default;
    ~Object();

    Value&       operator[](std::string k);
    [[nodiscard]] const Value* find(std::string_view k) const noexcept;

    [[nodiscard]] const std::vector<Entry>& entries() const noexcept { return e_; }

private:
    std::vector<Entry> e_;
};

// ─── JSON Array ────────────────────────────────────────────────────────────

using Array = std::vector<Value>;

// ─── JSON Value — ручной tagged union ─────────────────────────────────────

class Value {
public:
    enum class Tag : uint8_t { Null, Bool, Num, Str, Arr, Obj };

    // ── Конструкторы ────────────────────────────────────────────────────

    Value()  noexcept : tag_(Tag::Null)                    { }
    explicit Value(bool b)           : tag_(Tag::Bool)     { u_.b = b; }
    explicit Value(double n)         : tag_(Tag::Num)   { u_.n = n; }
    explicit Value(std::string s)    : tag_(Tag::Str)   { new(&u_.s) std::string(std::move(s)); }
    explicit Value(jwe::json::Array a) : tag_(Tag::Arr)  { new(&u_.a) jwe::json::Array(std::move(a)); }
    explicit Value(jwe::json::Object o): tag_(Tag::Obj) { new(&u_.o) jwe::json::Object(std::move(o)); }

    Value(const Value& o) : tag_(Tag::Null) { copyFrom(o); }
    Value(Value&& o) noexcept               { moveFrom(std::move(o)); }
    Value& operator=(const Value& o)        { if (this != &o) { destroy(); copyFrom(o); } return *this; }
    Value& operator=(Value&& o) noexcept    { if (this != &o) { destroy(); moveFrom(std::move(o)); } return *this; }
    ~Value()                                { destroy(); }

    // ── Предикаты ───────────────────────────────────────────────────────

    [[nodiscard]] bool isNull()   const noexcept { return tag_ == Tag::Null;   }
    [[nodiscard]] bool isBool()   const noexcept { return tag_ == Tag::Bool;   }
    [[nodiscard]] bool isNumber() const noexcept { return tag_ == Tag::Num; }
    [[nodiscard]] bool isString() const noexcept { return tag_ == Tag::Str; }
    [[nodiscard]] bool isArray()  const noexcept { return tag_ == Tag::Arr;  }
    [[nodiscard]] bool isObject() const noexcept { return tag_ == Tag::Obj; }

    // ── Аксессоры ───────────────────────────────────────────────────────

    [[nodiscard]] const std::string& asString() const {
        if (!isString()) throw ParseError("JSON: ожидается строка");
        return u_.s;
    }
    [[nodiscard]] const jwe::json::Array& asArray() const {
        if (!isArray()) throw ParseError("JSON: ожидается массив");
        return u_.a;
    }
    [[nodiscard]] const jwe::json::Object& asObject() const {
        if (!isObject()) throw ParseError("JSON: ожидается объект");
        return u_.o;
    }
    [[nodiscard]] jwe::json::Object& asObject() {
        if (!isObject()) throw ParseError("JSON: ожидается объект");
        return u_.o;
    }

    [[nodiscard]] const Value& operator[](std::string_view key) const {
        const Value* p = asObject().find(key);
        if (!p) throw ParseError(std::string("JSON: ключ не найден: ") + std::string(key));
        return *p;
    }
    [[nodiscard]] bool has(std::string_view key) const noexcept {
        return isObject() && u_.o.find(key) != nullptr;
    }

    // ── Внутренний доступ для serialize ─────────────────────────────────

    [[nodiscard]] bool   getBool()   const noexcept { return u_.b; }
    [[nodiscard]] double getNumber() const noexcept { return u_.n; }

private:
    Tag tag_{Tag::Null};

    union U {
        bool               b;
        double             n;
        std::string        s;
        jwe::json::Array   a;
        jwe::json::Object  o;
        U() {}   // не инициализируем — конструкторы Value делают это сами
        ~U() {}  // деструкторы вызывает Value::destroy()
    } u_;

    void destroy() noexcept {
        switch (tag_) {
            case Tag::Str: u_.s.~basic_string();    break;
            case Tag::Arr:  u_.a.~vector();          break;
            case Tag::Obj: u_.o.~Object();          break;
            default: break;
        }
        tag_ = Tag::Null;
    }

    void copyFrom(const Value& o) {
        tag_ = o.tag_;
        switch (tag_) {
            case Tag::Null:                                    break;
            case Tag::Bool:   u_.b = o.u_.b;                  break;
            case Tag::Num: u_.n = o.u_.n;                  break;
            case Tag::Str: new(&u_.s) std::string(o.u_.s); break;
            case Tag::Arr:  new(&u_.a) jwe::json::Array(o.u_.a);  break;
            case Tag::Obj: new(&u_.o) jwe::json::Object(o.u_.o); break;
        }
    }

    void moveFrom(Value&& o) noexcept {
        tag_ = o.tag_;
        switch (tag_) {
            case Tag::Null:                                              break;
            case Tag::Bool:   u_.b = o.u_.b;                            break;
            case Tag::Num: u_.n = o.u_.n;                            break;
            case Tag::Str: new(&u_.s) std::string(std::move(o.u_.s));break;
            case Tag::Arr:  new(&u_.a) jwe::json::Array(std::move(o.u_.a)); break;
            case Tag::Obj: new(&u_.o) jwe::json::Object(std::move(o.u_.o));break;
        }
        o.tag_ = Tag::Null;
    }
};

// ─── Object: определения методов (Value уже полный тип) ───────────────────

inline Object::~Object() {
    for (auto& e : e_) delete e.val;
}

inline Object::Object(const Object& o) {
    e_.reserve(o.e_.size());
    for (const auto& e : o.e_)
        e_.push_back({e.key, new Value(*e.val)});
}

inline Object& Object::operator=(const Object& o) {
    if (this != &o) {
        for (auto& e : e_) delete e.val;
        e_.clear();
        e_.reserve(o.e_.size());
        for (const auto& e : o.e_)
            e_.push_back({e.key, new Value(*e.val)});
    }
    return *this;
}

inline Value& Object::operator[](std::string k) {
    for (auto& e : e_)
        if (e.key == k) return *e.val;
    e_.push_back({std::move(k), new Value{}});
    return *e_.back().val;
}

inline const Value* Object::find(std::string_view k) const noexcept {
    for (const auto& e : e_)
        if (e.key == k) return e.val;
    return nullptr;
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
    char next() { char c = peek(); ++pos_; return c; }
    void expect(char c) {
        if (next() != c)
            throw ParseError(std::string("JSON: ожидается '") + c + "'");
    }
    void skipWs() noexcept {
        while (pos_ < src_.size() &&
               (src_[pos_]==' '||src_[pos_]=='\t'||
                src_[pos_]=='\n'||src_[pos_]=='\r')) ++pos_;
    }

    Value parseValue() {
        skipWs();
        char c = peek();
        if (c == '"') return Value{parseString()};
        if (c == '{') return parseObject();
        if (c == '[') return parseArray();
        if (c == 't') { pos_+=4; return Value{true};  }
        if (c == 'f') { pos_+=5; return Value{false}; }
        if (c == 'n') { pos_+=4; return Value{};      }
        return Value{parseNumber()};
    }

    std::string parseString() {
        expect('"');
        std::string s;
        while (true) {
            char c = next();
            if (c == '"') break;
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case '"': s+='"';  break; case '\\': s+='\\'; break;
                    case '/': s+='/';  break; case 'n':  s+='\n'; break;
                    case 'r': s+='\r'; break; case 't':  s+='\t'; break;
                    case 'b': s+='\b'; break; case 'f':  s+='\f'; break;
                    default:  s+=e;    break;
                }
            } else { s += c; }
        }
        return s;
    }

    Value parseObject() {
        expect('{');
        Object obj;
        skipWs();
        if (peek() == '}') { ++pos_; return Value{std::move(obj)}; }
        while (true) {
            skipWs();
            auto key = parseString();
            skipWs(); expect(':'); skipWs();
            obj[std::move(key)] = parseValue();
            skipWs();
            char sep = peek();
            if (sep == '}') { ++pos_; break; }
            if (sep != ',') throw ParseError("JSON: ожидается ',' или '}'");
            ++pos_;
        }
        return Value{std::move(obj)};
    }

    Value parseArray() {
        expect('[');
        Array arr;
        skipWs();
        if (peek() == ']') { ++pos_; return Value{std::move(arr)}; }
        while (true) {
            skipWs();
            arr.push_back(parseValue());
            skipWs();
            char sep = peek();
            if (sep == ']') { ++pos_; break; }
            if (sep != ',') throw ParseError("JSON: ожидается ',' или ']'");
            ++pos_;
        }
        return Value{std::move(arr)};
    }

    double parseNumber() {
        std::size_t start = pos_;
        if (pos_ < src_.size() && src_[pos_] == '-') ++pos_;
        while (pos_ < src_.size() && src_[pos_]>='0' && src_[pos_]<='9') ++pos_;
        if (pos_ < src_.size() && src_[pos_] == '.') {
            ++pos_;
            while (pos_ < src_.size() && src_[pos_]>='0' && src_[pos_]<='9') ++pos_;
        }
        if (pos_ < src_.size() && (src_[pos_]=='e'||src_[pos_]=='E')) {
            ++pos_;
            if (pos_ < src_.size() && (src_[pos_]=='+'||src_[pos_]=='-')) ++pos_;
            while (pos_ < src_.size() && src_[pos_]>='0' && src_[pos_]<='9') ++pos_;
        }
        if (pos_ == start) throw ParseError("JSON: ожидается число");
        return std::stod(std::string(src_.substr(start, pos_ - start)));
    }
};

// ─── Публичный API ─────────────────────────────────────────────────────────

[[nodiscard]] inline Value parse(std::string_view src) {
    return Parser(src).parse();
}

// ─── Сериализация ──────────────────────────────────────────────────────────

[[nodiscard]] inline std::string serialize(const Value& v) {
    if (v.isNull())   return "null";
    if (v.isBool())   return v.getBool() ? "true" : "false";
    if (v.isNumber()) {
        double n = v.getNumber();
        if (n == std::floor(n) && std::abs(n) < 1e15)
            return std::to_string(static_cast<long long>(n));
        return std::to_string(n);
    }
    if (v.isString()) {
        std::string s = "\"";
        for (char c : v.asString()) {
            if      (c=='"')  s+="\\\"";
            else if (c=='\\') s+="\\\\";
            else if (c=='\n') s+="\\n";
            else if (c=='\r') s+="\\r";
            else if (c=='\t') s+="\\t";
            else              s+=c;
        }
        return s + '"';
    }
    if (v.isArray()) {
        std::string s = "[";
        bool first = true;
        for (const auto& el : v.asArray()) {
            if (!first) s += ',';
            s += serialize(el);
            first = false;
        }
        return s + "]";
    }
    // Object
    std::string s = "{";
    bool first = true;
    for (const auto& e : v.asObject().entries()) {
        if (!first) s += ',';
        s += '"' + e.key + "\":" + serialize(*e.val);
        first = false;
    }
    return s + "}";
}

} // namespace jwe::json
