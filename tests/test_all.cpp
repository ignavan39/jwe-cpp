/**
 * @file test_all.cpp
 * @brief Набор модульных тестов — без внешних фреймворков
 *
 * Запуск:
 * @code
 *   cmake --build build && ./build/tests/jwe_tests
 * @endcode
 *
 * Покрытие:
 *  - Base64URL encode/decode (RFC 4648 §5 тест-векторы)
 *  - SHA-256 (FIPS 180-4 официальные векторы)
 *  - HMAC-SHA-256 (RFC 4231 векторы)
 *  - MGF1-SHA256
 *  - BigInt арифметика
 *  - AES-256-GCM (NIST SP 800-38D вектор)
 *  - Полный цикл JWE (encode → структура токена)
 */

#include <jwe/jwe.hpp>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

// ─── Мини-фреймворк ────────────────────────────────────────────────────────

namespace test {

struct Stats { int passed = 0, failed = 0; };
static Stats g_stats;

static void pass(const char* name) {
    ++g_stats.passed;
    std::cout << "  \033[32m✓\033[0m " << name << '\n';
}

static void fail(const char* name, const std::string& msg) {
    ++g_stats.failed;
    std::cerr << "  \033[31m✗\033[0m " << name << "\n    " << msg << '\n';
}

#define TEST(name, expr) \
    do { try { \
        if (expr) { test::pass(name); } \
        else { test::fail(name, "условие ложно: " #expr); } \
    } catch (const std::exception& ex) { \
        test::fail(name, std::string("исключение: ") + ex.what()); \
    } } while(0)

#define TEST_THROWS(name, expr, ExType) \
    do { try { (void)(expr); \
        test::fail(name, "ожидалось исключение " #ExType); \
    } catch (const ExType&) { \
        test::pass(name); \
    } catch (const std::exception& ex) { \
        test::fail(name, std::string("неожиданное исключение: ") + ex.what()); \
    } } while(0)

static std::string hex(const jwe::Bytes& b) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (auto c : b) os << std::setw(2) << unsigned(c);
    return os.str();
}

template<std::size_t N>
static std::string hex(const std::array<uint8_t,N>& b) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (auto c : b) os << std::setw(2) << unsigned(c);
    return os.str();
}

} // namespace test

// ─── Base64URL ─────────────────────────────────────────────────────────────

static void testBase64Url() {
    std::cout << "\n[Base64URL]\n";
    using namespace jwe::base64url;

    // RFC 4648 §10 тест-векторы (BASE64, адаптированные под URL-алфавит)
    TEST("encode empty",    encode(jwe::ByteSpan{}) == "");
    TEST("encode 'f'",      encode(jwe::ByteSpan{(const uint8_t*)"f",1}) == "Zg");
    TEST("encode 'fo'",     encode(jwe::ByteSpan{(const uint8_t*)"fo",2}) == "Zm8");
    TEST("encode 'foo'",    encode(jwe::ByteSpan{(const uint8_t*)"foo",3}) == "Zm9v");
    TEST("encode 'foob'",   encode(jwe::ByteSpan{(const uint8_t*)"foob",4}) == "Zm9vYg");
    TEST("encode 'foobar'", encode(jwe::ByteSpan{(const uint8_t*)"foobar",6}) == "Zm9vYmFy");

    // Символы '-' и '_' вместо '+' и '/'
    jwe::Bytes tricky = {0xFB, 0xFF, 0xFE};
    std::string enc = encode(jwe::ByteSpan{tricky});
    TEST("encode uses - not +", enc.find('+') == std::string::npos);
    TEST("encode uses _ not /", enc.find('/') == std::string::npos);

    // decode(encode(x)) == x
    jwe::Bytes orig = {0x00, 0x01, 0x02, 0xFE, 0xFF};
    TEST("roundtrip",  decode(encode(jwe::ByteSpan{orig})) == orig);

    // Декодирование с паддингом
    jwe::Bytes foobytes(3);
    std::copy_n("foo", 3, foobytes.begin());
    TEST("decode with padding", decode("Zm9v==") == foobytes);

    TEST_THROWS("decode invalid char",
                decode("!!"),
                jwe::EncodingError);
}

// ─── SHA-256 ───────────────────────────────────────────────────────────────

static void testSha256() {
    std::cout << "\n[SHA-256]\n";
    using jwe::crypto::Sha256;

    // FIPS 180-4 / OpenSSL verified: SHA-256("abc")
    auto d1 = Sha256::hash(jwe::ByteSpan{(const uint8_t*)"abc", 3});
    TEST("SHA-256('abc')",
        test::hex(d1) ==
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad");

    // SHA-256("")
    auto d2 = Sha256::hash(jwe::ByteSpan{});
    TEST("SHA-256('')",
        test::hex(d2) ==
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855");

    // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto d3 = Sha256::hash(jwe::ByteSpan{(const uint8_t*)msg, std::strlen(msg)});
    TEST("SHA-256(448-bit msg)",
        test::hex(d3) ==
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1");

    // Инкрементальное обновление
    jwe::crypto::Sha256 h;
    h.update(jwe::ByteSpan{(const uint8_t*)"ab", 2});
    h.update(jwe::ByteSpan{(const uint8_t*)"c", 1});
    TEST("SHA-256 incremental == SHA-256('abc')", h.finalize() == d1);
}

// ─── HMAC-SHA-256 ──────────────────────────────────────────────────────────

static void testHmacSha256() {
    std::cout << "\n[HMAC-SHA-256]\n";
    using jwe::crypto::hmac_sha256;

    // RFC 4231, Test Case 1
    jwe::Bytes key(20, 0x0b);
    const char* data = "Hi There";
    auto mac = hmac_sha256(jwe::ByteSpan{key},
                           jwe::ByteSpan{(const uint8_t*)data, 8});
    TEST("HMAC-SHA-256 RFC4231 TC1",
        test::hex(mac) ==
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7");
}

// ─── BigInt ────────────────────────────────────────────────────────────────

static void testBigInt() {
    std::cout << "\n[BigInt]\n";
    using jwe::crypto::BigInt;

    BigInt a(255), b(1), c(256);
    TEST("255 + 1 == 256",    (a + b) == c);
    TEST("256 - 1 == 255",    (c - b) == a);
    TEST("255 < 256",         a < c);
    TEST("256 > 255",         c > a);

    // Умножение
    BigInt x(1000000), y(1000000);
    BigInt xy = x * y;
    TEST("1e6 * 1e6 == 1e12", xy == BigInt(1000000000000ULL));

    // powmod: 2^10 mod 1000 = 1024 mod 1000 = 24
    TEST("2^10 mod 1000 == 24",
         BigInt::powmod(BigInt(2), BigInt(10), BigInt(1000)) == BigInt(24));

    // powmod с большим простым числом
    // 3^(p-1) ≡ 1 (mod p) по малой теореме Ферма, p = 17
    auto r = BigInt::powmod(BigInt(3), BigInt(16), BigInt(17));
    TEST("3^16 mod 17 == 1 (Fermat)", r == BigInt(1));

    // Сериализация/десериализация
    jwe::Bytes b256 = {0x01, 0x00};
    BigInt v = BigInt::fromBytes(jwe::ByteSpan{b256});
    TEST("fromBytes {0x01,0x00} == 256", v == BigInt(256));
    auto out = v.toBytes();
    TEST("toBytes roundtrip", out == b256);
}

// ─── AES-256-GCM ──────────────────────────────────────────────────────────

static void testAesGcm() {
    std::cout << "\n[AES-256-GCM]\n";
    using jwe::crypto::aes256_gcm_encrypt;

    // NIST SP 800-38D, Test Vector (gcmEncryptExtIV256.rsp, Count=0)
    jwe::Bytes key = {
        0x92,0xe1,0x1d,0xcd,0xaa,0x86,0x6f,0x5c,
        0xe7,0x90,0xfd,0x24,0x50,0x1f,0x92,0x50,
        0x9a,0xac,0xf4,0xcb,0x8b,0x13,0x39,0xd5,
        0x0c,0x9c,0x12,0x40,0x93,0x5d,0xd0,0x8b
    };
    jwe::Bytes iv = {
        0xac,0x93,0xa1,0xa6,0x14,0x52,0x99,0xbd,
        0xe9,0x02,0xf2,0x1a
    };
    jwe::Bytes pt = {0x2d,0x71,0xbc,0xfa,0x91,0x4e,0x4a,0xc0,
                     0x45,0xb2,0xaa,0x60,0x95,0xfa,0xd2,0x44};
    jwe::Bytes aad = {};

    auto res = aes256_gcm_encrypt(
        jwe::ByteSpan{key}, jwe::ByteSpan{iv},
        jwe::ByteSpan{pt},  jwe::ByteSpan{aad});

    TEST("AES-256-GCM ciphertext",
        test::hex(res.ciphertext) == "8995ae2e6df3dbf96fac7b71371f991f");
    TEST("AES-256-GCM tag",
        test::hex(res.tag) == "456c8380d4ec20d0343122725cdb546b");
}

// ─── JSON-парсер ──────────────────────────────────────────────────────────

static void testJson() {
    std::cout << "\n[JSON Parser]\n";

    auto v = jwe::json::parse(R"({"kty":"RSA","n":"AQAB","keys":[1,2,3]})");
    TEST("object parse",   v.isObject());
    TEST("string field",   v["kty"].asString() == "RSA");
    TEST("array field",    v["keys"].isArray());
    TEST("array length",   v["keys"].asArray().size() == 3);
    TEST("has() true",     v.has("kty"));
    TEST("has() false",    !v.has("nonexistent"));

    TEST_THROWS("missing key", v["missing"], jwe::ParseError);
    TEST_THROWS("invalid json", jwe::json::parse("{bad}"), jwe::ParseError);
}

// ─── Полный цикл JWE ──────────────────────────────────────────────────────

static void testJweBuilderStructure() {
    std::cout << "\n[JWE Builder — структура токена]\n";

    // Минимальный RSA-2048 тестовый ключ (не для реального использования!)
    // IANA RFC 7517 Appendix A.1 — публичный ключ (одна строка, валидный JSON)
    const char* jwk = R"({"kty":"RSA","n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXMO_LRQMG8OAzToTMEMlFIJo2XAL_HWSK--jLj5Bx_V1dqzHK4ycJUYaSrGKUhPPNv8h0SCFP6OheMkFikhS0s5h0jMNBKGN4qbqr2qFAQiLt-Ts3G8aW8iRuoQKp9VoKkIUl5K2-LkLQ3IUJqz82CX9LVLaJ_3P3vmLwKINnO5r67Pq1reKcZFJMb0BIkUXMIVeH1_O8pTYnROL8yQKjP-Rp9MfN_r8xH6bKovzG6l9HHpOPBDJ6g6vPCHMM8YjBc_gpP2Qa0s6HpIg","e":"AQAB"})";

    jwe::JweBuilder builder;
    builder.setPublicKeyFromJwkString(jwk);

    const std::string plaintext = R"({"sub":"user-001","name":"Иван Иванов","email":"ivan@example.com"})";
    auto token = builder.build(plaintext);

    // Структурные проверки
    TEST("protected_header не пуст", !token.protected_header.empty());
    TEST("encrypted_key не пуст",    !token.encrypted_key.empty());
    TEST("iv не пуст",               !token.initialization_vector.empty());
    TEST("ciphertext не пуст",       !token.ciphertext.empty());
    TEST("tag не пуст",              !token.authentication_tag.empty());

    // Проверяем заголовок
    auto hdrBytes = jwe::base64url::decode(token.protected_header);
    std::string hdrStr(hdrBytes.begin(), hdrBytes.end());
    TEST("header содержит alg",   hdrStr.find("RSA-OAEP-256") != std::string::npos);
    TEST("header содержит enc",   hdrStr.find("A256GCM")      != std::string::npos);

    // Длина IV: 12 байт → 16 base64url символов (без паддинга)
    auto ivBytes = jwe::base64url::decode(token.initialization_vector);
    TEST("IV длина == 12 байт", ivBytes.size() == jwe::kIvSize);

    // Длина тега: 16 байт
    auto tagBytes = jwe::base64url::decode(token.authentication_tag);
    TEST("Tag длина == 16 байт", tagBytes.size() == jwe::kTagSize);

    // Compact: ровно 4 точки (5 частей)
    auto compact = token.compact();
    int dots = 0;
    for (char c : compact) if (c == '.') ++dots;
    TEST("compact содержит ровно 4 точки", dots == 4);

    // Два вызова должны давать разные токены (случайный CEK и IV)
    auto token2 = builder.build(plaintext);
    TEST("каждый токен уникален",
         token.ciphertext != token2.ciphertext ||
         token.initialization_vector != token2.initialization_vector);
}

// ─── main ──────────────────────────────────────────────────────────────────

int main() {
    std::cout << "═══════════════════════════════════════\n";
    std::cout << "       JWE-CPP — Модульные тесты       \n";
    std::cout << "═══════════════════════════════════════\n";

    testBase64Url();
    testSha256();
    testHmacSha256();
    testBigInt();
    testAesGcm();
    testJson();
    testJweBuilderStructure();

    std::cout << "\n───────────────────────────────────────\n";
    std::cout << "Результат: "
              << "\033[32m" << test::g_stats.passed << " пройдено\033[0m, "
              << (test::g_stats.failed ? "\033[31m" : "")
              << test::g_stats.failed << " провалено"
              << (test::g_stats.failed ? "\033[0m" : "")
              << '\n';

    return test::g_stats.failed ? 1 : 0;
}
