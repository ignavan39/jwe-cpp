# jwe-cpp

> **JSON Web Encryption (JWE) — реализация с нуля на C++20, без сторонних зависимостей**

[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-green.svg)](https://cmake.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/your-org/jwe-cpp/ci.yml?label=CI)](/.github/workflows/ci.yml)
[![Стандарты](https://img.shields.io/badge/RFC-7516%20%7C%207517%20%7C%207518-lightgrey.svg)](https://tools.ietf.org/html/rfc7516)

---

## Содержание

- [Обзор](#обзор)
- [Архитектура](#архитектура)
- [Алгоритмы](#алгоритмы)
- [Быстрый старт](#быстрый-старт)
- [Структура проекта](#структура-проекта)
- [API](#api)
- [Сборка](#сборка)
- [Тестирование](#тестирование)
- [CLI-утилита](#cli-утилита)
- [Безопасность](#безопасность)
- [Ограничения](#ограничения)
- [Стандарты и ссылки](#стандарты-и-ссылки)

---

## Обзор

Библиотека реализует **JWE Compact Serialization** по [RFC 7516](https://tools.ietf.org/html/rfc7516) — шифрование JSON-полезной нагрузки с персональными данными:

```
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0
.<encrypted-key>
.<iv>
.<ciphertext>
.<authentication-tag>
```

**Ключевые свойства:**
- ✅ Полная реализация: AES-256, GCM, SHA-256, MGF1, RSA, BigInt — всё с нуля
- ✅ Нет зависимостей: только стандартная библиотека C++20
- ✅ Header-only: добавляется одним `#include`
- ✅ Кроссплатформенность: Linux, macOS, Windows
- ✅ Тесты на официальных векторах NIST/RFC

---

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                    Публичный API (jwe.hpp)                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               JweBuilder                               │  │
│  │  setPublicKeyFromJwkString() ──► build(plaintext)      │  │
│  │  setPublicKeyFromJwksUrl()       └─► JweToken.compact()│  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                  │
│          ┌────────────────┼────────────────┐                 │
│          ▼                ▼                ▼                  │
│  ┌──────────────┐ ┌─────────────┐ ┌──────────────┐          │
│  │  rsa_oaep    │ │  aes_gcm    │ │ jwks_fetcher │          │
│  │  (шаг 4)     │ │  (шаг 7)    │ │  (загрузка   │          │
│  │  RSA-OAEP-256│ │  A256GCM    │ │   ключей)    │          │
│  └──────┬───────┘ └──────┬──────┘ └──────┬───────┘          │
│         │                │               │                    │
│  ┌──────▼──────┐  ┌──────▼──────┐ ┌──────▼───────┐          │
│  │   bigint    │  │   sha256    │ │    json      │          │
│  │  (RSA math) │  │  SHA-256+   │ │  (парсер     │          │
│  │             │  │  HMAC+MGF1  │ │   JWKS)      │          │
│  └─────────────┘  └─────────────┘ └──────────────┘          │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐     │
│  │  base64url  │  types.hpp  (общие типы, исключения)  │     │
│  └─────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

Библиотека спроектирована по принципу **single responsibility**: каждый заголовочный файл реализует ровно одну примитивную операцию. `JweBuilder` оркестрирует шаги ТЗ, не содержа криптографической логики.

---

## Алгоритмы

| Компонент | Алгоритм | Стандарт |
|-----------|----------|----------|
| Шифрование ключа | RSA-OAEP-256 | RFC 8017 (PKCS #1 v2.2) |
| Шифрование данных | AES-256-GCM | NIST SP 800-38D |
| Хэш-функция | SHA-256 | FIPS 180-4 |
| Маскирующая функция | MGF1(SHA-256) | RFC 8017 §B.2.1 |
| Аутентификация MAC | GHASH | NIST SP 800-38D §6.4 |
| Кодирование | BASE64URL | RFC 4648 §5 |
| Формат ключей | JWK / JWKS | RFC 7517 |
| Формат токена | JWE Compact | RFC 7516 §7.1 |

---

## Быстрый старт

### Вариант 1: Ключ из JWK-строки

```cpp
#include <jwe/jwe.hpp>
#include <iostream>

int main() {
    // Публичный ключ сервис-провайдера в формате JWK
    const char* jwk = R"({
        "kty": "RSA",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "n":   "oahUIoWw0K0usKNu...",
        "e":   "AQAB"
    })";

    // Персональные данные для шифрования
    const std::string payload = R"({
        "sub":   "user-42",
        "name":  "Иванова Мария Сергеевна",
        "email": "m.ivanova@example.ru"
    })";

    jwe::JweBuilder builder;
    builder.setPublicKeyFromJwkString(jwk);

    auto token = builder.build(payload);

    // Компактный JWE-токен (5 частей через точку)
    std::cout << token.compact() << '\n';
}
```

### Вариант 2: Ключ из JWKS URL

```cpp
jwe::JweBuilder builder;
builder.setPublicKeyFromJwksUrl("http://idp.example.com/.well-known/jwks.json",
                                "key-2024-01");  // kid — опционально

auto token = builder.build(payload);
```

### Вариант 3: Доступ к отдельным компонентам

```cpp
auto token = builder.build(payload);

std::cout << "Protected Header: " << token.protected_header << '\n';
std::cout << "Encrypted Key:    " << token.encrypted_key    << '\n';
std::cout << "IV:               " << token.initialization_vector << '\n';
std::cout << "Ciphertext:       " << token.ciphertext       << '\n';
std::cout << "Auth Tag:         " << token.authentication_tag << '\n';
```

---

## Структура проекта

```
jwe-cpp/
├── include/
│   └── jwe/
│       ├── jwe.hpp          ← Единый включаемый заголовок
│       ├── types.hpp        ← Базовые типы, константы, исключения
│       ├── base64url.hpp    ← BASE64URL кодирование/декодирование (RFC 4648 §5)
│       ├── sha256.hpp       ← SHA-256, HMAC-SHA-256, MGF1 (FIPS 180-4)
│       ├── bigint.hpp       ← Арифметика больших чисел (для RSA)
│       ├── aes_gcm.hpp      ← AES-256-GCM (FIPS 197 + NIST SP 800-38D)
│       ├── rsa_oaep.hpp     ← RSA-OAEP-256 шифрование (RFC 8017)
│       ├── json.hpp         ← Минимальный JSON-парсер (для JWKS)
│       ├── jwks_fetcher.hpp ← Загрузка ключей из JWKS URL / JWK-строки
│       └── jwe_builder.hpp  ← Основной строитель JWE-токена
├── tests/
│   └── test_all.cpp         ← Модульные тесты (NIST/RFC тест-векторы)
├── examples/
│   ├── basic_usage.cpp      ← Пошаговый пример из ТЗ
│   └── encrypt_payload.cpp  ← CLI-утилита
├── cmake/
│   └── jweConfig.cmake.in   ← CMake install-конфигурация
├── docs/
│   └── ШАГИ_JWE.md          ← Детальное описание каждого шага
├── CMakeLists.txt
├── LICENSE
└── README.md
```

---

## API

### `jwe::JweBuilder`

| Метод | Описание |
|-------|----------|
| `setPublicKeyFromJwkString(jwk)` | Установить ключ из JSON-строки формата JWK |
| `setPublicKeyFromJwksUrl(url, kid)` | Загрузить ключ с JWKS URL (HTTP) |
| `setPublicKey(key)` | Установить ключ как `RsaPublicKey` |
| `build(plaintext)` | Построить JWE-токен |

### `jwe::JweToken`

| Поле | Описание |
|------|----------|
| `protected_header` | BASE64URL({"alg":"RSA-OAEP-256","enc":"A256GCM"}) |
| `encrypted_key` | BASE64URL(RSA-OAEP-256(CEK)) |
| `initialization_vector` | BASE64URL(random 96-bit IV) |
| `ciphertext` | BASE64URL(AES-256-GCM(plaintext)) |
| `authentication_tag` | BASE64URL(GCM auth tag) |
| `compact()` | Пять частей через точку (RFC 7516 §7.1) |

### Типы ошибок

| Исключение | Когда бросается |
|-----------|-----------------|
| `jwe::KeyError` | Ключ не задан, некорректный JWK, ключ не найден в JWKS |
| `jwe::CryptoError` | Ошибки шифрования (неверный размер ключа/IV) |
| `jwe::EncodingError` | Недопустимые символы в BASE64URL |
| `jwe::ParseError` | Некорректный JSON |
| `jwe::NetworkError` | DNS-ошибки, HTTP-ошибки при загрузке JWKS |

---

## Сборка

### Требования

- CMake ≥ 3.20
- C++23 компилятор: GCC 13+, Clang 17+, MSVC 2022+

### Linux / macOS

```bash
git clone https://github.com/your-org/jwe-cpp.git
cd jwe-cpp

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# Запустить пример
./build/basic_usage
```

### Отладочная сборка с AddressSanitizer

```bash
cmake -B build-san \
      -DCMAKE_BUILD_TYPE=Debug \
      -DJWE_BUILD_SANITIZE=ON
cmake --build build-san
./build-san/tests/jwe_tests
```

### Docker

```bash
# Собрать образ (тесты запустятся автоматически при сборке)
docker build -t jwe-cpp .

# Запустить демонстрационный пример
docker run --rm jwe-cpp

# Запустить тесты
docker run --rm jwe-cpp jwe_tests

# CLI-утилита: зашифровать через stdin
echo '{"sub":"42","name":"Иван"}' | \
  docker run --rm -i jwe-cpp \
  jwe_encrypt --jwk /dev/stdin
```

> Используется многоэтапная сборка: `builder` (GCC 13 + CMake) → `runtime` (debian:bookworm-slim).  
> Итоговый образ содержит только бинарники, без компилятора и исходников.



```cmd
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
.\build\examples\Release\basic_usage.exe
```

### Windows (MSVC)

```cmake
# Вариант 1: FetchContent
include(FetchContent)
FetchContent_Declare(jwe-cpp
    GIT_REPOSITORY https://github.com/your-org/jwe-cpp.git
    GIT_TAG        v1.0.0
)
FetchContent_MakeAvailable(jwe-cpp)
target_link_libraries(your_target PRIVATE jwe::jwe)

# Вариант 2: add_subdirectory
add_subdirectory(third_party/jwe-cpp)
target_link_libraries(your_target PRIVATE jwe::jwe)
```

---

## Тестирование

Тесты покрывают официальные тест-векторы из NIST и RFC:

```bash
cmake --build build
cd build && ctest --output-on-failure
# или
./build/tests/jwe_tests
```

**Покрытие тестами:**

| Модуль | Тест-векторы |
|--------|-------------|
| BASE64URL | RFC 4648 §10 (6 официальных векторов) |
| SHA-256 | FIPS 180-4 Appendix B (3 вектора, включая 448-bit сообщение) |
| HMAC-SHA-256 | RFC 4231 Test Case 1 |
| BigInt | Малая теорема Ферма, повторяемость умножения |
| AES-256-GCM | NIST SP 800-38D (официальный вектор gcmEncryptExtIV256) |
| JweBuilder | Структурные проверки, уникальность токенов |

Пример вывода:
```
═══════════════════════════════════════
       JWE-CPP — Модульные тесты       
═══════════════════════════════════════

[Base64URL]
  ✓ encode empty
  ✓ encode 'f'
  ✓ encode 'foobar'
  ✓ roundtrip
  ...

[AES-256-GCM]
  ✓ AES-256-GCM ciphertext
  ✓ AES-256-GCM tag

───────────────────────────────────────
Результат: 27 пройдено, 0 провалено
```

---

## CLI-утилита

```bash
# Зашифровать из JWK-файла
./jwe_encrypt --jwk public_key.json \
              --payload '{"sub":"user-1","name":"Иван"}'

# Зашифровать из JWKS URL
./jwe_encrypt --jwks http://idp.example.com/.well-known/jwks.json \
              --kid my-key-id \
              --payload '{"sub":"user-1"}'

# Из stdin, с подробным выводом
echo '{"sub":"1"}' | ./jwe_encrypt --jwk pub.json --verbose

# Справка
./jwe_encrypt --help
```

Утилита выводит компактный JWE-токен в stdout, ошибки — в stderr.

---

## Безопасность

### Что реализовано правильно

- **Случайность**: CEK и IV генерируются из `/dev/urandom` (Linux/macOS) — криптографически стойкий источник
- **OAEP padding**: MGF1(SHA-256) с проверкой lHash — защита от атак Блейхенбахера
- **GCM Authentication**: GHASH обеспечивает целостность и аутентификацию данных
- **AAD**: `ASCII(BASE64URL(header))` защищает заголовок от подмены

### Известные ограничения (не для продакшена)

> ⚠️ Данная реализация является **учебной** и демонстрирует все криптографические примитивы «изнутри». Для продакшена рекомендуется использовать проверенные библиотеки (OpenSSL, libsodium, Botan).

- **BigInt не защищён от timing-атак**: RSA-операция занимает разное время в зависимости от значения экспоненты. В реальных системах необходима Montgomery-форма с постоянным временем.
- **AES не защищён от cache-timing**: использование S-box через lookup таблицу уязвимо к атакам по сторонним каналам без AES-NI инструкций.
- **HTTPS не поддерживается**: JWKS-загрузка работает только по HTTP. TLS требует отдельной реализации или системного OpenSSL.
- **Только шифрование**: дешифрование не реализовано (не требуется по ТЗ).

---

## Ограничения

| Параметр | Значение |
|----------|----------|
| Алгоритм ключа | Только RSA-OAEP-256 |
| Алгоритм данных | Только A256GCM |
| Размер ключа RSA | Любой ≥ 2048 бит (рекомендуется 2048 или 4096) |
| OAEP label | Только пустой (стандартный для JWE) |
| IV | Строго 96 бит (рекомендуемый размер NIST для GCM) |
| JWKS протокол | Только HTTP (HTTPS требует OpenSSL) |
| Платформа | Linux, macOS (POSIX), Windows (без сокетов) |

---

## Стандарты и ссылки

| Документ | Назначение |
|----------|------------|
| [RFC 7516](https://tools.ietf.org/html/rfc7516) | JSON Web Encryption (JWE) |
| [RFC 7517](https://tools.ietf.org/html/rfc7517) | JSON Web Key (JWK) |
| [RFC 7518](https://tools.ietf.org/html/rfc7518) | JSON Web Algorithms (JWA) |
| [RFC 8017](https://tools.ietf.org/html/rfc8017) | PKCS #1 v2.2 — RSA-OAEP |
| [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) | AES (Advanced Encryption Standard) |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | SHA-256 |
| [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800/38/d/final) | AES-GCM |
| [RFC 4648](https://tools.ietf.org/html/rfc4648) | BASE64URL |
| [RFC 4231](https://tools.ietf.org/html/rfc4231) | HMAC-SHA-256 тест-векторы |

---

## Лицензия

MIT License — см. файл [LICENSE](LICENSE).

---

<div align="center">

**jwe-cpp** · C++20 · Header-only · No dependencies

</div>
