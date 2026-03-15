# Детальное описание шагов JWE

Этот документ описывает каждый шаг формирования JWE-токена с указанием исходного кода и стандарта.

---

## Шаг 1 — Подготовка Plaintext

**Файл:** `examples/basic_usage.cpp`, `examples/encrypt_payload.cpp`

Plaintext — это JSON-структура с персональными данными пользователя:

```json
{
    "sub":   "user-42",
    "name":  "Иванова Мария Сергеевна",
    "email": "m.ivanova@example.ru",
    "phone": "+7 900 123-45-67",
    "iat":   1710000000
}
```

Plaintext преобразуется в байты (UTF-8) перед шифрованием.

**Стандарт:** RFC 7516 §5.2 — Message Encryption

---

## Шаг 2 — Формирование JWE Protected Header

**Файл:** `include/jwe/jwe_builder.hpp` → метод `build()`

```cpp
const std::string headerJson =
    R"({"alg":"RSA-OAEP-256","enc":"A256GCM"})";
const std::string protectedHeader = base64url::encode(headerJson);
```

Заголовок сериализуется в компактный JSON (без пробелов), затем кодируется в BASE64URL:

```
{"alg":"RSA-OAEP-256","enc":"A256GCM"}
→ eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0
```

**Поля заголовка (RFC 7518):**
- `"alg": "RSA-OAEP-256"` — алгоритм шифрования ключа (CEK)
- `"enc": "A256GCM"` — алгоритм шифрования содержимого

**Стандарт:** RFC 7516 §5.1 (шаг 2)

---

## Шаг 3 — Генерация Content Encryption Key (CEK)

**Файл:** `include/jwe/jwe_builder.hpp`, `include/jwe/rsa_oaep.hpp`

```cpp
Bytes cek = crypto::randomBytes(kCekSize);  // kCekSize = 32 байта = 256 бит
```

CEK — случайный симметричный ключ для AES-256-GCM. Генерируется из `/dev/urandom`:

```cpp
// include/jwe/rsa_oaep.hpp
[[nodiscard]] inline Bytes randomBytes(std::size_t n) {
    Bytes out(n);
    FILE* f = fopen("/dev/urandom", "rb");
    fread(out.data(), 1, n, f);
    fclose(f);
    return out;
}
```

**Параметры:**
- Размер: 256 бит (32 байта) — требование A256GCM (RFC 7518 §5.3)
- Источник: `/dev/urandom` — криптографически стойкий ГПСЧ ядра Linux/macOS

**Стандарт:** RFC 7516 §5.1 (шаги 1-2), RFC 7518 §5.3

---

## Шаг 4 — Шифрование CEK (JWE Encrypted Key)

**Файл:** `include/jwe/rsa_oaep.hpp` → функция `rsaOaepEncrypt()`

```cpp
Bytes nBytes = base64url::decode(key_->n);  // модуль RSA из JWK
Bytes eBytes = base64url::decode(key_->e);  // экспонента RSA из JWK

Bytes encryptedKey = crypto::rsaOaepEncrypt(
    ByteSpan{nBytes},
    ByteSpan{eBytes},
    ByteSpan{cek});
```

### RSA-OAEP-256 (RFC 8017 §7.1.1)

```
OAEP-Encode(CEK):
  lHash = SHA-256("")           // хэш пустой метки
  DB    = lHash || 0x00...00 || 0x01 || CEK  // data block
  seed  = random(32 байта)
  dbMask    = MGF1(seed, len(DB))
  maskedDB  = DB  XOR dbMask
  seedMask  = MGF1(maskedDB, 32)
  maskedSeed= seed XOR seedMask
  EM = 0x00 || maskedSeed || maskedDB

RSA-Encrypt:
  m = OS2IP(EM)
  c = m^e mod n                 // возведение в степень по модулю
  return I2OSP(c, k)
```

Публичный ключ берётся из JWKS URL или передаётся напрямую как JWK:

```json
{
    "kty": "RSA",
    "n":   "<BASE64URL модуль>",
    "e":   "AQAB",
    "use": "enc",
    "alg": "RSA-OAEP-256"
}
```

**Стандарт:** RFC 7516 §5.1 (шаг 5), RFC 8017 §7.1, PKCS #1 v2.2

---

## Шаг 5 — Генерация Initialization Vector (IV)

**Файл:** `include/jwe/jwe_builder.hpp`

```cpp
Bytes iv = crypto::randomBytes(kIvSize);  // kIvSize = 12 байт = 96 бит
```

IV для AES-256-GCM:
- Размер: 96 бит — рекомендуемый NIST SP 800-38D для GCM
- При 96-битном IV инициализация `J0 = IV || 0x00000001` (без GHASH)
- Уникален для каждого сообщения, зашифрованного одним ключом

**Стандарт:** RFC 7516 §5.1 (шаг 9), NIST SP 800-38D §8.2.1

---

## Шаг 6 — Additional Authenticated Data (AAD)

**Файл:** `include/jwe/jwe_builder.hpp`

```cpp
// AAD = ASCII байты строки BASE64URL(Protected Header)
Bytes aad(protectedHeader.begin(), protectedHeader.end());
```

AAD — это байты ASCII-представления BASE64URL-закодированного заголовка. AAD **не шифруется**, но **аутентифицируется** тегом GCM. Это гарантирует, что заголовок не был изменён.

```
protectedHeader = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0"
AAD = bytes("eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0")
```

**Стандарт:** RFC 7516 §5.1 (шаг 14)

---

## Шаг 7 — Шифрование Plaintext (AES-256-GCM)

**Файл:** `include/jwe/aes_gcm.hpp` → функция `aes256_gcm_encrypt()`

```cpp
auto gcmResult = crypto::aes256_gcm_encrypt(
    ByteSpan{cek},   // 256-битный ключ
    ByteSpan{iv},    // 96-битный IV
    ByteSpan{pt},    // plaintext
    ByteSpan{aad}    // AAD (защита заголовка)
);
// gcmResult.ciphertext — зашифрованные данные
// gcmResult.tag        — 128-битный тег аутентификации
```

### AES-256-GCM (NIST SP 800-38D)

```
J0 = IV || 0x00000001             // начальный счётчик
H  = AES(key, 0^128)              // ключ аутентификации GCM

// GCTR: шифрование блоков CTR-режимом
для каждого блока i:
    CB_i = inc32(CB_{i-1})
    EK_i = AES(key, CB_i)
    C_i  = P_i XOR EK_i

// GHASH: аутентификация
S = GHASH(H, A, C)                // A=AAD, C=ciphertext
T = MSB_128(GCTR(J0, S))          // тег аутентификации
```

**Результат:**
- `JWE Ciphertext` = `BASE64URL(ciphertext)` — зашифрованные персональные данные
- `JWE Authentication Tag` = `BASE64URL(tag)` — 128-битный AEAD тег

**Стандарт:** RFC 7516 §5.1 (шаги 15-16), NIST SP 800-38D, RFC 7518 §5.3

---

## Итоговый токен

После выполнения всех шагов формируется **JWE Compact Serialization** (RFC 7516 §7.1):

```
BASE64URL(JWE Protected Header) . 
BASE64URL(JWE Encrypted Key) . 
BASE64URL(JWE Initialization Vector) . 
BASE64URL(JWE Ciphertext) . 
BASE64URL(JWE Authentication Tag)
```

Пример:

```
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0
.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
  ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
  Sv04uVuxIp5Zms1gNxKgVa7FRFRKl5Ek4gFv0tE3LpCtCRCEKGsIi7dkKiDVdUP
  e-dHl4jnw
.48V1_ALb6US04U3b
.5eym8TW_c8SuK0ltJ3rpYIzTe3eHiJyMH6Oo3BHyFRtk
.XFBoMYUZodetZdvTiFvSkQ
```

---

## Диаграмма потока данных

```
Plaintext (JSON)
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                    JweBuilder.build()                        │
│                                                               │
│  Шаг 2:  headerJson → BASE64URL → protectedHeader            │
│                                                               │
│  Шаг 3:  /dev/urandom → CEK (32 байта)                      │
│                                                               │
│  Шаг 4:  RSA-OAEP-256(CEK, n, e) → encryptedKey             │
│          ├── OAEP-pad: MGF1(SHA-256) + XOR-маски             │
│          └── RSA: m^e mod n (BigInt.powmod)                  │
│                                                               │
│  Шаг 5:  /dev/urandom → IV (12 байт)                        │
│                                                               │
│  Шаг 6:  ASCII(protectedHeader) → AAD                       │
│                                                               │
│  Шаг 7:  AES-256-GCM(plaintext, CEK, IV, AAD)               │
│          ├── AES KeyExpansion(CEK) → 15 раундовых ключей     │
│          ├── GCTR: CTR-шифрование блоков                     │
│          └── GHASH(H, AAD, ciphertext) → Authentication Tag  │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
JweToken {
    protected_header,     ← BASE64URL(headerJson)
    encrypted_key,        ← BASE64URL(RSA-OAEP-256(CEK))
    initialization_vector,← BASE64URL(IV)
    ciphertext,           ← BASE64URL(AES-256-GCM(plaintext))
    authentication_tag    ← BASE64URL(GCM Tag)
}
      │
      ▼
JWE Compact: hdr.ek.iv.ct.tag
```
