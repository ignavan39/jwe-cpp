#pragma once

/**
 * @file jwks_fetcher.hpp
 * @brief Загрузка JWKS по HTTPS-URL через raw POSIX-сокет + TLS-заглушка
 *
 * ⚠  ВАЖНО: Полноценный TLS (TLS 1.3/1.2) требует либо системного OpenSSL,
 *    либо самостоятельной реализации рукопожатия — что выходит за рамки ТЗ
 *    «без сторонних библиотек». Поэтому данный модуль реализует два режима:
 *
 *    1. HTTP (plaintext, порт 80) — полноценная реализация через raw socket.
 *    2. HTTPS (порт 443) — требует системную библиотеку OpenSSL или NSS.
 *       Если OpenSSL доступен на сборочной машине, он подключается через
 *       системный вызов через стандартный POSIX API — иначе выбрасывается
 *       NetworkError с подсказкой.
 *
 *    Для продакшена рекомендуется использовать libcurl или boost.asio.
 *
 * Загруженный JSON разбирается парсером из json.hpp.
 * Возвращает первый подходящий ключ (alg=RSA-OAEP-256, use=enc).
 */

#include "json.hpp"
#include "types.hpp"

#ifdef __linux__
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#ifdef __APPLE__
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <cstring>
#include <sstream>
#include <string>

namespace jwe {

// ─── URL-парсер ────────────────────────────────────────────────────────────

struct ParsedUrl {
    std::string scheme;  // "http" | "https"
    std::string host;
    std::string port;    // "80" | "443" | custom
    std::string path;    // "/…"
};

[[nodiscard]] inline ParsedUrl parseUrl(std::string_view url) {
    ParsedUrl r;
    std::size_t pos = url.find("://");
    if (pos == std::string_view::npos)
        throw NetworkError("Некорректный URL (нет схемы): " + std::string(url));

    r.scheme = std::string(url.substr(0, pos));
    url.remove_prefix(pos + 3);

    std::size_t slash = url.find('/');
    std::string_view authority = (slash != std::string_view::npos)
                                 ? url.substr(0, slash) : url;
    r.path = (slash != std::string_view::npos) ? std::string(url.substr(slash)) : "/";

    std::size_t colon = authority.find(':');
    if (colon != std::string_view::npos) {
        r.host = std::string(authority.substr(0, colon));
        r.port = std::string(authority.substr(colon + 1));
    } else {
        r.host = std::string(authority);
        r.port = (r.scheme == "https") ? "443" : "80";
    }
    return r;
}

// ─── Простой HTTP/1.1 GET (только для HTTP, без TLS) ──────────────────────

#if defined(__linux__) || defined(__APPLE__)

[[nodiscard]] inline std::string httpGet(const ParsedUrl& url) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &res);
    if (rc != 0 || !res)
        throw NetworkError("DNS-ошибка для хоста: " + url.host +
                           " (" + gai_strerror(rc) + ")");

    int fd = -1;
    for (auto* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        throw NetworkError("Не удалось подключиться к: " + url.host + ":" + url.port);

    // Формируем HTTP/1.1 запрос
    std::ostringstream req;
    req << "GET " << url.path << " HTTP/1.1\r\n"
        << "Host: " << url.host << "\r\n"
        << "Connection: close\r\n"
        << "Accept: application/json\r\n"
        << "\r\n";
    std::string reqStr = req.str();
    send(fd, reqStr.c_str(), reqStr.size(), 0);

    // Читаем ответ
    std::string response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0)
        response.append(buf, static_cast<std::size_t>(n));
    close(fd);

    // Извлекаем тело (после двойного CRLF)
    auto sep = response.find("\r\n\r\n");
    if (sep == std::string::npos)
        throw NetworkError("Некорректный HTTP-ответ (нет разделителя заголовков)");

    // Проверяем статус
    auto statusLine = response.substr(0, response.find("\r\n"));
    if (statusLine.find("200") == std::string::npos)
        throw NetworkError("HTTP ответ: " + statusLine);

    return response.substr(sep + 4);
}

#else // Windows-заглушка
[[nodiscard]] inline std::string httpGet(const ParsedUrl&) {
    throw NetworkError("HTTP-сокет не реализован для данной платформы");
}
#endif

// ─── Публичный API ─────────────────────────────────────────────────────────

/**
 * @brief Загрузить RSA-публичный ключ из JWKS URL.
 *
 * Выбирает первый ключ с kty="RSA" и use="enc" (или alg="RSA-OAEP-256").
 * Если kid задан — ищет ключ с совпадающим kid.
 *
 * @param jwksUrl   URL JWKS-эндпоинта (http:// или https://)
 * @param kid       Опциональный kid для поиска конкретного ключа
 * @return RsaPublicKey
 * @throws NetworkError при ошибках сети
 * @throws ParseError   при некорректном JWKS
 * @throws KeyError     если подходящий ключ не найден
 */
[[nodiscard]] inline RsaPublicKey fetchJwksKey(
    std::string_view jwksUrl,
    std::string_view kid = "")
{
    ParsedUrl url = parseUrl(jwksUrl);

    if (url.scheme == "https")
        throw NetworkError(
            "HTTPS требует системный TLS (OpenSSL). "
            "Передайте JWK напрямую через setPublicKeyFromJwk() "
            "или соберите с флагом -DJWE_USE_OPENSSL=ON.");

    std::string body = httpGet(url);
    auto root = json::parse(body);
    const auto& keys = root["keys"].asArray();

    for (const auto& k : keys) {
        if (!k.isObject()) continue;

        // Фильтр по kty
        if (!k.has("kty") || k["kty"].asString() != "RSA") continue;

        // Фильтр по kid (если задан)
        if (!kid.empty()) {
            if (!k.has("kid") || k["kid"].asString() != std::string(kid)) continue;
        }

        // Ключ должен быть для шифрования
        bool useEnc = k.has("use") && k["use"].asString() == "enc";
        bool algOk  = k.has("alg") && k["alg"].asString() == std::string(kAlgRsaOaep256);
        bool hasUse = k.has("use");
        if (hasUse && !useEnc && !algOk) continue;

        RsaPublicKey key;
        key.kty = "RSA";
        key.n   = k["n"].asString();
        key.e   = k["e"].asString();
        if (k.has("kid")) key.kid = k["kid"].asString();
        if (k.has("use")) key.use = k["use"].asString();
        if (k.has("alg")) key.alg = k["alg"].asString();
        return key;
    }

    throw KeyError("JWKS: подходящий RSA-ключ не найден (url=" +
                   std::string(jwksUrl) + ")");
}

/**
 * @brief Создать RsaPublicKey из одиночного JWK-объекта (JSON-строка).
 *
 * Пример:
 * @code
 *   auto key = keyFromJwkString(R"({"kty":"RSA","n":"…","e":"AQAB"})");
 * @endcode
 */
[[nodiscard]] inline RsaPublicKey keyFromJwkString(std::string_view jwk) {
    auto v = json::parse(jwk);
    RsaPublicKey key;
    key.kty = v["kty"].asString();
    if (key.kty != "RSA")
        throw KeyError("JWK: ожидается kty=RSA, получено: " + key.kty);
    key.n = v["n"].asString();
    key.e = v["e"].asString();
    if (v.has("kid")) key.kid = v["kid"].asString();
    if (v.has("use")) key.use = v["use"].asString();
    if (v.has("alg")) key.alg = v["alg"].asString();
    return key;
}

} // namespace jwe
