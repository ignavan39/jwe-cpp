# ──────────────────────────────────────────────────────────────────────────
# Dockerfile — jwe-cpp
#
# Многоэтапная сборка (multi-stage build):
#   Stage 1 "builder" — компиляция и тесты (GCC 13 + CMake)
#   Stage 2 "runtime" — минимальный образ только с бинарниками
#
# Использование:
#   docker build -t jwe-cpp .
#   docker run --rm jwe-cpp                    # запустить пример
#   docker run --rm jwe-cpp jwe_tests          # запустить тесты
#   docker run --rm jwe-cpp jwe_encrypt --help # справка по CLI
#
# ──────────────────────────────────────────────────────────────────────────

# ─── Stage 1: Сборка ──────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

LABEL stage="builder"
LABEL description="jwe-cpp build stage — GCC 13, CMake, C++23"

# Установка инструментов сборки
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++-13           \
        cmake            \
        make             \
        ca-certificates  \
    && rm -rf /var/lib/apt/lists/*

# Используем GCC 13 по умолчанию
ENV CC=gcc-13 CXX=g++-13

WORKDIR /src

# Копируем исходники
COPY . .

# ── Конфигурация CMake ────────────────────────────────────────────────────
RUN cmake -B /build             \
          -DCMAKE_BUILD_TYPE=Release \
          -DJWE_BUILD_TESTS=ON       \
          -DJWE_BUILD_EXAMPLES=ON    \
          -DJWE_BUILD_SANITIZE=OFF

# ── Сборка ────────────────────────────────────────────────────────────────
RUN cmake --build /build --parallel "$(nproc)"

# ── Запуск тестов при сборке образа ──────────────────────────────────────
# Сборка упадёт, если хоть один тест не прошёл — fail-fast.
RUN /build/tests/jwe_tests

# ─── Stage 2: Рабочий образ ───────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

LABEL maintainer="your-org"
LABEL version="1.0.0"
LABEL description="jwe-cpp — JWE encryption utility (RSA-OAEP-256 + AES-256-GCM)"

# Только необходимые runtime-зависимости (libstdc++ уже в slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем бинарники из builder
COPY --from=builder /build/tests/jwe_tests      /usr/local/bin/jwe_tests
COPY --from=builder /build/examples/basic_usage /usr/local/bin/basic_usage
COPY --from=builder /build/examples/jwe_encrypt /usr/local/bin/jwe_encrypt

# По умолчанию запускаем демонстрационный пример
CMD ["/usr/local/bin/basic_usage"]
