# ──────────────────────────────────────────────────────────────────────────
# Dockerfile — jwe-cpp
#
# Многоэтапная сборка:
#   builder  — Ubuntu 24.04 + GCC 13 + CMake (bookworm даёт только GCC 12)
#   release  — debian:bookworm-slim, только бинарники
#
# Использование:
#   docker build -t jwe-cpp .
#   docker run --rm jwe-cpp                     # демо-пример
#   docker run --rm jwe-cpp jwe_tests           # тесты
#   docker run --rm jwe-cpp jwe_encrypt --help  # CLI справка
# ──────────────────────────────────────────────────────────────────────────

# ─── Stage 1: сборка ──────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

LABEL stage="builder"
LABEL description="jwe-cpp builder — GCC 13, CMake 3.28, C++23"

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=gcc-13 CXX=g++-13

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++-13 cmake make ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -B /build                 \
          -DCMAKE_BUILD_TYPE=Release \
          -DJWE_BUILD_TESTS=ON       \
          -DJWE_BUILD_EXAMPLES=ON    \
          -DJWE_BUILD_SANITIZE=OFF

RUN cmake --build /build --parallel "$(nproc)"

# Тесты запускаем через ctest — он знает точный путь к бинарнику
RUN cd /build && ctest --output-on-failure

# ─── Stage 2: рабочий образ ───────────────────────────────────────────────
FROM debian:bookworm-slim AS release

LABEL maintainer="your-org"
LABEL version="1.0.0"
LABEL description="jwe-cpp — JWE (RSA-OAEP-256 + AES-256-GCM)"

RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/tests/jwe_tests       /usr/local/bin/jwe_tests
COPY --from=builder /build/examples/basic_usage  /usr/local/bin/basic_usage
COPY --from=builder /build/examples/jwe_encrypt  /usr/local/bin/jwe_encrypt

CMD ["/usr/local/bin/basic_usage"]
