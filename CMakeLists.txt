cmake_minimum_required(VERSION 3.20)

project(
    jwe-cpp
    VERSION 1.0.0
    DESCRIPTION "JWE (JSON Web Encryption) — реализация с нуля, без зависимостей"
    LANGUAGES CXX
)

# ─── Стандарт C++23 ────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Экспорт compile_commands.json (для clangd, IDE) ──────────────────────
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Предупреждения ────────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wshadow -Wnon-virtual-dtor
        -Wold-style-cast -Wcast-align
        -Wunused -Woverloaded-virtual
        -Wconversion -Wsign-conversion
        -Wformat=2
        -Wimplicit-fallthrough
    )
elseif(MSVC)
    add_compile_options(/W4 /permissive-)
endif()

# ─── Опции сборки ──────────────────────────────────────────────────────────
option(JWE_BUILD_TESTS    "Собрать тесты"          ON)
option(JWE_BUILD_EXAMPLES "Собрать примеры"         ON)
option(JWE_BUILD_SANITIZE "Включить AddressSanitizer (Debug)" OFF)

if(JWE_BUILD_SANITIZE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ─── Header-only библиотека ────────────────────────────────────────────────
add_library(jwe INTERFACE)
add_library(jwe::jwe ALIAS jwe)

target_include_directories(jwe
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(jwe INTERFACE cxx_std_20)

# ─── Тесты ─────────────────────────────────────────────────────────────────
if(JWE_BUILD_TESTS)
    enable_testing()

    add_executable(jwe_tests tests/test_all.cpp)
    target_link_libraries(jwe_tests PRIVATE jwe::jwe)

    # CTest интеграция
    add_test(NAME jwe_unit_tests COMMAND jwe_tests)
    set_tests_properties(jwe_unit_tests PROPERTIES
        LABELS "unit"
        TIMEOUT 30
    )
endif()

# ─── Примеры ───────────────────────────────────────────────────────────────
if(JWE_BUILD_EXAMPLES)
    add_executable(basic_usage   examples/basic_usage.cpp)
    add_executable(jwe_encrypt   examples/encrypt_payload.cpp)

    target_link_libraries(basic_usage PRIVATE jwe::jwe)
    target_link_libraries(jwe_encrypt PRIVATE jwe::jwe)

    # На Linux подключаем POSIX-сокеты
    if(UNIX)
        target_compile_definitions(jwe_encrypt PRIVATE _POSIX_C_SOURCE=200112L)
    endif()
endif()

# ─── Установка ─────────────────────────────────────────────────────────────
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS jwe
    EXPORT jweTargets
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

install(EXPORT jweTargets
    FILE jweTargets.cmake
    NAMESPACE jwe::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jwe
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/jweConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/jweConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/jweConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jwe
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/jweConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/jweConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jwe
)

# ─── Информационный вывод ──────────────────────────────────────────────────
message(STATUS "")
message(STATUS "  jwe-cpp v${PROJECT_VERSION}")
message(STATUS "  Компилятор : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Стандарт   : C++${CMAKE_CXX_STANDARD} (требуется GCC 13+, Clang 17+, MSVC 2022+)")
message(STATUS "  Конфигурация: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Тесты      : ${JWE_BUILD_TESTS}")
message(STATUS "  Примеры    : ${JWE_BUILD_EXAMPLES}")
message(STATUS "  Sanitizers : ${JWE_BUILD_SANITIZE}")
message(STATUS "")
