cmake_minimum_required(VERSION 3.20)
project(keyhunt LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -g")
add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(keyhunt_core STATIC
  src/hash.cpp
  src/encodings.cpp
  src/der.cpp
  src/aes.cpp
  src/fast_aes.cpp
  src/keysweep.cpp
  src/symmetric.cpp
  src/scanner.cpp
  src/bignum.cpp
  src/privkey.cpp
  src/kdf.cpp
  src/verify.cpp
  src/report.cpp
  src/pipeline.cpp
)
target_include_directories(keyhunt_core PUBLIC src)
target_link_libraries(keyhunt_core PUBLIC OpenSSL::Crypto Threads::Threads)

add_executable(keyhunt src/main.cpp)
target_link_libraries(keyhunt PRIVATE keyhunt_core)

add_executable(keyhunt-unit tests/unit_tests.cpp)
target_link_libraries(keyhunt-unit PRIVATE keyhunt_core)

# Test-image generator and end-to-end smoke test live in tests/.
add_executable(keyhunt-genimg tests/gen_image.cpp)
target_link_libraries(keyhunt-genimg PRIVATE keyhunt_core)

add_executable(keyhunt-e2e tests/e2e_test.cpp)
target_link_libraries(keyhunt-e2e PRIVATE keyhunt_core)

enable_testing()
add_test(NAME unit COMMAND keyhunt-unit)
add_test(NAME e2e COMMAND keyhunt-e2e)
