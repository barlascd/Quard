cmake_minimum_required(VERSION 3.20)
project(Quard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(QUARD_BUILD_BENCHMARKS "Build Google Benchmark targets" OFF)
option(QUARD_BUILD_PQC_TESTS "Build ML-KEM test (needs liboqs)" OFF)

find_package(Eigen3 REQUIRED)

add_library(math_engine cpp/math_engine.cpp)
target_include_directories(math_engine PUBLIC cpp)
target_link_libraries(math_engine PUBLIC Eigen3::Eigen)

enable_testing()
add_executable(math_engine_test cpp/math_engine_test.cpp)
target_link_libraries(math_engine_test PRIVATE math_engine)
add_test(NAME math_engine_test COMMAND math_engine_test)

if(QUARD_BUILD_BENCHMARKS)
    find_package(benchmark REQUIRED)
    add_executable(quard_benchmark cpp/benchmark.cpp)
    target_link_libraries(quard_benchmark PRIVATE math_engine benchmark::benchmark)
endif()

if(QUARD_BUILD_PQC_TESTS)
    find_package(liboqs REQUIRED)
    add_executable(kem_test cpp/kem_test.cpp)
    target_link_libraries(kem_test PRIVATE OQS::oqs)
    add_test(NAME kem_test COMMAND kem_test)
endif()
