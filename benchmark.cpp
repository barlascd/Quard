#include <benchmark/benchmark.h>

#include <Eigen/Dense>

#include "math_engine.hpp"

static void MatrixBenchmark(benchmark::State& state) {
    const int n = static_cast<int>(state.range(0));
    Eigen::MatrixXf A = Eigen::MatrixXf::Random(n, n);
    Eigen::MatrixXf B = Eigen::MatrixXf::Random(n, n);

    for (auto _ : state) {
        Eigen::MatrixXf C = quard::matrix_multiply(A, B);
        benchmark::DoNotOptimize(C);
    }
}
BENCHMARK(MatrixBenchmark)->Arg(64)->Arg(128)->Arg(256);

BENCHMARK_MAIN();
