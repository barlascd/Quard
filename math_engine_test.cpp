#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>

#include "math_engine.hpp"

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::cerr << "FAILED: " #cond " (line " << __LINE__ << ")\n"; \
            std::exit(1);                                                \
        }                                                                \
    } while (0)

template <typename F>
static bool throws_invalid(F f) {
    try {
        f();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

int main() {
    const float nan = std::numeric_limits<float>::quiet_NaN();
    const float inf = std::numeric_limits<float>::infinity();

    Eigen::VectorXf v(2);
    v << 3.0f, 4.0f;
    CHECK(std::abs(quard::feature_norm(v) - 5.0) < 1e-6);

    Eigen::VectorXf bad(2);
    bad << 1.0f, nan;
    CHECK(throws_invalid([&] { quard::feature_norm(bad); }));

    Eigen::VectorXf a(2), b(2), c(3);
    a << 1.0f, 2.0f;
    b << 3.0f, 4.0f;
    c << 1.0f, 2.0f, 3.0f;
    CHECK(std::abs(quard::dot_product(a, b) - 11.0f) < 1e-6f);
    CHECK(throws_invalid([&] { quard::dot_product(a, c); }));
    bad << inf, 1.0f;
    CHECK(throws_invalid([&] { quard::dot_product(a, bad); }));

    Eigen::MatrixXf m = Eigen::MatrixXf::Identity(3, 3);
    Eigen::MatrixXf n = Eigen::MatrixXf::Random(3, 3);
    CHECK((quard::matrix_multiply(m, n) - n).norm() < 1e-6f);
    CHECK(throws_invalid([&] { quard::matrix_multiply(Eigen::MatrixXf(2, 3), Eigen::MatrixXf(2, 3)); }));

    std::cout << "All C++ tests passed\n";
    return 0;
}
