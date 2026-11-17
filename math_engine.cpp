#include "math_engine.hpp"

#include <stdexcept>

namespace quard {

double feature_norm(const Eigen::VectorXf& features) {
    if (!features.allFinite()) {
        throw std::invalid_argument("Invalid numerical values");
    }
    return features.norm();
}

float dot_product(const Eigen::VectorXf& a, const Eigen::VectorXf& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Dimension mismatch");
    }
    if (!a.allFinite() || !b.allFinite()) {
        throw std::invalid_argument("Invalid numerical values");
    }
    return a.dot(b);
}

Eigen::MatrixXf matrix_multiply(const Eigen::MatrixXf& a, const Eigen::MatrixXf& b) {
    if (a.cols() != b.rows()) {
        throw std::invalid_argument("Invalid matrix dimensions");
    }
    if (!a.allFinite() || !b.allFinite()) {
        throw std::invalid_argument("Invalid matrix values");
    }
    return a * b;
}

}  // namespace quard
