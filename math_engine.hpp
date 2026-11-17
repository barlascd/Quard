#pragma once
#include <Eigen/Dense>

namespace quard {

// All functions throw std::invalid_argument on NaN/Inf or dimension mismatch.
double feature_norm(const Eigen::VectorXf& features);
float dot_product(const Eigen::VectorXf& a, const Eigen::VectorXf& b);
Eigen::MatrixXf matrix_multiply(const Eigen::MatrixXf& a, const Eigen::MatrixXf& b);

}  // namespace quard
