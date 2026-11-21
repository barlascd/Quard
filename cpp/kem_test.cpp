// ML-KEM-768 round trip through liboqs. Sizes are checked against the
// Rust implementation (src/pqc/kem.rs) so both sides stay interoperable.
#include <oqs/oqs.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

namespace {

struct KemDeleter {
    void operator()(OQS_KEM* k) const { OQS_KEM_free(k); }
};

// Wipes a buffer when it goes out of scope, on every return path.
struct Wipe {
    std::vector<uint8_t>& v;
    ~Wipe() { OQS_MEM_cleanse(v.data(), v.size()); }
};

}  // namespace

int main() {
    std::unique_ptr<OQS_KEM, KemDeleter> kem(OQS_KEM_new(OQS_KEM_alg_ml_kem_768));
    if (!kem) {
        std::cerr << "ML-KEM unavailable\n";
        return 1;
    }

    if (kem->length_public_key != 1184 || kem->length_ciphertext != 1088 ||
        kem->length_shared_secret != 32) {
        std::cerr << "Unexpected ML-KEM-768 sizes\n";
        return 1;
    }

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_sender(kem->length_shared_secret);
    std::vector<uint8_t> shared_receiver(kem->length_shared_secret);
    Wipe w1{secret_key}, w2{shared_sender}, w3{shared_receiver};

    if (OQS_KEM_keypair(kem.get(), public_key.data(), secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "keypair failed\n";
        return 1;
    }
    if (OQS_KEM_encaps(kem.get(), ciphertext.data(), shared_sender.data(),
                       public_key.data()) != OQS_SUCCESS) {
        std::cerr << "encaps failed\n";
        return 1;
    }
    if (OQS_KEM_decaps(kem.get(), shared_receiver.data(), ciphertext.data(),
                       secret_key.data()) != OQS_SUCCESS) {
        std::cerr << "decaps failed\n";
        return 1;
    }

    const bool success = shared_sender == shared_receiver;
    std::cout << "Key exchange: " << (success ? "SUCCESS" : "FAILED") << '\n';

    // A tampered ciphertext must not yield the same secret (implicit rejection).
    ciphertext[0] ^= 1;
    std::vector<uint8_t> tampered(kem->length_shared_secret);
    Wipe w4{tampered};
    if (OQS_KEM_decaps(kem.get(), tampered.data(), ciphertext.data(),
                       secret_key.data()) == OQS_SUCCESS &&
        tampered == shared_sender) {
        std::cerr << "Tampered ciphertext produced the original secret\n";
        return 1;
    }

    return success ? 0 : 1;
}
