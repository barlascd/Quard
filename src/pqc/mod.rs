//! Post-quantum cryptography for Quard.
//!
//! * [`kem`]            ML-KEM-768 key encapsulation (NIST FIPS 203)
//! * [`signature`]      ML-DSA-65 signatures (NIST FIPS 204)
//! * [`key_derivation`] HKDF-SHA256 to turn a KEM secret into an AES key
//! * [`encryption`]     AES-256-GCM authenticated encryption
//! * [`integrity`]      SHA3-256 hashing
//! * [`secrets`]        zeroizing key containers
//! * [`envelope`]       KEM + HKDF + AES-GCM composed into seal/open
//!
//! The underlying RustCrypto crates (`ml-kem`, `ml-dsa`) have not been
//! independently audited and are not FIPS 140 validated.
pub mod encryption;
pub mod envelope;
pub mod integrity;
pub mod kem;
pub mod key_derivation;
pub mod secrets;
pub mod signature;
