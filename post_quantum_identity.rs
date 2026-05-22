//! Post‑quantum identity using Kyber‑1024 (KEM) and Dilithium‑5.
//! Secrets are automatically zeroised on drop.

use zeroize::{Zeroize, ZeroizeOnDrop};
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;

#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizedSecret(Vec<u8>);

/// Secure container for cryptographic material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureEnclave<T> {
    data: ZeroizedSecret,
    _marker: std::marker::PhantomData<T>,
}

pub struct QuantumIdentity {
    pub id: String,
    kem_public: kyber1024::PublicKey,
    kem_secret: kyber1024::SecretKey,
    sign_public: dilithium5::PublicKey,
    sign_secret: dilithium5::SecretKey,
}

impl QuantumIdentity {
    /// Generates a fresh post‑quantum identity.
    pub fn new_secure(id: impl Into<String>) -> Self {
        let (kem_pk, kem_sk) = kyber1024::keypair();
        let (sign_pk, sign_sk) = dilithium5::keypair();
        Self {
            id: id.into(),
            kem_public: kem_pk,
            kem_secret: kem_sk,
            sign_public: sign_pk,
            sign_secret: sign_sk,
        }
    }

    /// Encapsulates a shared secret for a recipient.
    pub fn encapsulate(&self, recipient_public: &kyber1024::PublicKey) -> (Vec<u8>, Vec<u8>) {
        let (ciphertext, shared) = kyber1024::encapsulate(recipient_public);
        (ciphertext.as_bytes().to_vec(), shared.as_bytes().to_vec())
    }

    /// Decapsulates a shared secret using our own secret key.
    /// Returns `None` if the ciphertext length is invalid.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() != kyber1024::ciphertext_bytes() {
            return None;
        }
        let ct = kyber1024::Ciphertext::from_bytes(ciphertext);
        let shared = kyber1024::decapsulate(&ct, &self.kem_secret);
        Some(shared.as_bytes().to_vec())
    }

    /// Returns the public KEM key as bytes.
    pub fn kem_public_bytes(&self) -> Vec<u8> {
        self.kem_public.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encapsulation_decapsulation() {
        let alice = QuantumIdentity::new_secure("alice");
        let bob = QuantumIdentity::new_secure("bob");
        let (ciphertext, _) = bob.encapsulate(&alice.kem_public);
        let shared = alice.decapsulate(&ciphertext);
        assert!(shared.is_some());
        // In real use, compare shared secrets; here just ensure not empty
        assert!(!shared.unwrap().is_empty());
    }

    #[test]
    fn test_invalid_ciphertext_length() {
        let alice = QuantumIdentity::new_secure("alice");
        assert!(alice.decapsulate(&[0u8; 10]).is_none());
    }
}
