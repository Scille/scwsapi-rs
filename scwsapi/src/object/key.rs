use std::ops::Deref;

use sha2::Digest;
use wasm_bindgen::JsValue;

use crate::Provenance;

pub struct PublicKey {
    #[expect(dead_code)]
    handle: scwsapi_sys::object::Key,
    pub provenance: crate::Provenance,
}

impl PublicKey {
    pub(super) fn new(handle: scwsapi_sys::object::Key, provenance: crate::Provenance) -> Self {
        Self { handle, provenance }
    }
}

pub struct PrivateKey {
    handle: scwsapi_sys::object::Key,
    pub provenance: crate::Provenance,
}

impl Deref for PrivateKey {
    type Target = scwsapi_sys::object::Key;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl PrivateKey {
    pub(super) fn new(handle: scwsapi_sys::object::Key, provenance: crate::Provenance) -> Self {
        Self { handle, provenance }
    }

    /// Sign the provided message with the key.
    pub async fn sign(
        &self,
        message: &[u8],
    ) -> Result<(SignatureAlgorithm, Vec<u8>), SignHashError> {
        let hash = sha2::Sha256::digest(message);
        // We have access to more advanced signature algorithm when the key is hardware backed.
        let (algo_config, algo) = if self.provenance == Provenance::Hardware {
            (
                (&scwsapi_sys::object::RsaPssPadding {
                    mgf: scwsapi_sys::object::RsaPssMaskType::Sha256,
                    salt_len: sha2::Sha256::output_size(),
                })
                    .try_into()
                    .map_err(SignHashError::CannotGenerateSignatureConfig)?,
                SignatureAlgorithm::RsasaPssSha256,
            )
        } else {
            (
                (&scwsapi_sys::object::Pkcs1HashType::Sha256)
                    .try_into()
                    .map_err(SignHashError::CannotGenerateSignatureConfig)?,
                SignatureAlgorithm::RsasaPkcs1Sha256,
            )
        };
        let raw_signature = self
            .handle
            .sign(hash.as_ref(), Some(algo_config))
            .await
            .map_err(SignHashError::SignError)?;
        let signature = js_sys::Uint8Array::new(&raw_signature);
        log::debug!("Signature: {signature:?} {}", signature.length());
        Ok((algo, signature.to_vec()))
    }

    /// Decrypt the `ciphertext` encrypted with the `algorithm` with the key.
    pub async fn decrypt(
        &self,
        algorithm: EncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let config = scwsapi_sys::object::RsaEncryptionConfig::from(algorithm);
        let js_config = (&config)
            .try_into()
            .map_err(DecryptError::CannotGenerateEncryptionConfig)?;
        let raw_data = self
            .handle
            .decrypt(ciphertext, Some(js_config))
            .await
            .map_err(DecryptError::Decrypt)?;
        let data = js_sys::Uint8Array::new(&raw_data);
        Ok(data.to_vec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsasaPssSha256,
    RsasaPkcs1Sha256,
}

#[derive(Debug, thiserror::Error)]
pub enum SignHashError {
    #[error("cannot generate configuration for signature: {}", .0)]
    CannotGenerateSignatureConfig(serde_wasm_bindgen::Error),
    #[error("cannot sign")]
    SignError(JsValue),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    RsaPkcs1v15,
    RsaOaepSha256,
}

impl From<EncryptionAlgorithm> for scwsapi_sys::object::RsaEncryptionConfig {
    fn from(value: EncryptionAlgorithm) -> Self {
        match value {
            EncryptionAlgorithm::RsaPkcs1v15 => Self::Pkcs1,
            EncryptionAlgorithm::RsaOaepSha256 => Self::Oaep {
                hash_alg: scwsapi_sys::object::RsaOaepHashAlg::Sha256,
                mgf: scwsapi_sys::object::RsaOaepMaskType::Sha256,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("cannot generate configuration for encryption: {}", .0)]
    CannotGenerateEncryptionConfig(serde_wasm_bindgen::Error),
    #[error("cannot decrypt")]
    Decrypt(JsValue),
}
