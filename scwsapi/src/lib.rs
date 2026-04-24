mod object;
mod reader;
mod token;

use std::ops::Deref;

use futures::{Stream, StreamExt};
use wasm_bindgen::JsValue;

pub use object::{
    Certificate, DataContainer, DecryptError, EncryptionAlgorithm, Object, PrivateKey, PublicKey,
    RequestPrivateKeyError, SignError, SignatureAlgorithm,
};
pub use reader::Reader;
pub use token::Token;

pub struct Scws(scwsapi_sys::Scws);

#[cfg(feature = "auto-load-scws")]
impl Default for Scws {
    fn default() -> Self {
        Self::from(scwsapi_sys::SCWS.with(Clone::clone))
    }
}

impl From<scwsapi_sys::Scws> for Scws {
    fn from(value: scwsapi_sys::Scws) -> Self {
        Self(value)
    }
}

impl Deref for Scws {
    type Target = scwsapi_sys::Scws;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Scws {
    /// Entrypoint to start the mutual authentication process between the
    ///
    /// ```text
    /// middleware <-> client <-> server
    /// ```
    ///
    /// More information about the arguments of the method can be found here:
    /// [`SCWS.findService`](https://idopte.fr/scwsapi/javascript/2_API/envsetup.html#SCWS.findService)
    pub async fn find_service(
        &self,
        webapp_cert: &str,
        challenge: &[u8],
    ) -> Result<ServiceResponse, FindServiceError> {
        let encoded_challenge = hex::encode(challenge);
        let raw = self
            .0
            .find_service(webapp_cert, &encoded_challenge)
            .await
            .map_err(FindServiceError::FindError)?;

        let challenge = {
            let raw = raw.challenge();
            hex::decode(String::from(raw))
        }
        .map_err(FindServiceError::InvalidChallenge)?;

        let cryptogram = {
            let raw = raw.cryptogram();
            hex::decode(String::from(raw))
        }
        .map_err(FindServiceError::InvalidCryptogram)?;

        let key_id = raw.key_id();

        Ok(ServiceResponse {
            challenge,
            cryptogram,
            key_id,
        })
    }

    /// Method to finish the mutual authentication once the server has signed its challenge.
    ///
    /// More information about the argument of the method can be found here:
    /// [`SCWS.createEnvironment`](https://idopte.fr/scwsapi/javascript/2_API/envsetup.html#SCWS.createEnvironment)
    pub async fn create_environment(&self, signature: &[u8]) -> Result<(), CreateEnvironmentError> {
        let encoded_signature = hex::encode(signature);
        self.0
            .create_environment(&encoded_signature)
            .await
            .map_err(CreateEnvironmentError::CreateError)
    }

    /// Refresh the reader list, returning it as a result
    pub async fn update_reader_list(&self) -> Vec<reader::Reader> {
        self.0
            .update_reader_list()
            .await
            .into_iter()
            .map(From::from)
            .collect()
    }

    /// List working reader (that can be connected to) as [`token::Token`]
    #[must_use = "Tokens are handles that need to be disconnected when not in use"]
    pub fn iter_working_reader(&self) -> impl Stream<Item = token::Token> {
        futures::stream::iter(self.readers()).filter_map(|r| async move {
            r.connect()
                .await
                .inspect_err(|e| log::warn!("Failed to connect to reader#{}: {e:?}", r.name()))
                .ok()
                .map(|t| token::Token::new(t, Provenance::Hardware))
        })
    }

    /// Return a software [`token::Token`]
    pub async fn get_soft_token(&self) -> token::Token {
        let t = self.0.get_soft_token().await;
        token::Token::new(t, Provenance::Software)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FindServiceError {
    #[error("cannot find service")]
    FindError(JsValue),
    #[error("invalid service challenge value: {}", .0)]
    InvalidChallenge(hex::FromHexError),
    #[error("invalid service cryptogram value: {}", .0)]
    InvalidCryptogram(hex::FromHexError),
}

pub struct ServiceResponse {
    /// A challenge that need to be signed by the server.
    pub challenge: Vec<u8>,
    /// The signature of the provided challenge.
    pub cryptogram: Vec<u8>,
    /// The ID of the public key to use to verify the signature of the provided challenge.
    pub key_id: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateEnvironmentError {
    #[error("cannot create environment")]
    CreateError(JsValue),
}

/// From where the object come from.
///
/// Used to determine which feature is available since there's some limitation on the software
/// side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    Software,
    Hardware,
}
