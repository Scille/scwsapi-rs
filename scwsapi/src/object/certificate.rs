use std::ops::Deref;

use scwsapi_sys::object::InvalidTrustStatus;
use wasm_bindgen::{JsCast, JsValue};

use crate::{
    Provenance,
    object::{Object, PrivateKey},
};

pub struct Certificate {
    handle: scwsapi_sys::object::Certificate,
    pub provenance: crate::Provenance,
}

impl Deref for Certificate {
    type Target = scwsapi_sys::object::Certificate;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Certificate {
    pub(super) fn new(
        handle: scwsapi_sys::object::Certificate,
        provenance: crate::Provenance,
    ) -> Self {
        Self { handle, provenance }
    }

    pub async fn get_der(
        &self,
    ) -> Result<rustls_pki_types::CertificateDer<'static>, rustls_pki_types::pem::Error> {
        use rustls_pki_types::pem::PemObject;
        let raw_pem = self.handle.get_value().await;
        let pem = String::from(raw_pem);
        rustls_pki_types::CertificateDer::from_pem_slice(pem.as_bytes())
    }

    /// Try to request the associated private key to the certificate.
    ///
    /// ⚠️ May request the certificate pin to be able to find the key.
    pub async fn request_private_key(&self) -> Result<Option<PrivateKey>, RequestPrivateKeyError> {
        // Requesting a pin is needed to be able to list the private key associated with the
        // certificate.
        let Some(pin) = self.get_pin() else {
            log::warn!("Missing pin for certificate");
            return Ok(None);
        };

        // Delegate login if PIN is not already validated (e.g.: cached from previous call,
        // software token)
        if !pin.validated() {
            log::debug!("Delegating login to system ({pin:?})");
            pin.login(false.into(), JsValue::undefined())
                .await
                .map_err(RequestPrivateKeyError::LoginError)?;
        }

        Ok(self.get_private_key().await)
    }

    fn get_pin(&self) -> Option<scwsapi_sys::pin::Pin> {
        let parent = self.parent();
        let mut pins = parent.pins();
        let pin_number = self.pin_number();
        if pins.len() >= pin_number {
            Some(pins.swap_remove(pin_number))
        } else {
            None
        }
    }

    fn parent(&self) -> crate::token::Token {
        let t = self.handle.parent();
        crate::token::Token::new(t, self.provenance)
    }

    async fn get_private_key(&self) -> Option<PrivateKey> {
        let ck_id = self.handle.ck_id();
        log::debug!("Looking for a private with the following ck_id: {ck_id}");
        self.parent()
            .iter_objects()
            .await
            .filter_map(|obj| {
                if let Object::PrivateKey(key) = obj {
                    Some(key)
                } else {
                    None
                }
            })
            .find(|k| k.ck_id() == ck_id)
    }

    pub async fn get_trust(&self) -> Result<CertificateTrust, JsValue> {
        self.handle
            .get_trust()
            .await
            .map(|handle| CertificateTrust {
                handle,
                provenance: self.provenance,
            })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RequestPrivateKeyError {
    #[error("login error while requesting private key")]
    LoginError(JsValue),
}

pub struct CertificateTrust {
    handle: scwsapi_sys::object::CertificateTrust,
    provenance: Provenance,
}

impl Deref for CertificateTrust {
    type Target = scwsapi_sys::object::CertificateTrust;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl CertificateTrust {
    /// Return the trust status of the certificate
    ///
    /// ## Result
    ///
    /// When the certificate is not trusted, it return the reasons as error
    pub fn status(&self) -> Result<(), Vec<InvalidTrustStatus>> {
        let raw_status = self.handle.status();

        if matches!(raw_status.dyn_ref::<js_sys::JsString>(), Some(s) if s == "ok") {
            return Ok(());
        }

        Err(raw_status
            .dyn_into::<js_sys::Array>()
            .map(|raw_reasons| {
                raw_reasons
                    .into_iter()
                    .filter_map(|v| InvalidTrustStatus::from_js_value(&v))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn cert_path(&self) -> impl Iterator<Item = Certificate> {
        self.handle
            .cert_path()
            .into_iter()
            .map(|handle| Certificate {
                handle,
                provenance: self.provenance,
            })
    }
}
