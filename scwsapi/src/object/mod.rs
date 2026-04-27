mod certificate;
mod key;

pub use certificate::*;
pub use key::*;
use wasm_bindgen::JsValue;

/// A [`crate::token::Token`] object
pub enum Object {
    Certificate(Certificate),
    PublicKey(PublicKey),
    PrivateKey(PrivateKey),
    DataContainer(DataContainer),
}

impl TryFrom<(scwsapi_sys::object::Object, crate::Provenance)> for Object {
    type Error = scwsapi_sys::object::Object;

    fn try_from(
        (value, provenance): (scwsapi_sys::object::Object, crate::Provenance),
    ) -> Result<Self, Self::Error> {
        let ty = value.ty();
        match ty {
            scwsapi_sys::object::ObjectType::Certificate => {
                Ok(Self::Certificate(Certificate::new(
                    scwsapi_sys::object::Certificate::from(JsValue::from(value)),
                    provenance,
                )))
            }
            scwsapi_sys::object::ObjectType::PublicKey => Ok(Self::PublicKey(PublicKey::new(
                scwsapi_sys::object::Key::from(JsValue::from(value)),
                provenance,
            ))),
            scwsapi_sys::object::ObjectType::PrivateKey => Ok(Self::PrivateKey(PrivateKey::new(
                scwsapi_sys::object::Key::from(JsValue::from(value)),
                provenance,
            ))),
            scwsapi_sys::object::ObjectType::DataContainer => {
                Ok(Self::DataContainer(DataContainer::new(
                    scwsapi_sys::object::DataContainer::from(JsValue::from(value)),
                    provenance,
                )))
            }
            _ => Err(value),
        }
    }
}

pub struct DataContainer {
    #[expect(dead_code)]
    handle: scwsapi_sys::object::DataContainer,
    pub provenance: crate::Provenance,
}

impl DataContainer {
    fn new(handle: scwsapi_sys::object::DataContainer, provenance: crate::Provenance) -> Self {
        Self { handle, provenance }
    }
}
