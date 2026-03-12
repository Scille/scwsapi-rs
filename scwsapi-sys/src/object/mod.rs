mod certificate;
mod key;

use std::fmt::Debug;

pub use certificate::*;
pub use key::*;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug)]
pub enum ObjectType {
    Certificate = "certificate",
    PublicKey = "publicKey",
    PrivateKey = "privateKey",
    DataContainer = "dataContainer",
}

#[wasm_bindgen]
extern "C" {
    /// [SCWS.Object](https://idopte.fr/scwsapi/javascript/2_API/objects.html#SCWS.Object)
    #[derive(Clone)]
    pub type Object;

    /// The type of the object.
    #[wasm_bindgen(method, getter, js_name = "type")]
    pub fn ty(this: &Object) -> ObjectType;

    /// Identifier corresponding to the hexadecimal representation of the `CKA_ID` attribute of the
    /// object, as seen by the PKCS#11 interface.
    ///
    /// This value can be used to match keys and certificates that are linked together (belong in the
    /// same container).
    ///
    /// Unavailable for data container objects.
    #[wasm_bindgen(method, getter, js_name = "ckId")]
    fn ck_id(this: &Object) -> Option<String>;

    /// Label string, corresponding to the CKA_LABEL attribute of the object, as seen by the PKCS#11 interface.
    #[wasm_bindgen(method, getter, js_name = "ckLabel")]
    pub fn ck_label(this: &Object) -> String;

    /// Container ([`crate::token::Token`] or `CertStore`) from which the object has been retrieved.
    #[wasm_bindgen(method, getter)]
    pub fn parent(this: &Object) -> crate::token::Token;

    /// Index of the PIN which grants access to the object.
    /// This corresponds to the index within the [`crate::token::Token::pins()`] array.
    ///
    /// For public objects (certificates and public keys),
    /// it is the PIN which grants access to the corresponding private key (association is determined by the [`Object::ck_id()`] attribute).
    #[wasm_bindgen(method, getter)]
    pub fn pin_number(this: &Object) -> usize;

    /// [SCWS.DataContainer](https://idopte.fr/scwsapi/javascript/2_API/objects.html#data-container-objects)
    #[wasm_bindgen(extends = Object)]
    pub type DataContainer;

    /// Name of the application that manage the container
    #[wasm_bindgen(method, getter)]
    pub fn application(this: &DataContainer) -> String;

    /// The data of the container
    #[wasm_bindgen(method, getter)]
    pub async fn getValue(this: &DataContainer) -> js_sys::Uint8Array;
}

impl Debug for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Object")
            .field("id", &self.ck_id())
            .field("label", &self.ck_label())
            .field("type", &self.ty())
            .finish_non_exhaustive()
    }
}
