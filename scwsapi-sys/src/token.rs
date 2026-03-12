use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// Represents connection to a smart card (or more generally, any cryptographic device). Token objects are obtained by calling the [`crate::reader::Reader::connect()`] method.
    ///
    /// [SCWS.Token](https://idopte.fr/scwsapi/javascript/2_API/readerstokens.html#SCWS.Token)
    #[derive(Debug)]
    pub type Token;

    /// The [`crate::reader::Reader`] object from which this token is issued.
    #[wasm_bindgen(method, getter)]
    pub fn reader(this: &Token) -> crate::reader::Reader;

    /// The token serial number.
    #[wasm_bindgen(method, getter, js_name = "serialNumber")]
    pub fn serial_number(this: &Token) -> String;

    /// The token label.
    #[wasm_bindgen(method, getter)]
    pub fn label(this: &Token) -> String;

    #[wasm_bindgen(method, getter)]
    pub fn pins(this: &Token) -> Vec<crate::pin::Pin>;

    #[wasm_bindgen(method, getter, js_name = "protectedAuthPath")]
    pub fn protected_auth_path(this: &Token) -> bool;

    #[wasm_bindgen(method, js_name = "getObjects")]
    pub async fn get_objects(this: &Token) -> Vec<crate::object::Object>;
    /// Disconnects from the token.
    ///
    /// Must be called when the application terminates or before.
    #[wasm_bindgen(method)]
    pub async fn disconnect(this: &Token);
}
