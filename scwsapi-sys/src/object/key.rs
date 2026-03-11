use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum KeyType {
    Public = "publicKey",
    Private = "privateKey",
}

#[wasm_bindgen]
pub enum Algorithm {
    Rsa = "RSA",
    Ecdsa = "ECDSA",
}

#[wasm_bindgen]
extern "C" {
    /// [SCWS.Key](https://idopte.fr/scwsapi/javascript/2_API/objects.html#SCWS.Key)
    #[wasm_bindgen(extends = super::Object)]
    #[derive(Debug, Clone)]
    pub type Key;

    #[wasm_bindgen(method, getter, js_name = "ckId")]
    fn ck_id(this: &Key) -> String;

    #[wasm_bindgen(method, getter, js_name = "keyType")]
    pub fn key_type(this: &Key) -> KeyType;

    #[wasm_bindgen(method, getter, js_name = "algorithmName")]
    pub fn algorithm_name(this: &Key) -> Algorithm;

    #[wasm_bindgen(method, getter, js_name = "getDetails")]
    pub async fn get_details(this: &Key) -> JsValue;

    /// Signs the provided hash using a private key. For RSA keys, the operation will use PKCS#1 padding or PSS padding depending on given algorithm parameter. For EC keys, the returned signature is in RAW format.
    ///
    /// The algorithm parameter indicates the algorithm to use and can take the following values:
    ///
    /// - for RSA PKCS#1 padding, the algorithm of the hash needs to be indicated if the OID needs to be added within the signature block.
    ///   The algorithm parameter can take the following values:
    ///   - null or undefined: The hash data will be signed as provided.
    ///     Not available for qualified signature keys.
    ///   - `sha1`, `sha256`, `sha384` or `sha512`: The corresponding OID will be prepended.
    ///     Not available for qualified signature keys.
    ///   - `sha1-partial` or `sha256-partial`: The hash must be provided as a partial hash block (containing intermediate hash values) as defined by the IAS specifications.
    ///     The hash will be finalized by the card and the corresponding OID will be prepended.
    ///     Available only for qualified signature keys.
    /// - for RSA PSS padding, algorithm parameter is a JavaScript object with the following attributes:
    ///   - `mgf`: mask generation function to use as a string.
    ///     Can be `sha1`, `sha256`, `sha384` or `sha512`.
    ///   - `saltLen`: salt length to use as an integer.
    ///
    /// Note that the `Key.partialHash` property can be used to check whether the key is a qualified signature key that requires partial hashing.
    #[wasm_bindgen(catch, method)]
    pub async fn sign(
        this: &Key,
        hash: &[u8],
        algorithm: Option<JsValue>,
    ) -> Result<js_sys::ArrayBuffer, JsValue>;

    /// Decrypts the provided data using a private key. The operation will use PKCS#1 padding.
    #[wasm_bindgen(catch, method)]
    pub async fn decrypt(this: &Key, ciphertext: &[u8]) -> Result<js_sys::ArrayBuffer, JsValue>;
}
