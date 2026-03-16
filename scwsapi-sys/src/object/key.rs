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
    pub fn ck_id(this: &Key) -> String;

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
    ///
    /// The decryption algorithm to use as a javascript object by default if nothing is provided PKCS#1 will be used.
    /// - for **RSA OAEP** algorithm should be a javascript object containing:
    ///     - "type" : "oaep"
    ///     - "hashAlg" : the hash algorithm, values can be one among "sha1", "sha224", "sha256", "sha384", "sha512"
    ///     - "mgf" : the MGF for the OAEP, values can be one among "sha1", "sha224", "sha256", "sha384", "sha512"
    /// - for **RSA RAW**
    ///     - "type" : "raw"
    /// - for PKCS1:
    ///     - "type" : "pkcs1"
    #[wasm_bindgen(catch, method)]
    pub async fn decrypt(
        this: &Key,
        ciphertext: &[u8],
        algorithm: Option<JsValue>,
    ) -> Result<js_sys::ArrayBuffer, JsValue>;
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RsaPssPadding {
    pub mgf: RsaPssMaskType,
    pub salt_len: usize,
}

impl TryFrom<&RsaPssPadding> for JsValue {
    type Error = serde_wasm_bindgen::Error;

    fn try_from(value: &RsaPssPadding) -> Result<Self, Self::Error> {
        serde_wasm_bindgen::to_value(value)
    }
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RsaPssMaskType {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Pkcs1HashType {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<&Pkcs1HashType> for JsValue {
    type Error = serde_wasm_bindgen::Error;

    fn try_from(value: &Pkcs1HashType) -> Result<Self, Self::Error> {
        serde_wasm_bindgen::to_value(value)
    }
}

/// Allow configuring the decryption algorithm used by [`Key::decrypt`]
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum RsaEncryptionConfig {
    #[serde(rename_all = "camelCase")]
    Oaep {
        hash_alg: RsaOaepHashAlg,
        mgf: RsaOaepMaskType,
    },
    Raw,
    Pkcs1,
}

impl TryFrom<&RsaEncryptionConfig> for JsValue {
    type Error = serde_wasm_bindgen::Error;

    fn try_from(value: &RsaEncryptionConfig) -> Result<Self, Self::Error> {
        serde_wasm_bindgen::to_value(value)
    }
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RsaOaepHashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum RsaOaepMaskType {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}
