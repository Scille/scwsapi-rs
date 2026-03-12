use js_sys::JsString;
use wasm_bindgen::prelude::*;

pub mod object;
pub mod pin;
pub mod reader;
pub mod token;

// We set a placeholder path `@lib_scwsapi.js` that should be overwritten by configuring your
// webapp bundler to alias that path to the true path of `scwsapi.js`.
#[wasm_bindgen(module = "@lib_scwsapi.js")]
extern "C" {
    #[wasm_bindgen(thread_local_v2)]
    pub static SCWS: Scws;

    #[derive(Clone)]
    pub type Scws;

    #[wasm_bindgen(method, getter)]
    pub fn version(this: &Scws) -> String;

    #[wasm_bindgen(method, getter)]
    pub fn readers(this: &Scws) -> Vec<reader::Reader>;

    /// Attempts to contact the local SCWS service.
    ///
    /// The ports on which the service can potentially be listening are scanned, and the first from which a consistent answer can be obtained is selected.
    /// In order to authenticate the local SCWS service, a random challenge should be given as a parameter.
    /// The local service will then sign it with its private key, and return the corresponding cryptogram that must be used to verify signature, using the corresponding Idopte public key.
    #[wasm_bindgen(catch, method, structural, js_name = "findService")]
    pub async fn find_service(
        this: &Scws,
        webapp_cert: &str,
        challenge: &str,
    ) -> Result<ServiceResponse, JsValue>;

    /// Creates the working environment on the SCWS side. Required before any operation.
    ///
    /// Internally calls [`SCWS::update_reader_list`] (thus initializing the `SCWS.readers` array),
    /// and starts monitoring smart card reader events.
    #[wasm_bindgen(catch, method, structural, js_name = "createEnvironment")]
    pub async fn create_environment(this: &Scws, signature: &str) -> Result<(), JsValue>;

    /// Fills in or forces the update of the `SCWS.readers` array.
    ///
    /// If updates are made to the reader list within the processing, the appropriate event callbacks are called.
    /// The resulting value is the updated `SCWS.readers` array itself.
    #[wasm_bindgen(method, structural, js_name = "updateReaderList")]
    pub async fn update_reader_list(this: &Scws) -> Vec<reader::Reader>;

    /// The software token is a virtual cryptographic token containing the certificates and keys that are available on the local machine.
    /// On Windows, the objects comes from the contents of the “Personal” certificate store.
    /// On MacOS, the objects come from the contents of the “Session” keychain. On Linux, this function is currently unavailable.
    #[wasm_bindgen(method, structural, js_name = "getSoftToken")]
    pub async fn get_soft_token(this: &Scws) -> token::Token;

    pub type ServiceResponse;

    /// Hexadecimal string containing the random challenge that must be used to compute the remote server signature,
    /// prior to calling [`Scws::create_environment`].
    #[wasm_bindgen(method, structural)]
    pub fn challenge(this: &ServiceResponse) -> JsString;

    /// Hexadecimal string containing the cryptogram to verify (the challenge given as input signed by SCWS local service private key).
    #[wasm_bindgen(method, structural)]
    pub fn cryptogram(this: &ServiceResponse) -> JsString;

    /// Integer corresponding to the index of the public key to use among the keys in the IdoptePublicKeys file (provided by Idopte).
    #[wasm_bindgen(method, structural)]
    pub fn key_id(this: &ServiceResponse) -> usize;
}
