use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReaderStatus {
    /// Indicates the reader has been removed (unplugged from the computer).
    Unavailable = "unavailable",

    /// The inserted card is mute (no answer on reset), the connection is therefore impossible.
    Mute = "mute",

    /// The reader is being used in exclusive mode by another process, the connection is impossible
    /// yet.
    Exclusive = "exclusive",

    /// The reader is in a normal state (whether a card is inserted or not).
    Ok = "ok",
}

#[wasm_bindgen]
extern "C" {
    /// Represents a smart card reader (either a physical, hardware reader, or a virtual smart card reader).
    ///
    /// [SCWS.Reader](https://idopte.fr/scwsapi/javascript/2_API/readerstokens.html#SCWS.Reader)
    pub type Reader;

    /// The name of the reader.
    #[wasm_bindgen(method, getter)]
    pub fn name(this: &Reader) -> String;

    /// Status of the reader.
    #[wasm_bindgen(method, getter)]
    pub fn status(this: &Reader) -> ReaderStatus;

    /// Connects to the card inserted in the reader
    #[wasm_bindgen(method, catch)]
    pub async fn connect(this: &Reader) -> Result<crate::token::Token, JsValue>;
}
