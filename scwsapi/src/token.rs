use std::ops::Deref;

pub struct Token {
    handle: scwsapi_sys::token::Token,
    provenance: crate::Provenance,
}

impl Deref for Token {
    type Target = scwsapi_sys::token::Token;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Token {
    pub(crate) fn new(handle: scwsapi_sys::token::Token, provenance: crate::Provenance) -> Self {
        Self { handle, provenance }
    }

    /// List the objects present in the token
    ///
    /// > [!NOTE]
    /// > Some objects need to have their pin unlocked to be visible.
    pub async fn iter_objects(&self) -> impl Iterator<Item = crate::object::Object> {
        let result = wasm_bindgen_futures::JsFuture::from(self.handle.get_objects())
            .await
            .expect("getObjects() Promise rejected");
        js_sys::Array::from(&result)
            .iter()
            .filter_map(|obj| {
                use wasm_bindgen::JsCast as _;

                log::trace!("Found object: {obj:?}");
                let obj = obj.unchecked_into::<scwsapi_sys::object::Object>();
                crate::object::Object::try_from((obj, self.provenance))
                    .inspect_err(|obj| log::warn!("Unsupported object {obj:?}"))
                    .ok()
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}
