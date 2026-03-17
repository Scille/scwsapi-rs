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
        self.handle
            .get_objects()
            .await
            .into_iter()
            .inspect(|obj| log::trace!("Found object: {obj:?}"))
            .filter_map(|obj| {
                crate::object::Object::try_from((obj, self.provenance))
                    .inspect_err(|obj| log::warn!("Unsupported object {obj:?}"))
                    .ok()
            })
    }
}
