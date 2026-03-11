use std::fmt::Debug;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// Represents a PIN that protects smart card contents.
    ///
    /// [`SCWS.Pin`](https://idopte.fr/scwsapi/javascript/2_API/pins.html#SCWS.Pin)
    pub type Pin;

    /// The [`crate::token::Token`] object this PIN belongs to.
    #[wasm_bindgen(method, getter)]
    pub fn token(this: &Pin) -> crate::token::Token;

    /// The PIN label. Can be undefined if the card has a single PIN without explicit label defined.
    #[wasm_bindgen(method, getter)]
    pub fn label(this: &Pin) -> Option<String>;

    /// Number of remaining tries for the PIN verification. Can be undefined if the information is unavailable.
    #[wasm_bindgen(method, getter, js_name = "remainingTries")]
    pub fn remaining_tries(this: &Pin) -> Option<usize>;

    /// Boolean indicating if the PIN has been successfully verified (access to the private objects is granted).
    #[wasm_bindgen(method, getter)]
    pub fn validated(this: &Pin) -> bool;

    /// Starts a PIN cache session.
    ///
    /// On the next call to [`Pin::login()`] with false value, the value of the PIN will be saved for use on subsequent calls.
    ///
    /// Signatures with non-repudiable keys (see `SCWS.Key.alwaysAuthenticate`) through [`crate::object::Key::sign()`]
    /// and [`crate::object::Key::hashAndSign()`] can also be repeated without an explicit call to [`Pin::login()`].
    /// In this case, the login will be made implicitly if the user is no longer logged in.
    #[wasm_bindgen(method, js_name = "startAutoLogin")]
    pub async fn start_auto_login(this: &Pin, counter: Option<usize>);

    /// Stops a PIN cache session.
    ///
    /// The value of the PIN is removed from the cache.
    /// From this point, an explicit call to [`Pin::login()`] is required before any signature.
    ///
    /// On the next call to [`Pin::login()`] with `false` value parameter, the PIN value will not be saved anymore.
    #[wasm_bindgen(method, js_name = "stopAutoLogin")]
    pub async fn stop_auto_login(this: &Pin);

    /// Verifies the PIN.
    ///
    /// The value parameter can have the following values/types:
    ///
    /// - the PIN value as a string.
    /// - a `SCWS.CredentialValue` object.
    ///   From 6.23.1.0 middleware version, a SCWS.CredentialValue object can be created using Pin.requestCredential().
    /// - `null` or undefined if a protected authentication path exists (see `Token.protectedAuthPath`).
    /// - `false`, in which case the pin entering is delegated to the middleware through its own graphical interface,
    ///   which is the recommended option: this guarantees that the pin does not go through to the browser.
    ///
    /// The state parameter can take the following values:
    ///
    /// - `true` indicating that the verification operation must be made against the security officer (administrator or unblocking) PIN. Otherwise, targets the user PIN.
    /// - a `SCWS.CredentialState` to use with `Pin.requestCredential()`.
    ///   In this case, given state will be updated by this function call.
    ///   A further call of `Pin.requestCredential()` with the state parameter will display a PIN dialog with updated information.
    #[wasm_bindgen(catch, method)]
    pub async fn login(this: &Pin, value: JsValue, state: JsValue) -> Result<(), JsValue>;

    /// Resets the verified status of the PIN (cancels a call to [`Pin::login()`]).
    #[wasm_bindgen(method)]
    pub async fn logout(this: &Pin);
}

impl Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pin")
            .field("label", &self.label())
            .field("remaining_tries", &self.remaining_tries())
            .field("validated", &self.validated())
            .finish_non_exhaustive()
    }
}
