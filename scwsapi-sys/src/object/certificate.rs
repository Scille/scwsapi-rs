use std::fmt::Display;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum InvalidTrustStatus {
    NotTimeValid = "notTimeValid",
    NotTimeNested = "notTimeNested",
    Revoked = "revoked",
    RevocationStatusUnknown = "revocationStatusUnknown",
    RevocationOffline = "revocationOffline",
    SignatureInvalid = "signatureInvalid",
    InvalidUsage = "invalidUsage",
    UntrustedRoot = "untrustedRoot",
    CyclicChain = "cyclicChain",
    PartialChain = "partialChain",
    CtlNotTimeValid = "ctlNotTimeValid",
    CtlSignatureInvalid = "ctlSignatureInvalid",
    CtlInvalidUsage = "ctlInvalidUsage",
    InvalidExtension = "invalidExtension",
    InvalidPolicyConstraints = "invalidPolicyConstraints",
    InvalidBasicConstraints = "invalidBasicConstraints",
    InvalidNameConstraints = "invalidNameConstraints",
    UnsupportedNameConstraint = "unsupportedNameConstraint",
    UndefinedNameConstraint = "undefinedNameConstraint",
    ForbiddenNameConstraint = "forbiddenNameConstraint",
    ExcludedNameConstraint = "excludedNameConstraint",
    NoIssuanceChainPolicy = "noIssuanceChainPolicy",
    NotSupportedCriticalExtension = "notSupportedCriticalExtension",
    Unknown = "unknown",
}

impl Display for InvalidTrustStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

#[wasm_bindgen]
extern "C" {
    /// [SCWS.Certificate](https://idopte.fr/scwsapi/javascript/2_API/objects.html#certificate-objects)
    #[wasm_bindgen(extends = super::Object)]
    #[derive(Debug, Clone)]
    pub type Certificate;

    #[wasm_bindgen(method, getter, js_name = "ckId")]
    pub fn ck_id(this: &Certificate) -> String;

    /// Is the certificate a root certificate (issuer and subject similar).
    #[wasm_bindgen(method, getter)]
    pub fn root(this: &Certificate) -> bool;

    #[wasm_bindgen(method, getter, js_name = "notBefore")]
    pub fn not_before(this: &Certificate) -> String;

    #[wasm_bindgen(method, getter, js_name = "notAfter")]
    pub fn not_after(this: &Certificate) -> String;

    #[wasm_bindgen(method, js_name = "getDetails")]
    pub async fn get_details(this: &Certificate) -> JsValue;

    /// Retrieves the PEM-encoded value of the certificate.
    #[wasm_bindgen(method, js_name = "getValue")]
    pub async fn get_value(this: &Certificate) -> js_sys::JsString;

    /// Checks the validity of the certificate and retrieves detailed trust information.
    #[wasm_bindgen(catch, method, js_name = "getTrust")]
    pub async fn get_trust(this: &Certificate) -> Result<CertificateTrust, JsValue>;

    #[derive(Debug, Clone)]
    pub type CertificateTrust;

    /// Either the "ok" string if the certificate is valid according to the operating system criterias,
    /// or an array of strings indicating the (possibly multiple) reasons why the certificate validity checks failed.
    #[wasm_bindgen(method, getter, js_name = "trustStatus")]
    pub fn status(this: &CertificateTrust) -> JsValue;

    #[wasm_bindgen(method, getter)]
    pub fn usages(this: &CertificateTrust) -> Vec<CertificateUsage>;

    #[wasm_bindgen(method, getter, js_name = "certPath")]
    pub fn cert_path(this: &CertificateTrust) -> Vec<Certificate>;

    pub type CertificateUsage;

    #[wasm_bindgen(method, getter)]
    pub fn oid(this: &CertificateUsage) -> String;

    #[wasm_bindgen(method, getter, js_name = "shortName")]
    pub fn short_name(this: &CertificateUsage) -> String;

    #[wasm_bindgen(method, getter, js_name = "longName")]
    pub fn long_name(this: &CertificateUsage) -> String;
}
