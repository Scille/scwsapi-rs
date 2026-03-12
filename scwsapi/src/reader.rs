use std::ops::Deref;

pub struct Reader(scwsapi_sys::reader::Reader);

impl Deref for Reader {
    type Target = scwsapi_sys::reader::Reader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<scwsapi_sys::reader::Reader> for Reader {
    fn from(value: scwsapi_sys::reader::Reader) -> Self {
        Self(value)
    }
}
