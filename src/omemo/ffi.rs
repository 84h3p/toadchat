use std::ffi::{c_char, c_uchar};
use std::ptr;

#[repr(C)]
pub struct OmoContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct OmemoBundle {
    pub device_id: u32,
    pub identity_key: [u8; 32],
    pub signed_pre_key: [u8; 32],
}

#[repr(C)]
pub struct OmemoMessage {
    pub sid: u32,
    pub body: [u8; 256],
    pub body_len: usize,
}

unsafe extern "C" {
    pub fn omemo_context_create() -> *mut OmoContext;
    pub fn omemo_context_destroy(ctx: *mut OmoContext);
    pub fn omemo_bundle_create(ctx: *mut OmoContext, bundle: *mut OmemoBundle, device_id: u32) -> i32;
    pub fn omemo_encrypt(
        ctx: *mut OmoContext,
        plaintext: *const c_char,
        plaintext_len: usize,
        out: *mut c_uchar,
        out_capacity: usize,
        out_len: *mut usize,
    ) -> i32;
    pub fn omemo_decrypt(
        ctx: *mut OmoContext,
        ciphertext: *const c_uchar,
        ciphertext_len: usize,
        out: *mut c_char,
        out_capacity: usize,
        out_len: *mut usize,
    ) -> i32;
    pub fn omemo_message_create(
        ctx: *mut OmoContext,
        plaintext: *const c_char,
        plaintext_len: usize,
        message: *mut OmemoMessage,
    ) -> i32;
}

#[derive(Debug, Clone)]
pub struct FfiError {
    pub code: i32,
}

pub struct OmemoFfiContext {
    ptr: *mut OmoContext,
}

impl OmemoFfiContext {
    pub fn new() -> Result<Self, FfiError> {
        let ptr = unsafe { omemo_context_create() };
        if ptr.is_null() {
            return Err(FfiError { code: -1 });
        }
        Ok(Self { ptr })
    }

    pub fn generate_bundle(&self, device_id: u32) -> Result<OmemoBundle, FfiError> {
        let mut bundle = OmemoBundle {
            device_id: 0,
            identity_key: [0; 32],
            signed_pre_key: [0; 32],
        };
        let rc = unsafe { omemo_bundle_create(self.ptr, &mut bundle, device_id) };
        if rc != 0 {
            return Err(FfiError { code: rc });
        }
        Ok(bundle)
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, FfiError> {
        let bytes = plaintext.as_bytes();
        let mut out = vec![0u8; bytes.len().max(1)];
        let mut out_len = 0usize;
        let rc = unsafe {
            omemo_encrypt(
                self.ptr,
                bytes.as_ptr().cast(),
                bytes.len(),
                out.as_mut_ptr(),
                out.capacity(),
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(FfiError { code: rc });
        }
        out.truncate(out_len);
        Ok(out)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String, FfiError> {
        let mut out = vec![0i8; ciphertext.len().max(1)];
        let mut out_len = 0usize;
        let rc = unsafe {
            omemo_decrypt(
                self.ptr,
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr().cast(),
                out.len(),
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(FfiError { code: rc });
        }
        let bytes: Vec<u8> = out.into_iter().take(out_len).map(|byte| byte as u8).collect();
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

impl Drop for OmemoFfiContext {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { omemo_context_destroy(self.ptr) };
            self.ptr = ptr::null_mut();
        }
    }
}
