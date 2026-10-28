use std::ffi::{c_char, c_void};
use std::ptr;

use serde_json::{Value, json};

#[repr(C)]
pub struct Buffer {
    pub ptr: *mut u8,
    pub len: usize,
}

pub type HostCall =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize, *mut Buffer) -> i32;
pub type HostFree = unsafe extern "C" fn(*mut c_void, usize);

#[repr(C)]
pub struct HostApi {
    pub abi_version: u32,
    pub host_ctx: *mut c_void,
    pub call: Option<HostCall>,
    pub free_buffer: Option<HostFree>,
}

#[derive(Clone, Copy)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

pub struct Host {
    api: *const HostApi,
}

// SAFETY: CPA never frees the host API and accepts callbacks from any thread.
unsafe impl Send for Host {}
unsafe impl Sync for Host {}

impl Host {
    pub fn new(api: *const HostApi) -> Self {
        Self { api }
    }

    #[cfg(test)]
    pub fn detached() -> Self {
        Self { api: ptr::null() }
    }

    pub fn log(&self, level: Level, message: &str, fields: Value, callback: &str) {
        let level = match level {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        };

        let mut fields = fields;
        if let Some(fields) = fields.as_object_mut() {
            fields.insert("plugin".to_owned(), json!("redact"));
        }

        let request = json!({ "level": level, "message": message, "fields": fields, "host_callback_id": callback });
        self.call(
            c"host.log".as_ptr(),
            &serde_json::to_vec(&request).expect("a JSON value serializes"),
        );
    }

    fn call(&self, method: *const c_char, request: &[u8]) {
        let Some(api) = (unsafe { self.api.as_ref() }) else {
            return;
        };
        let (Some(call), Some(free)) = (api.call, api.free_buffer) else {
            return;
        };

        let mut response = Buffer {
            ptr: ptr::null_mut(),
            len: 0,
        };

        unsafe {
            call(
                api.host_ctx,
                method,
                request.as_ptr(),
                request.len(),
                &raw mut response,
            );

            if !response.ptr.is_null() {
                free(response.ptr.cast(), response.len);
            }
        }
    }
}
