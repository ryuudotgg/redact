use std::ffi::{CStr, c_char, c_void};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

use crate::host::{Buffer, Host, HostApi, Level};
use crate::placeholder::Key;
use crate::plugin::Plugin;
use crate::protocol;
use crate::vault::Vault;

const ABI_VERSION: u32 = 1;

type PluginCall = unsafe extern "C" fn(*const c_char, *const u8, usize, *mut Buffer) -> i32;
type PluginFree = unsafe extern "C" fn(*mut c_void, usize);
type PluginShutdown = unsafe extern "C" fn();

#[repr(C)]
pub struct PluginApi {
    abi_version: u32,
    call: Option<PluginCall>,
    free_buffer: Option<PluginFree>,
    shutdown: Option<PluginShutdown>,
}

static PLUGIN: RwLock<Option<Arc<Plugin>>> = RwLock::new(None);
static VAULT: LazyLock<Arc<Vault>> = LazyLock::new(|| Arc::new(Vault::new(Key::random())));

#[unsafe(no_mangle)]
unsafe extern "C" fn cliproxy_plugin_init(host: *const HostApi, plugin: *mut PluginApi) -> i32 {
    if host.is_null() || plugin.is_null() {
        return 1;
    }

    let started = panic::catch_unwind(|| {
        let instance = Arc::new(Plugin::new(Host::new(host), Arc::clone(&VAULT)));
        *PLUGIN.write().unwrap_or_else(PoisonError::into_inner) = Some(instance);
        let reporter = Host::new(host);
        panic::set_hook(Box::new(move |info| {
            let location = info.location().map(ToString::to_string).unwrap_or_default();
            reporter.log(
                Level::Error,
                "redact panicked",
                serde_json::json!({ "location": location }),
                "",
            );
        }));
    });

    if started.is_err() {
        return 1;
    }

    let api = PluginApi {
        abi_version: ABI_VERSION,
        call: Some(call),
        free_buffer: Some(free_buffer),
        shutdown: Some(shutdown),
    };

    unsafe { plugin.write(api) };
    0
}

unsafe extern "C" fn call(
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut Buffer,
) -> i32 {
    if response.is_null() {
        return 1;
    }

    let reply = panic::catch_unwind(AssertUnwindSafe(|| {
        let method = if method.is_null() {
            ""
        } else {
            unsafe { CStr::from_ptr(method) }
                .to_str()
                .unwrap_or_default()
        };

        let request = if request.is_null() || request_len == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(request, request_len) }
        };

        let instance = PLUGIN
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();

        let reply = match instance {
            Some(instance) => instance.call(method, request),
            None => protocol::error("not_initialized", "redact is not initialized"),
        };

        serde_json::to_vec(&reply).expect("a JSON value serializes")
    }));

    let bytes = reply
        .unwrap_or_else(|_| {
            br#"{"ok":false,"error":{"code":"internal","message":"redact failed"}}"#.to_vec()
        })
        .into_boxed_slice();

    let len = bytes.len();
    unsafe {
        response.write(Buffer {
            ptr: Box::into_raw(bytes).cast(),
            len,
        });
    };

    0
}

unsafe extern "C" fn free_buffer(ptr: *mut c_void, len: usize) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr.cast::<u8>(), len)) });
    }
}

unsafe extern "C" fn shutdown() {
    let _ = panic::catch_unwind(|| {
        PLUGIN
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    });
}
