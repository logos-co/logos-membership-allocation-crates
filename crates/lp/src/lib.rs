use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Duration;

use base64::Engine;
use serde_json::Value;

pub const LIBP2P_MODULE: &str = "libp2p_module";

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn bstr(bytes: &[u8]) -> Value {
    serde_json::json!({ "_bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes) })
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

#[cfg(not(any(test, feature = "test-fake")))]
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    pub struct LpClient {
        _private: [u8; 0],
    }

    pub type LpResultCb = extern "C" fn(ok: c_int, json: *const c_char, user_data: *mut c_void);

    extern "C" {
        pub fn lp_client_create(
            target_module: *const c_char,
            origin_module: *const c_char,
            target_transport_json: *const c_char,
            capability_transport_json: *const c_char,
        ) -> *mut LpClient;
        pub fn lp_invoke(
            client: *mut LpClient,
            method: *const c_char,
            args_json: *const c_char,
            timeout_ms: c_int,
            out_result_json: *mut *mut c_char,
            out_error_json: *mut *mut c_char,
        ) -> c_int;
        pub fn lp_invoke_async(
            client: *mut LpClient,
            method: *const c_char,
            args_json: *const c_char,
            timeout_ms: c_int,
            cb: LpResultCb,
            user_data: *mut c_void,
        ) -> c_int;
        pub fn lp_string_free(s: *mut c_char);
    }

    pub const LP_OK: c_int = 0;
}

#[cfg(any(test, feature = "test-fake"))]
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    pub struct LpClient {
        _private: [u8; 0],
    }

    pub type LpResultCb = extern "C" fn(ok: c_int, json: *const c_char, user_data: *mut c_void);

    pub unsafe fn lp_client_create(
        _t: *const c_char,
        _o: *const c_char,
        _tt: *const c_char,
        _ct: *const c_char,
    ) -> *mut LpClient {
        std::ptr::null_mut()
    }
    pub unsafe fn lp_invoke(
        _c: *mut LpClient,
        _m: *const c_char,
        _a: *const c_char,
        _t: c_int,
        _r: *mut *mut c_char,
        _e: *mut *mut c_char,
    ) -> c_int {
        -3
    }
    pub unsafe fn lp_invoke_async(
        _c: *mut LpClient,
        _m: *const c_char,
        _a: *const c_char,
        _t: c_int,
        _cb: LpResultCb,
        _u: *mut c_void,
    ) -> c_int {
        -3
    }
    pub unsafe fn lp_string_free(_s: *mut c_char) {}

    pub const LP_OK: c_int = 0;
}

struct ClientHandle(*mut ffi::LpClient);
// SAFETY: the wrapped `lp_client*` is never destroyed (nothing in this crate
// calls `lp_client_destroy`), so it is valid for the rest of the process, and
// logos_protocol.h makes handles thread-safe per handle ("calls on one handle
// may be made from any thread"). Moving it to the serve worker is sound.
unsafe impl Send for ClientHandle {}

static CLIENTS: Mutex<Option<HashMap<String, ClientHandle>>> = Mutex::new(None);
static OWNER: OnceLock<ThreadId> = OnceLock::new();

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn create_client(target: &str) -> bool {
    let (Ok(t), Ok(o)) = (CString::new(target), CString::new("core")) else {
        return false;
    };
    // SAFETY: `t` and `o` are NUL-terminated and outlive the call, which borrows
    // its `const char*` inputs only for its duration; NULL transports select the
    // process default. The handle is null-checked below and never destroyed.
    let raw = unsafe {
        ffi::lp_client_create(t.as_ptr(), o.as_ptr(), std::ptr::null(), std::ptr::null())
    };
    if raw.is_null() {
        eprintln!("lp: lp_client_create failed for {target}");
        return false;
    }
    lock(&CLIENTS)
        .get_or_insert_with(HashMap::new)
        .insert(target.to_string(), ClientHandle(raw));
    true
}

pub fn init(targets: &[&str]) {
    let _ = OWNER.set(std::thread::current().id());
    for t in targets {
        create_client(t);
    }
}

fn on_owner_thread() -> bool {
    OWNER
        .get()
        .is_some_and(|id| *id == std::thread::current().id())
}

pub fn ensure_client(target: &str) -> Result<(), String> {
    #[cfg(any(test, feature = "test-fake"))]
    if fake::installed() {
        return Ok(());
    }
    if cached_client(target).is_some() {
        return Ok(());
    }
    if !on_owner_thread() {
        return Err(format!(
            "cannot open lp client for {target} off the owner thread"
        ));
    }
    if create_client(target) {
        Ok(())
    } else {
        Err(format!(
            "lp_client_create failed for {target} (is the module loaded?)"
        ))
    }
}

fn cached_client(target: &str) -> Option<*mut ffi::LpClient> {
    lock(&CLIENTS).as_ref()?.get(target).map(|h| h.0)
}

fn client_ptr(target: &str) -> Option<*mut ffi::LpClient> {
    if let Some(client) = cached_client(target) {
        return Some(client);
    }
    if on_owner_thread() {
        create_client(target);
    }
    cached_client(target)
}

struct AsyncReply {
    tx: std::sync::mpsc::Sender<(bool, String)>,
}

extern "C" fn reply_trampoline(ok: c_int, json: *const c_char, user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    // SAFETY: this trampoline is only passed to `lp_invoke_async` in `call_json`,
    // with `user_data` from `Box::into_raw(Box<AsyncReply>)`. The protocol calls it
    // exactly once per call that returned LP_OK and never for a refused one (which
    // `call_json` reclaims itself), and no client is ever destroyed, so this is the
    // only reclaim of a live box. `AsyncReply` holds only an `mpsc::Sender` (Send),
    // so dropping it on the protocol's thread is sound; if the caller already timed
    // out, only the `send` below fails.
    let reply = unsafe { Box::from_raw(user_data as *mut AsyncReply) };
    let raw = if json.is_null() {
        String::new()
    } else {
        // SAFETY: `json` is non-null (checked above) and, per `lp_result_cb`, a
        // NUL-terminated string valid for the duration of this callback; it is copied
        // out before the callback returns.
        unsafe { CStr::from_ptr(json) }
            .to_string_lossy()
            .into_owned()
    };
    let _ = reply.tx.send((ok != 0, raw));
}

fn err_message(raw: &str) -> String {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| raw.to_string())
}

fn parse_ok(raw: &str) -> Value {
    if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
    }
}

pub enum CallError {
    Failed(String),
    Unanswered(String),
}

impl CallError {
    pub fn into_message(self) -> String {
        match self {
            CallError::Failed(m) | CallError::Unanswered(m) => m,
        }
    }
}

const NOT_RUN_CODES: [&str; 5] = [
    "invalid_arg",
    "invalid_args",
    "object_unavailable",
    "call_failed",
    "unauthorized",
];

fn kind_of(payload: &str) -> fn(String) -> CallError {
    let not_run = serde_json::from_str::<Value>(payload).is_ok_and(|v| {
        v.get("code")
            .and_then(Value::as_str)
            .is_some_and(|code| NOT_RUN_CODES.contains(&code))
    });
    if not_run {
        CallError::Failed
    } else {
        CallError::Unanswered
    }
}

pub fn call_json(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, String> {
    call_json_classified(target, method, args, timeout_ms).map_err(CallError::into_message)
}

pub fn call_json_classified(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, CallError> {
    #[cfg(any(test, feature = "test-fake"))]
    if let Some(r) = fake::intercept(target, method, args) {
        return r.map_err(|payload| kind_of(&payload)(payload));
    }
    let client = client_ptr(target)
        .ok_or_else(|| CallError::Failed(format!("no lp client for {target}")))?;
    let (Ok(method_c), Ok(args_c)) = (CString::new(method), CString::new(args.to_string())) else {
        return Err(CallError::Failed(format!(
            "{method}: args not CString-safe"
        )));
    };

    if on_owner_thread() {
        let mut result_json: *mut c_char = std::ptr::null_mut();
        let mut error_json: *mut c_char = std::ptr::null_mut();
        // SAFETY: `client` is a CLIENTS handle, never destroyed; `method_c` and `args_c`
        // are NUL-terminated and outlive the call; both out-pointers point at locals
        // initialised to null, which the library may set to strings this function then
        // owns and frees below.
        let rc = unsafe {
            ffi::lp_invoke(
                client,
                method_c.as_ptr(),
                args_c.as_ptr(),
                timeout_ms,
                &mut result_json,
                &mut error_json,
            )
        };
        if rc != ffi::LP_OK {
            if error_json.is_null() {
                return Err(CallError::Unanswered(format!("{method}: lp error {rc}")));
            }
            // SAFETY: `error_json` is non-null, NUL-terminated and owned by this function
            // until the `lp_string_free` below; it is copied out first.
            let m = unsafe { CStr::from_ptr(error_json) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `error_json` came from `lp_invoke`, is freed exactly once here and is
            // not read afterwards (`m` is an owned copy).
            unsafe { ffi::lp_string_free(error_json) };
            return Err(kind_of(&m)(m));
        }
        let raw = if result_json.is_null() {
            String::new()
        } else {
            // SAFETY: `result_json` is non-null, NUL-terminated and owned by this function
            // until the `lp_string_free` below; it is copied out first.
            let s = unsafe { CStr::from_ptr(result_json) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `result_json` came from `lp_invoke`, is freed exactly once here and
            // is not read afterwards (`s` is an owned copy).
            unsafe { ffi::lp_string_free(result_json) };
            s
        };
        return Ok(parse_ok(&raw));
    }

    let (tx, rx) = std::sync::mpsc::channel::<(bool, String)>();
    let user_data = Box::into_raw(Box::new(AsyncReply { tx })) as *mut c_void;
    // SAFETY: `client` is a never-destroyed CLIENTS handle and `lp_invoke_async`
    // may be called from any thread; `method_c` and `args_c` are NUL-terminated and
    // outlive the call. On LP_OK `user_data` belongs to the protocol until
    // `reply_trampoline` reclaims it; otherwise it is still ours (see below).
    let rc = unsafe {
        ffi::lp_invoke_async(
            client,
            method_c.as_ptr(),
            args_c.as_ptr(),
            timeout_ms,
            reply_trampoline,
            user_data,
        )
    };
    if rc != ffi::LP_OK {
        // SAFETY: a return other than LP_OK means the call was refused before dispatch
        // and the callback is never invoked (logos_protocol.h, lp_invoke_async), so
        // `user_data` is still the box made above and nothing else frees it.
        drop(unsafe { Box::from_raw(user_data as *mut AsyncReply) });
        return Err(CallError::Failed(format!(
            "{method}: lp_invoke_async dispatch failed rc={rc}"
        )));
    }
    let wait = Duration::from_millis(timeout_ms as u64 + 10_000);
    let (ok, raw) = rx
        .recv_timeout(wait)
        .map_err(|_| CallError::Unanswered(format!("{method}: reply channel timed out")))?;
    if !ok {
        return Err(kind_of(&raw)(format!("{method}: {}", err_message(&raw))));
    }
    Ok(parse_ok(&raw))
}

pub fn call_libp2p(method: &str, args: &Value, timeout_ms: i32) -> Result<Value, String> {
    let v = call_json(LIBP2P_MODULE, method, args, timeout_ms)?;
    let mut env = match v {
        Value::String(s) if !s.is_empty() => {
            serde_json::from_str(&s).map_err(|e| format!("{method}: reply parse: {e}"))?
        }
        other => other,
    };
    if env.is_object() && env.get("success").is_some() {
        let ok = env.get("success").and_then(Value::as_bool).unwrap_or(true);
        if !ok {
            let e = env
                .get("error")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("libp2p call failed");
            return Err(format!("{method}: {e}"));
        }
        return Ok(env.get_mut("value").map(Value::take).unwrap_or(Value::Null));
    }
    Ok(env)
}

pub type NodeCall = fn(&str, &Value, i32) -> Result<Value, String>;

static NODE: OnceLock<NodeCall> = OnceLock::new();

pub fn set_node(call: NodeCall) {
    let _ = NODE.set(call);
}

#[cfg(any(test, feature = "test-fake"))]
pub fn call_node(method: &str, args: &Value, timeout_ms: i32) -> Result<Value, String> {
    let _ = NODE.get();
    call_libp2p(method, args, timeout_ms)
}

#[cfg(not(any(test, feature = "test-fake")))]
pub fn call_node(method: &str, args: &Value, timeout_ms: i32) -> Result<Value, String> {
    match NODE.get() {
        Some(call) => call(method, args, timeout_ms),
        None => Err(format!("{method}: this module runs no libp2p node")),
    }
}

pub fn call_module_json(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, String> {
    call_module_json_classified(target, method, args, timeout_ms).map_err(CallError::into_message)
}

pub fn call_module_json_classified(
    target: &str,
    method: &str,
    args: &Value,
    timeout_ms: i32,
) -> Result<Value, CallError> {
    let v = call_json_classified(target, method, args, timeout_ms)?;
    match v {
        Value::String(s) if !s.is_empty() => serde_json::from_str(&s)
            .map_err(|e| CallError::Failed(format!("{method}: reply parse: {e}"))),
        Value::String(_) => Err(CallError::Failed(format!("{method}: empty reply"))),
        other => Ok(other),
    }
}

pub const PEER_DIRECTION_OUTBOUND: i64 = 1;
const PEERS_TIMEOUT_MS: i32 = 10_000;

fn outbound_peers_through(call: NodeCall) -> Result<usize, String> {
    let v = call(
        "connectedPeers",
        &serde_json::json!([PEER_DIRECTION_OUTBOUND]),
        PEERS_TIMEOUT_MS,
    )?;
    v.as_array()
        .map(Vec::len)
        .ok_or_else(|| format!("connectedPeers: not a peer list: {v}"))
}

pub fn outbound_peers() -> Result<usize, String> {
    outbound_peers_through(call_libp2p)
}

pub fn node_outbound_peers() -> Result<usize, String> {
    outbound_peers_through(call_node)
}

pub fn now_s() -> u64 {
    #[cfg(any(test, feature = "test-fake"))]
    if let Some(t) = fake::now() {
        return t;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn sleep_s(s: u64) {
    #[cfg(any(test, feature = "test-fake"))]
    if fake::advance(s) {
        return;
    }
    std::thread::sleep(Duration::from_secs(s));
}

#[cfg(any(test, feature = "test-fake"))]
pub mod fake {
    use std::cell::RefCell;

    use serde_json::Value;

    pub type Handler = Box<dyn Fn(&str, &str, &Value) -> Result<Value, String> + Send>;

    pub const START_S: u64 = 1_700_000_000;

    struct State {
        handler: Option<Handler>,
        calls: Vec<(String, Value)>,
        now: u64,
    }

    thread_local! {
        static FAKE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    pub fn install(handler: Handler) {
        FAKE.with(|f| {
            *f.borrow_mut() = Some(State {
                handler: Some(handler),
                calls: Vec::new(),
                now: START_S,
            })
        });
    }

    pub fn clear() {
        FAKE.with(|f| *f.borrow_mut() = None);
    }

    pub fn calls() -> Vec<(String, Value)> {
        FAKE.with(|f| {
            f.borrow()
                .as_ref()
                .map(|s| s.calls.clone())
                .unwrap_or_default()
        })
    }

    pub fn methods() -> Vec<String> {
        calls().into_iter().map(|(m, _)| m).collect()
    }

    pub(super) fn installed() -> bool {
        FAKE.with(|f| f.borrow().is_some())
    }

    pub(super) fn now() -> Option<u64> {
        FAKE.with(|f| f.borrow().as_ref().map(|s| s.now))
    }

    pub fn advance(s: u64) -> bool {
        FAKE.with(|f| match f.borrow_mut().as_mut() {
            Some(st) => {
                st.now += s;
                true
            }
            None => false,
        })
    }

    pub(super) fn intercept(
        target: &str,
        method: &str,
        args: &Value,
    ) -> Option<Result<Value, String>> {
        let handler = FAKE.with(|f| {
            let mut g = f.borrow_mut();
            let st = g.as_mut()?;
            st.calls.push((method.to_string(), args.clone()));
            st.handler.take()
        })?;
        let r = handler(target, method, args);
        FAKE.with(|f| {
            if let Some(st) = f.borrow_mut().as_mut() {
                st.handler = Some(handler);
            }
        });
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_failed(e: &CallError) -> bool {
        matches!(e, CallError::Failed(_))
    }

    #[test]
    fn kind_of_classifies_error_payloads() {
        let coded = |code: &str| format!(r#"{{"code":"{code}","message":"m","origin":"o"}}"#);

        for code in NOT_RUN_CODES {
            let e = kind_of(&coded(code))("x".to_string());
            assert!(is_failed(&e), "{code} must classify as Failed");
        }

        let unanswered = [
            coded("timeout"),
            coded("transport_error"),
            coded("some_future_code"),
            r#"{"message":"m","origin":"o"}"#.to_string(),
            r#"{"code":7,"message":"m"}"#.to_string(),
            "invalid_args".to_string(),
            "not json at all".to_string(),
            String::new(),
        ];
        for payload in &unanswered {
            let e = kind_of(payload)("x".to_string());
            assert!(!is_failed(&e), "{payload:?} must classify as Unanswered");
        }

        let method = "do_it";
        let raw = coded("invalid_args");
        let e = kind_of(&raw)(format!("{method}: {}", err_message(&raw)));
        assert!(is_failed(&e));
        assert_eq!(e.into_message(), "do_it: m");

        let raw = coded("timeout");
        let e = kind_of(&raw)(format!("{method}: {}", err_message(&raw)));
        assert!(!is_failed(&e));
        assert_eq!(e.into_message(), "do_it: m");

        let reformatted = format!("{method}: {}", err_message(&coded("invalid_args")));
        assert!(!is_failed(&kind_of(&reformatted)("x".to_string())));
    }
}
