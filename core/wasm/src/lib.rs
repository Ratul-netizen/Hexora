//! # hexora-wasm
//!
//! The sandbox that runs an extension's WebAssembly module. This is the half of the extension
//! system that executes untrusted code, so it is built to make "untrusted" true: the module is
//! instantiated with **no host imports at all**, which means it has no filesystem, no network, no
//! clock and no way to touch the machine — only the linear memory the host reads and writes. A
//! capability an extension was granted is honoured by what the host chooses to pass in and take
//! out, never by handing the module a function it could misuse.
//!
//! # The contract
//!
//! A module exports:
//!
//! - `memory` — its linear memory.
//! - `alloc(len: i32) -> i32` — reserve `len` bytes and return a pointer, so the host can place
//!   the input where the guest expects it.
//! - `run(ptr: i32, len: i32) -> i64` — the entry point. It reads `len` bytes of input JSON at
//!   `ptr`, does its work, and returns a packed `(out_ptr << 32) | out_len` pointing at its
//!   output JSON in the same memory.
//!
//! For a passive check the input is one exchange as JSON and the output is an array of
//! observations. The host never trusts the module to behave: execution is bounded by **fuel** so
//! an infinite loop is stopped rather than hanging the process, and memory growth is capped, so a
//! module cannot exhaust the host's RAM. Both limits turn a hostile or buggy extension into a
//! failed run, not a compromised tool.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use hexora_ext::{Capability, ExtensionKind, InstalledExtension};
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// What went wrong running a module. Every variant is a *contained* failure — the host is fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmError {
    /// A human reason.
    pub message: String,
}

impl WasmError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WasmError {}

/// The bounds a module runs under. Defaults are generous for a check over one exchange and still
/// far short of hanging or exhausting the host.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Interpreter fuel — units of work before execution is trapped. Bounds infinite loops.
    pub fuel: u64,
    /// The most linear memory the module may grow to, in bytes.
    pub max_memory_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 200_000_000,
            max_memory_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Store data: the memory limiter the interpreter consults before every growth.
struct HostState {
    limits: StoreLimits,
}

/// Whether an installed extension may run as a passive check over an exchange.
///
/// The capability gate: it must be a passive check, switched on, and hold `http:read` — without
/// that grant it is not allowed to see the traffic in the first place.
pub fn may_run_passive(ext: &InstalledExtension) -> Result<(), WasmError> {
    if ext.manifest.kind != ExtensionKind::PassiveCheck {
        return Err(WasmError::new(format!(
            "{} is a {}, not a passive check",
            ext.manifest.id,
            ext.manifest.kind.label()
        )));
    }
    if !ext.enabled {
        return Err(WasmError::new(format!("{} is disabled", ext.manifest.id)));
    }
    if !ext.grants.allows(Capability::HttpRead) {
        return Err(WasmError::new(format!(
            "{} was not granted http:read, so it may not see the exchange",
            ext.manifest.id
        )));
    }
    Ok(())
}

/// A compiled module, ready to run many times.
///
/// Compiling is the expensive step, so a scanner compiles an extension once and then runs it over
/// every exchange. Each [`Sandbox::run`] gets a **fresh** store and instance, so one exchange's
/// run cannot leak state into the next — isolation between invocations, not just between
/// extensions.
pub struct Sandbox {
    engine: Engine,
    module: Module,
}

impl Sandbox {
    /// Compiles a module. The engine is configured to meter fuel so every run can be bounded.
    pub fn compile(module_bytes: &[u8]) -> Result<Sandbox, WasmError> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, module_bytes)
            .map_err(|e| WasmError::new(format!("the module did not compile: {e}")))?;
        Ok(Sandbox { engine, module })
    }

    /// Runs the module's `run` entry over `input`, in a fresh sandbox, and returns its output.
    ///
    /// No imports, so the module can only compute over the bytes given. Fuel and a memory cap
    /// bound it; any misbehaviour — a trap, running out of fuel, a bad pointer — is an error,
    /// never a panic or a hang.
    pub fn run(&self, input: &[u8], limits: &Limits) -> Result<Vec<u8>, WasmError> {
        let state = HostState {
            limits: StoreLimitsBuilder::new()
                .memory_size(limits.max_memory_bytes)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(limits.fuel)
            .map_err(|e| WasmError::new(format!("could not set the fuel limit: {e}")))?;

        // No imports: an extension module gets memory and nothing else.
        let linker: Linker<HostState> = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| WasmError::new(format!("the module would not instantiate: {e}")))?
            .start(&mut store)
            .map_err(|e| WasmError::new(format!("the module's start function trapped: {e}")))?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| WasmError::new("the module exports no `memory`"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "alloc")
            .map_err(|_| WasmError::new("the module exports no `alloc(i32) -> i32`"))?;
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&store, "run")
            .map_err(|_| WasmError::new("the module exports no `run(i32, i32) -> i64`"))?;

        let len = i32::try_from(input.len())
            .map_err(|_| WasmError::new("the input is too large to pass to the module"))?;
        let ptr = alloc
            .call(&mut store, len)
            .map_err(|e| trap_message("alloc", e))?;
        if ptr < 0 {
            return Err(WasmError::new(
                "the module's alloc returned a negative pointer",
            ));
        }
        memory
            .write(&mut store, ptr as usize, input)
            .map_err(|_| WasmError::new("the module's alloc did not reserve enough memory"))?;

        let packed = run
            .call(&mut store, (ptr, len))
            .map_err(|e| trap_message("run", e))?;

        let out_ptr = (packed >> 32) as u32 as usize;
        let out_len = (packed & 0xffff_ffff) as u32 as usize;

        let data = memory.data(&store);
        let end = out_ptr
            .checked_add(out_len)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                WasmError::new("the module returned an output range outside its memory")
            })?;
        Ok(data[out_ptr..end].to_vec())
    }

    /// Runs the module as a passive check: an exchange JSON in, an observations JSON string out.
    pub fn run_passive(&self, exchange_json: &str, limits: &Limits) -> Result<String, WasmError> {
        let out = self.run(exchange_json.as_bytes(), limits)?;
        String::from_utf8(out)
            .map_err(|_| WasmError::new("the module's output was not valid UTF-8"))
    }
}

/// Runs a module's `run` entry over `input` once (compile + run). For repeated runs over many
/// exchanges, compile a [`Sandbox`] once and reuse it instead.
pub fn run(module_bytes: &[u8], input: &[u8], limits: &Limits) -> Result<Vec<u8>, WasmError> {
    Sandbox::compile(module_bytes)?.run(input, limits)
}

/// Runs a passive-check module once and returns the observations JSON string it produced.
pub fn run_passive(
    module_bytes: &[u8],
    exchange_json: &str,
    limits: &Limits,
) -> Result<String, WasmError> {
    Sandbox::compile(module_bytes)?.run_passive(exchange_json, limits)
}

/// Turns a wasmi trap into a message, naming fuel exhaustion specifically since that is the
/// expected outcome for a runaway module rather than a bug.
fn trap_message(what: &str, error: wasmi::Error) -> WasmError {
    let text = error.to_string();
    if text.contains("fuel") || text.contains("OutOfFuel") || text.contains("out of fuel") {
        WasmError::new(format!(
            "the module ran out of fuel during `{what}` — stopped before it could hang"
        ))
    } else {
        WasmError::new(format!("the module trapped during `{what}`: {text}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module with a bump allocator + `run` body. `run_body` is WAT for the `run` function.
    fn module(run_body: &str) -> Vec<u8> {
        let src = format!(
            r#"(module
              (memory (export "memory") 1)
              (global $bump (mut i32) (i32.const 1024))
              (func (export "alloc") (param $len i32) (result i32)
                (local $p i32)
                global.get $bump
                local.set $p
                global.get $bump
                local.get $len
                i32.add
                global.set $bump
                local.get $p)
              {run_body})"#
        );
        wat::parse_str(&src).expect("valid WAT")
    }

    /// Packs (ptr, len) the way the host unpacks it.
    fn packed(ptr: u32, len: u32) -> i64 {
        ((ptr as i64) << 32) | (len as i64)
    }

    #[test]
    fn a_module_that_returns_output_is_read_back() {
        // Writes `[{"t":"x"}]` (11 bytes) at offset 0 and returns (0 << 32) | 11.
        let body = r#"
            (data (i32.const 0) "[{\"t\":\"x\"}]")
            (func (export "run") (param i32) (param i32) (result i64)
              (i64.const 11))"#; // (0<<32)|11 == 11
        let out = run_passive(&module(body), "{}", &Limits::default()).unwrap();
        assert_eq!(out, r#"[{"t":"x"}]"#);
    }

    #[test]
    fn an_infinite_loop_is_stopped_by_fuel_not_hung() {
        let body = r#"(func (export "run") (param i32) (param i32) (result i64)
              (loop $l (br $l))
              (i64.const 0))"#;
        let limits = Limits {
            fuel: 1_000_000,
            ..Limits::default()
        };
        let err = run_passive(&module(body), "{}", &limits).unwrap_err();
        assert!(err.message.contains("fuel"), "{}", err.message);
    }

    #[test]
    fn an_output_range_outside_memory_is_refused() {
        // Returns a huge out_ptr/out_len that is not inside the one-page memory.
        let body = format!(
            r#"(func (export "run") (param i32) (param i32) (result i64)
              (i64.const {}))"#,
            packed(1_000_000, 1_000_000)
        );
        let err = run_passive(&module(&body), "{}", &Limits::default()).unwrap_err();
        assert!(
            err.message.contains("outside its memory"),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_module_without_run_is_refused() {
        let src = r#"(module (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) (i32.const 0)))"#;
        let bytes = wat::parse_str(src).unwrap();
        let err = run(&bytes, b"{}", &Limits::default()).unwrap_err();
        assert!(err.message.contains("run"), "{}", err.message);
    }

    #[test]
    fn garbage_bytes_do_not_compile() {
        let err = run(b"not wasm", b"{}", &Limits::default()).unwrap_err();
        assert!(err.message.contains("did not compile"), "{}", err.message);
    }

    #[test]
    fn the_capability_gate_requires_http_read_a_passive_kind_and_enabled() {
        use hexora_ext::Manifest;
        let manifest = |kind: &str, perms: &str| {
            Manifest::parse(
                format!(
                    r#"{{"id":"a.b","name":"N","version":"1","api_version":1,"kind":"{kind}","entry":"m.wasm","permissions":{perms}}}"#
                )
                .as_bytes(),
            )
            .unwrap()
        };

        // Passive + http_read granted + enabled -> allowed.
        let ok = InstalledExtension::install_required_only(manifest(
            "passive_check",
            r#"{"required":["http_read"]}"#,
        ));
        assert!(may_run_passive(&ok).is_ok());

        // Wrong kind.
        let report =
            InstalledExtension::install_required_only(manifest("report", r#"{"required":[]}"#));
        assert!(may_run_passive(&report).is_err());

        // Passive but without http_read granted.
        let no_read = InstalledExtension::install_required_only(manifest(
            "passive_check",
            r#"{"required":[]}"#,
        ));
        assert!(may_run_passive(&no_read).is_err());
    }
}
