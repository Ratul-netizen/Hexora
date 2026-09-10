//! `hexora proxy` — run the intercepting proxy.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hexora_engine::guard::ScopeDecision;
use hexora_engine::transport::Exchange;
use hexora_http::{TcpTransport, TlsConfig};
use hexora_proxy::{
    trust, CertificateAuthority, ExchangeObserver, Fanout, InterceptionPolicy, ProjectCapture,
    ProxyConfig, ProxyServer, TrustState,
};
use hexora_types::scope::Scope;
use hexora_types::{HexoraError, Result};

/// Options for `hexora proxy`.
pub struct ProxyArgs<'a> {
    pub project: Option<&'a Path>,
    pub in_scope_only: bool,
    pub listen: &'a str,
    pub ca_dir: Option<&'a Path>,
    pub exempt: &'a [String],
    pub only: &'a [String],
    pub insecure_upstream: bool,
}

/// Options for `hexora ca`.
pub struct CaArgs<'a> {
    pub dir: Option<&'a Path>,
    pub export: Option<&'a Path>,
    pub delete: bool,
    /// Install the CA into this user's trust store.
    pub install: bool,
    /// Remove the CA from the trust store, leaving the files alone.
    pub untrust: bool,
    /// Report whether the platform currently trusts it.
    pub status: bool,
    /// Skip the confirmation prompt before installing.
    pub yes: bool,
    pub json: bool,
}

/// Prints every exchange as a one-line summary.
struct ConsoleObserver;

impl ExchangeObserver for ConsoleObserver {
    fn observe(&self, exchange: &Exchange, decision: ScopeDecision) {
        // A marker rather than a word, so the column stays scannable when hundreds of
        // requests are streaming past.
        let scope_marker = match decision {
            ScopeDecision::Allowed => "+",
            ScopeDecision::AllowedOutOfScope => "?",
            ScopeDecision::Refused => "-",
        };
        println!(
            "{scope_marker} {:>3} {:<6} {:<7} {}",
            exchange.response.status,
            exchange.request.method,
            format!("{}ms", exchange.duration.as_millis()),
            exchange.request.url()
        );
    }
}

/// Runs the proxy until interrupted.
pub fn run(args: ProxyArgs<'_>) -> Result<()> {
    let bind: SocketAddr = args
        .listen
        .parse()
        .map_err(|e| HexoraError::invalid_input("listen", format!("{:?}: {e}", args.listen)))?;

    let ca_dir = resolve_ca_dir(args.ca_dir)?;
    let ca = Arc::new(CertificateAuthority::load_or_create(&ca_dir)?);

    let interception = if !args.only.is_empty() {
        InterceptionPolicy::only(args.only.to_vec())
    } else {
        InterceptionPolicy::exempting(args.exempt.to_vec())
    };

    let transport = if args.insecure_upstream {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };

    let config = ProxyConfig {
        bind,
        interception,
        ..Default::default()
    };

    // Opened before the runtime starts so a bad path fails immediately with a clear
    // message, rather than after the listener is already advertised as ready.
    let project = match args.project {
        Some(path) => Some(crate::open_project(path)?),
        None => None,
    };

    // Printing and recording are separate concerns and both are wanted at once: the
    // console line tells a tester the proxy is working, the project is what survives
    // the session.
    let mut observers = Fanout::new().with(ConsoleObserver);
    if let Some(project) = &project {
        let capture = ProjectCapture::new(Arc::new(project.traffic()));
        let capture = if args.in_scope_only {
            capture.in_scope_only()
        } else {
            capture
        };
        observers.push(Box::new(capture));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| HexoraError::Internal(format!("failed to start the async runtime: {e}")))?;

    runtime.block_on(async move {
        let server = ProxyServer::bind(
            config,
            // An empty scope does not block proxied traffic: the tester's browser
            // asked for it, and the proxy has to see a host before it can be scoped.
            Arc::new(Scope::new()),
            transport,
            Arc::new(observers),
            ca,
        )
        .await?;

        let addr = server.local_addr()?;
        eprintln!("Hexora proxy listening on {addr}");
        eprintln!("CA certificate: {}", ca_dir.join("hexora-ca.crt").display());
        eprintln!();
        eprintln!("Configure your browser to use {addr} as its HTTP and HTTPS proxy,");
        eprintln!("then install the CA certificate so HTTPS can be intercepted:");
        eprintln!("  hexora ca --export hexora-ca.crt");
        eprintln!();
        if args.insecure_upstream {
            eprintln!("WARNING: upstream certificate verification is OFF. Connections to");
            eprintln!("         targets are encrypted but NOT authenticated.");
            eprintln!();
        }
        match args.project {
            Some(path) => {
                eprintln!("Recording into {}", path.display());
                if args.in_scope_only {
                    eprintln!("  only in-scope traffic is being recorded");
                }
                eprintln!("Browse it later with: hexora history {}", path.display());
            }
            None => {
                eprintln!("NOT recording: pass --project DIR to keep what you capture.");
            }
        }
        eprintln!();
        eprintln!("  + in scope   ? out of scope   - refused");
        eprintln!();

        server.serve().await
    })
}

/// Manages the interception CA.
pub fn ca(args: CaArgs<'_>) -> Result<()> {
    let dir = resolve_ca_dir(args.dir)?;

    if args.delete {
        // Untrust before deleting. The other order leaves a trusted certificate in the
        // store with its files gone — still trusted, and now harder to find and remove,
        // which is the worst possible state to leave a root CA in.
        let fingerprint = CertificateAuthority::load_or_create(&dir)
            .ok()
            .map(|ca| ca.fingerprints());
        if let Some(fingerprint) = &fingerprint {
            match trust::uninstall(fingerprint) {
                Ok(()) => println!("Removed the CA from this user's trust store."),
                Err(e) => {
                    // Reported, not fatal: the files should still go, and the user is
                    // told exactly what is left behind.
                    eprintln!("warning: could not remove it from the trust store: {e}");
                    eprintln!(
                        "         remove it by hand — fingerprint {}",
                        fingerprint.sha256
                    );
                }
            }
        }

        CertificateAuthority::delete(&dir)?;
        println!("Removed the interception CA from {}", dir.display());
        println!();
        println!("Firefox keeps its own store; if you imported it there, remove it there too.");
        return Ok(());
    }

    let ca = CertificateAuthority::load_or_create(&dir)?;
    let fingerprint = ca.fingerprints();

    if args.untrust {
        trust::uninstall(&fingerprint)?;
        println!("Removed the CA from this user's trust store.");
        println!(
            "The files are still in {} — use --delete to remove them.",
            dir.display()
        );
        return Ok(());
    }

    if args.status {
        return print_status(&ca, &dir, args.json);
    }

    if args.install {
        return install(&ca, &dir, args.yes, args.json);
    }

    if let Some(path) = args.export {
        std::fs::write(path, ca.certificate_pem())
            .map_err(|e| HexoraError::Internal(format!("writing {}: {e}", path.display())))?;
        println!("Exported the CA certificate to {}", path.display());
        println!();
        print_trust_instructions(path);
        return Ok(());
    }

    println!("CA directory: {}", dir.display());
    println!("Fingerprint:  {}", ca.fingerprint_display());
    println!("Trust state:  {}", trust::status(&fingerprint));
    println!();
    print!("{}", ca.certificate_pem());
    Ok(())
}

/// Reports whether the platform trusts this CA.
fn print_status(ca: &CertificateAuthority, dir: &Path, json: bool) -> Result<()> {
    let fingerprint = ca.fingerprints();
    let state = trust::status(&fingerprint);

    if json {
        println!(
            "{}",
            serde_json::json!({
                "directory": dir.display().to_string(),
                "fingerprint_sha256": fingerprint.sha256,
                "trusted": state == TrustState::Trusted,
                "state": state.to_string(),
            })
        );
        return Ok(());
    }

    println!("CA directory: {}", dir.display());
    println!("Fingerprint:  {}", ca.fingerprint_display());
    println!("Trust state:  {state}");
    if state == TrustState::NotTrusted {
        println!();
        println!("Install it with:  hexora ca --install");
    }
    Ok(())
}

/// Installs the CA into this user's trust store, after saying what that means.
fn install(ca: &CertificateAuthority, dir: &Path, yes: bool, json: bool) -> Result<()> {
    let fingerprint = ca.fingerprints();
    let certificate = dir.join("hexora-ca.crt");

    if trust::status(&fingerprint) == TrustState::Trusted {
        println!("Already trusted — nothing to do.");
        println!("Fingerprint: {}", ca.fingerprint_display());
        return Ok(());
    }

    if !yes && !json {
        // Trusting a root CA is the most consequential thing a Hexora user is asked to
        // do, so it is never a side effect of anything and never silent.
        println!("About to install a root certificate authority into your trust store.");
        println!();
        println!("  Fingerprint: {}", ca.fingerprint_display());
        println!("  Private key: {}", dir.join("hexora-ca.key").display());
        println!();
        println!("This lets Hexora decrypt HTTPS on this machine. Anyone who obtains that");
        println!("private key could impersonate any site to you, so do this only on a");
        println!("machine you control, and remove it when you are done:");
        println!("  hexora ca --delete");
        println!();
        if !confirm("Install it?")? {
            println!("Not installed.");
            return Ok(());
        }
        println!();
    }

    let installed = trust::install(&certificate, &fingerprint)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "store": installed.store.name,
                "needed_elevation": installed.store.needed_elevation,
                "verified": installed.verified.to_string(),
                "fingerprint_sha256": fingerprint.sha256,
                "manual": installed
                    .manual
                    .iter()
                    .map(|step| serde_json::json!({
                        "application": step.application,
                        "instruction": step.instruction,
                    }))
                    .collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    println!("Installed into the {}.", installed.store.name);
    match installed.verified {
        TrustState::Trusted => println!("Verified: the platform reports it as trusted."),
        // Said out loud rather than inferred from a zero exit code, because a tester
        // who believes the CA is installed will blame Hexora for what follows.
        TrustState::NotTrusted => {
            println!("WARNING: the platform still does not report it as trusted.");
            println!("         Check your trust store before relying on interception.");
        }
        TrustState::Unknown(why) => {
            println!("Could not verify ({why}); check your trust store to be sure.");
        }
    }

    for step in &installed.manual {
        println!();
        println!("{} still needs doing by hand:", step.application);
        for line in step.instruction.lines() {
            println!("  {line}");
        }
    }

    println!();
    println!("Now run:  hexora proxy --project ./engagement");
    Ok(())
}

/// Asks a yes/no question on the terminal.
///
/// A non-interactive stdin answers "no": a script that pipes nothing must not be taken
/// to have agreed to trusting a root CA. `--yes` is how to agree deliberately.
pub fn confirm(question: &str) -> Result<bool> {
    use std::io::{BufRead, Write};

    print!("{question} [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| HexoraError::Internal(format!("writing to the terminal: {e}")))?;

    let mut answer = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| HexoraError::Internal(format!("reading from the terminal: {e}")))?;
    if read == 0 {
        return Ok(false);
    }
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Where the CA lives when the user has not said otherwise.
pub fn resolve_ca_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    // Under the user's own profile, which is already access-restricted to them.
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            HexoraError::Internal(
                "cannot determine a home directory; pass --ca-dir explicitly".to_string(),
            )
        })?;
    Ok(PathBuf::from(base).join(".hexora").join("ca"))
}

/// Prints per-platform trust instructions.
///
/// Installing a CA is the single most consequential thing a Hexora user will be asked
/// to do, so the instructions say what it means rather than only which button to press.
fn print_trust_instructions(path: &Path) {
    let path = path.display();
    println!("Installing this certificate lets Hexora decrypt HTTPS on this machine.");
    println!("Anyone who obtains the matching private key could impersonate any site to");
    println!("you, so install it only on a machine you control, and remove it when done:");
    println!("  hexora ca --delete");
    println!();
    println!("Firefox (its own trust store, all platforms):");
    println!("  Settings > Privacy & Security > Certificates > View Certificates");
    println!("  > Authorities > Import > {path}  (trust for websites)");
    println!();

    if cfg!(windows) {
        println!("Windows (Chrome, Edge and most applications):");
        println!("  certutil -user -addstore Root \"{path}\"");
        println!();
        println!("  Install it into the store rather than pointing a tool at the file.");
        println!("  Windows' own TLS stack (schannel) checks revocation, and a locally");
        println!("  generated CA has no revocation list — so a tool given the file");
        println!("  directly fails with CERT_TRUST_REVOCATION_STATUS_UNKNOWN even though");
        println!("  the certificate is otherwise fine. curl users testing quickly can");
        println!("  pass --ssl-revoke-best-effort.");
    } else if cfg!(target_os = "macos") {
        println!("macOS (Safari, Chrome and most applications):");
        println!("  sudo security add-trusted-cert -d -r trustRoot \\");
        println!("    -k /Library/Keychains/System.keychain \"{path}\"");
    } else {
        println!("Linux (system store; Chrome also uses its own NSS database):");
        println!("  sudo cp \"{path}\" /usr/local/share/ca-certificates/hexora.crt");
        println!("  sudo update-ca-certificates");
        println!();
        println!("  # Chrome/Chromium additionally:");
        println!("  certutil -d sql:$HOME/.pki/nssdb -A -t \"C,,\" -n Hexora -i \"{path}\"");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_ca_directory_is_used_verbatim() {
        let dir = Path::new("/tmp/custom-ca");
        assert_eq!(resolve_ca_dir(Some(dir)).unwrap(), dir);
    }

    #[test]
    fn the_default_ca_directory_is_under_the_user_profile() {
        // Not a shared or temporary location: the key must inherit the profile's
        // access restrictions.
        let dir = resolve_ca_dir(None).unwrap();
        assert!(dir.ends_with("ca"), "{dir:?}");
        assert!(dir.to_string_lossy().contains(".hexora"), "{dir:?}");
    }

    #[test]
    fn a_bad_listen_address_is_rejected_with_the_value() {
        let err = run(ProxyArgs {
            project: None,
            in_scope_only: false,
            listen: "not-an-address",
            ca_dir: None,
            exempt: &[],
            only: &[],
            insecure_upstream: false,
        })
        .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        assert!(err.to_string().contains("not-an-address"), "{err}");
    }

    #[test]
    fn exporting_writes_the_certificate_but_never_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join("exported.crt");

        ca(CaArgs {
            dir: Some(dir.path()),
            export: Some(&export),
            delete: false,
            install: false,
            untrust: false,
            status: false,
            yes: false,
            json: false,
        })
        .unwrap();

        let written = std::fs::read_to_string(&export).unwrap();
        assert!(written.contains("BEGIN CERTIFICATE"), "{written:.40}");
        assert!(
            !written.contains("PRIVATE KEY"),
            "the exported file must never carry the private key"
        );
    }

    #[test]
    fn deleting_removes_the_ca() {
        let dir = tempfile::tempdir().unwrap();
        ca(CaArgs {
            dir: Some(dir.path()),
            export: None,
            delete: false,
            install: false,
            untrust: false,
            status: false,
            yes: false,
            json: false,
        })
        .unwrap();
        assert!(dir.path().join("hexora-ca.crt").exists());

        ca(CaArgs {
            dir: Some(dir.path()),
            export: None,
            delete: true,
            install: false,
            untrust: false,
            status: false,
            yes: false,
            json: false,
        })
        .unwrap();
        assert!(!dir.path().join("hexora-ca.crt").exists());
        assert!(!dir.path().join("hexora-ca.key").exists());
    }
}
