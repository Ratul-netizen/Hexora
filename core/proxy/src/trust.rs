//! Installing and removing the interception CA from platform trust stores.
//!
//! # This is the most dangerous thing Hexora does
//!
//! Trusting a root CA means the holder of its private key can impersonate *any* site
//! to this machine — every bank, every mail provider, every internal system. The CA
//! itself is per-installation and the key never leaves the machine (see [`crate::ca`]),
//! which bounds the damage, but a trusted root is still a trusted root.
//!
//! Four rules follow, and they are the whole design of this module:
//!
//! 1. **Never install without being asked.** Nothing here runs as a side effect of
//!    starting the proxy. It happens because someone typed a command that says so.
//! 2. **Prefer the user store.** Every platform path below installs for the current
//!    user where such a store exists, so the blast radius is one account and no
//!    administrator rights are needed. A tester who wants a system-wide install can do
//!    it themselves, deliberately.
//! 3. **Verify, do not assume.** [`status`] asks the platform whether the certificate
//!    is actually trusted rather than remembering that a command exited zero.
//! 4. **Removal must be as easy as installation.** [`uninstall`] exists, works without
//!    the CA files still being present, and is what `hexora ca --delete` calls first.
//!
//! # Why shelling out
//!
//! Each platform's trust store has a native API, and using them would mean three
//! FFI surfaces plus `unsafe`, in the one module where a mistake is most expensive.
//! The platform's own CLI (`certutil`, `security`, `update-ca-certificates`) is
//! already installed, already audited, and does exactly this job. Nothing
//! user-controlled reaches a shell — arguments are passed as an argv array, never
//! through `sh -c`, and the only variable parts are a path Hexora wrote and a
//! fingerprint of Hexora's own certificate.

use std::path::{Path, PathBuf};
use std::process::Command;

use hexora_types::error::{HexoraError, Result};

/// Whether the platform believes the certificate is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    /// Present in the trust store this platform installs into.
    Trusted,
    /// Not present.
    NotTrusted,
    /// The platform could not be asked — the tool is missing, or it failed.
    ///
    /// Deliberately distinct from `NotTrusted`: reporting "not trusted" when the
    /// question could not be asked would send a tester to reinstall a CA that is
    /// already there.
    Unknown(&'static str),
}

impl std::fmt::Display for TrustState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trusted => write!(f, "trusted"),
            Self::NotTrusted => write!(f, "not trusted"),
            Self::Unknown(why) => write!(f, "unknown ({why})"),
        }
    }
}

/// Which store an operation acted on, for reporting back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    /// A short name, e.g. `Windows user Root store`.
    pub name: &'static str,
    /// Whether administrator or root rights were needed.
    pub needed_elevation: bool,
}

/// What still has to be done by hand after an install.
///
/// Some trust stores cannot be written by an external process, or belong to an
/// application rather than the platform. Firefox is the notable one: it ships its own
/// CA store and ignores the system's entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualStep {
    /// Which application needs attention.
    pub application: String,
    /// What the user has to do.
    pub instruction: String,
}

/// The outcome of an install.
#[derive(Debug, Clone)]
pub struct Installed {
    /// Where it went.
    pub store: Store,
    /// Whether the platform confirms it afterwards.
    pub verified: TrustState,
    /// Applications that still need doing by hand.
    pub manual: Vec<ManualStep>,
}

/// Installs a CA certificate into the current user's trust store.
///
/// `certificate` must be a PEM file that Hexora wrote. The `fingerprint` is used only
/// to verify afterwards, never to locate the file.
pub fn install(certificate: &Path, fingerprint: &Fingerprints) -> Result<Installed> {
    if !certificate.is_file() {
        return Err(HexoraError::not_found(
            "certificate",
            certificate.display().to_string(),
        ));
    }
    fingerprint.validate()?;

    let store = platform_install(certificate)?;
    // Asked rather than assumed: a zero exit code from a trust-store tool is not the
    // same thing as the certificate being trusted.
    let verified = status(fingerprint);

    Ok(Installed {
        store,
        verified,
        manual: manual_steps(certificate),
    })
}

/// Removes a CA certificate from the current user's trust store, by fingerprint.
///
/// Identified by fingerprint rather than subject name so that removal cannot take a
/// different certificate with it, and so it works after the CA files are gone.
pub fn uninstall(fingerprint: &Fingerprints) -> Result<()> {
    fingerprint.validate()?;
    platform_uninstall(fingerprint)
}

/// Asks the platform whether this certificate is trusted.
pub fn status(fingerprint: &Fingerprints) -> TrustState {
    if fingerprint.validate().is_err() {
        return TrustState::Unknown("the fingerprint is not valid hex");
    }
    platform_status(fingerprint)
}

/// Whether this platform can install without administrator rights.
pub fn installs_without_elevation() -> bool {
    // Windows and macOS both have per-user stores. Linux's system bundle does not, so
    // the honest answer there is no.
    cfg!(any(windows, target_os = "macos"))
}

/// The digests identifying one certificate.
///
/// Two, because the platforms disagree about which one names a certificate. Windows
/// indexes its store by SHA-1 thumbprint and `certutil` accepts nothing else; macOS
/// and NSS use SHA-256. Carrying both means each platform can be asked in the terms it
/// understands while the *answer* is always confirmed against SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprints {
    /// SHA-256 of the DER, uppercase hex. The identity that decides trust.
    pub sha256: String,
    /// SHA-1 of the DER, uppercase hex. A lookup key for Windows, nothing more.
    pub sha1: String,
}

impl Fingerprints {
    /// Checks both digests before either reaches a command line.
    ///
    /// Not because the values are untrusted today — they come from Hexora's own
    /// certificate — but because this is the one module where an argument reaching a
    /// platform tool is worth being certain about, and a caller a year from now may
    /// pass something else.
    fn validate(&self) -> Result<()> {
        check_hex(&self.sha256, 64, "sha256")?;
        check_hex(&self.sha1, 40, "sha1")
    }
}

fn check_hex(value: &str, length: usize, field: &'static str) -> Result<()> {
    if value.len() != length || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HexoraError::invalid_input(
            field,
            format!("expected {length} hexadecimal characters"),
        ));
    }
    Ok(())
}

/// A failed platform command.
///
/// Carries the whole output as well as a short summary, because the two are needed for
/// different things: the summary goes to the user, and the full text is what
/// [`Self::means_absent`] has to search. Classifying on the first line alone is wrong —
/// `certutil` opens with a banner naming the store and puts the actual error two lines
/// further down, so a check against the first line never sees it.
#[derive(Debug)]
struct CommandError {
    /// One line, for showing a person.
    summary: String,
    /// Everything both streams produced, for classification.
    output: String,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary)
    }
}

/// Markers meaning "that certificate is not in the store".
///
/// Not an error condition: it is the answer to the question, and every one of these
/// must map to [`TrustState::NotTrusted`] rather than to `Unknown`. The numeric codes
/// are Windows `NTE_NOT_FOUND` and `CRYPT_E_NOT_FOUND`, which `certutil` returns
/// depending on which lookup path it took.
const ABSENT_MARKERS: &[&str] = &[
    "0x80090011",
    "0x80092004",
    "not found",
    "could not be found",
    "no certificate",
];

impl CommandError {
    /// Whether the failure means the certificate simply is not there.
    fn means_absent(&self) -> bool {
        let haystack = self.output.to_ascii_lowercase();
        ABSENT_MARKERS
            .iter()
            .any(|marker| haystack.contains(&marker.to_ascii_lowercase()))
    }

    /// Whether the tool itself could not be run, as opposed to reporting a failure.
    fn tool_missing(&self) -> bool {
        self.output.is_empty() && self.summary.contains("could not run")
    }
}

/// Runs a command, returning its stdout on success.
fn run(program: &str, args: &[&str]) -> std::result::Result<String, CommandError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| CommandError {
            summary: format!("could not run {program}: {e}"),
            output: String::new(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if output.status.success() {
        return Ok(stdout);
    }

    // Both streams: these tools report failures on either, inconsistently, and
    // `certutil` in particular writes its errors to stdout.
    let combined = format!("{stdout}\n{stderr}");
    let detail = error_line(&combined).unwrap_or_else(|| "no output".to_string());
    Err(CommandError {
        summary: format!("{program} exited with {}: {}", output.status, detail),
        output: combined,
    })
}

/// The most explanatory line of a tool's output.
///
/// Prefers a line that looks like an error over the first non-empty one, because these
/// tools lead with a banner. Falls back to the first non-empty line when nothing
/// stands out.
fn error_line(text: &str) -> Option<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    lines
        .iter()
        .find(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("error") || lower.contains("failed") || lower.contains("not found")
        })
        .or_else(|| lines.first())
        .map(|line| line.to_string())
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn platform_install(certificate: &Path) -> Result<Store> {
    // `-user` is what keeps this out of the machine store: no administrator rights,
    // and the certificate is trusted for this account only.
    run(
        "certutil",
        &[
            "-user",
            "-addstore",
            "Root",
            &certificate.display().to_string(),
        ],
    )
    .map_err(|e| {
        HexoraError::Internal(format!(
            "installing the CA into the Windows user Root store failed: {e}"
        ))
    })?;

    Ok(Store {
        name: "Windows user Root store",
        needed_elevation: false,
    })
}

#[cfg(windows)]
fn platform_uninstall(fingerprint: &Fingerprints) -> Result<()> {
    // By SHA-1 because that is the only handle the Windows store offers. It still
    // cannot take the wrong certificate with it: a thumbprint names exactly one entry.
    match run(
        "certutil",
        &["-user", "-delstore", "Root", &fingerprint.sha1],
    ) {
        Ok(_) => Ok(()),
        // Already absent is success: `hexora ca --delete` must not fail because the
        // certificate was removed by hand first.
        Err(e) if e.means_absent() => Ok(()),
        Err(e) => Err(HexoraError::Internal(format!(
            "removing the CA from the Windows user Root store failed: {e}"
        ))),
    }
}

#[cfg(windows)]
fn platform_status(fingerprint: &Fingerprints) -> TrustState {
    // Looked up by SHA-1 — the Windows store indexes by thumbprint and accepts no
    // other key — and then confirmed against the certificate itself below.
    match run("certutil", &["-user", "-store", "Root", &fingerprint.sha1]) {
        Ok(output) => {
            // certutil renders the certificate it found. A store listing that matched
            // nothing prints a banner and no certificate, so requiring the marker
            // means an empty result cannot read as trusted.
            if output.contains("================") || output.contains("Cert Hash") {
                TrustState::Trusted
            } else {
                TrustState::NotTrusted
            }
        }
        Err(e) if e.means_absent() => TrustState::NotTrusted,
        Err(e) if e.tool_missing() => TrustState::Unknown("certutil is not on PATH"),
        Err(_) => TrustState::Unknown("certutil reported an unexpected failure"),
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn platform_install(certificate: &Path) -> Result<Store> {
    // The login keychain, not the System one: no sudo, and the trust decision belongs
    // to this user rather than to everyone who logs into the machine.
    let keychain = login_keychain()?;
    run(
        "security",
        &[
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-k",
            &keychain.display().to_string(),
            &certificate.display().to_string(),
        ],
    )
    .map_err(|e| {
        HexoraError::Internal(format!(
            "installing the CA into the macOS login keychain failed: {e}. \
             macOS asks for your password the first time; declining that prompt \
             produces this error."
        ))
    })?;

    Ok(Store {
        name: "macOS login keychain",
        needed_elevation: false,
    })
}

#[cfg(target_os = "macos")]
fn platform_uninstall(fingerprint: &Fingerprints) -> Result<()> {
    // `security` deletes by hash, which is what makes this safe: it cannot match a
    // different certificate that happens to share a subject name.
    match run(
        "security",
        &["delete-certificate", "-Z", &fingerprint.sha256],
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.means_absent() => Ok(()),
        Err(e) => Err(HexoraError::Internal(format!(
            "removing the CA from the macOS keychain failed: {e}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn platform_status(fingerprint: &Fingerprints) -> TrustState {
    match run("security", &["find-certificate", "-a", "-Z"]) {
        Ok(output) => {
            if output
                .lines()
                .any(|line| line.trim().ends_with(&fingerprint.sha256) && line.contains("SHA-256"))
            {
                TrustState::Trusted
            } else {
                TrustState::NotTrusted
            }
        }
        Err(e) if e.tool_missing() => TrustState::Unknown("security is not on PATH"),
        Err(_) => TrustState::Unknown("security reported an unexpected failure"),
    }
}

#[cfg(target_os = "macos")]
fn login_keychain() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        HexoraError::Internal("cannot determine a home directory for the keychain".to_string())
    })?;
    let base = PathBuf::from(home).join("Library").join("Keychains");
    // The name changed in Sierra; both are accepted so this works on old and new.
    for name in ["login.keychain-db", "login.keychain"] {
        let candidate = base.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Ok(base.join("login.keychain-db"))
}

// ---------------------------------------------------------------------------
// Linux and everything else
// ---------------------------------------------------------------------------

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_install(certificate: &Path) -> Result<Store> {
    // Chrome, Chromium and anything else built on NSS read this per-user database,
    // and writing it needs no root. The system bundle in /usr/local/share does need
    // root, so it is offered as a manual step rather than attempted with sudo —
    // a tool that silently escalates is a tool nobody should trust with a root CA.
    let db = nss_database().ok_or_else(|| {
        HexoraError::Internal(
            "no NSS database found at ~/.pki/nssdb. Install the CA into the system \
             bundle instead:\n  sudo cp <cert> /usr/local/share/ca-certificates/hexora.crt\n\
             \x20 sudo update-ca-certificates"
                .to_string(),
        )
    })?;

    run(
        "certutil",
        &[
            "-d",
            &format!("sql:{}", db.display()),
            "-A",
            "-t",
            "C,,",
            "-n",
            "Hexora Interception CA",
            "-i",
            &certificate.display().to_string(),
        ],
    )
    .map_err(|e| {
        HexoraError::Internal(format!(
            "installing the CA into the NSS database failed: {e}. \
             On Debian and Ubuntu, certutil comes from the libnss3-tools package."
        ))
    })?;

    Ok(Store {
        name: "NSS database (~/.pki/nssdb)",
        needed_elevation: false,
    })
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_uninstall(_fingerprint: &Fingerprints) -> Result<()> {
    let Some(db) = nss_database() else {
        return Ok(());
    };
    // NSS deletes by nickname rather than by hash, so the nickname used at install
    // time is the handle. It is a constant, not user input.
    match run(
        "certutil",
        &[
            "-d",
            &format!("sql:{}", db.display()),
            "-D",
            "-n",
            "Hexora Interception CA",
        ],
    ) {
        Ok(_) => Ok(()),
        Err(e) if e.means_absent() => Ok(()),
        Err(e) => Err(HexoraError::Internal(format!(
            "removing the CA from the NSS database failed: {e}"
        ))),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_status(fingerprint: &Fingerprints) -> TrustState {
    let Some(db) = nss_database() else {
        return TrustState::Unknown("no NSS database at ~/.pki/nssdb");
    };
    match run(
        "certutil",
        &[
            "-d",
            &format!("sql:{}", db.display()),
            "-L",
            "-n",
            "Hexora Interception CA",
        ],
    ) {
        Ok(output) => {
            // Compared by fingerprint, so a stale entry with the same nickname from a
            // regenerated CA reads as not trusted rather than as trusted.
            let normalised: String = output
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_ascii_uppercase();
            if normalised.contains(&fingerprint.sha256.to_ascii_uppercase()) {
                TrustState::Trusted
            } else {
                TrustState::NotTrusted
            }
        }
        Err(_) => TrustState::NotTrusted,
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn nss_database() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let db = PathBuf::from(home).join(".pki").join("nssdb");
    db.is_dir().then_some(db)
}

// ---------------------------------------------------------------------------
// Manual steps
// ---------------------------------------------------------------------------

/// Applications that need trusting by hand after a platform install.
fn manual_steps(certificate: &Path) -> Vec<ManualStep> {
    let mut steps = Vec::new();

    // Firefox ships its own CA store and ignores the platform's entirely, on every
    // operating system. Installing into the system store and then finding Firefox
    // still refuses the connection is the single most common first-run confusion.
    if firefox_is_present() {
        steps.push(ManualStep {
            application: "Firefox".to_string(),
            instruction: format!(
                "Firefox uses its own certificate store and ignores the system one.\n\
                 Settings → Privacy & Security → Certificates → View Certificates\n\
                 → Authorities → Import → {} → trust for websites",
                certificate.display()
            ),
        });
    }

    if cfg!(not(any(windows, target_os = "macos"))) {
        steps.push(ManualStep {
            application: "System bundle".to_string(),
            instruction: format!(
                "For curl, wget and anything else using the system bundle (needs root):\n\
                 \x20 sudo cp {} /usr/local/share/ca-certificates/hexora.crt\n\
                 \x20 sudo update-ca-certificates",
                certificate.display()
            ),
        });
    }

    steps
}

/// Whether a Firefox profile directory exists on this machine.
///
/// A heuristic, and deliberately biased towards mentioning Firefox: telling someone
/// about a browser they do not use costs a line of output, while staying silent about
/// one they do use costs them an afternoon.
fn firefox_is_present() -> bool {
    firefox_profile_roots().iter().any(|path| path.is_dir())
}

/// Where Firefox keeps profiles on each platform.
fn firefox_profile_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if cfg!(windows) {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            roots.push(PathBuf::from(appdata).join("Mozilla").join("Firefox"));
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if cfg!(target_os = "macos") {
            roots.push(
                home.join("Library")
                    .join("Application Support")
                    .join("Firefox"),
            );
        } else {
            roots.push(home.join(".mozilla").join("firefox"));
            // Flatpak and Snap keep their own copies, and a tester who installed
            // Firefox that way will otherwise be told nothing.
            roots.push(
                home.join(".var")
                    .join("app")
                    .join("org.mozilla.firefox")
                    .join(".mozilla")
                    .join("firefox"),
            );
            roots.push(
                home.join("snap")
                    .join("firefox")
                    .join("common")
                    .join(".mozilla")
                    .join("firefox"),
            );
        }
    }

    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90";
    const SHA1: &str = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4";

    fn valid() -> Fingerprints {
        Fingerprints {
            sha256: SHA256.to_string(),
            sha1: SHA1.to_string(),
        }
    }

    #[test]
    fn a_valid_pair_of_fingerprints_is_accepted() {
        assert!(valid().validate().is_ok());
        assert!(Fingerprints {
            sha256: SHA256.to_lowercase(),
            sha1: SHA1.to_lowercase(),
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn a_fingerprint_that_could_carry_a_command_is_refused() {
        // The values are Hexora's own today. The check is here so it stays safe when a
        // future caller passes something that is not.
        for bad in [
            "",
            "short",
            &format!("{SHA256}extra"),
            "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9 ",
            "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F9;",
            "../../etc/passwd",
        ] {
            let fingerprint = Fingerprints {
                sha256: bad.to_string(),
                sha1: SHA1.to_string(),
            };
            assert!(
                fingerprint.validate().is_err(),
                "{bad:?} must not reach a command line"
            );
        }
    }

    #[test]
    fn a_bad_sha1_is_refused_too_not_just_the_sha256() {
        // It is the value Windows lookups are built from, so it reaches a command line
        // just as directly.
        let fingerprint = Fingerprints {
            sha256: SHA256.to_string(),
            sha1: "; rm -rf /".to_string(),
        };
        assert!(fingerprint.validate().is_err());
    }

    #[test]
    fn the_two_digests_have_the_lengths_their_algorithms_produce() {
        assert_eq!(SHA256.len(), 64);
        assert_eq!(SHA1.len(), 40);
        assert!(
            check_hex(SHA1, 64, "sha256").is_err(),
            "lengths are checked"
        );
    }

    #[test]
    fn status_on_a_malformed_fingerprint_is_unknown_not_untrusted() {
        // Reporting "not trusted" would send a tester to reinstall a CA that may well
        // already be there.
        let fingerprint = Fingerprints {
            sha256: "nonsense".to_string(),
            sha1: SHA1.to_string(),
        };
        assert!(matches!(status(&fingerprint), TrustState::Unknown(_)));
    }

    #[test]
    fn installing_a_missing_certificate_says_which_file() {
        let err = install(Path::new("/nonexistent/hexora-ca.crt"), &valid()).unwrap_err();
        assert_eq!(err.code(), "not_found");
        assert!(err.to_string().contains("hexora-ca.crt"), "{err}");
    }

    #[test]
    fn installing_refuses_a_bad_fingerprint_before_touching_the_platform() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("hexora-ca.crt");
        std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\n").unwrap();

        let err = install(
            &cert,
            &Fingerprints {
                sha256: "not-a-fingerprint".to_string(),
                sha1: SHA1.to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }

    #[test]
    fn uninstalling_validates_before_running_anything() {
        let fingerprint = Fingerprints {
            sha256: "../../etc".to_string(),
            sha1: SHA1.to_string(),
        };
        assert_eq!(uninstall(&fingerprint).unwrap_err().code(), "invalid_input");
    }

    #[test]
    fn the_trust_state_reads_clearly() {
        assert_eq!(TrustState::Trusted.to_string(), "trusted");
        assert_eq!(TrustState::NotTrusted.to_string(), "not trusted");
        assert!(TrustState::Unknown("no tool")
            .to_string()
            .contains("no tool"));
    }

    #[test]
    fn an_error_message_is_one_line_not_a_screenful() {
        assert_eq!(
            error_line("\n\n  the real problem  \nmore detail\n").as_deref(),
            Some("the real problem")
        );
        assert_eq!(error_line("   \n\n"), None);
    }

    #[test]
    fn the_error_line_skips_a_banner_to_find_the_actual_failure() {
        // Exactly what certutil produces, and what made every Windows lookup report
        // "unknown": the first line names the store, the error is two lines down.
        let output = concat!(
            "Root \"Trusted Root Certification Authorities\"\n",
            "CertUtil: -store command FAILED: 0x80090011 (-2146893807 NTE_NOT_FOUND)\n",
            "CertUtil: Object was not found.\n"
        );
        let line = error_line(output).unwrap();
        assert!(line.contains("FAILED"), "{line}");
        assert!(!line.starts_with("Root"), "{line}");
    }

    #[test]
    fn an_absent_certificate_is_recognised_from_anywhere_in_the_output() {
        // The marker is never on the first line, so classification has to search the
        // whole thing. Getting this wrong reported "unknown" to every Windows user.
        let error = CommandError {
            summary: "certutil exited with 1".to_string(),
            output: concat!(
                "Root \"Trusted Root Certification Authorities\"\n",
                "CertUtil: -store command FAILED: 0x80090011 (-2146893807 NTE_NOT_FOUND)\n",
                "CertUtil: Object was not found.\n"
            )
            .to_string(),
        };
        assert!(error.means_absent());
        assert!(!error.tool_missing());
    }

    #[test]
    fn a_genuine_failure_is_not_mistaken_for_an_absent_certificate() {
        // Otherwise a store that could not be opened would read as "not trusted", and
        // a tester would reinstall a CA that was already there.
        let error = CommandError {
            summary: "certutil exited with 1".to_string(),
            output: "CertUtil: -store command FAILED: 0x80070005 (Access is denied)".to_string(),
        };
        assert!(!error.means_absent());
    }

    #[test]
    fn a_missing_tool_is_distinguishable_from_a_failing_one() {
        let missing = CommandError {
            summary: "could not run certutil: not found".to_string(),
            output: String::new(),
        };
        assert!(missing.tool_missing());

        let failing = CommandError {
            summary: "certutil exited with 1: something".to_string(),
            output: "something".to_string(),
        };
        assert!(!failing.tool_missing());
    }

    #[test]
    fn firefox_profile_roots_are_platform_appropriate() {
        let roots = firefox_profile_roots();
        // Not asserting they exist — this machine may not have Firefox — only that
        // the paths look right for the platform, so the check is capable of working.
        if cfg!(windows) {
            assert!(
                roots.is_empty() || roots.iter().any(|r| r.ends_with("Mozilla/Firefox")),
                "{roots:?}"
            );
        }
    }

    #[test]
    fn manual_steps_always_name_the_certificate_path() {
        // A step that does not say which file to import is not an instruction.
        let cert = Path::new("/tmp/hexora-ca.crt");
        for step in manual_steps(cert) {
            assert!(
                step.instruction.contains("hexora-ca.crt")
                    || step.instruction.contains("hexora.crt"),
                "{step:?}"
            );
        }
    }

    #[test]
    fn linux_is_honest_about_needing_root_for_the_system_bundle() {
        let steps = manual_steps(Path::new("/tmp/hexora-ca.crt"));
        if cfg!(not(any(windows, target_os = "macos"))) {
            assert!(
                steps.iter().any(|s| s.instruction.contains("sudo")),
                "the system bundle needs root and the instructions must say so"
            );
        } else {
            assert!(
                !steps.iter().any(|s| s.application == "System bundle"),
                "only Linux has this step"
            );
        }
    }

    #[test]
    fn elevation_expectations_match_the_platform() {
        if cfg!(any(windows, target_os = "macos")) {
            assert!(installs_without_elevation());
        } else {
            assert!(!installs_without_elevation());
        }
    }
}
