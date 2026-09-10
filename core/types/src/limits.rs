//! Resource limits.
//!
//! Hexora talks to systems that may be actively hostile. A target can answer with a
//! multi-gigabyte body, a header block that never ends, or 40 bytes of gzip that
//! expand to 40 GB. None of that may take the application down, so every network
//! path in the engine is bounded by a [`Limits`] value carried through the call.
//!
//! The defaults here are deliberately generous enough for real applications and
//! strict enough to survive `docs/threat-model.md`'s hostile-target cases.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{HexoraError, LimitError, Result};

/// Bounds applied to a single HTTP exchange.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Maximum size of the response header block, in bytes.
    pub max_header_bytes: usize,
    /// Maximum number of header fields.
    pub max_header_count: usize,
    /// Maximum body size retained in memory, in bytes.
    pub max_body_bytes: u64,
    /// Maximum size a body may reach *after* content-decoding.
    pub max_decompressed_bytes: u64,
    /// Maximum expansion ratio permitted while decompressing.
    ///
    /// Ratio alone is not enough (a small bomb has a huge ratio, a large legitimate
    /// JSON file has a modest one), so this works together with
    /// [`Limits::max_decompressed_bytes`].
    pub max_decompression_ratio: f64,
    /// Maximum redirects followed automatically.
    pub max_redirects: u8,
    /// Deadline for establishing a TCP connection.
    pub connect_timeout: Duration,
    /// Deadline for the TLS handshake.
    pub tls_timeout: Duration,
    /// Deadline for receiving the response head.
    pub read_head_timeout: Duration,
    /// Deadline for the whole exchange.
    pub total_timeout: Duration,
    /// Maximum concurrent in-flight requests per host.
    pub max_connections_per_host: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 256 * 1024,
            max_header_count: 200,
            max_body_bytes: 100 * 1024 * 1024,
            max_decompressed_bytes: 200 * 1024 * 1024,
            max_decompression_ratio: 200.0,
            max_redirects: 10,
            connect_timeout: Duration::from_secs(10),
            tls_timeout: Duration::from_secs(10),
            read_head_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(120),
            max_connections_per_host: 16,
        }
    }
}

impl Limits {
    /// Tighter limits for automated, high-volume subsystems (scanner, fuzzer), where
    /// thousands of requests are in flight and a single slow host must not stall the
    /// run.
    pub fn automated() -> Self {
        Self {
            max_body_bytes: 10 * 1024 * 1024,
            max_decompressed_bytes: 20 * 1024 * 1024,
            read_head_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            ..Self::default()
        }
    }

    /// Checks a declared or observed body size.
    pub fn check_body_size(&self, size: u64) -> Result<()> {
        if size > self.max_body_bytes {
            return Err(HexoraError::LimitExceeded(LimitError::BodyTooLarge {
                limit: self.max_body_bytes,
            }));
        }
        Ok(())
    }

    /// Checks the header block size.
    pub fn check_header_size(&self, size: usize) -> Result<()> {
        if size > self.max_header_bytes {
            return Err(HexoraError::LimitExceeded(LimitError::HeadersTooLarge {
                limit: self.max_header_bytes,
            }));
        }
        Ok(())
    }

    /// Checks decompression progress against both the absolute cap and the ratio cap.
    ///
    /// Called incrementally as bytes are produced, never only at the end — the point
    /// is to stop a bomb before it is fully expanded.
    pub fn check_decompression(&self, compressed: u64, decompressed: u64) -> Result<()> {
        if decompressed > self.max_decompressed_bytes {
            let ratio = if compressed == 0 {
                f64::INFINITY
            } else {
                decompressed as f64 / compressed as f64
            };
            return Err(HexoraError::LimitExceeded(LimitError::DecompressionBomb {
                limit: self.max_decompressed_bytes,
                ratio,
            }));
        }
        // Only apply the ratio check once there is enough output for the ratio to be
        // meaningful; tiny inputs produce wild ratios for legitimate reasons.
        const RATIO_FLOOR_BYTES: u64 = 64 * 1024;
        if compressed > 0 && decompressed > RATIO_FLOOR_BYTES {
            let ratio = decompressed as f64 / compressed as f64;
            if ratio > self.max_decompression_ratio {
                return Err(HexoraError::LimitExceeded(LimitError::DecompressionBomb {
                    limit: self.max_decompressed_bytes,
                    ratio,
                }));
            }
        }
        Ok(())
    }

    /// Checks a redirect chain length.
    pub fn check_redirects(&self, followed: u8) -> Result<()> {
        if followed >= self.max_redirects {
            return Err(HexoraError::LimitExceeded(LimitError::TooManyRedirects {
                limit: self.max_redirects,
            }));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_body_is_allowed() {
        assert!(Limits::default().check_body_size(1024 * 1024).is_ok());
    }

    #[test]
    fn an_oversized_body_is_rejected() {
        assert!(Limits::default().check_body_size(u64::MAX).is_err());
    }

    #[test]
    fn a_classic_zip_bomb_is_stopped_by_the_ratio_check() {
        let limits = Limits::default();
        // 1 MB in, 500 MB out: ratio 500x, well past the 200x cap.
        let err = limits.check_decompression(1024 * 1024, 500 * 1024 * 1024).unwrap_err();
        assert_eq!(err.code(), "limit_exceeded");
    }

    #[test]
    fn a_slow_bomb_is_stopped_by_the_absolute_cap() {
        // Ratio only 2x, so the ratio check passes, but the output is enormous.
        let limits = Limits::default();
        assert!(limits.check_decompression(500 * 1024 * 1024, 1000 * 1024 * 1024).is_err());
    }

    #[test]
    fn ordinary_compression_ratios_pass() {
        let limits = Limits::default();
        // 1 MB of JSON compressing to 100 KB is a 10x ratio: entirely normal.
        assert!(limits.check_decompression(100 * 1024, 1024 * 1024).is_ok());
    }

    #[test]
    fn tiny_payloads_do_not_trip_the_ratio_check() {
        let limits = Limits::default();
        // 20 bytes expanding to 32 KB is a 1600x ratio but harmless, and below the
        // ratio floor, so it must be allowed.
        assert!(limits.check_decompression(20, 32 * 1024).is_ok());
    }

    #[test]
    fn zero_compressed_bytes_does_not_divide_by_zero() {
        let limits = Limits::default();
        let err = limits.check_decompression(0, u64::MAX).unwrap_err();
        assert_eq!(err.code(), "limit_exceeded");
    }

    #[test]
    fn redirect_loops_terminate() {
        let limits = Limits::default();
        assert!(limits.check_redirects(0).is_ok());
        assert!(limits.check_redirects(limits.max_redirects).is_err());
    }

    #[test]
    fn automated_limits_are_stricter_than_interactive_ones() {
        let interactive = Limits::default();
        let automated = Limits::automated();
        assert!(automated.max_body_bytes < interactive.max_body_bytes);
        assert!(automated.total_timeout < interactive.total_timeout);
    }
}
