//! External NetBird instance detection (WP-45 §5 step 10, §3.3): before a
//! managed kernel-mode instance starts, check for another NetBird already
//! running on the host — the system default control socket, a responding
//! daemon behind it, or an existing NetBird network interface. Finding a
//! live kernel-mode NetBird blocks the managed instance with a reason
//! (two kernel instances would fight over routes and the interface).
//! Userspace (netstack) instances are unaffected.
//!
//! The probe results are injected so the detection logic is unit-testable
//! without a real system (WP-45 §6: 单元测试，模拟的查询结果).

/// The system service's default control socket (see [`crate::args`]).
pub const SYSTEM_SOCKET: &str = crate::args::SYSTEM_CONTROL_ADDR;

/// Result of one system probe round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemProbe {
    /// The system default control socket file exists.
    pub socket: bool,
    /// A network interface created by NetBird exists (`wt0`, `netbird0`,
    /// `utun*` with the netbird scheme on macOS).
    pub iface: bool,
}

impl SystemProbe {
    pub fn any(&self) -> bool {
        self.socket || self.iface
    }
}

/// Whether a managed kernel-mode instance may start: `None` means yes,
/// `Some(reason)` blocks it.
pub fn kernel_block_reason(probe: &SystemProbe, daemon_connected: bool) -> Option<&'static str> {
    if probe.any() && daemon_connected {
        Some(
            "检测到系统上已有一个已连接的内核模式 NetBird（控制套接字或网卡已存在）；\
             内核模式实例同时只能有一个，请先停止系统 NetBird 服务",
        )
    } else {
        None
    }
}

/// Probes the host: the default control socket and, on Linux, the
/// `/sys/class/net` entries. Best effort — any error counts as "not
/// found". `daemon_connected` must be provided by the caller (it runs
/// `netbird status` against the system socket).
pub async fn probe_system() -> SystemProbe {
    let socket = std::path::Path::new(SYSTEM_SOCKET)
        .try_exists()
        .unwrap_or(false);
    SystemProbe {
        socket,
        iface: netbird_iface_exists().await,
    }
}

/// Linux: scan `/sys/class/net` for NetBird's interface names. Other
/// platforms report false (the check is best effort there).
async fn netbird_iface_exists() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
            return false;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), "wt0" | "netbird0" | "netbird") {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Convenience for tests: build a probe from booleans.
pub fn probe(socket: bool, iface: bool) -> SystemProbe {
    SystemProbe { socket, iface }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netbird_external_instance_detected() {
        // Socket present and daemon connected: kernel instance blocked.
        assert!(kernel_block_reason(&probe(true, false), true).is_some());
        // Interface alone also proves an active kernel NetBird.
        assert!(kernel_block_reason(&probe(false, true), true).is_some());
        // Traces exist but the daemon is not connected: no block (the
        // leftover socket of a stopped service is not a live NetBird).
        assert_eq!(kernel_block_reason(&probe(true, true), false), None);
        // Nothing on the host: no block.
        assert_eq!(kernel_block_reason(&probe(false, false), false), None);
        assert_eq!(kernel_block_reason(&probe(false, false), true), None);
        assert!(probe(true, false).any());
        assert!(probe(false, true).any());
        assert!(!probe(false, false).any());
    }
}
