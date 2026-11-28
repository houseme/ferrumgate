//! Platform layer of the firewall sync. Only Linux touches the system:
//! the command backend drives `nft`, `iptables` (legacy) and `ipset` with
//! argument arrays and stdin payloads (never a shell), with a hard
//! [`NFT_TIMEOUT`] per invocation and error classification for the status
//! display. Every other platform compiles the explicit unsupported
//! implementation reporting [`FwError::Unsupported`] / the `not_linux`
//! reason; the public API is identical on both.

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use std::collections::BTreeMap;

    use super::super::{BanBackend, FwBackend, FwElement, FwError, FwUnavailable};

    /// Probes the host: always unavailable off Linux.
    pub(crate) fn detect() -> Result<Arc<dyn BanBackend>, FwUnavailable> {
        Err(FwUnavailable::not_linux())
    }

    /// The explicit unsupported implementation for platforms without
    /// firewall support; every operation fails without touching the
    /// system.
    #[allow(dead_code)]
    pub(crate) struct UnsupportedBackend;

    #[allow(dead_code)]
    impl BanBackend for UnsupportedBackend {
        fn kind(&self) -> Option<FwBackend> {
            None
        }

        fn rules_present(&self) -> Result<bool, FwError> {
            Err(FwError::Unsupported)
        }

        fn apply_full(&self, _elements: &[FwElement]) -> Result<(), FwError> {
            Err(FwError::Unsupported)
        }

        fn add_elements(&self, _elements: &[FwElement]) -> Result<(), FwError> {
            Err(FwError::Unsupported)
        }

        fn del_elements(&self, _elements: &[FwElement]) -> Result<(), FwError> {
            Err(FwError::Unsupported)
        }

        fn read_counters(&self) -> Result<BTreeMap<String, u64>, FwError> {
            Err(FwError::Unsupported)
        }

        fn remove_all(&self) -> Result<(), FwError> {
            Err(FwError::Unsupported)
        }
    }

    use std::sync::Arc;
}

#[cfg(not(target_os = "linux"))]
pub(crate) use unsupported::detect;

#[cfg(target_os = "linux")]
pub(crate) use linux::detect;

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::BTreeMap,
        io::{Read as _, Write as _},
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use super::super::{
        BanBackend, FwBackend, FwElement, FwError, FwUnavailable, IPT_CHAIN_DENY, IPT_CHAIN_PRE,
        IPT_SET_BAN4, IPT_SET_BAN6, IPT_TABLE, NFT_TIMEOUT, SetName, TABLE, render,
    };

    /// nftables backend: scripts go to `nft -f -` on stdin.
    struct NftBackend {
        nft: PathBuf,
    }

    impl BanBackend for NftBackend {
        fn kind(&self) -> Option<FwBackend> {
            Some(FwBackend::Nftables)
        }

        fn rules_present(&self) -> Result<bool, FwError> {
            match run(None, &self.nft, &["-j", "list", "table", "inet", TABLE]) {
                Ok(out) => Ok(render::parse_guard_table(&out)?.rules_present()),
                Err(FwError::CommandFailed(msg)) if missing_table(&msg) => Ok(false),
                Err(error) => Err(error),
            }
        }

        fn apply_full(&self, elements: &[FwElement]) -> Result<(), FwError> {
            run(
                Some(&render::guard_script(elements)),
                &self.nft,
                &["-f", "-"],
            )
            .map(|_| ())
        }

        fn add_elements(&self, elements: &[FwElement]) -> Result<(), FwError> {
            run(
                Some(&render::nft_add_script(elements)),
                &self.nft,
                &["-f", "-"],
            )
            .map(|_| ())
        }

        fn del_elements(&self, elements: &[FwElement]) -> Result<(), FwError> {
            run(
                Some(&render::nft_del_script(elements)),
                &self.nft,
                &["-f", "-"],
            )
            .map(|_| ())
        }

        fn read_counters(&self) -> Result<BTreeMap<String, u64>, FwError> {
            let out = run(None, &self.nft, &["-j", "list", "table", "inet", TABLE])?;
            Ok(render::parse_guard_table(&out)?.counters)
        }

        fn remove_all(&self) -> Result<(), FwError> {
            run(Some(&render::nft_remove_script()), &self.nft, &["-f", "-"]).map(|_| ())
        }
    }

    /// Whether an nft error just means the table does not exist (structure
    /// check on a fresh host): the answer is "not present", not a failure.
    fn missing_table(msg: &str) -> bool {
        let low = msg.to_lowercase();
        low.contains("no such file or directory") || low.contains("no such table")
    }

    /// iptables legacy + ipset backend: one mangle chain pair per family,
    /// ban addresses in ipset sets, CIDR bans as `GATELY_DENY` rules.
    struct IptBackend {
        ipt: PathBuf,
        ip6t: Option<PathBuf>,
        ipset: PathBuf,
    }

    impl IptBackend {
        /// The family binary, or `None` when the host has no IPv6 at all.
        fn bin_opt(&self, v6: bool) -> Option<&Path> {
            match v6 {
                true => self.ip6t.as_deref(),
                false => Some(&self.ipt),
            }
        }

        /// The deny elements of one family.
        fn deny_of<'a>(&self, v6: bool, elements: &'a [FwElement]) -> Vec<&'a FwElement> {
            let set = if v6 { SetName::Deny6 } else { SetName::Deny4 };
            elements
                .iter()
                .filter(|element| element.set == set)
                .collect()
        }

        /// Prepends the shared `-w -t mangle` arguments.
        fn args_for(&self, _v6: bool, rest: &[String]) -> Vec<String> {
            let mut args = vec!["-w".to_owned(), "-t".to_owned(), IPT_TABLE.to_owned()];
            args.extend(rest.iter().cloned());
            args
        }

        /// Recreates the chains of one family and installs the jump from
        /// `PREROUTING` (first position) when missing.
        fn setup_family(&self, v6: bool, elements: &[FwElement]) -> Result<(), FwError> {
            let Some(bin) = self.bin_opt(v6) else {
                return Ok(());
            };
            let query = |op: &str, chain: &str| -> Vec<String> {
                vec![
                    "-w".to_owned(),
                    "-t".to_owned(),
                    IPT_TABLE.to_owned(),
                    op.to_owned(),
                    chain.to_owned(),
                ]
            };
            if run(None, bin, &query("-S", IPT_CHAIN_PRE)).is_err() {
                run(None, bin, &query("-N", IPT_CHAIN_PRE))?;
            }
            run(None, bin, &query("-F", IPT_CHAIN_PRE))?;
            if run(None, bin, &query("-S", IPT_CHAIN_DENY)).is_err() {
                run(None, bin, &query("-N", IPT_CHAIN_DENY))?;
            }
            run(None, bin, &query("-F", IPT_CHAIN_DENY))?;
            for rule in render::ipt_pre_rules(v6) {
                run(None, bin, &self.args_for(v6, &rule))?;
            }
            for element in self.deny_of(v6, elements) {
                run(
                    None,
                    bin,
                    &self.args_for(v6, &render::ipt_deny_rule(&element.value)),
                )?;
            }
            let mut check = query("-C", "PREROUTING");
            check.extend(["-j".to_owned(), IPT_CHAIN_PRE.to_owned()]);
            if run(None, bin, &check).is_err() {
                let mut insert = query("-I", "PREROUTING");
                insert.extend(["1".to_owned(), "-j".to_owned(), IPT_CHAIN_PRE.to_owned()]);
                run(None, bin, &insert)?;
            }
            Ok(())
        }

        /// Whether one family still has the jump, the ban match rule and
        /// the deny chain wired up. Query failures other than missing
        /// rules (permission) surface as errors.
        fn family_present(&self, v6: bool) -> Result<bool, FwError> {
            let Some(bin) = self.bin_opt(v6) else {
                return Ok(true);
            };
            let query = |chain: &str| -> Vec<String> {
                vec![
                    "-w".to_owned(),
                    "-t".to_owned(),
                    IPT_TABLE.to_owned(),
                    "-S".to_owned(),
                    chain.to_owned(),
                ]
            };
            let jump = match run(None, bin, &query("PREROUTING")) {
                Ok(out) => out,
                Err(FwError::Permission) => return Err(FwError::Permission),
                Err(_) => return Ok(false),
            };
            if !jump
                .lines()
                .any(|line| line.contains(&format!("-j {IPT_CHAIN_PRE}")))
            {
                return Ok(false);
            }
            let ban_set = if v6 { IPT_SET_BAN6 } else { IPT_SET_BAN4 };
            let own = match run(None, bin, &query(IPT_CHAIN_PRE)) {
                Ok(out) => out,
                Err(FwError::Permission) => return Err(FwError::Permission),
                Err(_) => return Ok(false),
            };
            if !own.contains(&format!("--match-set {ban_set}"))
                || !own.contains(&format!("-j {IPT_CHAIN_DENY}"))
            {
                return Ok(false);
            }
            let deny = match run(None, bin, &query(IPT_CHAIN_DENY)) {
                Ok(out) => out,
                Err(FwError::Permission) => return Err(FwError::Permission),
                Err(_) => return Ok(false),
            };
            Ok(deny.contains("-j DROP"))
        }
    }

    impl BanBackend for IptBackend {
        fn kind(&self) -> Option<FwBackend> {
            Some(FwBackend::IptablesLegacy)
        }

        fn rules_present(&self) -> Result<bool, FwError> {
            for set in [IPT_SET_BAN4, IPT_SET_BAN6] {
                if run(None, &self.ipset, &["list", set]).is_err() {
                    return Ok(false);
                }
            }
            if !self.family_present(false)? {
                return Ok(false);
            }
            if self.ip6t.is_some() && !self.family_present(true)? {
                return Ok(false);
            }
            Ok(true)
        }

        fn apply_full(&self, elements: &[FwElement]) -> Result<(), FwError> {
            let restore = render::ipset_restore_full(&render::ipset_ban_elements(elements));
            run(Some(&restore), &self.ipset, &["restore", "-exist"]).map(|_| ())?;
            self.setup_family(false, elements)?;
            self.setup_family(true, elements)?;
            Ok(())
        }

        fn add_elements(&self, elements: &[FwElement]) -> Result<(), FwError> {
            let ban = render::ipset_ban_elements(elements);
            if !ban.is_empty() {
                run(
                    Some(&render::ipset_restore_adds(&ban)),
                    &self.ipset,
                    &["restore", "-exist"],
                )
                .map(|_| ())?;
            }
            for v6 in [false, true] {
                for element in self.deny_of(v6, elements) {
                    let Some(bin) = self.bin_opt(v6) else {
                        continue;
                    };
                    run(
                        None,
                        bin,
                        &self.args_for(v6, &render::ipt_deny_rule(&element.value)),
                    )?;
                }
            }
            Ok(())
        }

        fn del_elements(&self, elements: &[FwElement]) -> Result<(), FwError> {
            let ban = render::ipset_ban_elements(elements);
            if !ban.is_empty() {
                run(
                    Some(&render::ipset_restore_dels(&ban)),
                    &self.ipset,
                    &["restore", "-exist"],
                )
                .map(|_| ())?;
            }
            for v6 in [false, true] {
                for element in self.deny_of(v6, elements) {
                    let Some(bin) = self.bin_opt(v6) else {
                        continue;
                    };
                    run(
                        None,
                        bin,
                        &self.args_for(v6, &render::ipt_deny_delete_rule(&element.value)),
                    )?;
                }
            }
            Ok(())
        }

        fn read_counters(&self) -> Result<BTreeMap<String, u64>, FwError> {
            // iptables-legacy counters come from the locale-dependent `-L`
            // output; the status shows the nftables counters, this backend
            // reports none.
            Ok(BTreeMap::new())
        }

        fn remove_all(&self) -> Result<(), FwError> {
            for v6 in [false, true] {
                let Some(bin) = self.bin_opt(v6) else {
                    continue;
                };
                let query = |op: &str, chain: &str| -> Vec<String> {
                    vec![
                        "-w".to_owned(),
                        "-t".to_owned(),
                        IPT_TABLE.to_owned(),
                        op.to_owned(),
                        chain.to_owned(),
                    ]
                };
                // Every step tolerates absence: after a crash only some
                // pieces may still exist.
                for _ in 0..3 {
                    let mut delete = query("-D", "PREROUTING");
                    delete.extend(["-j".to_owned(), IPT_CHAIN_PRE.to_owned()]);
                    let _ = run(None, bin, &delete);
                }
                for op in ["-F", "-X"] {
                    let _ = run(None, bin, &query(op, IPT_CHAIN_PRE));
                    let _ = run(None, bin, &query(op, IPT_CHAIN_DENY));
                }
            }
            let _ = run(None, &self.ipset, &["destroy", IPT_SET_BAN4]);
            let _ = run(None, &self.ipset, &["destroy", IPT_SET_BAN6]);
            Ok(())
        }
    }

    /// Probes the host: nftables first, iptables legacy + ipset when the
    /// kernel has no nf_tables. Probe failures are reported with a stable
    /// reason code; nothing is written here.
    pub(super) fn detect() -> Result<Arc<dyn BanBackend>, FwUnavailable> {
        let nft = look_path("nft");
        if let Some(path) = &nft {
            match run(Some("list tables\n"), path, &["-f", "-"]) {
                Ok(_) => {
                    return Ok(Arc::new(NftBackend { nft: path.clone() }));
                }
                Err(FwError::Permission) => return Err(FwUnavailable::no_permission()),
                Err(error) => {
                    tracing::debug!(
                        module = "guard",
                        "nft probe failed, trying iptables legacy: {error}"
                    );
                }
            }
        }
        let ipt = find_legacy_bin("iptables");
        let ip6t = find_legacy_bin("ip6tables");
        let ipset = look_path("ipset");
        match (ipt, ipset) {
            (Some(ipt), Some(ipset)) => Ok(Arc::new(IptBackend { ipt, ip6t, ipset })),
            (Some(_), None) => Err(FwUnavailable::no_iptables()),
            (None, _) if nft.is_some() => Err(FwUnavailable::kernel_no_nf_tables()),
            (None, _) => Err(FwUnavailable::no_nft()),
        }
    }

    /// Finds a real legacy binary (`<name>-legacy` first, else `<name>`
    /// when it is not the nf_tables variant).
    fn find_legacy_bin(name: &str) -> Option<PathBuf> {
        if let Some(path) = look_path(&format!("{name}-legacy")) {
            return Some(path);
        }
        let path = look_path(name)?;
        match run(None, &path, &["-V"]) {
            Ok(version) if !version.contains("nf_tables") => Some(path),
            _ => None,
        }
    }

    /// Looks `name` up in PATH and then the usual sbin directories
    /// (`/usr/sbin` and friends are frequently missing from PATH when
    /// running as a service).
    fn look_path(name: &str) -> Option<PathBuf> {
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        dirs.extend(["/usr/sbin", "/sbin", "/usr/bin"].iter().map(PathBuf::from));
        dirs.iter()
            .map(|dir| dir.join(name))
            .find(|path| is_executable(path))
    }

    fn is_executable(path: &Path) -> bool {
        match path.metadata() {
            Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            Err(_) => false,
        }
    }

    /// Runs `bin` with an argument array (never a shell) and an optional
    /// stdin payload, with a hard [`NFT_TIMEOUT`]. Output is captured;
    /// failures are classified for the status display.
    fn run<S: AsRef<std::ffi::OsStr>>(
        stdin: Option<&str>,
        bin: &Path,
        args: &[S],
    ) -> Result<String, FwError> {
        let mut cmd = Command::new(bin);
        cmd.args(args);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => return Err(classify(&error.to_string())),
        };
        if let Some((input, mut pipe)) = stdin.zip(child.stdin.take()) {
            let _ = pipe.write_all(input.as_bytes());
        }
        let stdout_t = child.stdout.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                buf
            })
        });
        let stderr_t = child.stderr.take().map(|mut pipe| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                buf
            })
        });
        let deadline = Instant::now() + NFT_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(FwError::CommandFailed(format!(
                        "{} 执行超时",
                        bin.display()
                    )));
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => return Err(classify(&error.to_string())),
            }
        };
        let stdout = stdout_t
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default();
        let stderr = stderr_t
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default();
        if !status.success() {
            let mut msg = String::from_utf8_lossy(&stderr).trim().to_owned();
            if msg.is_empty() {
                msg = status.to_string();
            }
            return Err(classify(&msg));
        }
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{FwStatus, FwUnavailable, status_text};
    use std::collections::BTreeMap;

    use super::detect;

    /// Status text stays stable for the not_linux reason on every
    /// platform (this is what a macOS / Windows host reports).
    #[test]
    fn status_text_reports_not_linux_reason() {
        let status = FwStatus {
            enabled: true,
            unavailable: Some(FwUnavailable::not_linux()),
            ..FwStatus::default()
        };
        assert!(status_text(&status).contains("只支持 Linux"));
    }

    /// The unsupported stub fails every operation without side effects.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn unsupported_backend_reports_unsupported_everywhere() {
        use super::super::{BanBackend, FwError};
        use super::unsupported::UnsupportedBackend;
        let backend = UnsupportedBackend;
        assert_eq!(backend.kind(), None);
        assert_eq!(backend.rules_present(), Err(FwError::Unsupported));
        assert_eq!(backend.apply_full(&[]), Err(FwError::Unsupported));
        assert_eq!(backend.add_elements(&[]), Err(FwError::Unsupported));
        assert_eq!(backend.del_elements(&[]), Err(FwError::Unsupported));
        assert_eq!(
            backend.read_counters(),
            Err::<BTreeMap<String, u64>, FwError>(FwError::Unsupported)
        );
        assert_eq!(backend.remove_all(), Err(FwError::Unsupported));
        assert!(
            matches!(detect(), Err(unavailable) if unavailable.code == "not_linux"),
            "detection reports the platform limitation"
        );
    }

    /// Probe-path only: on real Linux the detection either finds a backend
    /// or reports one of the documented reasons; it never writes.
    #[test]
    #[cfg(target_os = "linux")]
    fn detect_probe_reports_backend_or_reason_without_writes() {
        match detect() {
            Ok(backend) => assert!(backend.kind().is_some()),
            Err(unavailable) => assert!(
                [
                    "no_permission",
                    "no_nft",
                    "no_iptables",
                    "kernel_no_nf_tables"
                ]
                .contains(&unavailable.code),
                "unexpected reason: {unavailable:?}"
            ),
        }
    }
}
