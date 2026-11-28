//! Detection of the external setups the WP-91 jobs and tests can require:
//! Pebble (ACME end to end), Docker (Alpine smoke tests), the real-network
//! opt-in and the real Lucky sample (WP-91 §3.2 `Env`). Tests and jobs read
//! this and skip with an explicit reason instead of vanishing quietly
//! (WP-91 §3.3「需要外部环境的测试」).

use std::path::PathBuf;

use crate::ci::jobs::Job;

/// The environment variables mirror the upstream `CONTRIBUTING.md` contract
/// (WP-91 §2): `GATELY_PEBBLE_BIN`, `GATELY_PEBBLE_SRC`, `GATELY_NET_TEST=1`
/// and `GATELY_LUCKY_SAMPLE`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env {
    pub has_pebble: bool,
    pub has_docker: bool,
    pub net_test: bool,
    pub lucky_sample: Option<PathBuf>,
}

impl Env {
    /// `Err(reason)` when the job's external setup is missing; the reason
    /// names the variable that provides it. Jobs without external needs are
    /// always ready.
    pub fn ready_for(&self, job: Job) -> Result<(), String> {
        match job {
            Job::Pebble if !self.has_pebble => Err(
                "needs Pebble: set GATELY_PEBBLE_BIN (path to the executable) or \
                 GATELY_PEBBLE_SRC (path to a checkout)"
                    .to_string(),
            ),
            Job::OpenwrtSmoke if !self.has_docker => {
                Err("needs Docker for the pinned-Alpine smoke-test container".to_string())
            }
            _ => Ok(()),
        }
    }

    /// Real public-network tests (real DNS providers, real notification
    /// channels) are never run in CI; locally they stay behind this opt-in.
    pub fn real_network_hint(&self) -> Option<String> {
        (!self.net_test).then(|| {
            "real-network tests stay skipped; set GATELY_NET_TEST=1 to enable them".to_string()
        })
    }
}

/// Probes the process environment; pure input for the skip decisions above.
pub fn detect() -> Env {
    Env {
        has_pebble: pebble_available(),
        has_docker: has_binary("docker"),
        net_test: std::env::var_os("GATELY_NET_TEST").is_some_and(|value| value == "1"),
        lucky_sample: std::env::var_os("GATELY_LUCKY_SAMPLE")
            .map(PathBuf::from)
            .filter(|path| path.exists()),
    }
}

fn pebble_available() -> bool {
    let bin = std::env::var_os("GATELY_PEBBLE_BIN")
        .map(PathBuf::from)
        .is_some_and(|path| path.is_file());
    let src = std::env::var_os("GATELY_PEBBLE_SRC")
        .map(PathBuf::from)
        .is_some_and(|path| path.is_dir());
    bin || src
}

/// PATH lookup without shelling out (works the same in CI and locally).
pub fn has_binary(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    let executable = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    std::env::split_paths(&paths).any(|dir| dir.join(&executable).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ci::jobs::Job;

    fn empty() -> Env {
        Env {
            has_pebble: false,
            has_docker: false,
            net_test: false,
            lucky_sample: None,
        }
    }

    #[test]
    fn env_detect_skips_with_reason() {
        // WP-91 §6: without Pebble / Docker the skip reasons must name the
        // setup, never fail silently or crash.
        let env = empty();
        let pebble = env.ready_for(Job::Pebble).unwrap_err();
        assert!(pebble.contains("GATELY_PEBBLE_BIN"), "{pebble}");
        let docker = env.ready_for(Job::OpenwrtSmoke).unwrap_err();
        assert!(docker.contains("Docker"), "{docker}");
        // Jobs without external needs are never blocked by the environment.
        for job in [Job::Clippy, Job::Matrix, Job::Docs] {
            assert!(
                env.ready_for(job).is_ok(),
                "{:?} needs no external setup",
                job
            );
        }
    }

    #[test]
    fn env_ready_when_setups_present() {
        let env = Env {
            has_pebble: true,
            has_docker: true,
            net_test: true,
            lucky_sample: None,
        };
        assert!(env.ready_for(Job::Pebble).is_ok());
        assert!(env.ready_for(Job::OpenwrtSmoke).is_ok());
        assert!(env.real_network_hint().is_none());
    }

    #[test]
    fn real_network_tests_report_the_opt_in() {
        let hint = empty().real_network_hint().expect("hint when net_test off");
        assert!(hint.contains("GATELY_NET_TEST"), "{hint}");
        let mut enabled = empty();
        enabled.net_test = true;
        assert!(enabled.real_network_hint().is_none());
    }
}
