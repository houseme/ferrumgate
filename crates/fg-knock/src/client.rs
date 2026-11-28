//! fwknop client command and `~/.fwknoprc` stanza generation (WP-54 §3.3
//! "客户端对话框"): the "client" dialog fills the rule's (or identity's)
//! keys — empty keys are generated at 32 / 64 bytes like `fwknop -k` — and
//! hands the command to the user.

use base64::Engine as _;

use crate::model::{Identity, Rule, limits};

/// Server address plus the client's own address for `-a`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientTarget {
    /// The Gately host (`-D`).
    pub server: String,
    /// The address to admit; empty means `-s` (source address).
    pub address: String,
}

/// Keys shown in the client dialog: shared or per identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientKeys {
    /// base64 encryption key (`--key-base64-rijndael`).
    pub enc: String,
    /// base64 HMAC key (`--key-base64-hmac`).
    pub hmac: String,
    /// Whether the values were freshly generated (shown as a hint).
    pub generated: bool,
}

/// Resolves the keys for a rule (shared) or one of its identities;
/// missing values are generated and reported via [`ClientKeys::generated`].
pub fn resolve_keys(rule: &Rule, identity: Option<&Identity>) -> ClientKeys {
    let (enc, hmac) = match identity {
        None => (rule.enc_key.clone(), rule.hmac_key.clone()),
        Some(identity) => (identity.enc_key.clone(), identity.hmac_key.clone()),
    };
    let (enc_empty, hmac_empty) = (enc.is_empty(), hmac.is_empty());
    ClientKeys {
        enc: if enc_empty {
            generate_key(limits::GENERATED_ENC_KEY_BYTES)
        } else {
            enc
        },
        hmac: if hmac_empty {
            generate_key(limits::GENERATED_HMAC_KEY_BYTES)
        } else {
            hmac
        },
        generated: enc_empty || hmac_empty,
    }
}

/// One fresh random key, base64 (`fwknop -k` equivalent lengths).
pub fn generate_key(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("OS entropy source is available");
    base64::engine::general_purpose::STANDARD.encode(buffer)
}

/// The `-A` access list: `tcp/22,udp/53`.
pub fn access_list(rule: &Rule) -> String {
    rule.ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The fwknop command for one knock:
/// `fwknop -A tcp/22 -a <address> -D <server> --use-hmac
///  --key-base64-rijndael <enc> --key-base64-hmac <hmac>`.
pub fn command(rule: &Rule, target: &ClientTarget, keys: &ClientKeys) -> String {
    let mut parts = vec!["fwknop".to_owned(), "-A".to_owned(), access_list(rule)];
    if target.address.is_empty() {
        parts.push("-s".to_owned());
    } else {
        parts.push("-a".to_owned());
        parts.push(target.address.clone());
    }
    parts.push("-D".to_owned());
    parts.push(target.server.clone());
    parts.push("--use-hmac".to_owned());
    parts.push("--key-base64-rijndael".to_owned());
    parts.push(keys.enc.clone());
    parts.push("--key-base64-hmac".to_owned());
    parts.push(keys.hmac.clone());
    parts.join(" ")
}

/// The `~/.fwknoprc` stanza for the same knock. Keys stay in the file —
/// fwknop requires `:KEY:`-style protection, so the stanza is only shown,
/// never auto-written.
pub fn fwknoprc_stanza(rule: &Rule, target: &ClientTarget, keys: &ClientKeys) -> String {
    let address = if target.address.is_empty() {
        "-s".to_owned()
    } else {
        target.address.clone()
    };
    format!(
        "[{name}]\nSPA_SERVER          {server}\nACCESS              {access}\nALLOW_IP            {address}\nUSE_HMAC            Y\nKEY_BASE64          {enc}\nHMAC_KEY_BASE64     {hmac}\n",
        name = stanza_name(rule, target),
        server = target.server,
        access = access_list(rule),
        enc = keys.enc,
        hmac = keys.hmac,
    )
}

/// Stanza name: the rule key (fwknoprc section labels are free-form).
fn stanza_name(rule: &Rule, _target: &ClientTarget) -> String {
    rule.key.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Access, Proto};

    fn rule() -> Rule {
        Rule {
            key: "a1b2c3d4e5f6".into(),
            name: "ssh".into(),
            enable: true,
            ports: vec![Access::new(Proto::Tcp, 22)],
            enc_key: "enc-b64".into(),
            hmac_key: "hmac-b64".into(),
            ..Rule::default()
        }
    }

    #[test]
    fn client_command_matches_fwknop_format() {
        let target = ClientTarget {
            server: "gate.example.com".into(),
            address: "203.0.113.7".into(),
        };
        let keys = ClientKeys {
            enc: "enc-b64".into(),
            hmac: "hmac-b64".into(),
            generated: false,
        };
        let command = command(&rule(), &target, &keys);
        assert_eq!(
            command,
            "fwknop -A tcp/22 -a 203.0.113.7 -D gate.example.com --use-hmac --key-base64-rijndael enc-b64 --key-base64-hmac hmac-b64"
        );
    }

    #[test]
    fn client_command_without_address_uses_source_flag() {
        let target = ClientTarget {
            server: "10.0.0.1".into(),
            address: String::new(),
        };
        let keys = ClientKeys {
            enc: "e".into(),
            hmac: "h".into(),
            generated: false,
        };
        assert!(command(&rule(), &target, &keys).contains(" -s -D 10.0.0.1"));
    }

    #[test]
    fn stanza_lists_server_access_and_keys() {
        let target = ClientTarget {
            server: "gate.example.com".into(),
            address: "203.0.113.7".into(),
        };
        let keys = ClientKeys {
            enc: "enc-b64".into(),
            hmac: "hmac-b64".into(),
            generated: false,
        };
        let stanza = fwknoprc_stanza(&rule(), &target, &keys);
        assert!(stanza.starts_with("[a1b2c3d4e5f6]\n"));
        assert!(stanza.contains("SPA_SERVER          gate.example.com"));
        assert!(stanza.contains("ACCESS              tcp/22"));
        assert!(stanza.contains("KEY_BASE64          enc-b64"));
        assert!(stanza.contains("HMAC_KEY_BASE64     hmac-b64"));
        // Multiple ports join with commas.
        let mut rule = rule();
        rule.ports = vec![Access::new(Proto::Tcp, 22), Access::new(Proto::Udp, 53)];
        assert!(fwknoprc_stanza(&rule, &target, &keys).contains("tcp/22,udp/53"));
    }

    #[test]
    fn resolve_keys_generates_missing_material() {
        let keys = resolve_keys(&rule(), None);
        assert_eq!(keys.enc, "enc-b64");
        assert_eq!(keys.hmac, "hmac-b64");
        assert!(!keys.generated);
        let mut empty = rule();
        empty.enc_key.clear();
        empty.hmac_key.clear();
        let generated = resolve_keys(&empty, None);
        assert!(generated.generated);
        // Same lengths as `fwknop -k`: 32-byte enc, 64-byte hmac.
        use base64::Engine as _;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&generated.enc)
                .unwrap()
                .len(),
            limits::GENERATED_ENC_KEY_BYTES
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&generated.hmac)
                .unwrap()
                .len(),
            limits::GENERATED_HMAC_KEY_BYTES
        );
        // Each identity resolves to its own keys.
        let identity = Identity {
            id: "alice".into(),
            name: "Alice".into(),
            enable: true,
            enc_key: "alice-enc".into(),
            hmac_key: "alice-hmac".into(),
            remark: String::new(),
        };
        let hers = resolve_keys(&rule(), Some(&identity));
        assert_eq!(
            (hers.enc.as_str(), hers.hmac.as_str()),
            ("alice-enc", "alice-hmac")
        );
    }
}
