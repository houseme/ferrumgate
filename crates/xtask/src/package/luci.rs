//! Architecture-independent LuCI application (`luci-app-ferrumgate`) staging
//! helper (WP-92 §3.3).
//!
//! Reads and writes the exact same UCI configuration (`/etc/config/ferrumgate`,
//! `main.enabled` and `main.port`) consumed by the procd init script in
//! [`crate::package::openwrt`].

use std::path::Path;

use anyhow::{Context, Result};

use crate::package::openwrt::{OpenwrtVersion, convert_version};

/// LuCI menu descriptor installed at `/usr/share/luci/menu.d/luci-app-ferrumgate.json`.
pub const LUCI_MENU_JSON: &str = r#"{
  "admin/services/ferrumgate": {
    "title": "FerrumGate",
    "order": 60,
    "action": {
      "type": "view",
      "path": "ferrumgate/config"
    },
    "depends": {
      "acl": [ "luci-app-ferrumgate" ]
    }
  }
}
"#;

/// RPCD ACL descriptor granting read/write access to UCI `ferrumgate`.
pub const LUCI_ACL_JSON: &str = r#"{
  "luci-app-ferrumgate": {
    "description": "Grant UCI access for FerrumGate LuCI configuration",
    "read": {
      "uci": [ "ferrumgate" ]
    },
    "write": {
      "uci": [ "ferrumgate" ]
    }
  }
}
"#;

/// LuCI client-side view editing `/etc/config/ferrumgate` (`main.enabled`, `main.port`).
pub const LUCI_VIEW_JS: &str = r#"'use strict';
'require view';
'require form';

return view.extend({
	render: function () {
		var m, s, o;

		m = new form.Map('ferrumgate', _('FerrumGate'),
			_('Configure the FerrumGate service managed by procd.'));

		s = m.section(form.NamedSection, 'main', 'main', _('General Settings'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('Admin Port'),
			_('Optional port override (1-65535). Preserves the configured listen host.'));
		o.datatype = 'port';
		o.placeholder = '16680';
		o.rmempty = true;

		return m.render();
	}
});
"#;

/// Renders the opkg `control` file for `luci-app-ferrumgate` (`Architecture: all`).
pub fn render_luci_control(version: &OpenwrtVersion) -> String {
    format!(
        "Package: luci-app-ferrumgate\n\
         Version: {}\n\
         Architecture: all\n\
         Depends: ferrumgate, luci-base\n\
         Maintainer: FerrumGate <https://github.com/houseme/ferrumgate>\n\
         Section: luci\n\
         Priority: optional\n\
         Description: LuCI support for FerrumGate\n",
        version.ipk
    )
}

/// Renders the apk-tools v3 package info for `luci-app-ferrumgate` (`arch = noarch`).
pub fn render_luci_apk_pkginfo(version: &OpenwrtVersion) -> String {
    format!(
        "pkgname = luci-app-ferrumgate\n\
         pkgver = {}\n\
         pkgdesc = LuCI support for FerrumGate\n\
         url = https://github.com/houseme/ferrumgate\n\
         arch = noarch\n\
         license = Apache-2.0\n\
         depend = ferrumgate\n\
         depend = luci-base\n",
        version.apk
    )
}

/// Stages the architecture-independent `luci-app-ferrumgate` tree.
pub fn stage_luci_tree(version: &str, staging_dir: &Path) -> Result<OpenwrtVersion> {
    let parsed_ver = convert_version(version)?;

    if staging_dir.exists() {
        std::fs::remove_dir_all(staging_dir)
            .with_context(|| format!("failed to clean {}", staging_dir.display()))?;
    }

    let rootfs = staging_dir.join("rootfs");
    let control = staging_dir.join("control");
    let apk_meta = staging_dir.join("apk");

    for dir in [
        rootfs.join("usr/share/luci/menu.d"),
        rootfs.join("usr/share/rpcd/acl.d"),
        rootfs.join("www/luci-static/resources/view/ferrumgate"),
        control.clone(),
        apk_meta.clone(),
    ] {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }

    std::fs::write(
        rootfs.join("usr/share/luci/menu.d/luci-app-ferrumgate.json"),
        LUCI_MENU_JSON,
    )?;
    std::fs::write(
        rootfs.join("usr/share/rpcd/acl.d/luci-app-ferrumgate.json"),
        LUCI_ACL_JSON,
    )?;
    std::fs::write(
        rootfs.join("www/luci-static/resources/view/ferrumgate/config.js"),
        LUCI_VIEW_JS,
    )?;
    std::fs::write(control.join("control"), render_luci_control(&parsed_ver))?;
    std::fs::write(
        apk_meta.join("PKGINFO"),
        render_luci_apk_pkginfo(&parsed_ver),
    )?;

    Ok(parsed_ver)
}
