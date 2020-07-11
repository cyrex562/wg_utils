use crate::defines::{WgcError, TEMPLATES};

use log::error;
use std::process::Command;
use std::result::Result as std_result;
use std::str;
use tera::Context;

///
/// mimics `sudo wg set wg4 peer PUBLIC_KEY allowed-ips 0.0.0.0/0`
///
pub fn add_peer(
    ifc_name: &str,
    endpoint: Option<String>,
    allowed_ips: &str,
    public_key: &str,
) -> std_result<(), WgcError> {
    // add config to
    let mut var_name = Command::new("sudo");
    let cmd = var_name.arg("wg").arg("set").arg(ifc_name).arg("peer").arg(public_key);

    if endpoint.is_some() {
        cmd.arg("endpoint").arg(endpoint.unwrap());
    }

    let mut result = cmd
        .arg("allowed-ips")
        .arg(allowed_ips)
        .output()
        .expect("failed to execute command");

    if !result.status.success() {
        error!(
            "failed to add peer to config: stdout: {}, stderr: {}",
            str::from_utf8(result.stdout.as_slice()).unwrap(),
            str::from_utf8(result.stderr.as_slice()).unwrap()
        );
        return Err(WgcError {
            message: format!("failed to add peer to config"),
        });
    }

    result = Command::new("sudo")
        .arg("wg-quick")
        .arg("save")
        .arg(&ifc_name)
        .output()
        .expect("failed execute command");
    if !result.status.success() {
        error!(
            "failed to save interface state to config: stdout: {}, stderr: {}",
            str::from_utf8(result.stdout.as_slice()).unwrap(),
            str::from_utf8(result.stderr.as_slice()).unwrap()
        );
        return Err(WgcError {
            message: format!("failed to save interface config"),
        });
    }
    Ok(())
}

pub fn remove_peer(ifc_name: &str, pub_key: &str) -> std_result<(), WgcError> {
    let mut output = Command::new("sudo")
        .arg("wg")
        .arg("set")
        .arg(&ifc_name)
        .arg("peer")
        .arg(&pub_key)
        .arg("remove")
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        error!(
            "failed to remove peer from interface: stdout: {}, stderr: {}",
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        );
        return Err(WgcError {
            message: String::from("failed to remove peer from interface"),
        });
    }

    output = Command::new("sudo")
        .arg("wg-quick")
        .arg("save")
        .arg(&ifc_name)
        .output()
        .expect("failed execute command");
    if !output.status.success() {
        error!(
            "failed to save interface state to config: stdout: {}, stderr: {}",
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        );
        return Err(WgcError {
            message: String::from("failed to save interface state to config file"),
        });
    }

    Ok(())
}

///
/// Generate a peer config
///
pub fn gen_peer_conf(
    public_key: &str,
    allowed_ips: &str,
    endpoint: &Option<String>,
    keepalive: &Option<u32>,
) -> Result<String, WgcError> {
    // let key_str = public_key;
    // let key_part = key_str.get(0..3).unwrap();
    let set_endpoint = endpoint.is_some();
    let ep = endpoint.clone().unwrap_or_else(|| "".to_string());
    let ka: u32 = keepalive.unwrap_or(25);
    let set_keepalive = keepalive.is_none();
    let mut ctx: Context = Context::new();
    ctx.insert("set_endpoint", &set_endpoint);
    if set_endpoint {
        ctx.insert("endpoint", &ep);
    }
    ctx.insert("public_key", &public_key);
    ctx.insert("allowed_ips", &allowed_ips);
    ctx.insert("set_keepalive", &set_keepalive);
    if set_keepalive {
        ctx.insert("keepalive", &ka);
    }

    match TEMPLATES.render("peer.conf.jn2", &ctx) {
        Ok(s) => Ok(s),
        Err(e) => {
            error!("failed to render peer conf template: {:?}", e);
            Err(WgcError {
                message: format!("failed to render peer conf template: {:?}", e),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen_logic::{gen_private_key, gen_public_key};
    use crate::interface_logic::{create_interface, gen_interface_conf, remove_interface};
    use crate::utils::init_logger;
    use log::debug;

    #[test]
    fn test_gen_peer_conf() {
        init_logger();
        let priv_key_res = gen_private_key();
        assert!(priv_key_res.is_ok());
        let priv_key = priv_key_res.unwrap();

        let addr = "192.0.0.1/24";
        let allowed_ips = "192.0.0.0/24";
        let endpoint = "192.1.0.1:51820";
        let port = 51820;
        let keepalive = 25;

        let result = gen_interface_conf(&priv_key, &addr, &port);
        assert!(result.is_ok());
        debug!("interface config: {:?}", result.unwrap());

        let pubkey_res = gen_public_key(&priv_key);
        assert!(pubkey_res.is_ok());
        let pubkey = pubkey_res.unwrap();

        let gen_peer_res = gen_peer_conf(&pubkey, allowed_ips, &Some(endpoint.to_string()), &Some(keepalive));
        assert!(gen_peer_res.is_ok());
        debug!("gen_peer_res: {:?}", gen_peer_res.unwrap());
    }

    #[test]
    fn test_add_remove_peer_conf() {
        init_logger();

        let pk_res_1 = gen_private_key();
        assert!(pk_res_1.is_ok());
        let priv_key_1 = pk_res_1.unwrap();

        let host_ifc_name = "wg_test_ifc_1";
        let host_addr = "192.0.0.1/24";
        let allowed_ips = "192.0.0.0/24";
        let port = 51820;
        // let keepalive = 25;

        let gen_ifc_res = gen_interface_conf(&priv_key_1, host_addr, &port);
        assert!(gen_ifc_res.is_ok());
        let gen_ifc = gen_ifc_res.unwrap();
        debug!("generated interface config: {}", gen_ifc);

        let rem_res = remove_interface(host_ifc_name);
        assert!(rem_res.is_ok());

        let create_ifc_res = create_interface(host_ifc_name, host_addr, &port, &priv_key_1);
        assert!(create_ifc_res.is_ok());

        let pk_res_2 = gen_private_key();
        assert!(pk_res_2.is_ok());
        let priv_key_2 = pk_res_2.unwrap();

        let pub_key_res = gen_public_key(&priv_key_2);
        assert!(pub_key_res.is_ok());
        let pub_key = pub_key_res.unwrap();

        let add_peer_res = add_peer(host_ifc_name, None, allowed_ips, &pub_key);
        assert!(add_peer_res.is_ok());

        let rem_peer_res = remove_peer(host_ifc_name, &pub_key);
        assert!(rem_peer_res.is_ok());

        let rem_res = remove_interface(host_ifc_name);
        assert!(rem_res.is_ok());
    }
}
