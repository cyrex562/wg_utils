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
    let mut var_name = Command::new("wg");
    let cmd = var_name
        .arg("set")
        .arg(ifc_name)
        .arg("peer")
        .arg(public_key);

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

///
/// Generate a peer config
///
pub fn gen_peer_conf(
    public_key: &str,
    allowed_ips: &str,
    endpoint: &Option<String>,
    keepalive: &Option<u32>,
) -> Result<String, WgcError> {
    let key_str = public_key;
    let key_part = key_str.get(0..3).unwrap();
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

    match TEMPLATES.render("peer.conf.template", &ctx) {
        Ok(s) => Ok(s),
        Err(e) => {
            error!("failed to render peer conf template: {:?}", e);
            Err(WgcError {
                message: format!("failed to render peer conf template: {:?}", e),
            })
        }
    }
}
