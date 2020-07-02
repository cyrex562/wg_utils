use crate::defines::WgcError;
use log::debug;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::result::Result as std_result;
use std::str;

///
/// Generate a Wireguard Private Key
///
pub fn gen_private_key() -> Result<String, WgcError> {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("genkey")
        .output()
        .expect("failed to execute command");
    if output.status.success() {
        let mut priv_key = output.stdout;
        priv_key.pop().unwrap();
        Ok(String::from_utf8(priv_key).unwrap())
    } else {
        Err(WgcError {
            message: format!(
                "wg genkey failed: code: {} stdout: {} stderr: {}",
                output.status.code().unwrap(),
                str::from_utf8(output.stdout.as_slice()).unwrap(),
                str::from_utf8(output.stderr.as_slice()).unwrap()
            ),
        })
    }
}

///
/// Generate a Wireguard public key from a private key
///
pub fn gen_public_key(private_key: &str) -> std_result<String, WgcError> {
    let mut child = match Command::new("sudo")
        .arg("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(p) => p,
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to spawn process: {:?}", e),
            })
        }
    };
    let child_stdin = match child.stdin.as_mut() {
        Some(si) => si,
        None => {
            return Err(WgcError {
                message: "failed to get child stdin".to_string(),
            })
        }
    };

    match child_stdin.write_all(private_key.as_bytes()) {
        Ok(()) => debug!("stdin written to child"),
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to write data to stdin: {:?}", e),
            })
        }
    };

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return Err(WgcError {
                message: format!("process failed: {:?}", e),
            })
        }
    };

    if output.status.success() {
        let mut pub_key = output.stdout;
        pub_key.pop().unwrap();
        return Ok(String::from_utf8(pub_key).unwrap());
    }

    Err(WgcError {
        message: format!(
            "command failed: code: {}, stdout: {}, stderr: {}",
            output.status.code().unwrap(),
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        ),
    })
}
