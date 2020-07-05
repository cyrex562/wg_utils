use crate::defines::WgcError;
use log::debug;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::result::Result as std_result;
use std::str;

///
/// Generate a Wireguard Private Key
/// ```
/// let result = gen_logic::gen_private_key();
/// assert!(result.is_ok(), true);
/// ```
///
pub fn gen_private_key() -> Result<String, WgcError> {
    #[cfg(not(target_os = "windows"))]
    let mut cmd = Command::new("sudo").arg("wg");
    #[cfg(target_os = "windows")]
    let mut cmd = Command::new("wg");

    let output = cmd.arg("genkey")
        .output()
        .expect("failed to execute command");
    let mut stdout = str::from_utf8(output.stdout.as_slice()).unwrap();
    stdout = stdout.trim();
    let mut stderr = str::from_utf8(output.stderr.as_slice()).unwrap();
    stderr = stderr.trim();
    if output.status.success() {
        Ok(stdout.to_string())
    } else {
        Err(WgcError {
            message: format!(
                "wg genkey failed: code: {} stdout: {} stderr: {}",
                output.status.code().unwrap(),
                stdout,
                stderr,
            ),
        })
    }
}

///
/// Generate a Wireguard public key from a private key
/// 
/// # Examples
/// 
/// ```
/// let priv_key_result = gen_logic::gen_private_key();
/// let priv_key = priv_key_result.unwrap();
/// let pub_key_result = gen_logic::gen_public_key(private_key: &str)(&priv_key);
/// assert!(pub_key_result.is_ok(), true);
/// ```
/// 
///
pub fn gen_public_key(private_key: &str) -> std_result<String, WgcError> {
    #[cfg(not(target_os = "windows"))]
    let mut cmd = Command::new("sudo").arg("wg");
    #[cfg(target_os="windows")]
    let mut cmd = Command::new("wg");
    
    let mut out = match cmd.arg("pubkey")
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
    let out_stdin = match out.stdin.as_mut() {
        Some(si) => si,
        None => {
            return Err(WgcError {
                message: "failed to get child stdin".to_string(),
            })
        }
    };

    match out_stdin.write_all(private_key.as_bytes()) {
        Ok(()) => debug!("stdin written to child"),
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to write data to stdin: {:?}", e),
            })
        }
    };

    let output = match out.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return Err(WgcError {
                message: format!("process failed: {:?}", e),
            })
        }
    };

    let mut stdout = str::from_utf8(output.stdout.as_slice()).unwrap();
    stdout = stdout.trim();
    let mut stderr = str::from_utf8(output.stderr.as_slice()).unwrap();
    stderr = stderr.trim();

    if output.status.success() {
        return Ok(stdout.to_string());
    }

    Err(WgcError {
        message: format!(
            "command failed: code: {}, stdout: {}, stderr: {}",
            output.status.code().unwrap(),
            stdout,
            stderr,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_priv_key() {
        let priv_key_res = gen_private_key();
        assert_eq!(priv_key_res.is_ok(), true);
    }

    #[test]
    fn test_gen_pub_key() {
        let priv_key = gen_private_key().unwrap();
        let pub_key_res = gen_public_key(&priv_key);
        assert_eq!(pub_key_res.is_ok(), true);
    }
}