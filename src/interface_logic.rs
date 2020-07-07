use crate::defines::{WgInterface, WgcError, TEMPLATES};

use actix_web::web;
// use kv::Msgpack;

use log::{debug, error, info};
use std::fs::File;

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::result::Result as std_result;
use std::str;
use tera::Context;

///
/// Generate an interface configuration
///
pub fn gen_interface_conf(
    private_key: &str,
    address: &str,
    listen_port: &u32,
) -> Result<String, WgcError> {
    let key_str = private_key;
    let key_part = key_str.get(0..3).unwrap();
    debug!(
        "generating interface config: private key: {}..., address: {}, listen_port: {}\n",
        key_part, &address, &listen_port
    );
    let mut ctx = Context::new();
    ctx.insert("address", address);
    ctx.insert("listen_port", listen_port);
    ctx.insert("private_key", private_key);
    ctx.insert("set_dns", &false);
    ctx.insert("set_table_off", &false);
    ctx.insert("set_table_value", &false);
    ctx.insert("set_mtu", &false);
    ctx.insert("set_pre_up", &false);
    ctx.insert("set_pre_down", &false);
    ctx.insert("set_post_up", &false);
    ctx.insert("set_post_down", &false);

    match TEMPLATES.render("interface.conf.template", &ctx) {
        Ok(s) => Ok(s),
        Err(e) => {
            println!("Error: {}", e);
            Err(WgcError {
                message: format!("{:?}", e),
            })
        }
    }
}

pub fn get_ifc_pub_key(ifc_name: &str) -> std_result<String, WgcError> {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg(ifc_name)
        .arg("public-key")
        .output()
        .expect("failed to execute command");
    let stdout_str = str::from_utf8(output.stdout.as_slice()).unwrap();
    let stderr_str = str::from_utf8(output.stderr.as_slice()).unwrap();
    if output.status.success() {
        let pub_key_str = stdout_str.trim();
        Ok(pub_key_str.to_string())
    } else {
        Err(WgcError {
            message: format!(
                "failed to get public key for interface {}: stdout: {}, stderr: {}",
                ifc_name, &stdout_str, &stderr_str
            ),
        })
    }
}
///
/// Gets an interface from the KV store's "interfaces" bucket, using the interface's name as its key.
///
// pub fn get_interface_from_store_by_name(
//     store: web::Data<kv::Store>,
//     name: &str,
// ) -> Result<WgInterface, WgcError> {
//     let bucket = match store.bucket::<&str, Msgpack<WgInterface>>(Some("interfaces")) {
//         Ok(b) => b,
//         Err(e) => {
//             error!("failed to get interfaces bucket: {:?}", e);
//             return Err(WgcError {
//                 message: format!("failed to get interfaces bucket: {:?}", e),
//             });
//         }
//     };

//     let ifc_msg = match bucket.get(name) {
//         Ok(m) => m,
//         Err(e) => {
//             error!("failed to get interface from bucket: {:?}", e);
//             return Err(WgcError {
//                 message: format!("failed to get interface from bucket: {:?}", e),
//             });
//         }
//     };

//     let msg = match ifc_msg {
//         Some(m) => m,
//         None => {
//             return Err(WgcError {
//                 message: String::from("failed to get message from MsgPack obj"),
//             })
//         }
//     };

//     let ifc = msg.0;
//     Ok(ifc)
// }

///
///
///
// fn get_interfaces_from_store(store: web::Data<kv::Store>) ->
//     Result<kv::Iter<&str, Msgpack<WgInterface>>, WgcError> {
//     let bucket = match store.bucket::<&str, Msgpack<WgInterface>>(Some("interfaces")) {
//         Ok(b) => b,
//         Err(e) => {
//             error!("failed to get interfaces bucket: {:?}", e);
//             return Err(WgcError {
//                 message: format!("failed to get interfaces bucket: {:?}", e)
//             })
//         }
//     };
//     Ok(bucket.iter())
// }

///
/// Adds an interface to the KV store in the "interfaces" bucket. The key for the interface is the interfaces' name.
///
// pub fn add_interface_to_store(
//     store: web::Data<kv::Store>,
//     ifc: WgInterface,
// ) -> Result<(), WgcError> {
//     let bucket = match store.bucket::<&str, Msgpack<WgInterface>>(Some("interfaces")) {
//         Ok(b) => b,
//         Err(e) => {
//             error!("failed to get interfaces bucket: {:?}", e);
//             return Err(WgcError {
//                 message: format!("failed to get interfaces bucket: {:?}", e),
//             });
//         }
//     };
//     match bucket.set(ifc.name.as_str(), Msgpack(ifc.clone())) {
//         Ok(()) => Ok(()),
//         Err(e) => {
//             error!("failed to push interface to store: {:?}", e);
//             Err(WgcError {
//                 message: format!("failed to push interface to store: {:?}", e),
//             }
//         }
//     }
// }

pub fn unix_bring_ifc_dn(ifc_name: &str) -> Result<(), WgcError> {
    let output = Command::new("sudo")
        .arg("wg-quick")
        .arg("down")
        .arg(ifc_name)
        .output()
        .expect("failed to execute command");
    let std_out_str = str::from_utf8(&output.stdout).unwrap();
    let std_err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to down wg interface {}, stdout: \"{}\", stderr: \"{}\"",
            ifc_name, std_out_str, std_err_str
        );
        return Err(WgcError {
            message: String::from("failed to down WG interface"),
        });
    }
    Ok(())
}

pub fn win_bring_ifc_dn(ifc_name: &str) -> Result<(), WgcError> {
    debug!("bringing interface down");
    let output = Command::new("C:\\Program Files\\Wireguard\\wireguard.exe")
        .arg("/uninstalltunnelservice")
        .arg(ifc_name)
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        debug!("failed to bring interface down");
        let output_str = str::from_utf8(&output.stdout).unwrap();
        let err_str = str::from_utf8(&output.stderr).unwrap();
        return Err(WgcError {
            message: format!(
                "failed to set wg interface to config file: stdout: \"{}\", stderr: \"{}\"",
                &output_str, &err_str
            ),
        });
    }

    debug!("interface brought down");
    Ok(())
}

pub fn unix_del_ifc_cfg_file(ifc_name: &str) -> Result<(), WgcError> {
    let ifc_wg_cfg_path = format!("/etc/wireguard/{}.conf", ifc_name);
    let output = Command::new("sudo")
        .arg("rm")
        .arg(ifc_wg_cfg_path)
        .output()
        .expect("failed to execute command");
    let std_out_str = str::from_utf8(&output.stdout).unwrap();
    let std_err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to delete interface {} config, stdout: \"{}\", stderr: \"{}\"",
            ifc_name, std_out_str, std_err_str
        );
        return Err(WgcError {
            message: String::from("failed to delete interface"),
        });
    }
    Ok(())
}

pub fn win_del_ifc_cfg_file(ifc_name: &str) -> Result<(), WgcError> {
    let ifc_cfg_file = format!("{}", ifc_name);
    let ifc_cfg_wg_path = format!("C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\WireGuard\\Configurations\\{}", ifc_cfg_file);

    debug!("checking if interface exists");
    if Path::new(&ifc_cfg_wg_path).exists() {
        match std::fs::remove_file(ifc_cfg_file) {
            Ok(()) => {
                debug!("interface file {} deleted", ifc_cfg_wg_path);
                return Ok(());
            }
            Err(e) => {
                error!(
                    "failed to delete interface file: {}: {:?}",
                    ifc_cfg_wg_path, e
                );
                return Err(WgcError {
                    message: String::from("failed to delete interface file"),
                });
            }
        };
    }

    Ok(())
}

pub fn remove_interface(ifc_name: &str) -> Result<(), WgcError> {
    #[cfg(target_family = "unix")]
    unix_bring_ifc_dn(ifc_name)?;

    #[cfg(target_family = "windows")]
    win_bring_ifc_dn(ifc_name)?;

    #[cfg(target_family = "unix")]
    unix_del_ifc_cfg_file(ifc_name)?;

    #[cfg(target_family = "windows")]
    win_del_ifc_cfg_file(ifc_name)?;

    Ok(())
}

fn unix_copy_interface_file(ifc_cfg_tmp_path: &str, ifc_cfg_wg_path: &str) -> Result<(), WgcError> {
    debug!("copying temp config file to wireguard config dir");
    let output = Command::new("sudo")
        .arg("cp")
        .arg(&ifc_cfg_tmp_path)
        .arg(&ifc_cfg_wg_path)
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        Err(WgcError {
            message: format!(
                "failed to copy tmp file to wg config dir: status: {}, stdout: {}, stderr: {}",
                output.status.code().unwrap(),
                str::from_utf8(&output.stdout).unwrap(),
                str::from_utf8(&output.stderr).unwrap()
            ),
        })
    } else {
        debug!("temp config file copied to wireguard config dir");
        Ok(())
    }
}

fn unix_bring_ifc_up(ifc_cfg_wg_path: &str) -> Result<(), WgcError> {
    debug!("bringing up wg interface");
    let output = Command::new("sudo")
        .arg("wg-quick")
        .arg("up")
        .arg(&ifc_cfg_wg_path)
        // .arg(info.name.clone())
        .output()
        .expect("failed to execute command");

    let output_str = str::from_utf8(&output.stdout).unwrap();
    let err_str = str::from_utf8(&output.stderr).unwrap();

    if !output.status.success() {
        debug!("failed to bring interface up");
        Err(WgcError {
            message: format!(
                "failed to set wg interface to config file: stdout: \"{}\", stderr: \"{}\"",
                &output_str, &err_str
            ),
        })
    } else {
        debug!("brought interface up");
        Ok(())
    }
}

fn win_bring_ifc_up(ifc_cfg_tmp_path: &str) -> Result<(), WgcError> {
    debug!("bringing interface up");
    let output = Command::new("C:\\Program Files\\Wireguard\\wireguard.exe")
        .arg("/installtunnelservice")
        .arg(ifc_cfg_tmp_path)
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        debug!("failed to bring interface up");
        let output_str = str::from_utf8(&output.stdout).unwrap();
        let err_str = str::from_utf8(&output.stderr).unwrap();
        return Err(WgcError {
            message: format!(
                "failed to set wg interface to config file: stdout: \"{}\", stderr: \"{}\"",
                &output_str, &err_str
            ),
        });
    }

    debug!("interface brought up");
    Ok(())
}

pub fn write_ifc_config_to_file(
    ifc_cfg_tmp_path: &str,
    ifc_cfg_data: &str,
) -> Result<(), WgcError> {
    debug!("creating interface config temp file");
    let mut file = match File::create(&ifc_cfg_tmp_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to create tmp ifc cfg file: {:?}", e),
            })
        }
    };
    debug!("interface config temp file created");

    debug!("writing interface config to temp file");
    match file.write_all(ifc_cfg_data.as_bytes()) {
        Ok(()) => (),
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to write interface config to tmp file: {:?}", e),
            })
        }
    };
    debug!("interface config written to tmp file");
    Ok(())
}

/// Create a WireGuard interface
///
pub fn create_interface(
    ifc_name: &str,
    address: &str,
    listen_port: &u32,
    private_key: &str,
) -> Result<String, WgcError> {
    debug!(
        "creating interface: ifc_name: {}, address: {}, listen_port: {} private_key: {}",
        ifc_name, address, listen_port, private_key
    );
    // TODO: support dns, mtu, table, and pre/post up/down
    let ifc_conf_data = gen_interface_conf(&private_key, address, listen_port)?;
    let ifc_cfg_file = format!("{}.conf", ifc_name);
    let mut ifc_cfg_tmp_path = std::env::temp_dir();
    ifc_cfg_tmp_path.push(ifc_cfg_file.clone());
    #[cfg(target_family = "unix")]
    let ifc_cfg_wg_path = format!("/etc/wireguard/{}", ifc_cfg_file);
    #[cfg(target_family = "windows")]
    let ifc_cfg_wg_path = format!("C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\WireGuard\\Configurations\\{}", ifc_cfg_file);

    let mut wg_ifc = WgInterface::default();
    wg_ifc.config_file_path = ifc_cfg_wg_path.clone();
    wg_ifc.name = ifc_name.to_string();
    wg_ifc.private_key = private_key.to_string();
    wg_ifc.address = address.to_string();
    wg_ifc.listen_port = *listen_port;

    debug!("checking if interface exists");
    if Path::new(&ifc_cfg_wg_path).exists() {
        return Err(WgcError {
            message: format!("interface config at {} already exists", &ifc_cfg_wg_path),
        });
    }

    let ifc_cfg_tmp_path_str = ifc_cfg_tmp_path.to_str().unwrap();

    write_ifc_config_to_file(&ifc_cfg_tmp_path_str, &ifc_conf_data)?;

    #[cfg(target_family = "unix")]
    unix_copy_interface_file(ifc_cfg_tmp_path, ifc_cfg_wg_path)?;

    // f.map_err(|e| MyCustomError::FileOpenError(e))?;
    #[cfg(target_family = "unix")]
    unix_bring_ifc_up(ifc_cfg_wg_path)?;

    #[cfg(target_family = "windows")]
    win_bring_ifc_up(&ifc_cfg_tmp_path_str)?;

    info!("interface {} created", &ifc_name);
    Ok(ifc_conf_data)
}

#[cfg(target_family = "unix")]
pub fn get_interfaces() -> Result<String, WgcError> {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg("interfaces")
        .output()
        .expect("failed to execute command");
    let output_str = String::from_utf8(output.stdout).unwrap();
    let err_str = String::from_utf8(output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to get interfaces: stdout: {}, stderr: {}",
            &output_str, &err_str
        );
        return Err(WgcError {
            message: String::from("failed to get interfaces"),
        });
    }
    Ok(output_str)
}

#[cfg(target_family = "windows")]
pub fn get_interfaces() -> Result<String, WgcError> {
    let output = Command::new("wg")
        .arg("show")
        .arg("interfaces")
        .output()
        .expect("failed to execute command");
    let output_str = String::from_utf8(output.stdout).unwrap();
    let err_str = String::from_utf8(output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to get interfaces: stdout: {}, stderr: {}",
            &output_str, &err_str
        );
        return Err(WgcError {
            message: String::from("failed to get interfaces"),
        });
    }
    Ok(output_str)
}

#[cfg(target_family = "unix")]
pub fn get_interface(ifc_name: &str) -> Result<String, WgcError> {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg(ifc_name)
        .output()
        .expect("failed to execute process");
    let output_str = str::from_utf8(&output.stdout).unwrap();
    let err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to get interface information: stdout: \"{}\", stderr: \"{}\"",
            &output_str, &err_str
        );
        return Err(WgcError { message: format!("failed to get information for interface: {}", ifc_name)});
    }
    return Ok(output_str.to_string())
} 

#[cfg(target_family = "windows")]
pub fn get_interface(ifc_name: &str) -> Result<String, WgcError> {
    let output = Command::new("wg")
        .arg("show")
        .arg(ifc_name)
        .output()
        .expect("failed to execute process");
    let output_str = str::from_utf8(&output.stdout).unwrap();
    let err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to get interface information: stdout: \"{}\", stderr: \"{}\"",
            &output_str, &err_str
        );
        return Err(WgcError { message: format!("failed to get information for interface: {}", ifc_name)});
    }
    Ok(output_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen_logic::gen_private_key;
    use crate::utils::init_logger;

    #[test]
    fn test_gen_interface_conf() {
        init_logger();
        let priv_key = gen_private_key().unwrap();
        let addr = "192.0.0.1/24";
        let port = 51820;
        let result = gen_interface_conf(&priv_key, &addr, &port);
        assert_eq!(result.is_ok(), true);
        let ifc_config = result.unwrap();
        debug!("interface conf: {:?}", ifc_config);
    }

    #[test]
    fn test_create_remove_interface() {
        init_logger();
        let ifc_name = "wg_test_ifc_1";
        let addr = "192.0.0.1/24";
        let port = 51820;
        let priv_key = gen_private_key().unwrap();
        let result = create_interface(&ifc_name, &addr, &port, &priv_key);
        assert_eq!(result.is_ok(), true);
        let ifc_config = result.unwrap();
        info!("Interface config: {:?}", ifc_config);
        let rem_res = remove_interface(&ifc_name);
        assert_eq!(rem_res.is_ok(), true);
    }

    #[test]
    fn test_get_interfaces() {
        init_logger();
        let result = get_interfaces();
        assert!(result.is_ok());
        debug!("get interfaces result: {:?}", result);
    }
}
