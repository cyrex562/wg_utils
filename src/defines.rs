use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use tera::Tera;

pub const DEF_CONTROLLER_PORT: &str = "8120";
pub const DEF_CONTROLLER_ADDR: &str = "127.0.0.1";
pub const DFLT_WG_PORT: u32 = 51820;
pub const DFLT_KEEPALIVE: u32 = 25;
pub const DFLT_CONFIG_FILE: &str = "./config.toml";

// #[derive(Debug)]
// struct SuperError {
//     side: SuperErrorSideKick,
// }

// impl fmt::Display for SuperError {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "SuperError is here!")
//     }
// }

// impl Error for SuperError {
//     fn source(&self) -> Option<&(dyn Error + 'static)> {
//         Some(&self.side)
//     }
// }

///
/// Custom error thrown by functions
///
#[derive(Debug)]
pub struct WgcError {
    pub message: String,
}

impl Error for WgcError {}

impl fmt::Display for WgcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message: {}", self.message)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenPubKeyRequest {
    pub private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenPrivKeyResponse {
    pub private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenPubKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetInterfacesResponse {
    pub interfaces: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetInterfaceResponse {
    pub interface: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenInterfaceRequest {
    pub private_key: Option<String>,
    pub address: String,
    pub listen_port: Option<u32>,
    pub dns: Option<String>,
    pub mtu: Option<u32>,
    pub table: Option<String>,
    pub pre_up: Option<String>,
    pub post_up: Option<String>,
    pub pre_down: Option<String>,
    pub post_down: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenInterfaceResponse {
    pub interface_config: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenPeerRequest {
    pub endpoint: Option<String>,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenPeerResponse {
    pub peer_conf: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePeerRequest {
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct WgPeer {
    pub public_key: String,
    pub private_key: String,
    pub address: String,
    pub endpoint: String,
    pub keepalive: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct WgInterface {
    pub config_file_path: String,
    pub name: String,
    pub public_key: String,
    pub private_key: String,
    pub address: String,
    pub listen_port: u32,
    pub dns: String,
    pub mtu: u32,
    pub table: String,
    pub pre_up: String,
    pub post_up: String,
    pub pre_down: String,
    pub post_down: String,
    pub peers: Vec<WgPeer>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Config {
    pub local_endpoint: String,
    pub interfaces: Vec<WgInterface>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ProvisionPeerRequest {
    pub remote_allowed_ips: Vec<String>,
    pub local_allowed_ips: Vec<String>,
    pub address: String,
    pub listen_port: Option<u32>,
    pub table: Option<String>,
    pub dns: Option<String>,
    pub mtu: Option<String>,
    pub remote_endpoint: Option<String>,
    pub local_endpoint: String,
    pub keepalive: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ProvisionPeerResult {
    pub interface_config: String,
}

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("failed to get/parse templates: {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec!["html"]);
        tera
    };
}
