use crate::{
    defines::{
        GenPeerRequest, GenPeerResponse, ProvisionPeerRequest, ProvisionPeerResult, DFLT_KEEPALIVE,
        DFLT_WG_PORT,
    },
    gen_logic::{gen_private_key, gen_public_key},
    interface_logic::{gen_interface_conf, get_ifc_pub_key},
    peer_logic::{add_peer, gen_peer_conf},
};

use actix_web::{web, HttpResponse};
use log::error;
use std::process::Command;
use std::str;

///
/// Route handler to add peer to an interface
///
pub async fn handle_add_peer(
    info: web::Json<GenPeerRequest>,
    path: web::Path<String>,
) -> HttpResponse {
    let ifc_name = path.to_string();
    let req = info.0;
    let keepalive = req.persistent_keepalive.unwrap_or(DFLT_KEEPALIVE);

    let mut allowed_ips = String::from("0.0.0.0/0");
    if req.allowed_ips.len() > 0 {
        allowed_ips = req.allowed_ips.join(",");
    }

    match add_peer(&ifc_name, req.endpoint, &allowed_ips, &req.public_key) {
        Ok(()) => HttpResponse::Ok().reason("peer added to config").finish(),
        Err(e) => {
            error!("failed to add peer to interface: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to add peer to interface")
                .finish()
        }
    }
}

///
/// Route handler to remove peer from an interface
///
pub async fn handle_remove_peer(
    info: web::Json<GenPeerRequest>,
    path: web::Path<String>,
) -> HttpResponse {
    let req = info.0;
    let ifc_name = path.to_string();
    let output = Command::new("sudo")
        .arg("wg")
        .arg("set")
        .arg(&ifc_name)
        .arg("peer")
        .arg(&req.public_key)
        .arg("remove")
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        error!(
            "failed to remove peer from interface: stdout: {}, stderr: {}",
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        );
        return HttpResponse::InternalServerError()
            .reason("failed to remove peer from interface")
            .finish();
    }

    let output = Command::new("sudo")
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
        return HttpResponse::InternalServerError()
            .reason("failed to save interface config")
            .finish();
    }

    HttpResponse::Ok().reason("peer added to config").finish()
}

pub async fn handle_provision_peer(
    info: web::Json<ProvisionPeerRequest>,
    path: web::Path<String>,
) -> HttpResponse {
    // get which interface to add the peer to from the path
    let ifc_name = path.to_string();

    // get the parameters and any defaults from the request
    let req = info.0;

    let mut remote_allowed_ips = String::from(format!("{}/32", &req.address));
    if req.remote_allowed_ips.len() > 0 {
        remote_allowed_ips = req.remote_allowed_ips.join(",");
    }

    let mut local_allowed_ips = String::from(format!("0.0.0.0/0"));
    if req.local_allowed_ips.len() > 0 {
        local_allowed_ips = req.local_allowed_ips.join(",");
    }

    let listen_port = req.listen_port.unwrap_or(DFLT_WG_PORT);
    let table = req.table.unwrap_or(String::from(""));
    let mtu = req.mtu.unwrap_or(String::from("1500"));
    let dns = req.dns.unwrap_or(String::from(""));
    // let peer_endpoint = req.peer_endpoint.unwrap_or(String::from(""));
    let keepalive = req.keepalive.unwrap_or(DFLT_KEEPALIVE);

    // generate a private key for the peer
    let peer_priv_key = match gen_private_key() {
        Ok(k) => k,
        Err(e) => {
            error!("failed to generate private key for peer: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to generate peer private key")
                .finish();
        }
    };

    // get the peer's public key
    let peer_pub_key = match gen_public_key(&peer_priv_key) {
        Ok(k) => k,
        Err(e) => {
            error!("failed to get public key for peer: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to get peer public key")
                .finish();
        }
    };

    // get the interfaces' public key
    let ifc_pub_key = match get_ifc_pub_key(&ifc_name) {
        Ok(k) => k,
        Err(e) => {
            error!("failed to get public key for interface: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to get interface public key")
                .finish();
        }
    };

    // add the peer to the interface
    match add_peer(
        &ifc_name,
        req.remote_endpoint,
        &remote_allowed_ips,
        &peer_pub_key,
    ) {
        Ok(()) => (),
        Err(e) => {
            error!("failed to add peer to target interface: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to add peer to interface")
                .finish();
        }
    };

    // gen the peer interface config
    let peer_ifc_config = match gen_interface_conf(&peer_priv_key, &req.address, &listen_port) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("failed to generate peer ifc config: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to generate peer if cconfig")
                .finish();
        }
    };

    // add remote peer to peer ifc config
    let remote_peer_config = match gen_peer_conf(
        &ifc_pub_key,
        &local_allowed_ips,
        &Some(req.local_endpoint),
        &None::<u32>,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("failed to generate remote peer config: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to generate remote peer config")
                .finish();
        }
    };

    let final_peer_ifc_cfg = format!(
        "{}\n{}\n\n{}",
        peer_ifc_config, keepalive, remote_peer_config
    );
    let resp = ProvisionPeerResult {
        interface_config: final_peer_ifc_cfg,
    };
    // return the peer's interface config
    HttpResponse::Ok().json(resp)
}

///
/// Route handler to generate a peer config
///
pub async fn handle_gen_peer(info: web::Json<GenPeerRequest>) -> HttpResponse {
    let req = info.0;

    let mut allowed_ips = String::from("0.0.0.0/0");
    if req.allowed_ips.len() > 0 {
        allowed_ips = req.allowed_ips.join(",");
    }

    match gen_peer_conf(
        &req.public_key,
        &allowed_ips,
        &req.endpoint,
        &req.persistent_keepalive,
    ) {
        Ok(pc) => {
            let resp = GenPeerResponse { peer_conf: pc };
            HttpResponse::Ok().json(resp)
        }
        Err(e) => {
            error!("failed to generate peer conf: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to generate peer conf")
                .finish()
        }
    }
}
