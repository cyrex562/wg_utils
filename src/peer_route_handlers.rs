use crate::peer_logic::remove_peer;
use crate::{
    defines::{
        GenPeerRequest, GenPeerResponse, ProvisionPeerRequest, ProvisionPeerResult, DFLT_KEEPALIVE, DFLT_WG_PORT,
    },
    gen_logic::{gen_private_key, gen_public_key},
    interface_logic::{gen_interface_conf, get_ifc_pub_key},
    peer_logic::{add_peer, gen_peer_conf},
};

use actix_web::{web, HttpResponse};
use log::error;

///
/// Route handler to add peer to an interface
///
pub async fn handle_add_peer(info: web::Json<GenPeerRequest>, path: web::Path<String>) -> HttpResponse {
    let ifc_name = path.to_string();
    let req = info.0;
    // let keepalive = req.persistent_keepalive.unwrap_or(DFLT_KEEPALIVE);

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
pub async fn handle_remove_peer(info: web::Json<GenPeerRequest>, path: web::Path<String>) -> HttpResponse {
    let req = info.0;
    let ifc_name = path.to_string();

    match remove_peer(&ifc_name, &req.public_key) {
        Ok(()) => HttpResponse::Ok().reason("peer removed").finish(),
        Err(e) => {
            error!("failed to remove peer: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to remove peer")
                .finish()
        }
    }
}

pub async fn handle_provision_peer(info: web::Json<ProvisionPeerRequest>, path: web::Path<String>) -> HttpResponse {
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
    // let table = req.table.unwrap_or(String::from(""));
    // let mtu = req.mtu.unwrap_or(String::from("1500"));
    // let dns = req.dns.unwrap_or(String::from(""));
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
    match add_peer(&ifc_name, req.remote_endpoint, &remote_allowed_ips, &peer_pub_key) {
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

    let final_peer_ifc_cfg = format!("{}\n{}\n\n{}", peer_ifc_config, keepalive, remote_peer_config);
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

    match gen_peer_conf(&req.public_key, &allowed_ips, &req.endpoint, &req.persistent_keepalive) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface_logic::{create_interface, remove_interface};
    use crate::utils::init_logger;
    use actix_web::{test, web, App};
    use log::debug;

    #[actix_rt::test]
    async fn test_handle_add_rm_peer() {
        init_logger();

        let pk_res: Result<String, crate::defines::WgcError> = gen_private_key();
        assert!(pk_res.is_ok());
        let private_key = pk_res.unwrap();

        let ifc_name = "test_ifc_1";
        let address = "192.0.0.1/24";
        let listen_port = 52810;

        let ri_res = remove_interface(&ifc_name);
        assert!(ri_res.is_ok());

        let ci_res = create_interface(&ifc_name, &address, &listen_port, &private_key);
        assert!(ci_res.is_ok());
        let ifc = ci_res.unwrap();
        debug!("create interface: {:?}", ifc);

        let path = format!("/{}", ifc_name);

        let pk_res_2 = gen_private_key();
        assert!(pk_res_2.is_ok());
        let peer_priv_key = pk_res_2.unwrap();

        let pub_key_res = gen_public_key(&peer_priv_key);
        assert!(pub_key_res.is_ok());
        let peer_pub_key = pub_key_res.unwrap();

        let allowed_ip = "192.0.0.0/24";
        let allowed_ips = vec![allowed_ip.to_string()];

        let mut app = test::init_service(
            App::new()
                .route("/{interface}", web::post().to(handle_add_peer))
                .route("/{interface}", web::delete().to(handle_remove_peer)),
        )
        .await;
        let gen_peer_req = GenPeerRequest {
            endpoint: None,
            public_key: peer_pub_key.clone(),
            allowed_ips: allowed_ips,
            persistent_keepalive: None,
        };
        let req = test::TestRequest::post()
            .uri(&path)
            .set_json(&gen_peer_req)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("response: {:?}", resp);
        assert!(resp.status().is_success());

        let rem_req = test::TestRequest::delete()
            .uri(&path)
            .set_json(&gen_peer_req)
            .to_request();
        let rem_resp = test::call_service(&mut app, rem_req).await;
        debug!("response: {:?}", rem_resp);
        assert!(rem_resp.status().is_success());

        let ri_res = remove_interface(&ifc_name);
        assert!(ri_res.is_ok());
    }

    #[actix_rt::test]
    async fn test_handle_provision_peer() {
        init_logger();

        let pk_res: Result<String, crate::defines::WgcError> = gen_private_key();
        assert!(pk_res.is_ok());
        let private_key = pk_res.unwrap();

        let ifc_name = "test_ifc_1";
        let address = "192.0.0.1/24";
        let port = 52810;

        let ri_res = remove_interface(&ifc_name);
        assert!(ri_res.is_ok());

        let ci_res = create_interface(&ifc_name, &address, &port, &private_key);
        assert!(ci_res.is_ok());
        let ifc = ci_res.unwrap();
        debug!("create interface: {:?}", ifc);

        let remote_allowed_ip = "192.0.0.0/24";
        let local_allowed_ip = "192.0.0.0/24";

        let remote_allowed_ips = vec![remote_allowed_ip.to_string()];
        let local_allowed_ips = vec![local_allowed_ip.to_string()];
        let address = String::from("192.0.0.2/24");
        let table = None;
        let dns = None;
        let mtu = None;
        let keepalive = None;
        let remote_endpoint = None;
        let listen_port = Some(port);
        let local_endpoint = String::from("1.2.3.4:51820");

        let prov_peer_req_obj = ProvisionPeerRequest {
            remote_allowed_ips,
            local_allowed_ips,
            address,
            listen_port,
            table,
            dns,
            mtu,
            remote_endpoint,
            local_endpoint,
            keepalive,
        };

        let path = format!("/{}", ifc_name);

        let mut app = test::init_service(App::new().route("/{interface}", web::post().to(handle_provision_peer))).await;
        let prov_peer_req = test::TestRequest::post()
            .uri(&path)
            .set_json(&prov_peer_req_obj)
            .to_request();
        let prov_peer_resp = test::call_service(&mut app, prov_peer_req).await;
        debug!("response: {:?}", prov_peer_resp);
        assert!(prov_peer_resp.status().is_success());

        let ri_res = remove_interface(&ifc_name);
        assert!(ri_res.is_ok());
    }
}
