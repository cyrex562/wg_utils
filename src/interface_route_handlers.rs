use crate::{
    defines::{GenInterfaceRequest, GenInterfaceResponse, GetInterfaceResponse, GetInterfacesResponse, DFLT_WG_PORT},
    gen_logic::gen_private_key,
    interface_logic::{create_interface, gen_interface_conf, get_interface, get_interfaces, remove_interface},
};
use actix_web::{web, HttpResponse, Responder, get, post, delete};
use log::{debug, error, info};

///
/// Gets a list of Wireguard interfaces present on the system
///
#[get("/interfaces")]
pub async fn handle_get_interfaces() -> impl Responder {
    // TODO: parse output into proper JSON object
    match get_interfaces() {
        Ok(ifcs) => {
            let resp = GetInterfacesResponse { interfaces: ifcs };
            HttpResponse::Ok().json(resp)
        }
        Err(e) => {
            error!("failed to get interfaces: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to get interfaces")
                .finish()
        }
    }
}

///
/// Gets information about a specific interface
///
#[get("/interfaces/{interface_name}")]
pub async fn handle_get_interface(interface_name: web::Path<String>) -> impl Responder {
    // todo: validate interface name
    debug!("handle get interface: info: {:?}", interface_name);
    info!(
        "request interface info for interface with name: {}",
        interface_name.clone()
    );

    match get_interface(&interface_name.to_string()) {
        Ok(info) => {
            debug!("interface info: \"{}\"", &info);
            let resp = GetInterfaceResponse { interface: info };
            HttpResponse::Ok().json(resp)
        }
        Err(e) => {
            error!("failed to get interface: {:}?", e);
            HttpResponse::InternalServerError()
                .reason("failed to get interface")
                .finish()
        }
    }
}

///
/// Route that handles requests to generate an interface config
///
#[post("/interfaces")]
pub async fn handle_gen_ifc_cfg(req: web::Json<GenInterfaceRequest>) -> impl Responder {
    let ifc_req = req.0;
    let priv_key = ifc_req.private_key.unwrap_or_else(|| gen_private_key().unwrap());
    let port = ifc_req.listen_port.unwrap_or(DFLT_WG_PORT);
    // TODO: handle dns, mut, table, pre/post up/down
    match gen_interface_conf(&priv_key, &ifc_req.address, &port) {
        Ok(conf) => {
            debug!("generated interface configuration:\"\n{}\"", &conf);
            let resp = GenInterfaceResponse { interface_config: conf };
            HttpResponse::Ok().json(resp)
        }
        Err(e) => {
            error!("failed to generate config: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to generate config")
                .finish()
        }
    }
}

///
/// Route handler for creating a Wireguard interface
///
#[post("/interfaces/{interface_name}")]
pub async fn handle_create_interface(
    interface_name: web::Path<String>,
    gen_ifc_req: web::Json<GenInterfaceRequest>,
) -> HttpResponse {
    let req = gen_ifc_req.0;
    let private_key = req.private_key.unwrap_or_else(|| gen_private_key().unwrap());
    let ifc_name = interface_name.to_string();
    let port = req.listen_port.unwrap_or(DFLT_WG_PORT);

    match create_interface(&ifc_name, &req.address, &port, &private_key) {
        Ok(d) => {
            debug!("interface created: {:?}", d);
            let resp_data = GenInterfaceResponse {
                interface_config: d.clone(),
            };
            HttpResponse::Ok().json(resp_data)
        }
        Err(e) => {
            error!("failed to create interface: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to create interface")
                .finish()
        }
    }
}

///
/// Route handler for removing an interface
///
#[delete("/interfaces/{name}")]
pub async fn handle_remove_interface(info: web::Path<String>) -> impl Responder {
    let interface_name = info.to_string();
    info!("request  remove interface with name: {}", &interface_name);

    match remove_interface(&interface_name) {
        Ok(()) => {
            debug!("interface removed");
            HttpResponse::Ok().reason("interface removed").finish()
        }
        Err(e) => {
            error!("failed to remove interface: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to remove interface")
                .finish()
        }
    }
}

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(handle_get_interface);
    cfg.service(handle_get_interfaces);
    cfg.service(handle_gen_ifc_cfg);
    cfg.service(handle_create_interface);
    cfg.service(handle_remove_interface);
}

// https://github.com/actix/examples/blob/8dab533b40d9d0640e5c75922c9e8e292ed4a7d5/sqlx_todo/src/todo/routes.rs
// https://github.com/actix/examples/tree/8dab533b40d9d0640e5c75922c9e8e292ed4a7d5/sqlx_todo/src
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::init_logger;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_handle_get_interfaces() {
        init_logger();
        // todo: create/add interfaces and verify they exist in the returned list
        let mut app = test::init_service(
            App::new().service(handle_get_interfaces)).await;
        let req = test::TestRequest::get().uri("/interfaces").to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("response: {:?}", resp);
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_handle_get_interface() {
        init_logger();
        // todo: create/add interface to check result properly
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

        let route_str = format!("/interfaces/{}", &ifc_name);

        let mut app = test::init_service(App::new().service(handle_get_interface)).await;
        let req = test::TestRequest::get().uri(&route_str).to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("response: {:?}", resp);
        assert!(resp.status().is_success());

        let rem_res = remove_interface(&ifc_name);
        assert!(rem_res.is_ok());
    }

    #[actix_rt::test]
    async fn test_handle_create_remove_interface() {
        init_logger();
        let mut app = test::init_service(
            App::new()
            .service(handle_create_interface)
            .service(handle_remove_interface)
        ).await;
        let req_data = GenInterfaceRequest {
            private_key: None,
            address: String::from("192.0.0.1/24"),
            listen_port: None,
            dns: None,
            mtu: None,
            table: None,
            pre_up: None,
            post_up: None,
            pre_down: None,
            post_down: None,
        };
        let ifc_name = "wg_test_ifc_1";
        let url = format!("/interfaces/{}", &ifc_name);
        let req = test::TestRequest::post()
            .uri(&url)
            .set_json(&req_data)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("create interface response:\n{:?}\n", resp);
        assert!(resp.status().is_success());

        let rem_req = test::TestRequest::delete()
            .uri(&url)
            .to_request();
        let rem_resp = test::call_service(&mut app, rem_req).await;
        debug!("resposne: {:?}", rem_resp);
        assert!(rem_resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_handle_gen_interface() {
        // let ifc_name = "wg_test_ifc_1";
        let address = "192.0.0.1/24";
        let req_data = GenInterfaceRequest {
            private_key: None,
            address: address.to_string(),
            listen_port: None,
            dns: None,
            mtu: None,
            table: None,
            pre_up: None,
            post_up: None,
            pre_down: None,
            post_down: None,
        };
        let mut app = test::init_service(
            App::new()
            .service(handle_gen_ifc_cfg)
        ).await;
        let req = test::TestRequest::post()
            .uri("/interfaces")
            .set_json(&req_data)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("response: {:?}", resp);
        assert!(resp.status().is_success());
    }
}
