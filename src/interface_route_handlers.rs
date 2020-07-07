use crate::{
    defines::{
        GenInterfaceRequest, GenInterfaceResponse, GetInterfaceResponse, GetInterfacesResponse,
        DFLT_WG_PORT,
    },
    gen_logic::gen_private_key,
    interface_logic::{create_interface, gen_interface_conf, remove_interface, get_interfaces, get_interface},
};
use actix_web::{web, HttpResponse, Responder};
use log::{debug, error, info};

///
/// Gets a list of Wireguard interfaces present on the system
///
pub async fn handle_get_interfaces() -> HttpResponse {
    // TODO: parse output into proper JSON object
    match get_interfaces() {
        Ok(ifcs) => {
            let resp = GetInterfacesResponse {
                interfaces: ifcs,
            };
            HttpResponse::Ok().json(resp)
        },
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
pub async fn handle_get_interface(info: web::Path<String>) -> HttpResponse {
    // todo: validate interface name
    let interface_name = info;
    info!(
        "request interface info for interface with name: {}",
        interface_name.clone()
    );

    match get_interface(&interface_name) {
        Ok(info) => {
            debug!("interface info: \"{}\"", &info);
            let resp = GetInterfaceResponse {
                interface: info,
            };
            HttpResponse::Ok().json(resp)
        },
        Err(e) => {
            HttpResponse::InternalServerError().reason("failed to get interface").finish()
        }
    }
}

///
/// Route that handles requests to generate an interface config
///
pub async fn handle_gen_ifc_cfg(info: web::Json<GenInterfaceRequest>) -> impl Responder {
    let ifc_req = info.0;

    let priv_key = ifc_req
        .private_key
        .unwrap_or_else(|| gen_private_key().unwrap());
    let port = ifc_req.listen_port.unwrap_or(DFLT_WG_PORT);
    // TODO: handle dns, mut, table, pre/post up/down
    match gen_interface_conf(&priv_key, &ifc_req.address, &port) {
        Ok(conf) => {
            debug!("generated interface configuration:\"\n{}\"", &conf);
            let resp = GenInterfaceResponse {
                interface_config: conf,
            };
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
pub async fn handle_create_interface(
    path: web::Path<String>,
    info: web::Json<GenInterfaceRequest>,
    web_store: web::Data<kv::Store>,
) -> HttpResponse {
    let req = info.0;
    let private_key = req
        .private_key
        .unwrap_or_else(|| gen_private_key().unwrap());
    let ifc_name = path.to_string();
    let port = req.listen_port.unwrap_or(DFLT_WG_PORT);

    match create_interface(&ifc_name, &req.address, &port, &private_key) {
        Ok(d) => {
            debug!("interface created: {:?}", d);
            HttpResponse::Ok().reason("interface created").finish()
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
pub async fn handle_remove_interface(info: web::Path<String>) -> HttpResponse {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::init_logger;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_handle_get_interfaces() {
        init_logger();
        // todo: create/add interfaces and verify they exist in the returned list
        let mut app =
            test::init_service(App::new().route("/", web::get().to(handle_get_interfaces))).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("response: {:?}", resp);
        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_handle_get_interface() {
        // todo: create/add interface to check result properly
        let pk_res = gen_private_key();
        assert!(pk_res.is_ok());
        let private_key = pk_res.unwrap();

        let ifc_name = "test_ifc_1";
        let address = "192.0.0.1/24";
        let listen_port = 52810;

        let ci_res = create_interface(&ifc_name, &address, &listen_port, &private_key);
        assert!(ci_res.is_ok());
        let ifc = ci_res.unwrap();
        debug!("create interface: {:?}", ifc);

        let mut app =
            test::init_service(App::new().route(format!("/{}", &ifc_name), web::get().to(handle_get_interface))).await;
        let req = test::TestRequest::get().uri(format!("/{}", &ifc_name)).to_request();
        let resp = test::call_service(&mut app, req).await;
        debug!("response: {:?}", resp);
        assert!(resp.status().is_success());

        let rem_res = remove_interface(&ifc_name);
        assert!(rem_res.is_ok());
    }

    #[actix_rt::test]
    async fn test_gen_ifc_cfg() {
        let pk_res = gen_private_key();
        assert!(pk_res.is_ok());
        let private_key = pk_res.unwrap();

        let ifc_name = "test_ifc_1";
        let address = "192.0.0.1/24";
        let listen_port = 52810;

        let ifc_cfg_res = gen_interface_conf(&private_key, &address, &listen_port);
        assert!(ifc_cfg_res.is_ok());
        let ifc_cfg = ifc_cfg_res.unwrap();
        debug!("interface config: {:?}", ifc_cfg);
    }
}