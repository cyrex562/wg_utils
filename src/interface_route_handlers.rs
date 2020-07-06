use crate::{
    defines::{
        GenInterfaceRequest, GenInterfaceResponse, GetInterfaceResponse, GetInterfacesResponse,
        DFLT_WG_PORT,
    },
    gen_logic::gen_private_key,
    interface_logic::{create_interface, gen_interface_conf, remove_interface},
};
use actix_web::{web, HttpResponse, Responder};
use log::{debug, error, info};
use std::process::Command;
use std::str;

///
/// Gets a list of Wireguard interfaces present on the system
///
pub async fn handle_get_interfaces() -> HttpResponse {
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
        return HttpResponse::InternalServerError()
            .reason("failed to get interfaces")
            .finish();
    }
    // TODO: parse output into proper JSON object

    let resp = GetInterfacesResponse {
        interfaces: output_str,
    };
    HttpResponse::Ok().json(resp)
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
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg(interface_name.clone())
        .output()
        .expect("failed to execute process");
    let output_str = str::from_utf8(&output.stdout).unwrap();
    let err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to get interface information: stdout: \"{}\", stderr: \"{}\"",
            &output_str, &err_str
        );
        return HttpResponse::BadRequest()
            .reason("failed to get interface info by name")
            .finish();
    }
    debug!("interface info: \"{}\"", &output_str);
    let resp = GetInterfaceResponse {
        interface: output_str.to_string(),
    };
    HttpResponse::Ok().json(resp)
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
}
