mod defines;
mod gen_logic;
mod gen_route_handlers;
mod interface_logic;
mod interface_route_handlers;
mod peer_logic;
mod peer_route_handlers;
mod utils;

use crate::defines::{DEF_CONTROLLER_PORT, DFLT_CONFIG_FILE};
use actix_files as fs;
use actix_web::error as web_error;
use actix_web::http::{header, StatusCode};

use actix_web::{guard, middleware, web, App, HttpRequest, HttpResponse, HttpServer};

use log::debug;

use gen_route_handlers::{handle_gen_priv_key, handle_gen_pub_key, p404};
use interface_route_handlers::{
    handle_create_interface, handle_gen_ifc_cfg, handle_get_interface, handle_get_interfaces,
    handle_remove_interface,
};
use peer_route_handlers::{handle_add_peer, handle_gen_peer, handle_remove_peer};
use std::io;
use utils::init_logger;

///
/// Program entry point
///
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let matches = clap::App::new("wg_controller")
        .version("0.1")
        .about("wrapper for wireguard configuration management")
        .author("Josh M.")
        .arg(clap::Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("PORT")
            .help("controller listen port")
            .takes_value(true))
        .arg(clap::Arg::with_name("address")
            .short("a")
            .long("address")
            .value_name("ADDRESS")
            .help("controller listen address")
            .takes_value(true))
        .arg(clap::Arg::with_name("endpoint")
            .short("e")
            .long("endpoint")
            .value_name("ENDPOINT_ADDRESS")
            .help("enpoint IP address for client configs, generally public IP or IP of the internet-facing interface")
            .required(true)
            .takes_value(true))
        .arg(clap::Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("CONFIG_FILE")
            .help("path to a configuration file to use")
            .takes_value(true))
        .get_matches();

    let controller_port = matches.value_of("port").unwrap_or(DEF_CONTROLLER_PORT);
    let controller_addr = matches.value_of("address").unwrap_or(DEF_CONTROLLER_PORT);
    let config_file = matches.value_of("config").unwrap_or(DFLT_CONFIG_FILE);

    let kv_config = kv::Config::new(config_file);
    let kv_store = match kv::Store::new(kv_config) {
        Ok(st) => st,
        Err(e) => panic!("failed to get kv store: {:?}", e),
    };
    let web_store: web::Data<kv::Store> = web::Data::new(kv_store);

    debug!(
        "controller binding: {}:{}",
        controller_addr, controller_port
    );

    let _endpoint_addr = matches.value_of("endpoint").unwrap();
    let controller_bind = format!("{}:{}", controller_addr, controller_port);

    init_logger();

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web_store.clone())
            .service(web::resource("/interfaces").route(web::get().to(handle_get_interfaces)))
            .service(web::resource("/utils/gen_priv_key").route(web::get().to(handle_gen_priv_key)))
            .service(web::resource("/utils/gen_pub_key").route(web::post().to(handle_gen_pub_key)))
            .service(
                web::resource("/interfaces/{interface_name}")
                    .route(web::get().to(handle_get_interface)),
            )
            .service(web::resource("/interfaces").route(web::post().to(handle_gen_ifc_cfg)))
            .service(
                web::resource("/interfaces/{interface_name}")
                    .route(web::post().to(handle_create_interface)),
            )
            .service(
                web::resource("/interfaces/{interface_name}")
                    .route(web::delete().to(handle_remove_interface)),
            )
            .service(web::resource("/peers").route(web::post().to(handle_gen_peer)))
            .service(
                web::resource("/peers/{interface_name}").route(web::post().to(handle_add_peer)),
            )
            .service(
                web::resource("/peers/{interface_name").route(web::delete().to(handle_remove_peer)),
            )
            .service(web::resource("/error").to(|| async {
                web_error::InternalError::new(
                    io::Error::new(io::ErrorKind::Other, "test"),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }))
            .service(fs::Files::new("/static", "static").show_files_listing())
            .service(web::resource("/").route(web::get().to(|req: HttpRequest| {
                println!("{:?}", req);
                HttpResponse::Found()
                    .header(header::LOCATION, "static/index.html")
                    .finish()
            })))
            .default_service(
                web::resource("").route(web::get().to(p404)).route(
                    web::route()
                        .guard(guard::Not(guard::Get()))
                        .to(HttpResponse::MethodNotAllowed),
                ),
            )
    })
    .bind(controller_bind)?
    .run()
    .await
}
