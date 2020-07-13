mod defines;
mod gen_logic;
mod gen_route_handlers;
mod interface_logic;
mod interface_route_handlers;
mod peer_logic;
mod peer_route_handlers;
mod utils;

use actix_web::Responder;
use crate::defines::DFLT_CONFIG_FILE;
use actix_files as fs;
use actix_web::http::{header};
use std::io::Read;
use actix_web::{guard, middleware, web, App, HttpRequest, HttpResponse, HttpServer, get};
use log::debug;
use defines::{Config, DB_FILE};
use gen_route_handlers::p404;
use std::{fs::File, path::Path};
use utils::init_logger;

// TODO: add route to show config

#[get("/swagger-client")]
pub async fn get_swagger_client() -> impl Responder {
    HttpResponse::Found()
                    .header(header::LOCATION, "static/swagger_client.html")
                    .finish()
}

#[get("/rapidoc")]
pub async fn get_rapidoc() -> impl Responder {
    HttpResponse::Found()
        .header(header::LOCATION, "static/rapidoc.html")
        .finish()
}

#[get("/")]
pub async fn get_index() -> impl Responder {
    HttpResponse::Found()
        .header(header::LOCATION, "static/index.html")
        .finish()
}

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(get_swagger_client);
    cfg.service(get_rapidoc);
    cfg.service(get_index);
}

///
/// Program entry point
///
#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let matches = clap::App::new("wg_controller")
        .version("0.1")
        .about("wrapper for wireguard configuration management")
        .author("Josh M.")
        .arg(
            clap::Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("CONFIG_FILE")
                .required(true)
                .help("path to a configuration file to use")
                .default_value(DFLT_CONFIG_FILE)
                .takes_value(true),
        )
        .get_matches();

    let config_file = matches.value_of("config").unwrap();
    if !Path::new(config_file).exists() {
        panic!("config file {} not found", config_file)
    }
    let mut file = File::open(config_file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: Config = toml::from_str(&contents)?;
    let web_config: web::Data<Config> = web::Data::new(config.clone());

    let kv_config = kv::Config::new(DB_FILE);
    let kv_store = match kv::Store::new(kv_config) {
        Ok(st) => st,
        Err(e) => panic!("failed to get kv store: {:?}", e),
    };
    let web_store: web::Data<kv::Store> = web::Data::new(kv_store);

    debug!(
        "controller binding: {}:{}",
        &config.controller_address, &config.controller_port
    );

    let _endpoint_addr = config.local_endpoint;
    let controller_bind = format!("{}:{}", &config.controller_address, &config.controller_port);

    init_logger();

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web_store.clone())
            .app_data(web_config.clone())
            .configure(gen_route_handlers::init)
            .configure(interface_route_handlers::init)
            .configure(peer_route_handlers::init)
            .configure(init)
            .service(fs::Files::new("/static", "static").show_files_listing())
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
