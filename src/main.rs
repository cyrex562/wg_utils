#[macro_use]
extern crate lazy_static;

use actix_files as fs;
use actix_rt;
// use actix_utils::mpsc;
use actix_web::http::{header, Method, StatusCode};
use actix_web::{
    error, get, guard, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer,
    Responder, Result,
};
use clap;
use log;
use std::io;
use std::process::Command;
use std::str;
use tera::{Context, Tera};

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

const DEF_CONTROLLER_PORT: &str = "8120";
const DEF_CONTROLLER_ADDR: &str = "127.0.0.1";

fn gen_interface_conf(
    private_key: String,
    ifc_ip: String,
    ifc_mask: String,
    listen_port: String,
) -> Result<String> {
    let mut ctx = Context::new();
    ctx.insert("virtual_ip", ifc_ip.as_str());
    ctx.insert("mask", ifc_mask.as_str());
    ctx.insert("listen_port", listen_port.as_str());
    ctx.insert("private_key", private_key.as_str());
}

#[get("/interfaces")]
async fn get_interfaces() -> impl Responder {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg("interfaces")
        .output()
        .expect("failed to execute process");
    let raw_output = output.stdout;
    let output_str = str::from_utf8(&raw_output).unwrap();
    HttpResponse::Ok().body(format!("wg show interfaces output: {}", output_str))
}

#[get("/interfaces/{interface_name}")]
async fn get_interface(info: web::Path<String>, req: HttpRequest) -> impl Responder {
    // todo: validate interface name
    let interface_name = info;
    println!("request: {:?}", req);
    println!("interface_name: {:?}", interface_name);
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg(interface_name.clone())
        .output()
        .expect("failed to execute process");
    let raw_output = output.stdout;
    let output_str = str::from_utf8(&raw_output).unwrap();
    HttpResponse::Ok().body(format!(
        "wg show interface {} output: {}",
        interface_name, output_str
    ))
}

/// 404 handler
async fn p404() -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/404.html")?.set_status_code(StatusCode::NOT_FOUND))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let matches = clap::App::new("wg_controller")
        .version("0.1")
        .about("wrapper for wireguard configfuration management")
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
        .arg(clap::Arg::with_name("endpoint_address")
            .short("e")
            .long("endpoint")
            .value_name("ENDPOINT_ADDRESS")
            .help("enpoint IP address for client configs, generally public IP or IP of the internet-facing interface")
            .required(true)
            .takes_value(true))
        .get_matches();

    let controller_port = matches.value_of("port").unwrap_or(DEF_CONTROLLER_PORT);
    let controller_addr = matches.value_of("address").unwrap_or(DEF_CONTROLLER_ADDR);
    println!(
        "controller binding: {}:{}",
        controller_addr, controller_port
    );
    let endpoint_addr = matches.value_of("endpoint").unwrap();
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            // .service(index1)
            .service(get_interfaces)
            .service(get_interface)
            .service(web::resource("/error").to(|| async {
                error::InternalError::new(
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
    .bind("0.0.0.0:8100")?
    .run()
    .await
}
