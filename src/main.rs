use actix_files as fs;
use actix_rt;
use serde::Deserialize;
use std::fs::File;
use std::process::Stdio;
// use actix_utils::mpsc;
use actix_web::http::{header, Method, StatusCode};
use actix_web::web::Query;
use actix_web::{
    get, guard, middleware, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};

use actix_web::error as web_error;
use actix_web::Error as WebError;
use actix_web::Result as WebResult;

use lazy_static::lazy_static;

use clap;
use log::{debug, error, info, warn};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use std::fmt;
use std::io;
use std::io::Write;
use std::process::Command;
use std::result::Result as std_result;
use std::str;
use tera::{Context, Tera};

#[derive(Debug)]
struct WgcError {
    message: String,
}

impl fmt::Display for WgcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message: {}", self.message)
    }
}

#[derive(Deserialize)]
struct GenPubKeyQuery {
    private: String,
}

#[derive(Deserialize)]
struct GenIfcConfigQuery {
    private: String,
    ip: String,
    mask: String,
    port: String,
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

const DEF_CONTROLLER_PORT: &str = "8120";
const DEF_CONTROLLER_ADDR: &str = "127.0.0.1";

const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'+')
    .add(b'=');

fn gen_interface_conf(
    private_key: String,
    ifc_ip: String,
    ifc_mask: String,
    listen_port: String,
) -> Result<String, WgcError> {
    let mut ctx = Context::new();
    ctx.insert("virtual_ip", ifc_ip.as_str());
    ctx.insert("mask", ifc_mask.as_str());
    ctx.insert("listen_port", listen_port.as_str());
    ctx.insert("private_key", private_key.as_str());
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

fn gen_private_key() -> Result<Vec<u8>, WgcError> {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("genkey")
        .output()
        .expect("failed to execute command");
    if output.status.success() {
        let mut priv_key = output.stdout.clone();
        priv_key.pop().unwrap();
        Ok(priv_key)
    } else {
        Err(WgcError {
            message: format!(
                "wg genkey failed: code: {} stdout: {} stderr: {}",
                output.status.code().unwrap(),
                str::from_utf8(output.stdout.as_slice()).unwrap(),
                str::from_utf8(output.stderr.as_slice()).unwrap()
            ),
        })
    }
}

fn gen_public_key(private_key: &Vec<u8>) -> std_result<Vec<u8>, WgcError> {
    let mut child = match Command::new("sudo")
        .arg("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(p) => p,
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to spawn process: {:?}", e),
            })
        }
    };
    let child_stdin = match child.stdin.as_mut() {
        Some(si) => si,
        None => {
            return Err(WgcError {
                message: format!("failed to get child stdin"),
            })
        }
    };

    match child_stdin.write_all(private_key.as_slice()) {
        Ok(()) => debug!("stdin written to child"),
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to write data to stdin: {:?}", e),
            })
        }
    };

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return Err(WgcError {
                message: format!("process failed: {:?}", e),
            })
        }
    };

    if output.status.success() {
        let mut pub_key = output.stdout.clone();
        pub_key.pop().unwrap();
        return Ok(pub_key);
    }

    Err(WgcError {
        message: format!(
            "command failed: code: {}, stdout: {}, stderr: {}",
            output.status.code().unwrap(),
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        ),
    })
}

fn create_interface(
    ifc_name: String,
    ifc_ip: String,
    ifc_mask: String,
    listen_port: String,
) -> Result<(), WgcError> {
    let private_key = gen_private_key()?;

    let public_key = gen_public_key(&private_key)?;

    let private_key_str = match String::from_utf8(private_key) {
        Ok(s) => s,
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to convert private_key vec to string: {:?}", e),
            })
        }
    };

    let ifc_conf_data = gen_interface_conf(private_key_str, ifc_ip, ifc_mask, listen_port)?;

    let ifc_cfg_file = format!("{}.conf", ifc_name);
    let ifc_cfg_tmp_path = format!("/tmp/{}", ifc_cfg_file);
    let ifc_cfg_wg_path = format!("/etc/{}", ifc_cfg_file);

    let mut file = match File::create(ifc_cfg_tmp_path.clone()) {
        Ok(f) => f,
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to create tmp ifc cfg file: {:?}", e),
            })
        }
    };

    match file.write_all(ifc_conf_data.as_bytes()) {
        Ok(()) => debug!("wrote cfg to tmp file"),
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to write interface config to tmp file: {:?}", e),
            })
        }
    };

    let output = Command::new("sudo")
        .arg("cp")
        .arg(ifc_cfg_tmp_path)
        .arg(ifc_cfg_wg_path)
        .output()
        .expect("failed to execute command");
    if output.status.success() {
        return Ok(());
    }
    Err(WgcError {
        message: format!(
            "failed to copy tmp file to wg config dir: status: {}, stdout: {}, stderr: {}",
            output.status.code().unwrap(),
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        ),
    })
}

#[get("/interfaces")]
async fn get_interfaces() -> impl Responder {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg("interfaces")
        .output()
        .expect("failed to execute command");
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

#[get("/utils/gen_ifc_config")]
async fn utils_gen_ifc_config(info: Query<GenIfcConfigQuery>) -> impl Responder {
    let private_key = info.private.clone();
    let ifc_ip = info.ip.clone();
    let ifc_mask = info.mask.clone();
    let listen_port = info.port.clone();

    match gen_interface_conf(private_key, ifc_ip, ifc_mask, listen_port) {
        Ok(conf) => HttpResponse::Ok().body(format!("config:\n{}\n", conf)),
        Err(e) => {
            error!("failed to generate config: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to generate config")
                .finish()
        }
    }
}

#[get("/utils/gen_priv_key")]
async fn utils_gen_priv_key() -> impl Responder {
    match gen_private_key() {
        Ok(pk) => {
            let pk_str = String::from_utf8(pk).unwrap();
            let pk_pe_str = utf8_percent_encode(pk_str.as_str(), FRAGMENT);
            HttpResponse::Ok().body(format!(
                "private key: {}\nprivate key (% encoded): {}",
                pk_str, pk_pe_str
            ))
        }
        Err(e) => {
            error!("failed to generate private key: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to generate private key")
                .finish()
        }
    }
}

#[get("/utils/gen_pub_key")]
async fn utils_gen_pub_key(info: Query<GenPubKeyQuery>) -> impl Responder {
    let private_key_bytes = info.private.clone().into_bytes();
    match gen_public_key(&private_key_bytes) {
        Ok(pk) => {
            let pk_str = String::from_utf8(pk).unwrap();
            let pk_pe_str = utf8_percent_encode(pk_str.as_str(), FRAGMENT);
            HttpResponse::Ok().body(format!(
                "public key: {}\npublic key (% encoded): {}\n",
                pk_str, pk_pe_str
            ))
        }
        Err(e) => {
            error!("failed to generate public key: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to generate public key")
                .finish()
        }
    }
}

/// 404 handler
async fn p404() -> WebResult<fs::NamedFile> {
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
        .arg(clap::Arg::with_name("endpoint")
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
    let controller_bind = format!("{}:{}", controller_addr, controller_port);

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            // .service(index1)
            .service(get_interfaces)
            .service(get_interface)
            .service(utils_gen_pub_key)
            .service(utils_gen_priv_key)
            .service(utils_gen_ifc_config)
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
