use actix_files as fs;
use actix_rt;
use actix_web::error as web_error;
use actix_web::http::{header, Method, StatusCode};
use actix_web::middleware::Logger;
use actix_web::web::Query;
use actix_web::Error as WebError;
use actix_web::Result as WebResult;
use actix_web::{
    get, guard, middleware, web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chrono;
use clap;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::result::Result as std_result;
use std::str;
use tera::{Context, Tera};

///
/// Custom error thrown by functions
///
#[derive(Debug)]
struct WgcError {
    message: String,
}

impl fmt::Display for WgcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message: {}", self.message)
    }
}

///
/// HTTP query parameters for generating a public key
///
#[derive(Deserialize)]
struct GenPubKeyQuery {
    private: String,
}

///
/// HTTP query parameters for generating an interface configuration
///
#[derive(Deserialize)]
struct GenIfcConfigQuery {
    private: String,
    ip: String,
    mask: String,
    port: String,
}

#[derive(Deserialize)]
struct CreateIfcQuery {
    name: String,
    ip: String,
    mask: String,
    port: Option<String>,
    key: Option<String>,
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
const DFLT_WG_PORT: &str = "51820";

const FRAGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'+')
    .add(b'=');

pub fn init_logger() -> Result<(), fern::InitError> {
    // let formatter = syslog::Formatter3164 {
    //     facility: syslog::Facility::LOG_USER,
    //     hostname: None,
    //     process: "prism_tank".to_owned(),
    //     pid: 0,
    // };
    fern::Dispatch::new()
        .chain(
            fern::Dispatch::new()
                .level(log::LevelFilter::Debug)
                .format(|out, message, record| {
                    out.finish(format_args!(
                        "{}:{}:{}:{}",
                        chrono::Local::now().format("%Y-%m-%d-%H:%M:%S"),
                        record.target(),
                        record.level(),
                        message
                    ))
                })
                .chain(std::io::stdout()),
        )
        // .chain(
        //     fern::Dispatch::new()
        //         .level(log::LevelFilter::Info)
        //         .chain(syslog::unix(syslog::Facility::LOG_USER)?)
        // )
        .apply()?;

    Ok(())
}

///
/// Generate an interface configuration
///
fn gen_interface_conf(
    private_key: String,
    ifc_ip: String,
    ifc_mask: String,
    listen_port: String,
) -> Result<String, WgcError> {
    let key_str = private_key.clone();
    let key_part = key_str.get(0..3).unwrap();
    debug!("generating interface config: private key: {}..., ifc_ip: {}, ifc_mask: {}, listen_port: {}\n",
key_part, ifc_ip, ifc_mask, listen_port);
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

///
/// Generate a Wireguard Private Key
///
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

///
/// Generate a Wireguard public key from a private key
///
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

///
/// Create a WireGuard interface
///
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

///
/// Gets a list of Wireguard interfaces present on the system
///
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

///
/// Gets information about a specific interface
///
#[get("/interfaces/{interface_name}")]
async fn get_interface(info: web::Path<String>, req: HttpRequest) -> impl Responder {
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
    if output.status.success() == false {
        error!(
            "failed to get interface information: stdout: \"{}\", stderr: \"{}\"",
            output_str.clone(),
            err_str.clone()
        );
        return HttpResponse::BadRequest()
            .reason("failed to get interface info by name")
            .finish();
    }
    HttpResponse::Ok().body(format!(
        "wg show interface {} output: {}",
        interface_name, output_str
    ))
}

///
/// Route that handles requests to generate an interface config
///
#[get("/interfaces/do/gen_config")]
async fn interfaces_gen_config(info: Query<GenIfcConfigQuery>) -> impl Responder {
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

///
/// Route handler that generates a private key
///
#[get("/interfaces/do/gen_priv_key")]
async fn interfaces_gen_priv_key() -> impl Responder {
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

///
/// Route handler that generates a public key from a specified private key
///
#[get("/interfaces/do/gen_pub_key")]
async fn interfaces_gen_pub_key(info: Query<GenPubKeyQuery>) -> impl Responder {
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

#[get("/interfaces/do/create")]
async fn interfaces_create(info: Query<CreateIfcQuery>) -> impl Responder {
    let tmp_priv_key = match gen_private_key() {
        Ok(k) => k,
        Err(e) => {
            error!("failed to generate private key: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to generate private key")
                .finish();
        }
    };
    let tmp_priv_key_string = String::from_utf8(tmp_priv_key).unwrap();
    let private_key = info.key.clone().unwrap_or(tmp_priv_key_string);

    // check if file with interface name exists, and bail if it does
    let ifc_wg_cfg_path = format!("/etc/wireguard/{}.conf", info.name);
    let ifc_tmp_cfg_path = format!("/tmp/{}.conf", info.name);
    if Path::new(&ifc_wg_cfg_path).exists() == true {
        return HttpResponse::BadRequest()
            .reason("interface with same name already exists")
            .finish();
    }

    let port = info.port.clone().unwrap_or(DFLT_WG_PORT.to_string());
    let ifc_cfg = match gen_interface_conf(private_key, info.ip.clone(), info.mask.clone(), port) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to generate interface config: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to generate interface config")
                .finish();
        }
    };

    let mut fd1 = match File::create(ifc_tmp_cfg_path.clone()) {
        Ok(fd) => fd,
        Err(e) => {
            error!("failed to create tmp wg config file descriptor: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to create tmp wg config file descriptor")
                .finish();
        }
    };

    match fd1.write_all(ifc_cfg.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            error!("failed to write config to tmp file: {:?}", e);
            return HttpResponse::InternalServerError()
                .reason("failed to write config to tmp file")
                .finish();
        }
    };

    let mut output = Command::new("sudo")
        .arg("cp")
        .arg(ifc_tmp_cfg_path)
        .arg(ifc_wg_cfg_path.clone())
        .output()
        .expect("failed to execute command");
    if output.status.success() == false {
        error!("failed to copy ifc cfg file from tmp to wireguard conf dir");
        return HttpResponse::InternalServerError()
            .reason("failed to copy ifc cfg file from tmp to wireguard conf dir")
            .finish();
    }

    output = Command::new("sudo")
        .arg("wg-quick")
        .arg("up")
        .arg(ifc_wg_cfg_path.clone())
        // .arg(info.name.clone())
        .output()
        .expect("failed to execute command");
    if output.status.success() == false {
        let output_str = str::from_utf8(&output.stdout).unwrap();
        let err_str = str::from_utf8(&output.stderr).unwrap();
        error!(
            "failed to set wg interface to config file: stdout: \"{}\", stderr: \"{}\"",
            output_str, err_str
        );
        return HttpResponse::InternalServerError()
            .reason("failed to set wg interface to config file")
            .finish();
    }
    info!("interface {} created", info.name.clone());
    return HttpResponse::Ok().reason("interface created").finish();
}

#[get("/interfaces/do/remove/{interface_name}")]
async fn interfaces_remove(info: web::Path<String>, req: HttpRequest) -> impl Responder {
    let interface_name = info;
    info!("request  remove interface with name: {}", interface_name.clone());

    let output = Command::new("sudo")
        .arg("wg-quick")
        .arg("down")
        .arg(interface_name)
        .output()
        .expect("failed to execute command");
    let raw_out = output.stdout;
    let raw_out_str = str::from_utf8(&raw_out).unwrap();
    if output.status.success() == false {
        error!("failed to down wg interface {}")
    }
}

/// 404 handler
async fn p404() -> WebResult<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/404.html")?.set_status_code(StatusCode::NOT_FOUND))
}



///
/// Program entry point
///
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

    match init_logger() {
        Ok(_) => (),
        Err(e) => panic!("failed to init logger: {}", e),
    };

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            // .service(index1)
            .service(get_interfaces)
            .service(get_interface)
            .service(interfaces_gen_pub_key)
            .service(interfaces_gen_priv_key)
            .service(interfaces_gen_config)
            .service(interfaces_create)
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
