mod defines;

use kv::{Store, Msgpack};
use crate::defines::{Config, GenInterfaceRequest, GenInterfaceResponse, GenPeerRequest, GenPeerResponse, GenPrivKeyResponse, GenPubKeyRequest, GenPubKeyResponse, GetInterfaceResponse, GetInterfacesResponse, WgcError, DEF_CONTROLLER_PORT, DFLT_CONFIG_FILE, DFLT_KEEPALIVE, DFLT_WG_PORT, WgInterface, WgPeer};
use actix_files as fs;
use actix_web::error as web_error;
use actix_web::http::{header, StatusCode};
use actix_web::Result as WebResult;
use actix_web::{guard, middleware, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use lazy_static::lazy_static;
use log::{debug, error, info};
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use std::result::Result as std_result;
use std::str;
use tera::{Context, Tera};
use kv;


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

///
/// Initialize the fern logger
///
fn init_logger() -> Result<(), fern::InitError> {
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
        .apply()?;

    Ok(())
}

///
/// Generate an interface configuration
///
fn gen_interface_conf(
    private_key: &str,
    address: &str,
    listen_port: &u32,
) -> Result<String, WgcError> {
    let key_str = private_key;
    let key_part = key_str.get(0..3).unwrap();
    debug!(
        "generating interface config: private key: {}..., address: {}, listen_port: {}\n",
        key_part, &address, &listen_port
    );
    let mut ctx = Context::new();
    ctx.insert("address", address);
    ctx.insert("listen_port", listen_port);
    ctx.insert("private_key", private_key);
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
/// Generate a peer config
///
fn gen_peer_conf(
    public_key: &str,
    allowed_ips: &[String],
    endpoint: &Option<String>,
    keepalive: &Option<u32>,
) -> Result<String, WgcError> {
    let key_str = public_key;
    let key_part = key_str.get(0..3).unwrap();
    let set_endpoint = endpoint.is_some();
    let ep = endpoint.clone().unwrap_or_else(|| "".to_string());
    let ka: u32 = keepalive.unwrap_or(25);
    let allowed_ips_joined = allowed_ips.join(",v");
    let set_keepalive = keepalive.is_none();
    debug!(
        "generating peer config: key: \"{}\", endpoint: \"{}\" allowed_ips: \"{}\"",
        key_part, ep, allowed_ips_joined
    );
    let mut ctx: Context = Context::new();
    ctx.insert("set_endpoint", &set_endpoint);
    if set_endpoint {
        ctx.insert("endpoint", &ep);
    }
    ctx.insert("public_key", &public_key);
    ctx.insert("allowed_ips", &allowed_ips_joined);
    ctx.insert("set_keepalive", &set_keepalive);
    if set_keepalive {
        ctx.insert("keepalive", &ka);
    }

    match TEMPLATES.render("peer.conf.template", &ctx) {
        Ok(s) => Ok(s),
        Err(e) => {
            error!("failed to render peer conf template: {:?}", e);
            Err(WgcError {
                message: format!("failed to render peer conf template: {:?}", e),
            })
        }
    }
}

///
/// Generate a Wireguard Private Key
///
fn gen_private_key() -> Result<String, WgcError> {
    let output = Command::new("sudo")
        .arg("wg")
        .arg("genkey")
        .output()
        .expect("failed to execute command");
    if output.status.success() {
        let mut priv_key = output.stdout;
        priv_key.pop().unwrap();
        Ok(String::from_utf8(priv_key).unwrap())
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
fn gen_public_key(private_key: &str) -> std_result<String, WgcError> {
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
                message: "failed to get child stdin".to_string(),
            })
        }
    };

    match child_stdin.write_all(private_key.as_bytes()) {
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
        let mut pub_key = output.stdout;
        pub_key.pop().unwrap();
        return Ok(String::from_utf8(pub_key).unwrap());
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
/// 
/// 
// fn get_interfaces_from_store(store: web::Data<kv::Store>) -> 
//     Result<kv::Iter<&str, Msgpack<WgInterface>>, WgcError> {
//     let bucket = match store.bucket::<&str, Msgpack<WgInterface>>(Some("interfaces")) {
//         Ok(b) => b,
//         Err(e) => {
//             error!("failed to get interfaces bucket: {:?}", e);
//             return Err(WgcError {
//                 message: format!("failed to get interfaces bucket: {:?}", e)
//             })
//         }
//     };
//     Ok(bucket.iter())
// }

///
/// Adds an interface to the KV store in the "interfaces" bucket. The key for the interface is the interfaces' name.
/// 
fn add_interface_to_store(store: web::Data<kv::Store>, ifc: WgInterface) -> 
Result<(), WgcError> {
    let bucket = match store.bucket::<&str, Msgpack<WgInterface>>(Some("interfaces")) {
        Ok(b) => b,
        Err(e) => {
            error!("failed to get interfaces bucket: {:?}", e);
            return Err(WgcError {
                message: format!("failed to get interfaces bucket: {:?}", e)
            })
        }
    };
    match bucket.set(ifc.name.as_str(), Msgpack(ifc)) {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("failed to push interface to store: {:?}", e);
            Err(WgcError {
                message: format!("failed to push interface to store: {:?}", e)
            })
        }
    }
}

///
/// Gets an interface from the KV store's "interfaces" bucket, using the interface's name as its key. 
///
fn get_interface_from_store_by_name(store: web::Data<kv::Store>, name: &str) ->
    Result<WgInterface, WgcError> {
        let bucket = match store.bucket::<&str, Msgpack<WgInterface>>(Some("interfaces")) {
            Ok(b) => b,
            Err(e) => {
                error!("failed to get interfaces bucket: {:?}", e);
                return Err(WgcError {
                    message: format!("failed to get interfaces bucket: {:?}", e)
                })
            }
        };
        
    let ifc_msg = match bucket.get(name) {
        Ok(m) => m,
        Err(e) => {
            error!("failed to get interface from bucket: {:?}", e);
            return Err(WgcError {
                message: format!("failed to get interface from bucket: {:?}", e)
            })
        }
    };

    let msg = match ifc_msg {
        Some(m) => m,
        None => Err(WgcError{
            message: String::from("failed to get message from MsgPack obj")
        })
    };
}

/// Create a WireGuard interface
///
fn create_interface(
    store: web::Data<kv::Store>,
    ifc_name: &str,
    address: &str,
    listen_port: &u32,
    private_key: &str,
) -> Result<(), WgcError> {
    // TODO: support dns, mtu, table, and pre/post up/down
    let ifc_conf_data = gen_interface_conf(&private_key, address, listen_port)?;
    let ifc_cfg_file = format!("{}.conf", ifc_name);
    let ifc_cfg_tmp_path = format!("/tmp/{}", ifc_cfg_file);
    let ifc_cfg_wg_path = format!("/etc/wireguard/{}", ifc_cfg_file);

    let mut wg_ifc = WgInterface::default();
    wg_ifc.config_file_path = ifc_cfg_wg_path.clone();
    wg_ifc.name = ifc_name.to_string().clone();
    wg_ifc.private_key = private_key.to_string().clone();
    wg_ifc.address = address.to_string().clone();
    wg_ifc.listen_port = *listen_port;

    if Path::new(&ifc_cfg_wg_path).exists() {
        return Err(WgcError {
            message: format!("interface config at {} already exists", &ifc_cfg_wg_path),
        });
    }

    let mut file = match File::create(&ifc_cfg_tmp_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to create tmp ifc cfg file: {:?}", e),
            })
        }
    };

    match file.write_all(ifc_conf_data.as_bytes()) {
        Ok(()) => (),
        Err(e) => {
            return Err(WgcError {
                message: format!("failed to write interface config to tmp file: {:?}", e),
            })
        }
    };

    let mut output = Command::new("sudo")
        .arg("cp")
        .arg(&ifc_cfg_tmp_path)
        .arg(&ifc_cfg_wg_path)
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        return Err(WgcError {
            message: format!(
                "failed to copy tmp file to wg config dir: status: {}, stdout: {}, stderr: {}",
                output.status.code().unwrap(),
                str::from_utf8(&output.stdout).unwrap(),
                str::from_utf8(&output.stderr).unwrap()
            ),
        });
    }

    output = Command::new("sudo")
        .arg("wg-quick")
        .arg("up")
        .arg(&ifc_cfg_wg_path)
        // .arg(info.name.clone())
        .output()
        .expect("failed to execute command");
    if !output.status.success() {
        let output_str = str::from_utf8(&output.stdout).unwrap();
        let err_str = str::from_utf8(&output.stderr).unwrap();
        return Err(WgcError {
            message: format!(
                "failed to set wg interface to config file: stdout: \"{}\", stderr: \"{}\"",
                &output_str, &err_str
            ),
        });
    }

    add_interface_to_store(store, wg_ifc)?;

    info!("interface {} created", &ifc_name);
    Ok(())
}

///
/// Gets a list of Wireguard interfaces present on the system
///
async fn handle_get_interfaces() -> HttpResponse {
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
    // TODO: parse ouptut into proper JSON object

    let resp = GetInterfacesResponse {
        interfaces: output_str,
    };
    HttpResponse::Ok().json(resp)
}

///
/// Gets information about a specific interface
///
async fn handle_get_interface(info: web::Path<String>) -> HttpResponse {
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
async fn handle_gen_ifc_cfg(info: web::Json<GenInterfaceRequest>) -> impl Responder {
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
/// Route handler that generates a private key
///
async fn handle_gen_priv_key() -> HttpResponse {
    match gen_private_key() {
        Ok(pk) => {
            let priv_key_obj = GenPrivKeyResponse { private_key: pk };
            HttpResponse::Ok().json(priv_key_obj)
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

async fn handle_gen_pub_key(info: web::Json<GenPubKeyRequest>) -> impl Responder {
    debug!("gen pub key request: {:?}", &info);
    let private_key: String = info.0.private_key;
    match gen_public_key(&private_key) {
        Ok(pk) => {
            let pub_key_resp = GenPubKeyResponse { public_key: pk };
            HttpResponse::Ok().json(pub_key_resp)
        }
        Err(e) => {
            error!("failed to generate public key: {:?}", e);
            HttpResponse::InternalServerError()
                .reason("failed to generate public key")
                .finish()
        }
    }
}

///
/// Route handler for creating a Wireguard interface
///
async fn handle_create_interface(
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

    match create_interface(web_store, &ifc_name, &req.address, &port, &private_key) {
        Ok(()) => {
            debug!("interface created");
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
async fn handle_remove_interface(info: web::Path<String>) -> HttpResponse {
    let interface_name = info.to_string();
    info!("request  remove interface with name: {}", &interface_name);

    let mut output = Command::new("sudo")
        .arg("wg-quick")
        .arg("down")
        .arg(interface_name.clone())
        .output()
        .expect("failed to execute command");
    let std_out_str = str::from_utf8(&output.stdout).unwrap();
    let std_err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to down wg interface {}, stdout: \"{}\", stderr: \"{}\"",
            interface_name, std_out_str, std_err_str
        );
        return HttpResponse::InternalServerError()
            .reason("failed to down WG interface")
            .finish();
    }

    let ifc_wg_cfg_path = format!("/etc/wireguard/{}.conf", interface_name);
    output = Command::new("sudo")
        .arg("rm")
        .arg(ifc_wg_cfg_path)
        .output()
        .expect("failed to execute command");
    let std_out_str = str::from_utf8(&output.stdout).unwrap();
    let std_err_str = str::from_utf8(&output.stderr).unwrap();
    if !output.status.success() {
        error!(
            "failed to delete interface {} config, stdout: \"{}\", stderr: \"{}\"",
            interface_name, std_out_str, std_err_str
        );
        return HttpResponse::InternalServerError()
            .reason("failed to delete WG interface config")
            .finish();
    }

    info!("interface {} removed", interface_name);
    HttpResponse::Ok().reason("interface removed").finish()
}

///
/// Route handler to generate a peer config
///
async fn handle_gen_peer(info: web::Json<GenPeerRequest>) -> HttpResponse {
    let req = info.0;
    match gen_peer_conf(
        &req.public_key,
        &req.allowed_ips,
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

///
/// Route handler to add peer to an interface
///
async fn handle_add_peer(info: web::Json<GenPeerRequest>, path: web::Path<String>) -> HttpResponse {
    let ifc_name = path.to_string();
    let req = info.0;

    // add config to
    let mut output = if req.endpoint.is_some() {
        Command::new("sudo")
            .arg("wg")
            .arg("set")
            .arg(&ifc_name)
            .arg("peer")
            .arg(&req.public_key)
            .arg("endpoint")
            .arg(&req.endpoint.unwrap())
            .arg("persistent-keepalive")
            .arg(format!(
                "{}",
                req.persistent_keepalive.unwrap_or(DFLT_KEEPALIVE)
            ))
            .arg("allowed-ips")
            .arg(&req.allowed_ips.join(","))
            .output()
            .expect("failed to execute command")
    } else {
        Command::new("sudo")
            .arg("wg")
            .arg("set")
            .arg(&ifc_name)
            .arg("peer")
            .arg(&req.public_key)
            .arg("persistent-keepalive")
            .arg(format!(
                "{}",
                req.persistent_keepalive.unwrap_or(DFLT_KEEPALIVE)
            ))
            .arg("allowed-ips")
            .arg(&req.allowed_ips.join(","))
            .output()
            .expect("failed to execute command")
    };

    if !output.status.success() {
        error!(
            "failed to add peer to config: stdout: {}, stderr: {}",
            str::from_utf8(output.stdout.as_slice()).unwrap(),
            str::from_utf8(output.stderr.as_slice()).unwrap()
        );
        return HttpResponse::InternalServerError()
            .reason("failed to add peer to config")
            .finish();
    }

    output = Command::new("sudo")
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

///
/// Route handler to remove peer from an interface
///
async fn handle_remove_peer(
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
        Err(e) => {
            panic!("failed to get kv store: {:?}", e)
        }
    };
    let web_store: web::Data<kv::Store> = web::Data::new(kv_store);
    
    debug!(
        "controller binding: {}:{}",
        controller_addr, controller_port
    );

    let _endpoint_addr = matches.value_of("endpoint").unwrap();
    let controller_bind = format!("{}:{}", controller_addr, controller_port);

    match init_logger() {
        Ok(_) => (),
        Err(e) => panic!("failed to init logger: {}", e),
    };

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
