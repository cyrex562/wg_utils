use actix_web::{web, App, HttpRequest, HttpServer, Responder, HttpResponse, get, middleware, Error, Result, error, guard,};
use actix_web::http::{header, Method, StatusCode};
use actix_rt;
use log;
use std::process::Command;
use std::str;
use std::{env, io};
use actix_files as fs;
use actix_utils::mpsc;
use tera::Tera;

let tera = match Tera::new("templates/*.template") {
    Ok(t) => t,
    Err(e) => {
        println!("failed to compile templates: {}", e);
        ::std::process::exit(1);
    }
}

// #[get("/index")]
// async fn index1() -> impl Responder {
//     HttpResponse::Ok().body("hello, world")
// }

async fn index2(req: HttpRequest) -> Result<NamedFile> {
    let path: PathBuf = req.match_info().query("filename").parse().unwrap();
}

#[get("/interfaces")]
async fn get_interfaces() -> impl Responder {
    let output = Command::new("sudo")
    .arg("wg")
    .arg("show")
    .arg("interfaces")
    .output()
    .expect("failed to execute process");
    let raw_output
     = output.stdout;
    let output_str = str::from_utf8(&raw_output
    ).unwrap();
    HttpResponse::Ok().body(format!("wg show interfaces output: {}", output_str))
}

#[get("/interfaces/{interface_name}")]
async fn get_interface(
    info: web::Path<String>,
    req: HttpRequest) -> impl Responder {
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
    HttpResponse::Ok().body(format!("wg show interface {} output: {}", interface_name, output_str))
}

/// 404 handler
async fn p404() -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/404.html")?.set_status_code(StatusCode::NOT_FOUND))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
        .wrap(middleware::Logger::default())
            .service(index1)
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
                web::resource("")
                    .route(web::get().to(p404))
                    .route(
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