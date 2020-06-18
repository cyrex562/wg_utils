use actix_web::{web, App, HttpRequest, HttpServer, Responder, HttpResponse, get};
use actix_rt;
use log;
use std::process::Command


#[get("/index")]
async fn index1() -> impl Responder {
    HttpResponse::Ok().body("hello, world")
}

#[get("/interfaces")]
async fn showconf() -> {
    let output = Command::new("sh")
    .arg("-c")
    .arg("wg")
    .arg("show")
    .arg("interfaces")
    .output()
    .expect("failed to execute process");
    let interfaces_raw_output = output.stdout;
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(index1)
    })
    .bind("127.0.0.1:8100")?
    .run()
    .await
}