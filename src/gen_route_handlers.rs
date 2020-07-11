use crate::defines::{GenPrivKeyResponse, GenPubKeyRequest, GenPubKeyResponse};
use crate::gen_logic::{gen_private_key, gen_public_key};
use actix_files as fs;
use actix_web::http::StatusCode;
use actix_web::Result as WebResult;
use actix_web::{web, HttpResponse, Responder};
use log::{debug, error};

///
/// Route handler that generates a private key
///
pub async fn handle_gen_priv_key() -> HttpResponse {
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

pub async fn handle_gen_pub_key(info: web::Json<GenPubKeyRequest>) -> impl Responder {
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

/// 404 handler
pub async fn p404() -> WebResult<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/404.html")?.set_status_code(StatusCode::NOT_FOUND))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn test_handle_gen_priv_key() {
        let mut app = test::init_service(App::new().route("/", web::get().to(handle_gen_priv_key))).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp: GenPrivKeyResponse = test::read_response_json(&mut app, req).await;
        println!("response: {:?}", resp);
        assert_ne!(resp.private_key.len(), 0);
    }
}
