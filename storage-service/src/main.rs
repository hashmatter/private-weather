mod utils;
mod controllers;

#[macro_use]
extern crate rouille;

use std::env;
use std::vec::Vec;
use std::sync::Arc;

use curve25519_dalek::scalar::Scalar; 
use sinkhole_core::traits::core::Storage;
use elgamal_ristretto::ciphertext::Ciphertext; 

fn main() {
    println!("SINKHOLE: Bootstapping service..");

    let config_path = match env::var("CONFIG_PATH") {
        Ok(p) => p,
        Err(_) => {
            println!("Config: Environment variable CONFIG_PATH not defined");
            std::process::exit(0x0100); 
        },
    };

    let (sk, pk) = utils::get_or_generate_keypair();
    let configs = utils::parse_configs(config_path);

    const K: u32 = 13; // 2^K database entries
    let size_storage: u32 = 2u32.pow(K);
    let mut content: Vec<Scalar> = (1..size_storage + 1)
        .map(|_| Scalar::zero())
        .collect();

    let storage = Arc::new(sinkhole_core::elgamal::Storage::new(sk, content));

    let addr = format!("{}:{}", configs.host, configs.port);
    println!("< SERVER: now listening on {}", addr);

    rouille::start_server(addr, move |req| {
        router!(req,
            (GET) (/v1/meta) => {
                println!("GET /v1/meta"); 

                let meta_res = controllers::meta_request();
                rouille::Response::text(format!("{:?}", meta_res))
            },
            (GET) (/v1/query) => {
                println!("GET /v1/query");

                let query: Vec<Ciphertext> = vec![];
                let encrypted_result = storage.retrieve(query);
                rouille::Response::text(format!("{:?}", encrypted_result))
            },
            _ => rouille::Response::empty_404()
        ) 
    });
}
