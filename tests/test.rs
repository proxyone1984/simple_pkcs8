use simple_pkcs8::{KeyPKCS8Builder};
use std::fs::File;
use std::io::Read;
use std::io::BufWriter;
use std::io::prelude::*;


fn read_file(f: &str) -> std::io::Result<Vec<u8>> {
    let mut fd = File::open(f)?;
    let mut data = Vec::new();
    let _amt = fd.read_to_end(&mut data)?;

    Ok(data)
}

fn write_file(f: &str, data: &Vec<u8>) -> std::io::Result<()> {
    let mut buffer = BufWriter::new(File::create(f)?);
    buffer.write_all(data)?;
    buffer.flush()?;

    Ok(())
}

#[test]
fn pkcs8_create_test_rsa() {
    let der_orig = match read_file("keys/rsa.pkcs8.der") {
        Ok(data) => data,
        Err(_) => panic!("Failed (Test): Read RSA key file")
    };

    let version: u64 = 0;
    let modulus: Vec<u8> = vec![
        0x00, 0xC0, 0x83, 0x23, 0xDC, 0x56, 0x88, 0x1B, 0xB8, 0x30, 0x20, 0x69,
        0xF5, 0xB0, 0x85, 0x61, 0xC6, 0xEE, 0xBE, 0x7F, 0x05, 0xE2, 0xF5, 0xA8, 0x42, 0x04, 0x8A, 0xBE,
        0x8B, 0x47, 0xBE, 0x76, 0xFE, 0xAE, 0xF2, 0x5C, 0xF2, 0x9B, 0x2A, 0xFA, 0x32, 0x00, 0x14, 0x16,
        0x01, 0x42, 0x99, 0x89, 0xA1, 0x5F, 0xCF, 0xC6, 0x81, 0x5E, 0xB3, 0x63, 0x58, 0x3C, 0x2F, 0xD2,
        0xF2, 0x0B, 0xE4, 0x98, 0x32, 0x83, 0xDD, 0x81, 0x4B, 0x16, 0xD7, 0xE1, 0x85, 0x41, 0x7A, 0xE5,
        0x4A, 0xBC, 0x29, 0x6A, 0x3A, 0x6D, 0xB5, 0xC0, 0x04, 0x08, 0x3B, 0x68, 0xC5, 0x56, 0xC1, 0xF0,
        0x23, 0x39, 0x91, 0x64, 0x19, 0x86, 0x4D, 0x50, 0xB7, 0x4D, 0x40, 0xAE, 0xCA, 0x48, 0x4C, 0x77,
        0x35, 0x6C, 0x89, 0x5A, 0x0C, 0x27, 0x5A, 0xBF, 0xAC, 0x49, 0x9D, 0x5D, 0x7D, 0x23, 0x62, 0xF2,
        0x9C, 0x5E, 0x02, 0xE8, 0x71,
    ];
    let pub_exp: Vec<u8> = vec![ 0x01, 0x00, 0x01 ];
    let priv_exp: Vec<u8> = vec![
        0x00, 0xBE, 0x86,
        0x0B, 0x0B, 0x99, 0xA8, 0x02, 0xA6, 0xFB, 0x1A, 0x59, 0x43, 0x8A, 0x7B, 0xB7, 0x15, 0x06, 0x5B,
        0x09, 0xA3, 0x6D, 0xC6, 0xE9, 0xCA, 0xCC, 0x6B, 0xF3, 0xC0, 0x2C, 0x34, 0xD7, 0xD7, 0x9E, 0x94,
        0xC6, 0x60, 0x64, 0x28, 0xD8, 0x8C, 0x7B, 0x7F, 0x65, 0x77, 0xC1, 0xCD, 0xEA, 0x64, 0x07, 0x4A,
        0xBE, 0x8E, 0x72, 0x86, 0xDF, 0x1F, 0x08, 0x11, 0xDC, 0x97, 0x28, 0x26, 0x08, 0x68, 0xDE, 0x95,
        0xD3, 0x2E, 0xFC, 0x96, 0xB6, 0xD0, 0x84, 0xFF, 0x27, 0x1A, 0x5F, 0x60, 0xDE, 0xFC, 0xC7, 0x03,
        0xE7, 0xA3, 0x8E, 0x6E, 0x29, 0xBA, 0x9A, 0x3C, 0x5F, 0xC2, 0xC2, 0x80, 0x76, 0xB6, 0xA8, 0x96,
        0xAF, 0x1D, 0x34, 0xD7, 0x88, 0x28, 0xCE, 0x9B, 0xDD, 0xB1, 0xF3, 0x4F, 0x9C, 0x94, 0x04, 0x43,
        0x07, 0x81, 0x29, 0x8E, 0x20, 0x13, 0x16, 0x72, 0x5B, 0xBD, 0xBC, 0x99, 0x3A, 0x41,
    ];
    let prime1: Vec<u8> = vec![
        0x00, 0xE1, 0xC6, 0xD9, 0x27, 0x64, 0x6C, 0x09, 0x16, 0xEC, 0x36, 0x82, 0x6D, 0x59, 0x49, 0x83,
        0x74, 0x0C, 0x21, 0xF1, 0xB0, 0x74, 0xC4, 0xA1, 0xA5, 0x98, 0x67, 0xC6, 0x69, 0x79, 0x5C, 0x85,
        0xD3, 0xDC, 0x46, 0x4C, 0x5B, 0x92, 0x9E, 0x94, 0xBF, 0xB3, 0x4E, 0x0D, 0xCC, 0x50, 0x14, 0xB1,
        0x0F, 0x13, 0x34, 0x1A, 0xB7, 0xFD, 0xD5, 0xF6, 0x04, 0x14, 0xD2, 0xA3, 0x26, 0xCA, 0xD4, 0x1C,
        0xC5,
    ];
    let prime2: Vec<u8> = vec![
        0x00, 0xDA, 0x48, 0x59, 0x97, 0x78, 0x5C, 0xD5, 0x63, 0x0F, 0xB0, 0xFD, 0x8C,
        0x52, 0x54, 0xF9, 0x8E, 0x53, 0x8E, 0x18, 0x98, 0x3A, 0xAE, 0x9E, 0x6B, 0x7E, 0x6A, 0x5A, 0x7B,
        0x5D, 0x34, 0x37, 0x55, 0xB9, 0x21, 0x8E, 0xBD, 0x40, 0x32, 0x0D, 0x28, 0x38, 0x7D, 0x78, 0x9F,
        0x76, 0xFA, 0x21, 0x8B, 0xCC, 0x2D, 0x8B, 0x68, 0xA5, 0xF6, 0x41, 0x8F, 0xBB, 0xEC, 0xA5, 0x17,
        0x9A, 0xB3, 0xAF, 0xBD,
    ];
    let exp1: Vec<u8> = vec![
        0x50, 0xFE, 0xFC, 0x32, 0x64, 0x95, 0x59, 0x61, 0x6E, 0xD6,
        0x53, 0x4E, 0x15, 0x45, 0x09, 0x32, 0x9D, 0x93, 0xA3, 0xD8, 0x10, 0xDB, 0xE5, 0xBD, 0xB9, 0x82,
        0x29, 0x2C, 0xF7, 0x8B, 0xD8, 0xBA, 0xDB, 0x80, 0x20, 0xAE, 0x8D, 0x57, 0xF4, 0xB7, 0x1D, 0x05,
        0x38, 0x6F, 0xFE, 0x9E, 0x9D, 0xB2, 0x71, 0xCA, 0x34, 0x77, 0xA3, 0x49, 0x99, 0xDB, 0x76, 0xF8,
        0xE5, 0xEC, 0xE9, 0xC0, 0xD4, 0x9D,
    ];
    let exp2: Vec<u8> = vec![
        0x15, 0xB7, 0x4C, 0xF2, 0x7C, 0xCE, 0xFF, 0x8B,
        0xB3, 0x6B, 0xF0, 0x4D, 0x9D, 0x83, 0x46, 0xB0, 0x9A, 0x2F, 0x70, 0xD2, 0xF4, 0x43, 0x9B, 0x0F,
        0x26, 0xAC, 0x7E, 0x03, 0xF7, 0xE9, 0xD1, 0xF7, 0x7D, 0x4B, 0x91, 0x5F, 0xD2, 0x9B, 0x28, 0x23,
        0xF0, 0x3A, 0xCB, 0x5D, 0x52, 0x00, 0xE0, 0x85, 0x7F, 0xF2, 0xA8, 0x03, 0xE9, 0x3E, 0xEE, 0x96,
        0xD6, 0x23, 0x5C, 0xE9, 0x54, 0x42, 0xBC, 0x21,
    ];
    let coef: Vec<u8> = vec![
        0x00, 0x90, 0xA7, 0x45, 0xDA, 0x89,
        0x70, 0xB2, 0xCD, 0x64, 0x96, 0x60, 0x32, 0x42, 0x28, 0xC5, 0xF8, 0x28, 0x56, 0xFF, 0xD6, 0x65,
        0xBA, 0x9A, 0x85, 0xC8, 0xD6, 0x0F, 0x1B, 0x8B, 0xEE, 0x71, 0x7E, 0xCD, 0x2C, 0x72, 0xEA, 0xE0,
        0x1D, 0xAD, 0x86, 0xBA, 0x76, 0x54, 0xD4, 0xCF, 0x45, 0xAD, 0xB5, 0xF1, 0xF2, 0xB3, 0x1D, 0x9F,
        0x81, 0x22, 0xCF, 0xA5, 0xF1, 0xA5, 0x57, 0x0F, 0x9B, 0x2D, 0x25,
    ];

    let alg: Vec<u64> = vec![ 1, 2, 840, 113549, 1, 1, 1 ]; /* rsaEncryption (PKCS #1) */

    let rsa_key_pkcs8_1 = KeyPKCS8Builder::new().
        version(0).
        alg_id_rsa(alg).
        key_rsa(version, modulus, pub_exp, priv_exp, prime1, prime2, exp1, exp2, coef).
        build();

    let der1 = match rsa_key_pkcs8_1.to_der() {
        Some(d) => d,
        None => panic!("Failed (Test): pkcs8_to_der()"),
    };
    // println!("\n> rsa key pkcs8:\n{}", der1.hex_dump());
    assert_eq!(der1, der_orig);

    // let err = write_file("keys/new_rsa.der", &der1).map_err(|e| e.kind());
    // assert_eq!(err, Ok(()));
    // println!("\n> SAVED in keys/new_rsa.der");

    let rsa_key_pkcs8_2 = KeyPKCS8Builder::new().
        from_der(&der_orig).
        build();

    // let der2 = match rsa_key_pkcs8_2.to_der() {
    //     Some(data) => data,
    //     None => panic!("Failed (Test): pkcs8_to_der()"),
    // };
    // assert_eq!(der2, der_orig);

    rsa_key_pkcs8_2.display();
}

#[test]
fn pkcs8_create_test_ec() {
    let der_orig = match read_file("keys/ec.pkcs8.der") {
        Ok(data) => data,
        Err(_) => panic!("Failed (Test): Read key file")
    };

    let version: u64 = 1;
    let priv_key: Vec<u8> = vec![
        0x5F, 0xFE, 0x06, 0x61, 0xD9, 0x1B, 0x1B, 0xDA, 0x2A, 0x1B, 0x31, 0xDC,
        0x34, 0x03, 0x07, 0xAE, 0x69, 0x33, 0xD1, 0xEB, 0xD4, 0x2C, 0x0D, 0x83, 0xD7, 0xE4, 0x1E, 0xE5,
        0xC5, 0x40, 0x5F, 0xE2,
    ];
    let pub_key: Vec<u8> = vec![
        0x04, 0x9D, 0x6F, 0xE4, 0x63, 0x76, 0xCA,
        0xDF, 0x02, 0x20, 0x8C, 0xFB, 0x49, 0xBB, 0x13, 0x61, 0x90, 0xF0, 0x1E, 0xBB, 0xAC, 0xCA, 0xEC,
        0x36, 0x71, 0xC9, 0xA8, 0xEB, 0x51, 0x8B, 0x52, 0x94, 0x9C, 0xFB, 0xD6, 0xB9, 0x61, 0x4C, 0xB0,
        0x1E, 0x20, 0xBC, 0xF3, 0xC7, 0x84, 0x36, 0x5F, 0x20, 0x1C, 0x69, 0x61, 0x68, 0x66, 0xBF, 0x03,
        0xAD, 0x03, 0xF5, 0x40, 0x6B, 0x49, 0xF3, 0x54, 0xD9, 0xE0,
    ];

    let alg: Vec<u64> = vec![ 1, 2, 840, 10045, 2, 1 ]; /* ecPublicKey (ANSI X9.62 public key type) */
    let par: Vec<u64> = vec![ 1, 2, 840, 10045, 3, 1, 7]; /* prime256v1 (ANSI X9.62 named elliptic curve) */

    let ec_key_pkcs8_1 = KeyPKCS8Builder::new().
        version(0).
        alg_id_ec(alg, par).
        key_ec(version, priv_key, pub_key).
        build();

    let der1 = match ec_key_pkcs8_1.to_der() {
        Some(d) => d,
        None => panic!("Failed (Test): pkcs8_to_der()"),
    };
    // println!("\n> ec key pkcs8:\n{}", der1.hex_dump());

    assert_eq!(der1, der_orig);

    // let err = write_file("keys/new_ec.der", &der1).map_err(|e| e.kind());    
    // assert_eq!(err, Ok(()));
    // println!("\n> SAVED in keys/new_ec.der");

    let ec_key_pkcs8_2 = KeyPKCS8Builder::new().
        from_der(&der_orig).
        build();
    
    let der2 = match ec_key_pkcs8_2.to_der() {
        Some(d) => d,
        None => panic!("Failed (Test): pkcs8_to_der()"),
    };
    assert_eq!(der2, der_orig);
}