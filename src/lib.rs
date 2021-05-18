use simple_asn1::{ASN1Block, ASN1Class, OID, ASN1DecodeErr, BigInt, BigUint};
use num_traits::{FromPrimitive, One, Zero};
use pretty_hex::*;

#[derive(Debug, PartialEq, Clone)]
struct RsaKey {
    version: u64,
    modulus: Vec<u8>,
    pub_exp: Vec<u8>,
    priv_exp: Vec<u8>,
    prime1: Vec<u8>,
    prime2: Vec<u8>,
    exp1: Vec<u8>,
    exp2: Vec<u8>,
    coef: Vec<u8>,
}

#[derive(Debug, PartialEq)]
struct EcKey {
    version: u64,
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
}

#[derive(Debug, PartialEq)]
enum KeyValue {
    RSA(RsaKey),
    EC(EcKey),
}

#[derive(Debug, PartialEq)]
struct AlgorithmIdentifier {
    alg: Vec<u64>,
    par: Vec<u64>,
}

#[derive(Debug, PartialEq)]
pub struct KeyPKCS8 {
    version: Option<u64>,
    alg_id: Option<AlgorithmIdentifier>,
    key: Option<KeyValue>,
}

fn serialize(a: &ASN1Block) -> Option<Vec<u8>> {
    match simple_asn1::to_der(a) {
        Ok(d) => Some(d),
        Err(_) => None,
    }
}

fn deserialize(d: &Vec<u8>) -> Option<Vec<ASN1Block>> {
    match simple_asn1::from_der(d) {
        Ok(a) => Some(a),
        Err(_) => None,
    }
}

fn decode_base127(i: &[u8], index: &mut usize) -> Result<BigUint, ASN1DecodeErr> {
    let mut res = BigUint::zero();

    loop {
        if *index >= i.len() {
            return Err(ASN1DecodeErr::Incomplete);
        }

        let nextbyte = i[*index];

        *index += 1;
        res = (res << 7) + BigUint::from(nextbyte & 0x7f);
        if (nextbyte & 0x80) == 0 {
            return Ok(res);
        }
    }
}

fn oid_u8_to_u64(body: &Vec<u8>) -> Result<Vec<u64>, ASN1DecodeErr> {
    let mut value1 = BigUint::zero();
    if body.len() == 0 {
        return Err(ASN1DecodeErr::Incomplete);
    }
    let mut value2 = BigUint::from_u8(body[0]).unwrap();
    let mut oidres = Vec::new();
    let mut bindex = 1;
    let mut res = Vec::new();

    if body[0] >= 40 {
        if body[0] < 80 {
            value1 = BigUint::one();
            value2 = value2 - BigUint::from_u8(40).unwrap();
        } else {
            value1 = BigUint::from_u8(2).unwrap();
            value2 = value2 - BigUint::from_u8(80).unwrap();
        }
    }

    oidres.push(value1);
    oidres.push(value2);
    while bindex < body.len() {
        oidres.push(decode_base127(body, &mut bindex)?);
    }
    for i in 0..oidres.len() {
        res.push(oidres[i].to_u64_digits()[0]);
    }
    Ok(res)
}

impl KeyPKCS8 {
    fn oid_new(id: &Vec<u64>) -> OID {
        let mut res = Vec::new();

        for i in 0..id.len() {
            res.push(BigUint::from(id[i]));
        }

        OID::new(res)
    }

    fn null_oid(oid: &Vec<u64>) -> Vec<ASN1Block> {
        let mut sa = Vec::new();
        sa.push(ASN1Block::ObjectIdentifier(0, KeyPKCS8::oid_new(oid)));
        sa.push(ASN1Block::Null(0));

        sa
    }

    fn full_oid(oid1: &Vec<u64>, oid2: &Vec<u64>) -> Vec<ASN1Block> {
        let mut sa = Vec::new();
        sa.push(ASN1Block::ObjectIdentifier(0, KeyPKCS8::oid_new(oid1)));
        sa.push(ASN1Block::ObjectIdentifier(0, KeyPKCS8::oid_new(oid2)));

        sa
    }

    fn rsa_key_pack(key: RsaKey) -> ASN1Block {
        let mut key_asn1 = Vec::new();
        key_asn1.push(ASN1Block::Integer(0, BigInt::from(key.version)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.modulus)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.pub_exp)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.priv_exp)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.prime1)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.prime2)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.exp1)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.exp2)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&key.coef)));

        let key_der = simple_asn1::to_der(&ASN1Block::Sequence(0, key_asn1)).unwrap();

        ASN1Block::OctetString(0, key_der)
    }

    fn ec_key_pack(key: EcKey) -> ASN1Block {
        let mut key_asn1 = Vec::new();
        key_asn1.push(ASN1Block::Integer(0, BigInt::from(key.version)));
        key_asn1.push(ASN1Block::OctetString(0, key.priv_key));

        key_asn1.push(ASN1Block::Explicit(
            ASN1Class::ContextSpecific, 0,
            BigUint::from(1 as u32),
            Box::new(ASN1Block::BitString(0, 8*key.pub_key.len(), key.pub_key)))
        );

        let key_der = simple_asn1::to_der(&ASN1Block::Sequence(0, key_asn1)).unwrap();

        ASN1Block::OctetString(0, key_der)
    }

    pub fn to_der(self) -> Option<Vec<u8>>
    {
        let mut key_der = Vec::new();

        /* Version */
        if let Some(v) = self.version {
            key_der.push(ASN1Block::Integer(0, BigInt::from(v)));
        }

        match self.key {
            Some(KeyValue::RSA(rsa)) => {
                if let Some(a) = self.alg_id {
                    key_der.push(ASN1Block::Sequence(0, KeyPKCS8::null_oid(&a.alg)));
                }
                key_der.push(KeyPKCS8::rsa_key_pack(rsa));
            }
            Some(KeyValue::EC(ec)) => {
                if let Some(a) = self.alg_id {
                    key_der.push(ASN1Block::Sequence(0, KeyPKCS8::full_oid(&a.alg, &a.par)));
                }
                key_der.push(KeyPKCS8::ec_key_pack(ec));
            }
            None => {
                println!("Failed: no public key");
                return None;
            }
        };

        let mut key_pkcs8_full = Vec::new();
        key_pkcs8_full.push(ASN1Block::Sequence(0, key_der));
        serialize(key_pkcs8_full.first().unwrap())
    }
}

#[derive(Default)]
pub struct KeyPKCS8Builder {
    version: Option<u64>,
    alg_id: Option<AlgorithmIdentifier>,
    key: Option<KeyValue>,
}

impl KeyPKCS8Builder {
    pub fn new() -> KeyPKCS8Builder {
        KeyPKCS8Builder {
            version: None,
            alg_id: None,
            key: None,
        }
    }

    pub fn version(mut self, version: u64) -> KeyPKCS8Builder {
        self.version = Some(version);
        self
    }

    pub fn alg_id(mut self, alg: Vec<u64>, par: Vec<u64>) -> KeyPKCS8Builder {
        let alg_id = AlgorithmIdentifier {
            alg : alg,
            par : par,
        };
        self.alg_id = Some(alg_id);
        self
    }


    pub fn key_rsa(mut self, version: u64, modulus: Vec<u8>, pub_exp: Vec<u8>, priv_exp: Vec<u8>, prime1: Vec<u8>,
        prime2: Vec<u8>, exp1: Vec<u8>, exp2: Vec<u8>, coef: Vec<u8>) -> KeyPKCS8Builder {
        let key = KeyValue::RSA(RsaKey {
            version: version,
            modulus: modulus,
            pub_exp: pub_exp,
            priv_exp: priv_exp,
            prime1: prime1,
            prime2: prime2,
            exp1: exp1,
            exp2: exp2,
            coef: coef,
        });
        self.key = Some(key);
        self
    }

    pub fn key_ec(mut self, version: u64, priv_key: Vec<u8>, pub_key: Vec<u8>) -> KeyPKCS8Builder {
        let key = KeyValue::EC(EcKey {
            version: version,
            priv_key: priv_key,
            pub_key: pub_key,
        });
        self.key = Some(key);
        self
    }

    fn asn1_seq(b: &mut ASN1Block, idx: usize) -> Option<&mut ASN1Block> {
        match b {
            ASN1Block::Sequence(_, v) => v.get_mut(idx),
            _ => None,
        }
    }

    fn asn1_int(b: &mut ASN1Block) -> Option<&mut BigInt> {
        match b {
            ASN1Block::Integer(_, s) => Some(s),
            _ => None,
        }
    }

    fn asn1_oid(b: &mut ASN1Block) -> Option<&mut OID> {
        match b {
            ASN1Block::ObjectIdentifier(_, s) => Some(s),
            _ => None,
        }
    }

    fn get_item<'a>(b: &'a mut ASN1Block, p: &'a [usize]) -> Option<&'a mut ASN1Block> {
        let mut item = b;
        for i in 0..p.len() {
            let ret = KeyPKCS8Builder::asn1_seq(item, p[i]);
    
            item = match ret {
                Some(v) => v,
                None => {
                    println!("Failed on: path[{}] = {:?}", i, p[i]);
                    return None;
                }
            };
        }
    
        Some(item)
    }

    pub fn from_der(mut self, der: &Vec<u8>) -> KeyPKCS8Builder {
        let mut vec = deserialize(der).unwrap();
        let pkcs8_1 = &mut vec[0].clone();
        let pkcs8_2 = &mut vec[0].clone();
        let pkcs8_3 = &mut vec[0].clone();
        let version_path: [usize; 1] = [0];
        let alg_path: [usize; 2] = [1, 0];
        let par_path: [usize; 2] = [1, 1];
        let version_asn1 = match KeyPKCS8Builder::get_item(pkcs8_1, &version_path) {
            Some(c) => c,
            None => panic!("Failed to get version"),
        };
        let version = match KeyPKCS8Builder::asn1_int(version_asn1) {
            Some(c) => c,
            None => panic!("Failed to get version"),
        };

        let alg_asn1 = match KeyPKCS8Builder::get_item(pkcs8_2, &alg_path) {
            Some(c) => c,
            None => panic!("Failed to get alg"),
        };
        let alg = match KeyPKCS8Builder::asn1_oid(alg_asn1) {
            Some(c) => c,
            None => panic!("Failed to get alg"),
        };
        let par_asn1 = match KeyPKCS8Builder::get_item(pkcs8_3, &par_path) {
            Some(c) => c,
            None => panic!("Failed to get alg"),
        };
        let par = match KeyPKCS8Builder::asn1_oid(par_asn1) {
            Some(c) => c,
            None => panic!("Failed to get alg"),
        };
        println!("\n> Alg: {}", alg.as_raw().unwrap().hex_dump());
        let alg_u64 = oid_u8_to_u64(&alg.as_raw().unwrap()).unwrap();
        let par_u64 = oid_u8_to_u64(&par.as_raw().unwrap()).unwrap();
        self = KeyPKCS8Builder::version(self, version.to_biguint().unwrap().to_bytes_be()[0] as u64).
        alg_id(alg_u64, par_u64);
        println!("\n> Version: {:#?}", self.alg_id);
        self
    }

    pub fn build(self) -> KeyPKCS8 {
        KeyPKCS8 {
            version: self.version,
            alg_id: self.alg_id,
            key: self.key,
        }
    }
}