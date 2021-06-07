use simple_asn1::{ASN1Block, ASN1Class, OID, BigInt, BigUint};
use num_traits::cast::ToPrimitive;

#[derive(Debug)]
pub struct KeyPKCS8 {
    version: ASN1Block,
    alg_id: ASN1Block,
    key: ASN1Block,
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

    pub fn to_der(self) -> Option<Vec<u8>> {
        let mut key_pkcs8 = Vec::new();

        key_pkcs8.push(self.version);
        key_pkcs8.push(self.alg_id);
        key_pkcs8.push(self.key);

        let mut key_pkcs8_full = Vec::new();
        key_pkcs8_full.push(ASN1Block::Sequence(0, key_pkcs8));
        serialize(key_pkcs8_full.first()?)
    }

    pub fn display(self) {
        let ver = match self.version {
            ASN1Block::Integer(_, d) => d.to_u64(),
            _ => None,
        };
        match ver {
            Some(version) => println!("\nVersion: {}", version),
            None => { 
                println!("\nFailed: Version data is in wrong format");
                return;
            },
        };

        let alg_seq_ = match self.alg_id {
            ASN1Block::Sequence(_, d) => Some(d),
            _ => None,
        };
        let alg_seq = match alg_seq_ {
            Some(d) => d,
            None => {
                println!("\nFailed: Algorithm data is in wrong format");
                return;
            },
        };

        for i in alg_seq {
            match i {
                ASN1Block::ObjectIdentifier(_, o) => println!("\nAlgorithm: {:?}", o.as_vec().unwrap() as Vec<u64>),
                ASN1Block::Null(_) => println!("\nNULL"),
                _ => {
                    println!("\nFailed: Algorithm data is in wrong format");
                    return;
                },
            };
        };

        let oct_str_ = match self.key {
            ASN1Block::OctetString(_, d) => Some(d),
            _ => None,
        };
        let oct_str = match oct_str_ {
            Some(d) => d,
            None => {
                println!("\nFailed: Key data is in wrong format");
                return;
            },
        };
        println!("\nVersion:\n {:?}", oct_str);
    }
}

pub struct KeyPKCS8Builder {
    version: ASN1Block,
    alg_id: ASN1Block,
    key: ASN1Block,
}

impl KeyPKCS8Builder {
    pub fn new() -> KeyPKCS8Builder {
        KeyPKCS8Builder {
            version: ASN1Block::Null(0),
            alg_id: ASN1Block::Null(0),
            key: ASN1Block::Null(0),
        }
    }

    pub fn version(mut self, version: u64) -> KeyPKCS8Builder {
        self.version = ASN1Block::Integer(0, BigInt::from(version));
        self
    }

    pub fn alg_id_rsa(mut self, alg: Vec<u64>) -> KeyPKCS8Builder {
        self.alg_id = ASN1Block::Sequence(0, KeyPKCS8::null_oid(&alg));
        self
    }

    pub fn alg_id_ec(mut self, alg: Vec<u64>, par: Vec<u64>) -> KeyPKCS8Builder {
        self.alg_id = ASN1Block::Sequence(0, KeyPKCS8::full_oid(&alg, &par));
        self
    }

    pub fn key_rsa(mut self, version: u64, modulus: Vec<u8>, pub_exp: Vec<u8>, priv_exp: Vec<u8>, prime1: Vec<u8>,
        prime2: Vec<u8>, exp1: Vec<u8>, exp2: Vec<u8>, coef: Vec<u8>) -> KeyPKCS8Builder {
        let mut key_asn1 = Vec::new();
        key_asn1.push(ASN1Block::Integer(0, BigInt::from(version)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&modulus)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&pub_exp)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&priv_exp)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&prime1)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&prime2)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&exp1)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&exp2)));
        key_asn1.push(ASN1Block::Integer(0, BigInt::from_signed_bytes_be(&coef)));

        match simple_asn1::to_der(&ASN1Block::Sequence(0, key_asn1)) {
            Ok(key_der) => self.key = ASN1Block::OctetString(0, key_der),
            Err(_) => println!("Failed: Serialize RSA key")
        };

        self
    }

    pub fn key_ec(mut self, version: u64, priv_key: Vec<u8>, pub_key: Vec<u8>) -> KeyPKCS8Builder {
        let mut key_asn1 = Vec::new();
        key_asn1.push(ASN1Block::Integer(0, BigInt::from(version)));
        key_asn1.push(ASN1Block::OctetString(0, priv_key));

        key_asn1.push(ASN1Block::Explicit(
            ASN1Class::ContextSpecific, 0,
            BigUint::from(1 as u32),
            Box::new(ASN1Block::BitString(0, 8*pub_key.len(), pub_key)))
        );

        match simple_asn1::to_der(&ASN1Block::Sequence(0, key_asn1)) {
            Ok(key_der) => self.key = ASN1Block::OctetString(0, key_der),
            Err(_) => println!("Failed: Serialize EC key")
        };

        self
    }

    fn asn1_seq(b: &ASN1Block, idx: usize) -> Option<&ASN1Block> {
        match b {
            ASN1Block::Sequence(_, v) => v.get(idx),
            _ => None,
        }
    }

    pub fn from_der(mut self, der: &Vec<u8>) -> KeyPKCS8Builder {
        let vec = match deserialize(der) {
            Some(d) => d,
            None => panic!("Failed: Deserialize provided key"),
        };
        let pkcs8 = match vec.get(0) {
            Some(d) => d,
            None => panic!("Failed: Deserialize provided key"),
        };

        let version = match KeyPKCS8Builder::asn1_seq(pkcs8, 0) {
            Some(d) => d,
            None => panic!("Failed: Get version"),
        };
        let alg_id = match KeyPKCS8Builder::asn1_seq(pkcs8, 1) {
            Some(d) => d,
            None => panic!("Failed: Get alg"),
        };
        let key = match KeyPKCS8Builder::asn1_seq(pkcs8, 2) {
            Some(d) => d,
            None => panic!("Failed: Get key"),
        };
        self.version = version.clone();
        self.alg_id = alg_id.clone();
        self.key = key.clone();
        // println!("\n> Version: {:#?}", self.version);
        // println!("\n> Alg Id: {:#?}", self.alg_id);
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