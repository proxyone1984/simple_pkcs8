use simple_asn1::{ASN1Block, ASN1Class, OID, ASN1DecodeErr, BigInt, BigUint};
use num_traits::{FromPrimitive, One, Zero};
use pretty_hex::*;

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Default)]
struct EcKey {
    version: u64,
    priv_key: Vec<u8>,
    pub_key: Vec<u8>,
}

#[derive(Debug)]
enum KeyValue {
    RSA(RsaKey),
    EC(EcKey),
}

#[derive(Debug, Default)]
struct AlgorithmIdentifier {
    alg: Vec<u64>,
    par: Vec<u64>,
}

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

// fn decode_base127(i: &[u8], index: &mut usize) -> Result<BigUint, ASN1DecodeErr> {
//     let mut res = BigUint::zero();

//     loop {
//         if *index >= i.len() {
//             return Err(ASN1DecodeErr::Incomplete);
//         }

//         let nextbyte = i[*index];

//         *index += 1;
//         res = (res << 7) + BigUint::from(nextbyte & 0x7f);
//         if (nextbyte & 0x80) == 0 {
//             return Ok(res);
//         }
//     }
// }

// fn oid_u8_to_u64(body: &Vec<u8>) -> Result<Vec<u64>, ASN1DecodeErr> {
//     let mut value1 = BigUint::zero();
//     if body.len() == 0 {
//         return Err(ASN1DecodeErr::Incomplete);
//     }
//     let mut value2 = BigUint::from_u8(body[0]).unwrap();
//     let mut oidres = Vec::new();
//     let mut bindex = 1;
//     let mut res = Vec::new();

//     if body[0] >= 40 {
//         if body[0] < 80 {
//             value1 = BigUint::one();
//             value2 = value2 - BigUint::from_u8(40).unwrap();
//         } else {
//             value1 = BigUint::from_u8(2).unwrap();
//             value2 = value2 - BigUint::from_u8(80).unwrap();
//         }
//     }

//     oidres.push(value1);
//     oidres.push(value2);
//     while bindex < body.len() {
//         oidres.push(decode_base127(body, &mut bindex)?);
//     }
//     for i in 0..oidres.len() {
//         res.push(oidres[i].to_u64_digits()[0]);
//     }
//     Ok(res)
// }

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
        let mut key_pkcs8 = Vec::new();

        /* Version */
        // if let Some(v) = self.version {
        //     key_der.push(ASN1Block::Integer(0, BigInt::from(v)));
        // }

        // match self.key {
        //     Some(KeyValue::RSA(rsa)) => {
        //         if let Some(a) = self.alg_id {
        //             key_der.push(ASN1Block::Sequence(0, KeyPKCS8::null_oid(&a.alg)));
        //         }
        //         key_der.push(KeyPKCS8::rsa_key_pack(rsa));
        //     }
        //     Some(KeyValue::EC(ec)) => {
        //         if let Some(a) = self.alg_id {
        //             key_der.push(ASN1Block::Sequence(0, KeyPKCS8::full_oid(&a.alg, &a.par)));
        //         }
        //         key_der.push(KeyPKCS8::ec_key_pack(ec));
        //     }
        //     None => {
        //         println!("Failed: no public key");
        //         return None;
        //     }
        // };

        key_pkcs8.push(self.version);
        key_pkcs8.push(self.alg_id);
        key_pkcs8.push(self.key);

        let mut key_pkcs8_full = Vec::new();
        key_pkcs8_full.push(ASN1Block::Sequence(0, key_pkcs8));
        serialize(key_pkcs8_full.first().unwrap())
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

        match serialize(&ASN1Block::Sequence(0, key_asn1)) {
            Some(key_der) => self.key = ASN1Block::OctetString(0, key_der),
            None => println!("Failed: serialize RSA key")
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
            Err(_) => println!("Failed: serialize EC key")
        };

        self
    }

    fn asn1_seq(b: &ASN1Block, idx: usize) -> Option<&ASN1Block> {
        match b {
            ASN1Block::Sequence(_, v) => v.get(idx),
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

    // fn get_block(data: &Vec<ASN1Block>, num: usize) -> Option<&ASN1Block> {
    //     let seq = data.get(0).unwrap();
    //     let block = KeyPKCS8Builder::asn1_seq(seq, num);

        // for i in 0..p.len() {
        //     let ret = KeyPKCS8Builder::asn1_seq(block, p[i]);
    
        //     block = match ret {
        //         Some(v) => v,
        //         None => {
        //             println!("Failed on: path[{}] = {:?}", i, p[i]);
        //             return None;
        //         }
        //     };
        // }
    
    //     block
    // }

    pub fn from_der(mut self, der: &Vec<u8>) -> KeyPKCS8Builder {
        let vec = deserialize(der).unwrap();
        let pkcs8 = vec.get(0).unwrap();

        let version = match KeyPKCS8Builder::asn1_seq(pkcs8, 0) {
            Some(c) => c,
            None => panic!("Failed to get version"),
        };
        let alg_id = match KeyPKCS8Builder::asn1_seq(pkcs8, 1) {
            Some(c) => c,
            None => panic!("Failed to get alg"),
        };
        let key = match KeyPKCS8Builder::asn1_seq(pkcs8, 2) {
            Some(c) => c,
            None => panic!("Failed to get alg"),
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