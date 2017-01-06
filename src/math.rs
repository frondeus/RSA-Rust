use ramp::Int;

// use byteorder::{LittleEndian, BigEndian, WriteBytesExt, ReadBytesExt};
// use std::io::Cursor;
// use sha2::{Sha256, Digest};


fn fast_pow_mod(mut a: Int, mut b: Int, n: Int) -> Int {
    let mut w: Int = Int::one();
    while &b > &Int::zero() {
        if (&b).is_even() == false {
            w = (w * &a) % &n;
        }
        a = (&a * &a) % &n;
        b >>= 1;
    }

    (w + &n) % &n
}

fn gcd(a: Int, b: Int) -> (Int, Int, Int) {
    let (mut u_a, mut v_a, mut u_b, mut v_b) = (Int::one(), Int::zero(), Int::zero(), Int::one());
    let (mut aa, mut bb) = (a, b);

    while &aa != &Int::zero() {
        let q = &bb / &aa;

        let new_a = &bb - &q * &aa;
        bb = aa;
        aa = new_a;

        let new_u_a = u_b - &q * &u_a;
        u_b = u_a;
        u_a = new_u_a;

        let new_v_a = v_b - &q * &v_a;
        v_b = v_a;
        v_a = new_v_a;
    }

    (bb, u_b, v_b)
}

pub fn mod_inv(b: Int, n: Int) -> Option<Int> {
    let (gcd, inv, _) = gcd(b, n.clone());

    if gcd != Int::one() {
        None
    } else {
        Some(inv % n)
    }
}

pub fn encrypt(msg: Int, key: Int, n: Int) -> Int {
    fast_pow_mod(msg.clone(), key.clone(), n)
}

pub fn decrypt(ciphertext: Int, key: Int, n: Int) -> Int {
    fast_pow_mod(ciphertext.clone(), key.clone(), n)
}

pub fn decrypt_crt(ciphertext: Int, dp: Int, dq: Int, p: Int, q: Int, q_inv: Int) -> Int {
    let m1 = fast_pow_mod(ciphertext.clone(), dp.clone(), p.clone());
    let m2 = fast_pow_mod(ciphertext.clone(), dq.clone(), q.clone());

    let h = (q_inv * (&m1 - &m2)) % &p;
    return m2 + h * q;
}


pub fn hash(input: Int) -> Int {
    input
    // let mut sha = Sha256::new();
    // let mut bytes = vec![];
    // bytes.write_i64::<BigEndian>(input).unwrap();
    //
    // println!("Bytes of {} are {:?}", input, bytes);
    // sha.input(&bytes);
    //
    // let hashed_bytes = sha.result();
    // println!("Hashed bytes are {:?}", hashed_bytes);
    // let mut rdr = Cursor::new(hashed_bytes.as_slice());
    // let hashed_input = rdr.read_i64::<BigEndian>().unwrap();
    //
    // println!("Hashed input: {}", hashed_input);
    // hashed_input
    //
}
