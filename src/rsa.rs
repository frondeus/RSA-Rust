use ramp::int::Int;
use pumpkin::prime;

use math;

fn generate_p_q() -> (Int, Int) {
    let p = prime::new(512).unwrap();
    let q = prime::new(512).unwrap();

    // println!("Primes: {}, {}", p, q);
    (p, q)
}

fn generate_e_d(p: Int, q: Int) -> Option<(Int, Int)> {
    let phi_n = (p - Int::one()) * (q - Int::one());
    let e = Int::from(1619);
    match math::mod_inv(e.clone(), phi_n.clone()) {
        Some(d) => {
            if (&e * &d) % phi_n != 1 {
                None
            } else {
                Some((e, d))
            }
        }
        None => None,
    }
}

pub struct PublicKey {
    e: Int,
    n: Int,
}

pub struct PrivateKey {
    d: Int,
    n: Int,
    dp: Int,
    dq: Int,
    p: Int,
    q: Int,
    q_inv: Int,
}

impl PublicKey {
    pub fn new(e: Int, n: Int) -> PublicKey {
        PublicKey { e: e, n: n }
    }

    pub fn encrypt(&self, msg: Int) -> Int {
        math::encrypt(msg, self.e.clone(), self.n.clone())
    }

    pub fn verify_signature(&self, msg: Int, signature: Int) -> bool {
        let decrypted = math::decrypt(signature, self.e.clone(), self.n.clone());

        let hash_message = math::hash(msg);
        hash_message == decrypted
    }
}

impl PrivateKey {
    pub fn new(p: Int, q: Int, d: Int, n: Int) -> PrivateKey {
        PrivateKey {
            dp: (&d % (&p - 1)),
            dq: (&d % (&q - 1)),
            q_inv: math::mod_inv(q.clone(), p.clone()).unwrap(),
            d: d,
            n: n,
            p: p,
            q: q,
        }
    }

    pub fn decrypt(&self, msg: Int) -> Int {
        math::decrypt(msg, self.d.clone(), self.n.clone())
    }

    pub fn decrypt_crt(&self, msg: Int) -> Int {
        math::decrypt_crt(msg,
                          self.dp.clone(),
                          self.dq.clone(),
                          self.p.clone(),
                          self.q.clone(),
                          self.q_inv.clone())
    }

    pub fn sign(&self, msg: Int) -> Int {
        let hashed_msg = math::hash(msg);
        math::encrypt(hashed_msg, self.d.clone(), self.n.clone())
    }
}

pub fn generate_keys() -> (PublicKey, PrivateKey) {
    let mut res: Option<(Int, Int)> = None;
    let (mut p, mut q) = (Int::zero(), Int::zero());
    while res.is_none() {
        let (_p, _q) = generate_p_q();
        p = _p;
        q = _q;
        res = generate_e_d(p.clone(), q.clone());
    }
    let (e, d) = res.unwrap();

    let n = &p * &q;
    let public = PublicKey::new(e, n.clone());
    let private = PrivateKey::new(p, q, d, n);

    (public, private)
}
