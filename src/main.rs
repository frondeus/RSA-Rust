mod rsa;
mod math;

extern crate byteorder;
extern crate sha2;
extern crate pumpkin;
extern crate ramp;

use ramp::int::Int;

fn main() {
    let (public, private) = rsa::generate_keys();

    let mut msg = Int::from(1337);

    // Encrypting
    let ciphertext = public.encrypt(msg.clone());
    println!("Encrypting:\n{} ----> {}", &msg, &ciphertext);
    println!("");

    // Decrypting
    let msg2 = private.decrypt(ciphertext.clone());
    println!("Decrypting:\n{} ----> {}", &ciphertext, msg2);
    println!("");

    // Decrypting using Chinese Rest Theorem
    let msg3 = private.decrypt_crt(ciphertext.clone());
    println!("Decrypting using CRT:\n{} ----> {}", &ciphertext, msg3);
    println!("");

    // Signing
    let signed = private.sign(msg.clone());
    println!("Signing:\n{} ----> {}", &msg, &signed);
    println!("");

    // Veryfying valid signature
    println!("Checking valid signature:\nSignature: {}",
             public.verify_signature(msg.clone(), signed.clone()));
    println!("");

    // Veryfying invalid signature
    msg = Int::from(1233);
    println!("Checking invalid signature:\nSignature: {}",
             public.verify_signature(msg, signed));
    println!("");

}