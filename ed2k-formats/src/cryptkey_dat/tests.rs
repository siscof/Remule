// SPDX-License-Identifier: GPL-2.0-or-later
//! cryptkey.dat tests. aMule has no unit test for this file; these follow
//! ClientCreditsList.cpp and Crypto++'s Base64Encoder/Decoder behaviour.

use super::*;
use rsa::traits::PublicKeyParts;

#[test]
fn base64_encodes_like_cryptopp() {
    // RFC 4648 vectors, plus Crypto++'s terminating newline.
    assert_eq!(encode_base64(b""), "\n");
    assert_eq!(encode_base64(b"f"), "Zg==\n");
    assert_eq!(encode_base64(b"fo"), "Zm8=\n");
    assert_eq!(encode_base64(b"foo"), "Zm9v\n");
    assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy\n");
    // 54 bytes are exactly one 72-character line: no empty line follows.
    let one_line = encode_base64(&[0u8; 54]);
    assert_eq!(one_line.len(), 73);
    assert_eq!(one_line.matches('\n').count(), 1);
    // 55 bytes spill into a second line.
    let two = encode_base64(&[0xFFu8; 55]);
    let lines: Vec<&str> = two.split_terminator('\n').collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].len(), LINE_LEN);
    assert_eq!(lines[1], "/w==");
}

#[test]
fn base64_decodes_like_cryptopp() {
    assert_eq!(decode_base64(b"Zm9vYmFy\n"), b"foobar");
    // CRLF, spaces and padding are skipped.
    assert_eq!(decode_base64(b"Zm9v\r\n Ym\tFy\r\n"), b"foobar");
    assert_eq!(decode_base64(b"Zg=="), b"f");
    // Bits that do not make a whole byte are dropped.
    assert_eq!(decode_base64(b"Zm9"), b"fo");
    // Crypto++ does not stop at '=': it is just another skipped character.
    assert_eq!(decode_base64(b"Zg==Zg=="), [0x66, 0x06, 0x60]);
    assert!(decode_base64(b"!!!").is_empty());
    for len in 0..200usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        assert_eq!(
            decode_base64(encode_base64(&data).as_bytes()),
            data,
            "len {len}"
        );
    }
}

fn rng() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}

#[test]
fn generated_key_is_what_amule_makes() {
    let key = CryptKey::generate(&mut rng()).unwrap();
    let file = key.write();
    // Base64 lines of at most 72 characters, ending in a newline.
    let text = std::str::from_utf8(&file).unwrap();
    assert!(text.ends_with('\n'));
    assert!(text
        .split_terminator('\n')
        .all(|l| !l.is_empty() && l.len() <= LINE_LEN));

    let back = CryptKey::read(&file).unwrap();
    assert_eq!(back, key);
    let private = back.private_key().unwrap();
    assert_eq!(private.size() * 8, KEY_BITS);
    assert_eq!(private.e(), &BigUint::from(PUBLIC_EXPONENT));
    // PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier rsaEncryption, OCTET STRING { ... } }.
    let der = back.der();
    assert_eq!(der[0], 0x30);
    assert!(der
        .windows(9)
        .any(|w| w == [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01]));
}

/// The public key aMule announces: a 76-byte SubjectPublicKeyInfo laid out
/// as Crypto++'s `X509PublicKey::DEREncode` writes it for a 384-bit key.
#[test]
fn public_key_is_a_76_byte_subject_public_key_info() {
    let key = CryptKey::generate(&mut rng()).unwrap();
    let spki = key.public_key().unwrap();
    assert_eq!(spki.len(), 76);
    let prefix = [
        0x30, 0x4a, // SEQUENCE, 74 bytes
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
        0x00, // rsaEncryption, NULL
        0x03, 0x39, 0x00, // BIT STRING, no unused bits
        0x30, 0x36, // RSAPublicKey
        0x02, 0x31, 0x00, // modulus: 48 bytes with a leading zero
    ];
    assert_eq!(&spki[..prefix.len()], prefix);
    assert_eq!(&spki[spki.len() - 3..], [0x02, 0x01, 0x11], "exponent 17");
}

#[test]
fn file_bytes_round_trip_unchanged() {
    let key = CryptKey::generate(&mut rng()).unwrap();
    // The same key with Windows line ends and no trailing newline: still the
    // same key, and written back exactly as read.
    let text = String::from_utf8(key.write()).unwrap();
    let odd = text.trim_end().replace('\n', "\r\n");
    let back = CryptKey::read(odd.as_bytes()).unwrap();
    assert_eq!(back.write(), odd.as_bytes());
    assert_eq!(back.der(), key.der());
    assert_eq!(back.public_key().unwrap(), key.public_key().unwrap());
    // from_der writes what Crypto++ would.
    assert_eq!(CryptKey::from_der(key.der()).write(), key.write());
}

#[test]
fn errors_not_panics() {
    assert_eq!(CryptKey::read(b""), Err(Error::Empty));
    let garbage = CryptKey::read(b"not a key at all\n").unwrap();
    assert!(matches!(garbage.private_key(), Err(Error::BadKey(_))));
    assert!(matches!(garbage.public_key(), Err(Error::BadKey(_))));
    // Arbitrary bytes never panic.
    let noise: Vec<u8> = (0..500u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let k = CryptKey::read(&noise).unwrap();
    assert!(k.private_key().is_err());
    // A truncated key fails cleanly.
    let good = CryptKey::generate(&mut rng()).unwrap();
    let cut = CryptKey::from_der(&good.der()[..good.der().len() / 2]);
    assert!(cut.private_key().is_err());
}

#[test]
fn debug_does_not_print_key_material() {
    let key = CryptKey::generate(&mut rng()).unwrap();
    let s = format!("{key:?}");
    assert!(s.starts_with("CryptKey("));
    assert!(!s.contains(&encode_base64(&key.der()[..12]).trim_end()[..8]));
}
