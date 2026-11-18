// SPDX-License-Identifier: GPL-2.0-or-later
//! SRP-6a login, client side. Port of `libs/ec/cpp/ECSRP.cpp`; the
//! construction is specified in `docs/EC_SRP.md`.
//!
//! Group: RFC 5054 3072-bit prime, g = 5, H = SHA-256, PAD = 384 bytes.
//! `x = scrypt(MD5(password) as 16 raw bytes, salt, N=2^15, r=8, p=1, 32)`.

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::Error;

pub const WIDTH: usize = 384;
pub const PROFILE_BYTES: [u8; 4] = [1, 15, 8, 1];
pub const SALT_LEN: usize = 16;

/// Which credential the proof is made with (`ECSRP::Credential`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Credential {
    Password = 0,
    ApiToken = 1,
    WebToken = 2,
}

const MODULUS_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B",
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9",
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6",
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8F",
    "D24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670",
    "C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E",
    "86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995",
    "497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A",
    "33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F8",
    "5A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE",
    "6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE1175",
    "77A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E",
    "4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

struct Group {
    n: BigUint,
    g: BigUint,
    k: BigUint,
}

impl Group {
    fn new() -> Self {
        let n = BigUint::parse_bytes(MODULUS_HEX.as_bytes(), 16).expect("valid modulus");
        let g = BigUint::from(5u32);
        let k = num(&sha256(&[&pad(&n), &pad(&g)]));
        Group { n, g, k }
    }
}

fn num(b: &[u8]) -> BigUint {
    BigUint::from_bytes_be(b)
}

/// Big-endian, left-padded to `WIDTH` bytes.
fn pad(n: &BigUint) -> Vec<u8> {
    let b = n.to_bytes_be();
    let mut out = vec![0u8; WIDTH.saturating_sub(b.len())];
    out.extend_from_slice(&b);
    out
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Parse a 32-character hex MD5 digest.
pub fn unhex_digest(digest: &str) -> Result<[u8; 16], Error> {
    let s = digest.as_bytes();
    if s.len() != 32 {
        return Err(Error::Auth(
            "the password digest must be 32 hex characters".into(),
        ));
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (s[2 * i] as char).to_digit(16);
        let lo = (s[2 * i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => *o = (h * 16 + l) as u8,
            _ => return Err(Error::Auth("the password digest is not hex".into())),
        }
    }
    Ok(out)
}

/// MD5 hex of a plaintext password, the form every EC client config stores.
pub fn password_digest(password: &str) -> String {
    use md5::Digest as _;
    md5::Md5::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `ECSRP::IsPasswordDigest`: well-formed and not the digest of "" (or zero).
pub fn is_password_digest(digest: &str) -> bool {
    match unhex_digest(digest) {
        Ok(b) => b != [0; 16] && b != unhex_digest("d41d8cd98f00b204e9800998ecf8427e").unwrap(),
        Err(_) => false,
    }
}

/// `x` for a digest and salt. Costs ~32 MiB and a noticeable fraction of a
/// second; it runs once per login.
fn derive_x(digest: &[u8; 16], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params =
        scrypt::Params::new(15, 8, 1, 32).map_err(|e| Error::Auth(format!("scrypt: {e}")))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(digest, salt, &params, &mut out[..])
        .map_err(|e| Error::Auth(format!("scrypt: {e}")))?;
    Ok(out)
}

/// The proof context `C` of EC_SRP.md.
fn context(
    credential: u8,
    salt: &[u8],
    transcript: &[u8],
    a: &[u8],
    b: &[u8],
) -> Result<Vec<u8>, Error> {
    if credential > Credential::WebToken as u8 || salt.len() != SALT_LEN || transcript.is_empty() {
        return Err(Error::Auth("invalid SRP context".into()));
    }
    let mut out = vec![
        PROFILE_BYTES[0],
        credential,
        PROFILE_BYTES[1],
        PROFILE_BYTES[2],
        PROFILE_BYTES[3],
    ];
    out.extend_from_slice(salt);
    out.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
    out.extend_from_slice(transcript);
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    Ok(out)
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// M1 and M2 from the shared secret `S`.
fn evidence(
    s: &[u8],
    credential: u8,
    salt: &[u8],
    transcript: &[u8],
    a: &[u8],
    b: &[u8],
) -> Result<([u8; 32], [u8; 32]), Error> {
    let ctx = context(credential, salt, transcript, a, b)?;
    let k = Zeroizing::new(sha256(&[s]));
    let m1 = hmac(&k[..], &[b"ec-srp-client", &ctx]);
    let m2 = hmac(&k[..], &[b"ec-srp-server", &ctx, &m1]);
    Ok((m1, m2))
}

fn scrambling(g: &Group, a: &[u8], b: &[u8]) -> Result<BigUint, Error> {
    let zero = BigUint::from(0u32);
    let (an, bn) = (num(a), num(b));
    if a.len() != WIDTH || b.len() != WIDTH || an == zero || an >= g.n || bn == zero || bn >= g.n {
        return Err(Error::Auth(
            "invalid SRP public value from the daemon".into(),
        ));
    }
    let u = num(&sha256(&[a, b]));
    if u == zero {
        return Err(Error::Auth("invalid SRP scrambling value".into()));
    }
    Ok(u)
}

/// `S = ((B - k*g^x) mod N)^(a + u*x) mod N`, with a non-negative modulo as
/// Crypto++'s `Integer::operator%` gives.
fn client_secret(
    g: &Group,
    a_pub: &[u8],
    b_pub: &[u8],
    a: &BigUint,
    x: &BigUint,
) -> Result<Vec<u8>, Error> {
    let u = scrambling(g, a_pub, b_pub)?;
    let kv = (&g.k * g.g.modpow(x, &g.n)) % &g.n;
    let base = (num(b_pub) + &g.n - kv) % &g.n;
    Ok(pad(&base.modpow(&(a + u * x), &g.n)))
}

/// One login attempt's SRP state.
pub struct Client {
    group: Group,
    a: Zeroizing<Vec<u8>>,
    a_pub: Vec<u8>,
    expected_m2: Option<Zeroizing<[u8; 32]>>,
}

impl Client {
    /// Pick a fresh `a` and compute `A`.
    pub fn start() -> Self {
        loop {
            let a: [u8; 32] = crate::crypt::random_bytes();
            if a != [0u8; 32] {
                return Self::with_secret(&a);
            }
        }
    }

    fn with_secret(a: &[u8]) -> Self {
        let group = Group::new();
        let a_pub = pad(&group.g.modpow(&num(a), &group.n));
        Client {
            group,
            a: Zeroizing::new(a.to_vec()),
            a_pub,
            expected_m2: None,
        }
    }

    /// `A`, for `EC_TAG_SRP_A`.
    pub fn public(&self) -> &[u8] {
        &self.a_pub
    }

    /// Answer the daemon's challenge with `M1`. Validates every public value
    /// before running the (expensive) KDF.
    pub fn respond(
        &mut self,
        digest: &str,
        credential: Credential,
        salt: &[u8],
        b_pub: &[u8],
        transcript: &[u8],
    ) -> Result<[u8; 32], Error> {
        scrambling(&self.group, &self.a_pub, b_pub)?;
        context(credential as u8, salt, transcript, &self.a_pub, b_pub)?;
        let d = Zeroizing::new(unhex_digest(digest)?);
        let x = derive_x(&d, salt)?;
        let s = Zeroizing::new(client_secret(
            &self.group,
            &self.a_pub,
            b_pub,
            &num(&self.a),
            &num(&x[..]),
        )?);
        let (m1, m2) = evidence(&s, credential as u8, salt, transcript, &self.a_pub, b_pub)?;
        self.expected_m2 = Some(Zeroizing::new(m2));
        self.a = Zeroizing::new(Vec::new());
        Ok(m1)
    }

    /// Check the daemon's `M2` in constant time. One use.
    pub fn verify(&mut self, m2: &[u8]) -> bool {
        match self.expected_m2.take() {
            Some(exp) => m2.len() == 32 && bool::from(exp[..].ct_eq(m2)),
            None => false,
        }
    }
}

/// The profile prefix of a stored verifier (`ECSRP::Profile`).
const VERIFIER_PREFIX: &str = "v1:15:8:1:";

/// What the daemon keeps instead of the password (`ECSRP::Verifier`): a
/// salt and `v = g^x`, stored as `/ExternalConnect/ECPasswordVerifier`
/// (EC_SRP.md, "verifier format v1").
#[derive(Clone, PartialEq, Eq)]
pub struct Verifier {
    pub salt: [u8; SALT_LEN],
    /// `WIDTH` bytes, big-endian.
    pub value: Vec<u8>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Verifier(..)")
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str, len: usize) -> Option<Vec<u8>> {
    if s.len() != 2 * len || !s.is_ascii() {
        return None;
    }
    (0..len)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

impl Verifier {
    /// `Verifier::Create`: the verifier of a password digest with this salt.
    /// Runs the KDF once.
    pub fn create(digest: &str, salt: [u8; SALT_LEN]) -> Result<Verifier, Error> {
        if !is_password_digest(digest) {
            return Err(Error::Auth("invalid EC password digest".into()));
        }
        let g = Group::new();
        let x = derive_x(&unhex_digest(digest)?, &salt)?;
        let v = Verifier {
            salt,
            value: pad(&g.g.modpow(&num(&x[..]), &g.n)),
        };
        if !v.valid() {
            return Err(Error::Auth("could not generate the EC verifier".into()));
        }
        Ok(v)
    }

    /// With a fresh random salt.
    pub fn create_random(digest: &str) -> Result<Verifier, Error> {
        Self::create(digest, crate::crypt::random_bytes())
    }

    /// A verifier no password opens: what a credential the daemon does not
    /// have is checked against, so it fails as a wrong password does.
    pub fn dummy() -> Verifier {
        let g = Group::new();
        let v = pad(&g.g.modpow(&num(&crate::crypt::random_bytes::<32>()), &g.n));
        Verifier {
            salt: crate::crypt::random_bytes(),
            value: v,
        }
    }

    /// `Verifier::Valid`: `1 < v < N`.
    pub fn valid(&self) -> bool {
        let v = num(&self.value);
        self.value.len() == WIDTH && v > BigUint::from(1u32) && v < Group::new().n
    }

    /// `Verifier::Encode`: `v1:15:8:1:<salt hex>:<v hex>`, lowercase.
    pub fn encode(&self) -> String {
        format!("{VERIFIER_PREFIX}{}:{}", hex(&self.salt), hex(&self.value))
    }

    /// `Verifier::Decode`: either case of hex; anything else fails.
    pub fn decode(text: &str) -> Result<Verifier, Error> {
        let bad = || Error::Auth("invalid or unsupported ECPasswordVerifier".into());
        let rest = text.strip_prefix(VERIFIER_PREFIX).ok_or_else(bad)?;
        if rest.len() != 2 * SALT_LEN + 1 + 2 * WIDTH || rest.as_bytes()[2 * SALT_LEN] != b':' {
            return Err(bad());
        }
        let salt = unhex(&rest[..2 * SALT_LEN], SALT_LEN).ok_or_else(bad)?;
        let value = unhex(&rest[2 * SALT_LEN + 1..], WIDTH).ok_or_else(bad)?;
        let v = Verifier {
            salt: salt.try_into().map_err(|_| bad())?,
            value,
        };
        if !v.valid() {
            return Err(Error::Auth("invalid ECPasswordVerifier value".into()));
        }
        Ok(v)
    }

    /// `Verifier::Matches`: whether this digest makes this verifier.
    pub fn matches(&self, digest: &str) -> bool {
        let Ok(d) = unhex_digest(digest) else {
            return false;
        };
        let Ok(x) = derive_x(&d, &self.salt) else {
            return false;
        };
        let g = Group::new();
        let v = pad(&g.g.modpow(&num(&x[..]), &g.n));
        bool::from(v[..].ct_eq(&self.value[..]))
    }
}

/// The daemon's half of one login (`ECSRP::Server`).
pub struct Server {
    group: Group,
    b: Zeroizing<Vec<u8>>,
    a_pub: Vec<u8>,
    b_pub: Vec<u8>,
    verifier: Verifier,
    credential: u8,
    transcript: Vec<u8>,
}

impl Server {
    /// `Server::Start`: check `A` and the context, and pick `b`. `B` is
    /// [`Server::public`].
    pub fn start(
        v: &Verifier,
        credential: u8,
        a_pub: &[u8],
        transcript: &[u8],
    ) -> Result<Server, Error> {
        if !v.valid() {
            return Err(Error::Auth("invalid SRP verifier".into()));
        }
        let group = Group::new();
        let a = num(a_pub);
        if a_pub.len() != WIDTH || a == BigUint::from(0u32) || a >= group.n {
            return Err(Error::Auth("invalid SRP public value".into()));
        }
        let b = loop {
            let b: [u8; 32] = crate::crypt::random_bytes();
            if b != [0u8; 32] {
                break b;
            }
        };
        let b_pub =
            pad(&((&group.k * num(&v.value) + group.g.modpow(&num(&b), &group.n)) % &group.n));
        scrambling(&group, a_pub, &b_pub)?;
        context(credential, &v.salt, transcript, a_pub, &b_pub)?;
        Ok(Server {
            group,
            b: Zeroizing::new(b.to_vec()),
            a_pub: a_pub.to_vec(),
            b_pub,
            verifier: v.clone(),
            credential,
            transcript: transcript.to_vec(),
        })
    }

    /// `B`, for `EC_TAG_SRP_B`.
    pub fn public(&self) -> &[u8] {
        &self.b_pub
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.verifier.salt
    }

    /// `Server::Verify`: `Some(M2)` when `m1` proves the credential. One
    /// use: the exchange is spent either way.
    pub fn verify(self, m1: &[u8]) -> Option<[u8; 32]> {
        if m1.len() != 32 {
            return None;
        }
        let g = &self.group;
        let u = scrambling(g, &self.a_pub, &self.b_pub).ok()?;
        let v = num(&self.verifier.value);
        let base = (num(&self.a_pub) * v.modpow(&u, &g.n)) % &g.n;
        let s = Zeroizing::new(pad(&base.modpow(&num(&self.b), &g.n)));
        let (exp_m1, m2) = evidence(
            &s,
            self.credential,
            &self.verifier.salt,
            &self.transcript,
            &self.a_pub,
            &self.b_pub,
        )
        .ok()?;
        bool::from(exp_m1[..].ct_eq(m1)).then_some(m2)
    }
}

/// The fake daemon's challenge, on [`Server`].
#[cfg(any(test, feature = "fake-daemon"))]
pub(crate) mod server {
    use super::*;

    pub struct Challenge {
        server: Server,
        pub b_pub: Vec<u8>,
    }

    /// A challenge for `digest` with this salt.
    pub fn challenge(digest: &str, salt: &[u8], a_pub: &[u8], transcript: &[u8]) -> Challenge {
        let v = Verifier::create(digest, salt.try_into().unwrap()).unwrap();
        let server = Server::start(&v, 0, a_pub, transcript).unwrap();
        Challenge {
            b_pub: server.public().to_vec(),
            server,
        }
    }

    impl Challenge {
        /// `Some(M2)` when `m1` proves the client knows the password.
        pub fn verify(self, m1: &[u8]) -> Option<[u8; 32]> {
            self.server.verify(m1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // unittests/tests/ECSRPVector.h (generated by GenerateECSRPVector.py,
    // independent of Crypto++).
    const X: &str = "edb279e7728b94d836804399739054ac4cdd450bf37d531f7e73634755ce0f90";
    const V: &str = concat!(
        "4acf9c3ef792b769469daa0ebf73302eaa6144b6b05fa5e5530f633a12e5cce42fb07cc565194c3c781f564cd18a28f6",
        "41b551845f9a7d77a3d13257a86b3381f45340fe36b21812f600979e301e158e47059f163f78dbea30286fd0aa34b89e",
        "c4e01ce7339467d0196d19d31aaffd43d6ffb66ddf3ee14d9ec98a13a0b5c799ffac7fa7b1d70245843a0293fc2b00b1",
        "58ed69e7403ed3ef7168131bd52373cd2d9d9be0fb6e34c3dcdc922cae1efd526feaa9e06900edbb1e3438f33f06ccae",
        "40866efbae3a1a3826565751b361f49ba65b8e26ab18a916b832af1b21c1e35a906c9e1f5e0824a31a0fd93e185869e9",
        "45209bdff5fe43edb569273065b1866bf24a56275076789ac4a4989b5ef3120c4306fc6d791bfc0afe323e9fef099b39",
        "df8027c4c491ddeed4c83bb2619cbd146a3cb98023f3fe6c0ab0a411fefe1b43e34739bd9e3d07a08e6226618d677974",
        "895f2a2c60e42fee0ee80a0afef3e876cdb6bdc1395174cfd2926aa48b894446095346f383c46c346daf847e3cd76dcd",
    );
    const A: &str = concat!(
        "203e5bc55133e8d2917aac4b7d78b82c725d9085efc46dd33c449ebfb09816bee2ae6e218c9873a99a1e01bd0e7ca47e",
        "dca05889319bfebb30bdea7701cba20c6419a59b7c6ee0f80c59fcb9ec9e43da57885775e6d343288c7bdca766361e51",
        "1c8d7f1ac4c521c2fbdd22e145fb83fcf0722949ab5520de4963661c5d27658a010cb50514a6d8ff10a8448117545c4a",
        "9cd12002b1bf0f81775f0426ad609d2eaaee21736fc6d766a9e8977a4b467c1a67a4de79e6c185b555028633cd028b39",
        "17fc6f0d8e07871b2d531ea6e4f9f5bbed5cf6aaee6f1f429126c6bac9644df264bf61fcf5a8c5a42c99d42f1bf87c89",
        "488649991be2bcdce6c1d87a6a463a7998150a20b33e7fbbcaa366e8a77c5529421dadf8132ef97e09d30eadae3149b8",
        "f15025354b7c6148fbd754c9ca6caead032f4e322fc93049805f5ea415bf535deab62f603340cc2d9bd99874c9bdf2c6",
        "a07d1963bfb79ee527fc252db63696b00ec434bdc69e9158ba02ac9dbe0ff85e5263c57f178dd4d529eaa23940ed2e47",
    );
    const B: &str = concat!(
        "bbfa1584ae7c7bf1a399f85121a4633cf3a146c8dec7792c14264d9f456144182d0598c6ac60d9b788108cd463745150",
        "54818fc87f521355c36742657ef2106a604876b3ced4e96d54430a3fb83fca405434f2a2d6d3264b8c51e48dd23c22a8",
        "bf0c7776c86e66faf0e656a5bb3c6ada4ac943a9e97199e4423a9b35a3a1669555c5c6465e494b76825d60346064f66e",
        "40b5bd5dedb9068b3862aa6fed77e3baa69c5e4f967ffb41406f93dc8924544747b7c1f69513acdcd0c9a06c67bb9c2a",
        "40993044e1ee30b99676a598de066e25b669b3e193a86b6762089b5a6fa7c131ffcda3b69f740b6a356c3f1fd1d5f975",
        "888f5fdae4a1c0d073bfcde0813344f776ada5c581b64f90fc8f8e4b1a80957dd29463c66d5b442094faaede0cc5ba31",
        "7109a75bfd919850ffaf47950b86094cf24c945b099954a8b46b6be8daddbbe4595f27bd38dc76ddf55fb1a61fe7b70f",
        "a21c05010776e16764226667986656aeba82d6f7fb19018e8aa8dc1d51300866a05d32d71e08d2b762a07712a144412b",
    );
    const S: &str = concat!(
        "29ec3b3a88816b0f00c0390ffaff25258d89d679e38ec2060f7e3f0dff8000954e3e066e1e8614c6e0522baf220c72bb",
        "e69bea44b05a3312d4877acb984decec94cf9a923d19c400a5acce50e8e4d17ecdc9cbdf91681cea2402cf767c5bd74e",
        "e601c38fab62693d2560776d1d19a30386fbdd74b94cd29368d4cd36f592d0386cf1369bcd38ba3fea5e3351086b87d0",
        "99a23426b70dcd39f72d94d3b6a92fdd6cfd716536f6ba0e27003bbf76818dba68cb15bce0d1bac1839e5bcbeeb9af36",
        "82346d0d34890f9ebdb07445b7491f89a594a4db0757c859dd210aea18a115eb0354c21ea5c0c46eb17ad24bf055fec6",
        "7412e63645826b8a77012067eed1e157b07716950a3319a164aff2e86895897ecfe294718237a722ff8ba23665d30ed3",
        "d29209e79408d0ca2ab1e085ea2b5aa74227f9624888c649da1e175cf2e071f257813e762de20c958c9140b486baa728",
        "e7c065b6fc0ffc16cf282d73f7978971d0e0438af0996c376e058d064e53c330e5cac94feca090866727d4a1787458ae",
    );
    const M1: &str = "73a65de8539d3ea7d876a3f29af15f7ed1a6cdb5835feae5cc5a5718d3cecaa2";
    const M2: &str = "a99b41113fad5967aacd4c0e8f816965468c948bdd13c9eb33e8cda6781c831e";

    const DIGEST: &str = "0123456789abcdef0123456789abcdef";

    fn salt() -> Vec<u8> {
        (0u8..16).collect()
    }
    fn transcript() -> Vec<u8> {
        (0u8..163).collect()
    }

    #[test]
    fn v1_vector_arithmetic() {
        let g = Group::new();
        let x = derive_x(&unhex_digest(DIGEST).unwrap(), &salt()).unwrap();
        assert_eq!(x.to_vec(), h(X), "scrypt input");
        assert_eq!(pad(&g.g.modpow(&num(&x[..]), &g.n)), h(V), "verifier");

        let a: Vec<u8> = (0u8..32).collect();
        let client = Client::with_secret(&a);
        assert_eq!(client.public(), &h(A)[..], "A");

        let s = client_secret(&g, &h(A), &h(B), &num(&a), &num(&x[..])).unwrap();
        assert_eq!(s, h(S), "client S");

        let (m1, m2) = evidence(&s, 0, &salt(), &transcript(), &h(A), &h(B)).unwrap();
        assert_eq!(m1.to_vec(), h(M1));
        assert_eq!(m2.to_vec(), h(M2));
    }

    #[test]
    fn v1_vector_full_client_flow() {
        let a: Vec<u8> = (0u8..32).collect();
        let mut c = Client::with_secret(&a);
        let m1 = c
            .respond(DIGEST, Credential::Password, &salt(), &h(B), &transcript())
            .unwrap();
        assert_eq!(m1.to_vec(), h(M1));
        assert!(c.verify(&h(M2)));
        assert!(!c.verify(&h(M2)), "a proof verifies once");
    }

    #[test]
    fn wrong_server_proof_is_refused() {
        let a: Vec<u8> = (0u8..32).collect();
        let mut c = Client::with_secret(&a);
        c.respond(DIGEST, Credential::Password, &salt(), &h(B), &transcript())
            .unwrap();
        let mut bad = h(M2);
        bad[31] ^= 1;
        assert!(!c.verify(&bad));
    }

    #[test]
    fn degenerate_public_values_are_refused_before_the_kdf() {
        let mut c = Client::start();
        let zero = vec![0u8; WIDTH];
        assert!(c
            .respond(DIGEST, Credential::Password, &salt(), &zero, &transcript())
            .is_err());
        let n = pad(&Group::new().n);
        assert!(c
            .respond(DIGEST, Credential::Password, &salt(), &n, &transcript())
            .is_err());
        assert!(c
            .respond(
                DIGEST,
                Credential::Password,
                &salt(),
                &h(B)[1..],
                &transcript()
            )
            .is_err());
    }

    #[test]
    fn password_digests() {
        assert_eq!(password_digest(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert!(!is_password_digest(&password_digest("")));
        assert!(!is_password_digest("00000000000000000000000000000000"));
        assert!(is_password_digest(&password_digest("secret")));
        assert!(!is_password_digest("xyz"));
    }
}
