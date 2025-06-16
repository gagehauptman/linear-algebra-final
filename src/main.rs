use nalgebra::{DMatrix, DVector};
use rand::distr::Uniform;
use rand::prelude::*;

// type Polynomial = DVector<i32>;
type Polynomial = Vec<i64>;

struct SecretKey {
    s: Polynomial
}

struct PublicKey {
    a: Polynomial,
    b: Polynomial,
    a_hat: Polynomial,
    b_hat: Polynomial,
}

struct CipherData {
    u: Polynomial,
    v: Polynomial,
}

struct CipherParams {
    n: usize,
    q: i64,
    T: i64,
    root: i64,
}

fn add_vec(a: &[i64], b: &[i64]) -> Vec<i64> {
    assert_eq!(a.len(), b.len(), "Vectors must have the same length");
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| x + y)
        .collect()
}

impl CipherParams {
    // Solve for the mathematical modulo of a polynomial
    fn modulo_q(&self, p: Polynomial) -> Polynomial {
        p.into_iter().map(|x| {
            let r = x % self.q;

            // Ensure there are no negative numbers
            if r < 0 {
                r + self.q
            } else {
                r
            }
        }).collect()
    }


    // Multiply two polynomials using NTT
    fn polynomial_ntt(&self, a: &Polynomial, b: &Polynomial) -> Polynomial {
        let prod = ntt::polymul_ntt(a, b, self.n, self.q as i64, self.root);
        self.modulo_q(prod)
    }

    // Create a polynomial with coefficients uniformly from -bound to bound
    fn uniform_polynomial(&self, rng: &mut ThreadRng, bound: i32) -> Polynomial {
        let uniform = Uniform::new(-bound, bound+1).unwrap();
        (0..self.n).map(|_| uniform.sample(rng) as i64).collect()
    }

    // Key generation
    fn keygen(&self, rng: &mut ThreadRng) -> (PublicKey, SecretKey) {
        // Uniform a in value of possible outputs of mod q
        let uni_mod_q = Uniform::new(0, self.q).unwrap();
        let a = (0..self.n).map(|_| uni_mod_q.sample(rng) as i64).collect();

        // Secret s and small error e
        let s = self.uniform_polynomial(rng, 1);
        let e = self.uniform_polynomial(rng, 1);

        // b = (a*s + e) mod q
        let b_poly = add_vec(&self.polynomial_ntt(&a, &s), &e);
        let b = self.modulo_q(b_poly);

        let r = self.uniform_polynomial(rng, 1);

        let a_hat = self.polynomial_ntt(&a, &r);
        let b_hat = self.polynomial_ntt(&b, &r);

        (PublicKey { a, b, a_hat, b_hat }, SecretKey { s })
    }

    // Encrypt function
    fn encrypt(&self, public_key: &PublicKey, m: &Polynomial, rng: &mut ThreadRng) -> CipherData {
        let e1 = self.uniform_polynomial(rng, 1);
        let e2 = self.uniform_polynomial(rng, 1);


        let u_poly = &public_key.a_hat;
        let u = self.modulo_q(add_vec(&u_poly, &e1));

        // v = b * r + e2 + (q/2) * m

        let product = &public_key.b_hat;
        let scale = (self.q / self.T) as i64;
        let scaled_m: Vec<i64> = m.iter()
            .map(|coeff| coeff * scale)
            .collect();
        let br_plus_e2 = add_vec(&product, &e2);
        let pre_mod = add_vec(&br_plus_e2, &scaled_m);
        let v = self.modulo_q(pre_mod);

        CipherData { u, v }
    }

    // Decrypt function
    fn decrypt(&self, secret_key: &SecretKey, cipher_data: &CipherData) -> Polynomial {
        let scale = self.q / self.T;

        let u_times_s = self.polynomial_ntt(&cipher_data.u, &secret_key.s);
        let diff: Vec<i64> = cipher_data
            .v
            .iter()
            .zip(u_times_s.iter())
            .map(|(v_i, u_i)| v_i - u_i)
            .collect();
        let v_minus_u_s = self.modulo_q(diff);
        // map back to message coefficients
        v_minus_u_s.into_iter().map(|coeff| (coeff + scale/2) / scale).collect()
    }
}

fn string_to_bits_polynomial(params: &CipherParams, msg: &str) -> Vec<i64> {
    msg.as_bytes()
        .iter()
        .flat_map(|&b| {
            (0..8).rev().map(move |i| ((b >> i) & 1) as i64)
        })
        .chain(std::iter::repeat(0_i64))
        .take(params.n)
        .collect()
}

fn bits_polynomial_to_string(poly: &Polynomial) -> String {
    let mut bytes = Vec::new();
    for chunk in poly.chunks(8) {
        if chunk.len() < 8 { break; }

        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= ((bit as u8) & 1) << (7 - i);
        }
        bytes.push(byte);
    }

    while let Some(&0) = bytes.last() {
        bytes.pop();
    }

    String::from_utf8(bytes).expect("Decrypted bits were not valid UTF-8")
}

// DATA

fn test_data_size(params: &CipherParams, iters: usize) -> u128 {
    let mut rng = rand::thread_rng();
    let (public_key, secret_key) = params.keygen(&mut rng);
    let start = std::time::Instant::now();

    let msg = "wow look, encryption"; // Must be less than 128 characters long
    for i in 0..iters {
        let m: Polynomial = string_to_bits_polynomial(&params, msg);
        let cipher = params.encrypt(&public_key, &m, &mut rng);
        // let decrypted = params.decrypt(&secret_key, &cipher, ntt);
    }

    let duration = start.elapsed();

    duration.as_micros()
}

fn test_data_bandwidth(params: &CipherParams) -> i64 {
    let mut rng = rand::thread_rng();
    let (public_key, secret_key) = params.keygen(&mut rng);
    let start = std::time::Instant::now();

    let msg = "wow look, encryption";
    let mut count = 0;
    while start.elapsed().as_micros() < 1000000 {
        let m: Polynomial = string_to_bits_polynomial(&params, msg);
        let cipher = params.encrypt(&public_key, &m, &mut rng);
        count += 1;
    }

    return (count as f64 * 0.125) as i64;
}

fn main() {
    let params = CipherParams { n: 1024, q: 12289, T: 2, root: ntt::omega(12289i64, 1024) };
    println!("Data encryption size tests:");
    for i in 0..30 {
        println!("{:?} KB: {:?} us", i as f32 * 0.125, test_data_size(&params, i));
    }
    println!("Data bandwidth test:");
    println!("{:?} kB/s", test_data_bandwidth(&params));
}