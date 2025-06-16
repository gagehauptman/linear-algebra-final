use nalgebra::{DMatrix, DVector};
use rand::distr::Uniform;
use rand::prelude::*;

type Polynomial = DVector<i64>;

struct SecretKey {
    s: Polynomial
}

struct PublicKey {
    a: Polynomial,
    b: Polynomial,
}

struct CipherData {
    u: Polynomial,
    v: Polynomial,
}

struct CipherParams {
    n: usize,
    q: i64,
    T: i64,
}

impl CipherParams {
    // Constructs a circulant matrix from polynomial a using CipherParams n
    fn build_circulant_matrix(&self, a: &Polynomial) -> DMatrix<i64> {
        let mut m = DMatrix::<i64>::zeros(self.n, self.n);
        for i in 0..self.n {
            for j in 0..self.n {
                let index = (i + self.n - j) % self.n;
                m[(i,j)] = a[index];
            }
        }

        m
    }

    // Solve for the mathematical modulo of a polynomial
    fn modulo_q(&self, p: Polynomial) -> Polynomial {
        p.map(|x| {
            let r = x % self.q;

            // Ensure there are no negative numbers
            if r < 0 {
                r + self.q
            } else {
                r
            }
        })
    }

    // Multiply two polynomials using circulant matrix multiplication
    fn polynomial_multiply(&self, a: &Polynomial, b: &Polynomial) -> Polynomial {
        let m = self.build_circulant_matrix(a);
        let product = m * b;
        self.modulo_q(product)
    }

    // Create a polynomial with coefficients uniformly from -bound to bound
    fn uniform_polynomial(&self, rng: &mut ThreadRng, bound: i64) -> Polynomial {
        let uniform = Uniform::new(-bound, bound+1).unwrap();
        DVector::from_fn(self.n, |_,_| uniform.sample(rng))
    }

    // Key generation
    fn keygen(&self, rng: &mut ThreadRng) -> (PublicKey, SecretKey) {
        // Uniform a in value of possible outputs of mod q
        let uni_mod_q = Uniform::new(0, self.q).unwrap();
        let a = DVector::from_fn(self.n, |_,_| uni_mod_q.sample(rng));

        // Secret s and small error e
        let s = self.uniform_polynomial(rng, 1);
        let e = self.uniform_polynomial(rng, 1);

        // b = (a*s + e) mod q
        let b_poly = self.polynomial_multiply(&a, &s) + e;
        let b = self.modulo_q(b_poly);

        (PublicKey { a, b }, SecretKey { s })
    }

    // Encrypt function
    fn encrypt(&self, public_key: &PublicKey, m: &Polynomial, rng: &mut ThreadRng) -> CipherData {
        let r = self.uniform_polynomial(rng, 1);
        let e1 = self.uniform_polynomial(rng, 1);
        let e2 = self.uniform_polynomial(rng, 1);

        // u = a*r + e1
        let u_poly = self.polynomial_multiply(&public_key.a, &r);
        let u = self.modulo_q(u_poly + e1);
        // v = b * r + e2 + (q/2) * m
        let product = self.polynomial_multiply(&public_key.b, &r);
        let v = self.modulo_q(product + e2 + m * (self.q / self.T));

        CipherData { u, v }
    }

    // Decrypt function
    fn decrypt(&self, secret_key: &SecretKey, cipher_data: &CipherData) -> DVector<i64> {
        let scale = self.q / self.T;
        let u_times_s = self.polynomial_multiply(&cipher_data.u, &secret_key.s);
        let v_minus_u_s = self.modulo_q(&cipher_data.v - u_times_s);
        // map back to message coefficients
        v_minus_u_s.map(|coeff| (coeff + scale/2) / scale)
    }
}

fn string_to_bits_polynomial(params: &CipherParams, msg: &str) -> Polynomial {
    let bits = msg.as_bytes()
        .iter()
        .flat_map(|&b| (0..8).rev().map(move |i| ((b>>i)&1) as i64))
        .chain(std::iter::repeat(0))
        .take(params.n);
    let poly = DVector::from_iterator(params.n, bits);
    poly
}

fn bits_polynomial_to_string(params: &CipherParams, poly: &Polynomial) -> String {
    let bits: Vec<i64> = poly.iter()
        .cloned()
        .take(params.n)
        .collect();

    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
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


fn main() {
    let start = std::time::Instant::now();
    let msg = "wow look, encryption"; // Must be less than 128 characters long
    let n = 1024;

    println!("Original String: {:?}", msg);

    let params = CipherParams { n, q: 12289, T: 2 };
    let mut rng = rand::thread_rng();

    let (public_key, secret_key) = params.keygen(&mut rng);
    let m: Polynomial = string_to_bits_polynomial(&params, msg);
    let cipher = params.encrypt(&public_key, &m, &mut rng);
    let decrypted = params.decrypt(&secret_key, &cipher);
    println!("Decrypted String: {:?}", bits_polynomial_to_string(&params, &decrypted));
}