use nalgebra::{DMatrix, DVector};
use rand::distr::Uniform;
use rand::prelude::*;

const T: i64 = 256;

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
        let v = self.modulo_q(product + e2 + m * (self.q / T));

        CipherData { u, v }
    }

    // Decrypt function
    fn decrypt(&self, secret_key: &SecretKey, cipher_data: &CipherData) -> DVector<u8> {
        let scale = self.q / T;
        let thing1 = self.polynomial_multiply(&cipher_data.u, &secret_key.s);
        let thing2 = self.modulo_q(&cipher_data.v - thing1);
        thing2.map(|x| ((x + scale/2) / scale) as u8)
    }

}

fn main() {
    let params = CipherParams { n: 8, q: 2_i64.pow(16) };
    let mut rng = rand::rng();

    let (public_key, secret_key) = params.keygen(&mut rng);
    let msg_bytes = "Haii OwO".as_bytes();
    let m: Polynomial = DVector::from_iterator(params.n, msg_bytes.iter().map(|&b| b as i64));
    println!("Original Bytes:\n{:?}", m);

    let cipher = params.encrypt(&public_key, &m, &mut rng);
    println!("Cipher Bytes:\n{:?}\n{:?}", cipher.u, cipher.v);

    let decrypted = params.decrypt(&secret_key, &cipher);
    let decrypted_bytes: Vec<u8> = decrypted.iter().cloned().collect();
    println!("Decrypted bytes:\n{:?}", decrypted_bytes);
    println!("Decrypted string:\n{}", String::from_utf8_lossy(&decrypted_bytes));
}