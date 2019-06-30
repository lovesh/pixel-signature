use rand::{RngCore, CryptoRng};

use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use amcl_wrapper::extension_field_gt::GT;

use crate::setup::{Sigkey, Verkey};
use crate::errors::PixelError;
use crate::setup::from_node_num_to_path;
use crate::setup::GeneratorSet;

use std::any::Any;
#[macro_export]
macro_rules! ate_pairing {
    ( $g1:expr, $g2:expr ) => {{
        if let Some(f) = (&$g1 as &Any).downcast_ref::<G1>() {
            GT::ate_pairing(&$g1, &$g2)
        } else if let Some(f) = (&$g1 as &Any).downcast_ref::<G2>() {
            GT::ate_pairing(&$g2, &$g1)
        } else {
            panic!("I dunno what to do");
        }
    }};
}

pub struct Signature<G: GroupElement, GPrime: GroupElement> {
    sigma_1: G,
    sigma_2: GPrime,
}

impl<G: GroupElement, G_prime: GroupElement> Signature<G, G_prime> {
    pub fn new<R: RngCore + CryptoRng>(msg: &[u8], t: u128, l:u8 ,
                                       gens: &GeneratorSet<G, G_prime>,
                                       sig_key: &Sigkey<G, G_prime>,
                                       rng: &mut R) -> Result<Self, PixelError> {
        // TODO: Check length of sig_key is sufficient to for t. Also check for sufficient length of gens.
        let path = from_node_num_to_path(t, l)?;
        let c: G_prime = sig_key.0.clone();
        let d: G = sig_key.1[0].clone();
        let r = FieldElement::random_using_rng(rng);
        // Hash(msg) -> FieldElement
        let m = Self::hash_message(msg);

        let mut sigma_1 = d;
        // e_l
        let e_l: G = sig_key.1[sig_key.1.len()-1].clone();
        // sigma_1 += e_l^Hash(msg)
        sigma_1 = sigma_1.plus(&e_l.scalar_mul_const_time(&m));

        let mut sigma_1_1 = Self::calculate_sigma_1_1(&m, t, l, gens)?;
        sigma_1_1 = sigma_1_1.scalar_mul_const_time(&r);
        sigma_1 = sigma_1.plus(&sigma_1_1);

        let sigma_2 = c.plus(&gens.0.scalar_mul_const_time(&r));
        Ok(
            Self { sigma_1: sigma_1.clone(), sigma_2: sigma_2.clone() }
        )
    }


    pub fn verify(&self, msg: &[u8], t: u128, l:u8 ,
                  gens: &GeneratorSet<G, G_prime>, verkey: &Verkey<G_prime>) -> Result<bool, PixelError> {
        // Hash(msg) -> FieldElement
        let h = &gens.1[0];
        let g2 = &gens.0;
        let y = &verkey.value;
        let m = Self::hash_message(msg);
        let mut sigma_1_1 = Self::calculate_sigma_1_1(&m, t, l, gens)?;
        /*let lhs = match &self.sigma_1 {
            sigma_1: &G1 => {

            }
        };*/
        //let lhs = ate_pairing!(self.sigma_1, g2);
        assert!(G_prime::is_extension() ^ G::is_extension());
        let lhs = match G_prime::is_extension() {
            true => {
                GT::ate_pairing(&self.sigma_1, &g2)
            }
            false => {
                GT::ate_pairing(&g2, &self.sigma_1)
            }
        };
        unimplemented!()
    }

    /// Calculate h_0*h_1^path[0]*h_2^path[2]*......h_l^m
    fn calculate_sigma_1_1(m: &FieldElement, t: u128, l:u8 ,
                           gens: &GeneratorSet<G, G_prime>) -> Result<G, PixelError> {
        // TODO: Find better name for this function
        let path = from_node_num_to_path(t, l)?;

        let mut sigma_1_1: G = gens.1[1].clone();     // h_0

        // TODO: move them to lazy_static
        let f1 = FieldElement::one();       // f1 = 1
        let f2 = f1 + f1;                   // f1 = 2

        // h_0*h_1^path[0]*h_2^path[2]*......
        for (i, p) in path.iter().enumerate() {
            if *p == 1 {
                sigma_1_1 = sigma_1_1.plus(&gens.1[2+i].scalar_mul_const_time(&f1))
            } else {
                sigma_1_1 = sigma_1_1.plus(&gens.1[2+i].scalar_mul_const_time(&f2))
            }
        }

        // h_0*h_1^path[0]*h_2^path[2]*......h_l^m
        Ok(sigma_1_1.plus(&gens.1[l as usize +1].scalar_mul_const_time(&m)))
    }

    pub fn hash_message(message: &[u8]) -> FieldElement {
        // Fixme: This is not accurate and might affect the security proof but should work in practice
        FieldElement::from_msg_hash(message)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;
    use crate::setup::{setup, calculate_l};

    # [test]
    fn test_sig_verify() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let (gens, vk, set,_) = setup::<ThreadRng, G1, G2>(T, "test_pixel", &mut rng).unwrap();
        let t = 1u128;
        let sk = set.get_key(t).unwrap();
        let msg = "Hello".as_bytes();
        let sig = Signature::new(msg, t, l, &gens, &sk, &mut rng).unwrap();
    }
}