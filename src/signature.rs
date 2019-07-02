use rand::{RngCore, CryptoRng};

use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;
use amcl_wrapper::extension_field_gt::GT;

use crate::setup::{Sigkey, Verkey};
use crate::errors::PixelError;
use crate::setup::GeneratorSet;
use crate::util::{from_node_num_to_path, calculate_path_factor_using_t_l};

/*use std::any::Any;
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
}*/

pub struct Signature {
    sigma_1: G1,
    sigma_2: G2,
}

impl Signature {
    pub fn new<R: RngCore + CryptoRng>(msg: &[u8], t: u128, l:u8 ,
                                       gens: &GeneratorSet,
                                       sig_key: &Sigkey,
                                       rng: &mut R) -> Result<Self, PixelError> {
        // TODO: Check length of sig_key is sufficient to for t. Also check for sufficient length of gens.
        let path = from_node_num_to_path(t, l)?;
        let c: G2 = sig_key.0.clone();
        let d: G1 = sig_key.1[0].clone();
        let r = FieldElement::random_using_rng(rng);
        // Hash(msg) -> FieldElement
        let m = Self::hash_message(msg);

        let mut sigma_1 = d;
        // e_l
        let e_l: G1 = sig_key.1[sig_key.1.len()-1].clone();
        // sigma_1 += e_l^Hash(msg)
        sigma_1 += &e_l * &m;

        let mut sigma_1_1 = calculate_path_factor_using_t_l(t, l, gens)?;
        sigma_1_1 += &gens.1[l as usize +1] * m;
        sigma_1_1 = sigma_1_1 * &r;
        sigma_1 += sigma_1_1;

        let sigma_2 = c + (&gens.0 * &r);
        Ok(
            Self { sigma_1: sigma_1.clone(), sigma_2: sigma_2.clone() }
        )
    }


    pub fn verify(&self, msg: &[u8], t: u128, l:u8 ,
                  gens: &GeneratorSet, verkey: &Verkey) -> Result<bool, PixelError> {
        // Hash(msg) -> FieldElement
        let h = &gens.1[0];
        let g2 = &gens.0;
        let y = &verkey.value;
        let m = Self::hash_message(msg);
        let mut sigma_1_1 = calculate_path_factor_using_t_l(t, l, gens)?;
        sigma_1_1 += &gens.1[l as usize +1] * m;
        let lhs = GT::ate_pairing(&self.sigma_1, &g2);
        let rhs1 = GT::ate_pairing(h, y);
        let rhs2 = GT::ate_pairing(&sigma_1_1, &self.sigma_2);
        let rhs = GT::mul(&rhs1, &rhs2);
        Ok(lhs == rhs)
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
    use crate::setup::{setup, SigkeySet};
    use crate::util::calculate_l;

    fn create_sig_and_verify<R: RngCore + CryptoRng>(set: &SigkeySet, t: u128, vk: &Verkey, l: u8, gens: &GeneratorSet, mut rng: &mut R) {
        let sk = set.get_key(t).unwrap();
        let msg = "Hello".as_bytes();
        let sig = Signature::new(msg, t, l, &gens, &sk, &mut rng).unwrap();
        assert!(sig.verify(msg, t, l, &gens, &vk).unwrap());
    }

    fn fast_forward_sig_and_verify<R: RngCore + CryptoRng>(set: &mut SigkeySet, t: u128, vk: &Verkey, l: u8, gens: &GeneratorSet, mut rng: &mut R) {
        set.fast_forward_update(t, &gens, &mut rng).unwrap();
        create_sig_and_verify(&set, t, &vk, l, &gens, &mut rng);
    }

    # [test]
    fn test_sig_verify_initial() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let (gens, vk, set,_) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();
        let t = 1u128;
        create_sig_and_verify::<ThreadRng>(&set, t, &vk, l, &gens, &mut rng);
    }

    # [test]
    fn test_sig_verify_post_simple_update_by_7() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let (gens, vk, mut set,_) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

        // t=2
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 2u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 5u128, &vk, l, &gens, &mut rng);

        // t=3
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 3u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 4u128, &vk, l, &gens, &mut rng);

        // t=4
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 4u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 5u128, &vk, l, &gens, &mut rng);

        // t=5
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 5u128, &vk, l, &gens, &mut rng);

        // t=6
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 6u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 7u128, &vk, l, &gens, &mut rng);

        // t=7
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 7u128, &vk, l, &gens, &mut rng);
    }

    # [test]
    fn test_sig_verify_post_simple_update_by_15() {
        let mut rng = rand::thread_rng();
        let T = 15;
        let l = calculate_l(T).unwrap();
        let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

        // t=2
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 2u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=3
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 3u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 6u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=4
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 4u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 5u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 6u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=5
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 5u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 6u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=6
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 6u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=7
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 7u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 8u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=8
        set.simple_update(&gens, &mut rng).unwrap();

        // t=9
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 9u128, &vk, l, &gens, &mut rng);

        // t=10
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 10u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 13u128, &vk, l, &gens, &mut rng);

        // t=11
        set.simple_update(&gens, &mut rng).unwrap();
        create_sig_and_verify::<ThreadRng>(&set, 11u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 12u128, &vk, l, &gens, &mut rng);
        create_sig_and_verify::<ThreadRng>(&set, 13u128, &vk, l, &gens, &mut rng);
    }

    # [test]
    fn test_sig_verify_post_fast_forward_update_7() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let mut t = 1u128;

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 3;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 4;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 5;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 6;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 7;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }
    }

    # [test]
    fn test_sig_verify_post_fast_forward_update_repeat_7() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let mut t = 1u128;

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 2;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);

            t = 4;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);

            t = 6;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }
    }

    # [test]
    fn test_sig_verify_post_fast_forward_update_repeat_15() {
        let mut rng = rand::thread_rng();
        let T = 15;
        let l = calculate_l(T).unwrap();
        let mut t = 1u128;

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 3;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);

            t = 8;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);

            t = 13;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }

        {
            let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 6;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);

            t = 8;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);

            t = 13;
            fast_forward_sig_and_verify(&mut set, t, &vk, l, &gens, &mut rng);
        }
    }
}