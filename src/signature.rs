use rand::{CryptoRng, RngCore};

use amcl_wrapper::extension_field_gt::GT;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use crate::errors::PixelError;
use crate::keys::GeneratorSet;
use crate::keys::{Sigkey, Verkey};
use crate::util::{calculate_path_factor_using_t_l, from_node_num_to_path};

pub struct Signature {
    pub sigma_1: G1,
    pub sigma_2: G2,
}

impl Signature {
    pub fn new<R: RngCore + CryptoRng>(
        msg: &[u8],
        t: u128,
        l: u8,
        gens: &GeneratorSet,
        sig_key: &Sigkey,
        rng: &mut R,
    ) -> Result<Self, PixelError> {
        if gens.1.len() < (l as usize + 2) {
            return Err(PixelError::NotEnoughGenerators { n: l as usize + 2 });
        }

        let c: G2 = sig_key.0.clone();
        let d: G1 = sig_key.1[0].clone();
        let r = FieldElement::random_using_rng(rng);
        // Hash(msg) -> FieldElement
        let m = Self::hash_message(msg);

        let mut sigma_1 = d;
        // e_l
        let e_l: G1 = sig_key.1[sig_key.1.len() - 1].clone();
        // sigma_1 += e_l^Hash(msg)
        sigma_1 += &e_l * &m;

        let mut sigma_1_1 = calculate_path_factor_using_t_l(t, l, gens)?;
        sigma_1_1 += &gens.1[l as usize + 1] * m;
        sigma_1_1 = sigma_1_1 * &r;
        sigma_1 += sigma_1_1;

        let sigma_2 = c + (&gens.0 * &r);
        Ok(Self {
            sigma_1: sigma_1.clone(),
            sigma_2: sigma_2.clone(),
        })
    }

    pub fn verify(
        &self,
        msg: &[u8],
        t: u128,
        l: u8,
        gens: &GeneratorSet,
        verkey: &Verkey,
    ) -> Result<bool, PixelError> {
        if gens.1.len() < (l as usize + 2) {
            return Err(PixelError::NotEnoughGenerators { n: l as usize + 2 });
        }

        if self.is_identity() || verkey.is_identity() || !self.has_correct_oder() {
            return Ok(false);
        }
        Self::verify_naked(&self.sigma_1, &self.sigma_2, &verkey.value, msg, t, l, gens)
    }

    /// Hash message in the field before signing or verification
    pub fn hash_message(message: &[u8]) -> FieldElement {
        // Fixme: This is not accurate and might affect the security proof but should work in practice
        FieldElement::from_msg_hash(message)
    }

    pub fn verify_naked(
        sigma_1: &G1,
        sigma_2: &G2,
        verkey: &G2,
        msg: &[u8],
        t: u128,
        l: u8,
        gens: &GeneratorSet,
    ) -> Result<bool, PixelError> {
        let h = &gens.1[0];
        let g2 = &gens.0;
        let y = verkey;
        let m = Self::hash_message(msg);
        let mut sigma_1_1 = calculate_path_factor_using_t_l(t, l, gens)?;
        sigma_1_1 += &gens.1[l as usize + 1] * m;
        /*let lhs = GT::ate_pairing(sigma_1, &g2);
        let rhs1 = GT::ate_pairing(h, y); // This can be pre-computed
        let rhs2 = GT::ate_pairing(&sigma_1_1, sigma_2);
        let rhs = GT::mul(&rhs1, &rhs2);
        Ok(lhs == rhs)*/

        // Check that e(sigma_1, g2) == e(h, y) * e(sigma_1_1, sigma_2)
        // This is equivalent to checking e(h, y) * e(sigma_1_1, sigma_2) * e(sigma_1, g2)^-1 == 1
        // Which comes out to be e(h, y) * e(sigma_1_1, sigma_2) * e(sigma_1, -g2) == 1 which can put in a multi-pairing.
        // -g2 can be precomputed if performance is critical
        // Similarly it might be better to precompute e(h, y) and do a 2-pairing than a 3-pairing
        let e = GT::ate_mutli_pairing(vec![(&sigma_1, &g2.negation()), (h, y), (&sigma_1_1, sigma_2)]);
        Ok(e.is_one())
    }

    pub fn is_identity(&self) -> bool {
        if self.sigma_1.is_identity() {
            println!("Signature point in G1 at infinity");
            return true;
        }
        if self.sigma_2.is_identity() {
            println!("Signature point in G2 at infinity");
            return true;
        }
        return false;
    }

    pub fn has_correct_oder(&self) -> bool {
        if !self.sigma_1.has_correct_order() {
            println!("Signature point in G1 has incorrect order");
            return false;
        }
        if !self.sigma_2.has_correct_order() {
            println!("Signature point in G2 has incorrect order");
            return false;
        }
        return true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{setup, SigkeySet};
    use crate::util::calculate_l;
    use rand::rngs::ThreadRng;

    pub fn create_sig_and_verify<R: RngCore + CryptoRng>(
        set: &SigkeySet,
        t: u128,
        vk: &Verkey,
        l: u8,
        gens: &GeneratorSet,
        mut rng: &mut R,
    ) {
        let sk = set.get_key(t).unwrap();
        let msg = "Hello".as_bytes();
        let sig = Signature::new(msg, t, l, &gens, &sk, &mut rng).unwrap();
        assert!(sig.verify(msg, t, l, &gens, &vk).unwrap());
    }

    fn fast_forward_sig_and_verify<R: RngCore + CryptoRng>(
        set: &mut SigkeySet,
        t: u128,
        vk: &Verkey,
        l: u8,
        gens: &GeneratorSet,
        mut rng: &mut R,
    ) {
        set.fast_forward_update(t, &gens, &mut rng).unwrap();
        create_sig_and_verify(&set, t, &vk, l, &gens, &mut rng);
    }

    #[test]
    fn test_sig_verify_initial() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let (gens, vk, set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();
        let t = 1u128;
        create_sig_and_verify::<ThreadRng>(&set, t, &vk, l, &gens, &mut rng);
    }

    #[test]
    fn test_sig_verify_post_simple_update_by_7() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let (gens, vk, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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
