use rand::{CryptoRng, RngCore};

use crate::keys::{Verkey, Sigkey, MasterSecret, ProofOfPossession, Keypair};
use amcl_wrapper::field_elem::{FieldElement, FieldElementVector};
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use secret_sharing::polynomial::Polynomial;
use secret_sharing::shamir_secret_sharing::get_shared_secret;
use crate::{VerkeyGroup, SignatureGroup, VerkeyGroupVec, SignatureGroupVec};
use std::collections::{HashMap, HashSet};
use std::mem;
use crate::errors::PixelError;
use crate::signature::Signature;

pub struct Signer {
    pub id: usize,
    pub sigkey_initial: Sigkey,
    pub verkey: Verkey,
    pub pop: ProofOfPossession,
}

/// Takes shares for secret and generate signing and verification keys
fn keygen_from_shares<R: RngCore + CryptoRng>(
    num_signers: usize,
    mut master_secret_shares: HashMap<usize, FieldElement>,
    rng: &mut R,
    gen: &VerkeyGroup,
    gens: &[SignatureGroup],
) -> Result<Vec<Signer>, PixelError> {
    let mut signers = vec![];

    for i in 0..num_signers {
        let id = i + 1;
        let x_i = master_secret_shares.remove(&id).unwrap();
        let master_secret = MasterSecret {value: x_i};
        let verkey = Verkey::from_master_secret(&master_secret, gen);
        let pop = Keypair::gen_pop(&verkey, &master_secret);
        let sigkey_initial = Sigkey::initial_secret_key(
            gen,
            gens,
            &master_secret,
            rng,
        )?;
        mem::drop(master_secret);

        signers.push(Signer {
            id,
            sigkey_initial,
            verkey,
            pop
        })
    }
    Ok(signers)
}

/// USING TRUSTED THIRD PARTY ONLY FOR DEMONSTRATION, IN PRACTICE A DECENTRALIZED KEY GENERATION
/// PROTOCOL WILL BE USED.
/// Keygen done by trusted party using Shamir secret sharing. Creates signing and verification
/// keys for each signer. The trusted party will know every signer's secret keys and the
/// aggregate secret keys and can create signatures.
/// Outputs 2 items, first is the shared secret and should be destroyed.
/// The second contains the keys, 1 item corresponding to each signer.
pub fn trusted_party_SSS_keygen<R: RngCore + CryptoRng>(
    threshold: usize,
    total: usize,
    rng: &mut R,
    gen: &VerkeyGroup,
    gens: &[SignatureGroup],
) -> Result<(FieldElement, Vec<Signer>), PixelError> {
    let (secret_x, x_shares) = get_shared_secret(threshold, total);
    Ok((secret_x, keygen_from_shares(total, x_shares, rng, gen, gens)?))
}

pub struct ThresholdScheme {}

impl ThresholdScheme {
    /// Combine at least `threshold` number of signatures to create a threshold signature
    pub fn aggregate_sigs(threshold: usize, sigs: Vec<(usize, Signature)>) -> Signature {
        assert!(sigs.len() >= threshold);

        let mut sigma_1_bases = SignatureGroupVec::with_capacity(threshold);
        let mut sigma_1_exps = FieldElementVector::with_capacity(threshold);
        let mut sigma_2_bases = VerkeyGroupVec::with_capacity(threshold);
        let mut sigma_2_exps = FieldElementVector::with_capacity(threshold);

        let signer_ids = sigs
            .iter()
            .take(threshold)
            .map(|(i, _)| *i)
            .collect::<HashSet<usize>>();
        for (id, sig) in sigs.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), id);
            sigma_1_bases.push(sig.sigma_1.clone());
            sigma_1_exps.push(l.clone());
            sigma_2_bases.push(sig.sigma_2.clone());
            sigma_2_exps.push(l);
        }
        // threshold signature = (\product( sig[i].sigma_1^l ), \product( sig[i].sigma_2^l )) for all i
        Signature {
            sigma_1: sigma_1_bases.multi_scalar_mul_const_time(sigma_1_exps.as_ref()).unwrap(),
            sigma_2: sigma_2_bases.multi_scalar_mul_const_time(sigma_2_exps.as_ref()).unwrap(),
        }
    }

    /// Create a verification key to verify a threshold signature. Such a key can be created
    /// once and persisted to be used for any threshold signature
    pub fn aggregate_vk(threshold: usize, keys: Vec<(usize, &Verkey)>) -> Verkey {
        assert!(keys.len() >= threshold);

        let mut vk_bases = VerkeyGroupVec::with_capacity(threshold);
        let mut vk_exps = FieldElementVector::with_capacity(threshold);

        let signer_ids = keys
            .iter()
            .take(threshold)
            .map(|(i, _)| *i)
            .collect::<HashSet<usize>>();
        for (id, vk) in keys.into_iter().take(threshold) {
            let l = Polynomial::lagrange_basis_at_0(signer_ids.clone(), id);
            vk_bases.push(vk.value.clone());
            vk_exps.push(l.clone());
        }

        // threshold verkey = vk_1^l_1 * vk_2^l_2 * ... vk_i^l_i for i in threshold

        Verkey {
            value: vk_bases.multi_scalar_mul_var_time(vk_exps.as_ref()).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::ThreadRng;
    use crate::util::{GeneratorSet, calculate_l};
    use crate::signature::Signature;
    use crate::keys::{InMemorySigKeyDb, SigkeyManager};

    fn check_threshold_key_gen(
        threshold: usize,
        secret_x: FieldElement,
        signers: &[Signer],
        gen: &VerkeyGroup,
    ) {
        let threshold_vk = ThresholdScheme::aggregate_vk(
            threshold,
            signers
                .iter()
                .take(threshold)
                .map(|s| (s.id, &s.verkey))
                .collect::<Vec<(usize, &Verkey)>>(),
        );

        let expected_vk = gen * &secret_x;
        assert_eq!(expected_vk, threshold_vk.value);
    }

    fn check_threshold_key_gen_gaps_in_ids(
        threshold: usize,
        secret_x: FieldElement,
        keys_to_aggr: Vec<(usize, &Verkey)>,
        gen: &VerkeyGroup,
    ) {
        let threshold_vk = ThresholdScheme::aggregate_vk(threshold, keys_to_aggr);

        let expected_vk = gen * &secret_x;
        assert_eq!(expected_vk, threshold_vk.value);
    }

    fn check_signing_on_random_msgs(threshold: usize, signers: &[Signer], mut sigkey_dbs: Vec<InMemorySigKeyDb>, mut sk_managers: Vec<SigkeyManager>, T: u128, l: u8, gens: &GeneratorSet) {
        let mut rng = rand::thread_rng();
        for t in 1..=T {
            let msg = FieldElement::random().to_bytes();
            let mut sigs = vec![];
            for i in 0..threshold {
                let sk = sk_managers[i].get_current_key(&sigkey_dbs[i]).unwrap();
                let sig = Signature::new(&msg, t, l, &gens, sk, &mut rng).unwrap();
                assert!(sig.verify(&msg, t, l, gens, &signers[i].verkey).unwrap());
                sigs.push((signers[i].id, sig));
            }

            let threshold_sig = ThresholdScheme::aggregate_sigs(threshold, sigs);

            let threshold_vk = ThresholdScheme::aggregate_vk(
                threshold,
                signers
                    .iter()
                    .map(|s| (s.id, &s.verkey))
                    .collect::<Vec<(usize, &Verkey)>>(),
            );

            assert!(threshold_sig.verify(&msg, t, l, gens, &threshold_vk).unwrap());
            for i in 0..threshold {
                sk_managers[i].simple_update(&gens, &mut rng, &mut sigkey_dbs[i]).unwrap();
            }
        }
    }

    #[test]
    fn test_verkey_aggregation_shamir_secret_sharing_keygen() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let generators = GeneratorSet::new(T, "test_pixel").unwrap();
        let threshold = 3;
        let total = 5;

        let (secret_x, signers) = trusted_party_SSS_keygen(threshold, total, &mut rng, &generators.0, &generators.1).unwrap();

        check_threshold_key_gen(threshold, secret_x, &signers, &generators.0)
    }

    #[test]
    fn test_verkey_aggregation_gaps_in_ids_shamir_secret_sharing_keygen() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let generators = GeneratorSet::new(T, "test_pixel").unwrap();
        let threshold = 3;
        let total = 5;

        let (secret_x, signers) = trusted_party_SSS_keygen(threshold, total, &mut rng, &generators.0, &generators.1).unwrap();

        let mut keys = vec![];
        keys.push((signers[0].id, &signers[0].verkey));
        keys.push((signers[2].id, &signers[2].verkey));
        keys.push((signers[4].id, &signers[4].verkey));

        check_threshold_key_gen_gaps_in_ids(threshold, secret_x, keys, &generators.0);
    }

    #[test]
    fn test_sign_verify_shamir_secret_sharing_keygen() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let generators = GeneratorSet::new(T, "test_pixel").unwrap();
        let threshold = 3;
        let total = 5;

        let (secret_x, signers) = trusted_party_SSS_keygen(threshold, total, &mut rng, &generators.0, &generators.1).unwrap();

        let mut sk_managers = Vec::<SigkeyManager>::new();
        let mut sigkey_dbs = Vec::<InMemorySigKeyDb>::new();
        for i in 0..total {
            let mut db = InMemorySigKeyDb::new();
            let sk_manager = SigkeyManager::new(T, l, signers[i].sigkey_initial.clone(), &mut db).unwrap();
            sigkey_dbs.push(db);
            sk_managers.push(sk_manager);
        }
        check_signing_on_random_msgs(threshold, &signers, sigkey_dbs, sk_managers, T, l, &generators)
    }
}