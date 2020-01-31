use rand::{CryptoRng, RngCore};

use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::errors::PixelError;
use crate::util::{
    calculate_l, calculate_path_factor, from_node_num_to_path, node_successor_paths,
    path_to_node_num, GeneratorSet,
};
use amcl_wrapper::extension_field_gt::GT;
use std::collections::{HashMap, HashSet};
use std::mem;

/// MasterSecret will be cleared on drop as FieldElement is cleared on drop
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasterSecret {
    value: FieldElement,
}

impl MasterSecret {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            value: FieldElement::random_using_rng(rng),
        }
    }

    pub fn from_bytes(sk_bytes: &[u8]) -> Result<Self, SerzDeserzError> {
        FieldElement::from_bytes(sk_bytes).map(|x| Self { value: x })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes()
    }
}

// The public key can be in group G1 or G2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verkey {
    pub value: G2,
}

impl Verkey {
    pub fn from_master_secret(master_secret: &MasterSecret, generator: &G2) -> Self {
        Self {
            value: generator * &master_secret.value,
        }
    }

    pub fn aggregate(ver_keys: Vec<&Self>) -> Self {
        let mut avk: G2 = G2::identity();
        for vk in ver_keys {
            avk += &vk.value;
        }
        Self { value: avk }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<Verkey, SerzDeserzError> {
        G2::from_bytes(vk_bytes).map(|value| Verkey { value })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes()
    }

    pub fn is_identity(&self) -> bool {
        if self.value.is_identity() {
            println!("Verkey point at infinity");
            return true;
        }
        return false;
    }
}

/// Proof of Possession of signing key. It is a signature on the verification key and can be
/// group in G1 or G2. But it is in different group than Verkey.
/// If Verkey is in G2 then proof of possession is in G1 and vice versa.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfPossession {
    pub value: G1,
}

/// Keypair consisting of a master secret, the corresponding verkey and the proof of possession
/// Type GPrime denotes group for public key and type G denotes group for proof of possession.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keypair {
    pub ver_key: Verkey,
    pub pop: ProofOfPossession,
}

const PrefixPoP: &[u8] = b"PoP";

impl<'a> Keypair {
    pub fn new<R: RngCore + CryptoRng>(
        T: u128,
        generators: &GeneratorSet,
        rng: &mut R,
        db: &'a mut dyn SigKeyDb,
    ) -> Result<(Self, SigkeyManager<'a>), PixelError> {
        let master_secret = MasterSecret::new(rng);
        let ver_key = Verkey::from_master_secret(&master_secret, &generators.0);
        let pop = Self::gen_pop(&ver_key, &master_secret);
        let sigkey_initial = Sigkey::initial_secret_key(
            &generators.0,
            &generators.1.as_slice(),
            &master_secret,
            rng,
        )?;
        mem::drop(master_secret);
        let l = calculate_l(T)?;
        let sigkeys = SigkeyManager::new(T, l, sigkey_initial, db)?;
        let kp = Self { ver_key, pop };
        Ok((kp, sigkeys))
    }

    /// Generate proof of possession
    fn gen_pop(vk: &Verkey, x: &MasterSecret) -> ProofOfPossession {
        ProofOfPossession {
            value: Self::msg_for_pop(vk) * &x.value,
        }
    }

    /// Verify proof of possession
    pub fn verify_pop(pop: &ProofOfPossession, vk: &Verkey, gen: &G2) -> bool {
        let lhs = GT::ate_pairing(&pop.value, &gen);
        let rhs = GT::ate_pairing(&Self::msg_for_pop(vk), &vk.value);
        lhs == rhs
    }

    fn msg_for_pop(vk: &Verkey) -> G1 {
        let mut s = PrefixPoP.to_vec();
        s.extend_from_slice(&vk.to_bytes());
        G1::from_msg_hash(&s)
    }
}

/// Secret key sk can be seen as (sk', sk'') where sk'' is itself a vector with initial (and max) length l+1
/// Sigkey will be cleared on drop as both G1 and G2 elements are cleared on drop
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sigkey(pub G2, pub Vec<G1>);

impl Sigkey {
    /// Create secret key for the beginning, i.e. t=1
    pub fn initial_secret_key<R: RngCore + CryptoRng>(
        gen: &G2,
        gens: &[G1],
        master_secret: &MasterSecret,
        rng: &mut R,
    ) -> Result<Self, PixelError> {
        if gens.len() < 3 {
            return Err(PixelError::NotEnoughGenerators { n: 3 });
        }
        let r = FieldElement::random_using_rng(rng);
        // g^r
        let sk_prime = gen * &r;
        let mut sk_prime_prime = vec![];
        let h_x = &gens[0] * &master_secret.value;
        let h0_r = &gens[1] * &r;
        // h^x.h_0^r
        sk_prime_prime.push(h_x + &h0_r);
        for i in 2..gens.len() {
            // h_i^r
            sk_prime_prime.push(&gens[i] * &r);
        }
        Ok(Self(sk_prime, sk_prime_prime))
    }
}

/// `T` denotes the maximum time period supported and `t` denotes the current time period.
pub struct SigkeyManager<'a> {
    l: u8,
    T: u128,
    t: u128,
    db: &'a mut dyn SigKeyDb,
}

impl<'a> SigkeyManager<'a> {
    pub fn new(T: u128, l: u8, sigkey: Sigkey, db: &'a mut dyn SigKeyDb) -> Result<Self, PixelError> {
        let t = 1;
        db.insert_key(t.clone(), sigkey);
        Ok(Self { l, T, t, db })
    }

    pub fn load(T: u128, l: u8, t: u128, db: &'a mut dyn SigKeyDb) -> Result<Self, PixelError> {
        Ok(Self { l, T, t, db })
    }

    pub fn has_key(&self, t: u128) -> bool {
        self.db.has_key(t)
    }

    pub fn get_key(&self, t: u128) -> Result<&Sigkey, PixelError> {
        self.db.get_key(t)
    }

    pub fn get_current_key(&self) -> Result<&Sigkey, PixelError> {
        self.db.get_key(self.t)
    }

    /// Update time by 1
    pub fn simple_update<R: RngCore + CryptoRng>(
        &mut self,
        gens: &GeneratorSet,
        rng: &mut R,
    ) -> Result<u128, PixelError> {
        let path = from_node_num_to_path(self.t, self.l)?;
        let path_len = path.len();
        let sk = self.get_current_key()?;
        // sk.1.len() + path_len == l+1
        debug_assert_eq!(self.l as usize + 1, sk.1.len() + path_len);

        // Index of key that will be removed
        let removed_key_idx: u128;

        if path_len < (self.l as usize - 1) {
            // Create signing keys for left and right child
            let c: G2 = sk.0.clone();
            let d: G1 = sk.1[0].clone();

            // key for left child
            let mut sk_left_prime_prime = vec![&d + &sk.1[1]];
            for i in 2..sk.1.len() {
                sk_left_prime_prime.push(sk.1[i].clone());
            }

            // key for right child
            let mut path_right = path.clone();
            path_right.push(2);
            let path_right_len = path_right.len();
            let node_num_right = path_to_node_num(&path_right, self.l)?;

            let r = FieldElement::random_using_rng(rng);
            // d * e_j^2
            let mut sk_right_prime_prime = vec![&d + (sk.1[1].double())];
            // h_0 * h_1^path[0] * h_2^path[1] * ... h_k^path[-1]
            let path_factor = calculate_path_factor(path_right, &gens)?;
            // d * e_j^2 * (h_0 * h_1^path[0] * h_2^path[1] * ... h_k^path[-1])^r
            sk_right_prime_prime[0] += (&path_factor * &r);

            for i in 2..sk.1.len() {
                let e = &sk.1[i] + (&gens.1[path_right_len + i] * &r);
                sk_right_prime_prime.push(e);
            }

            // Update the set with keys for both children and remove key corresponding to current time period
            self.db
                .insert_key(self.t + 1, Sigkey(c.clone(), sk_left_prime_prime));
            self.db.insert_key(
                node_num_right,
                Sigkey(&c + (&gens.0 * &r), sk_right_prime_prime),
            );
            removed_key_idx = self.t.clone();
            self.t = self.t + 1;
        } else {
            // Current node is at leaf, so remove current leaf. Already have rest of the keys.
            removed_key_idx = self.t.clone();
            self.t = self.t + 1;
        }
        self.db.remove_key(removed_key_idx);
        Ok(removed_key_idx)
    }

    /// Update time to given `t`
    pub fn fast_forward_update<R: RngCore + CryptoRng>(
        &mut self,
        t: u128,
        gens: &GeneratorSet,
        rng: &mut R,
    ) -> Result<Vec<u128>, PixelError> {
        if t > ((1 << self.l) - 1) as u128 {
            return Err(PixelError::InvalidNodeNum { t, l: self.l });
        }

        if t < self.t {
            return Err(PixelError::SigkeyUpdateBackward {
                old_t: t,
                current_t: self.t,
            });
        }
        if t == self.t {
            return Err(PixelError::SigkeyAlreadyUpdated { t });
        }

        if (t - self.t) == 1 {
            // Simple update is more efficient
            let removed = self.simple_update(gens, rng)?;
            return Ok(vec![removed]);
        }

        // Find key for t and all of t's successors
        let t_path = from_node_num_to_path(t, self.l)?;
        let successor_paths = node_successor_paths(t, self.l)?;
        // The set might already have keys for some successors, filter them out.
        let successors_to_update_paths: Vec<_> = successor_paths
            .iter()
            .filter(|p| {
                let n = path_to_node_num(p, self.l).unwrap();
                !self.has_key(n)
            })
            .collect();

        match self.get_key(t) {
            Ok(_) => (), // Key and thus all needed successors already present
            Err(_) => {
                // Key absent. Calculate the highest predecessor path and key to derive necessary children.
                let pred_sk_path: Vec<u8> = if self.has_key(1) {
                    vec![]
                } else {
                    let mut cur_path = vec![];
                    for p in &t_path {
                        cur_path.push(*p);
                        if self.has_key(path_to_node_num(&cur_path, self.l)?) {
                            break;
                        }
                    }
                    cur_path
                };
                let pred_node_num = path_to_node_num(&pred_sk_path, self.l)?;
                let pred_sk = { self.get_key(pred_node_num)? };
                let pred_sk_path_len = pred_sk_path.len();

                let keys = {
                    let mut keys = vec![];
                    // Calculate key for time t
                    let sk_t =
                        Self::derive_key(&t_path, pred_sk, pred_sk_path_len, self.l, gens, rng)?;
                    keys.push((t, sk_t));

                    for path in &successors_to_update_paths {
                        let n = path_to_node_num(*path, self.l)?;
                        keys.push((
                            n,
                            Self::derive_key(&path, pred_sk, pred_sk_path_len, self.l, gens, rng)?,
                        ));
                    }
                    keys
                };

                for (i, k) in keys {
                    //self.keys.insert(i, k);
                    self.db.insert_key(i, k);
                }
            }
        };

        // Remove all nodes except successors and the node for time t.
        let all_key_node_nums: HashSet<_> = self.db.get_key_indices();
        // Keep successors
        let mut node_num_to_keep: HashSet<u128> = successor_paths
            .iter()
            .map(|p| path_to_node_num(p, self.l).unwrap())
            .collect();
        // Keep the node for time being forwarded to
        node_num_to_keep.insert(t);
        // Remove all others
        let nodes_to_remove = all_key_node_nums.difference(&node_num_to_keep);
        let mut removed = vec![];
        for n in nodes_to_remove {
            self.db.remove_key(*n);
            removed.push(n.clone())
        }
        self.t = t;
        Ok(removed)
    }

    /// Derive signing key denoted by path `key_path` using its predecessor node's signing key `pred_sk`
    fn derive_key<R: RngCore + CryptoRng>(
        key_path: &[u8],
        pred_sk: &Sigkey,
        pred_sk_path_len: usize,
        l: u8,
        gens: &GeneratorSet,
        rng: &mut R,
    ) -> Result<Sigkey, PixelError> {
        let key_path_len = key_path.len();
        let r = FieldElement::random_using_rng(rng);

        let c: G2 = pred_sk.0.clone();
        let mut d: G1 = pred_sk.1[0].clone();
        for i in pred_sk_path_len..key_path_len {
            if key_path[i] == 1 {
                d += &pred_sk.1[i - pred_sk_path_len + 1];
            } else {
                d += &pred_sk.1[i - pred_sk_path_len + 1].double();
            }
        }
        let path_factor = calculate_path_factor(key_path.to_vec(), &gens)?;
        d += (&path_factor * &r);

        let sk_t_prime = c + (&gens.0 * &r);
        let mut sk_t_prime_prime = vec![];
        sk_t_prime_prime.push(d);

        let pred_sk_len = pred_sk.1.len();
        let gen_len = gens.1.len();
        for i in (key_path_len + 1)..(l as usize + 1) {
            let j = l as usize - i + 1;
            let a = &pred_sk.1[pred_sk_len - j];
            let b = &(&gens.1[gen_len - j] * &r);
            let e = a + b;
            sk_t_prime_prime.push(e);
        }

        Ok(Sigkey(sk_t_prime, sk_t_prime_prime))
    }
}

/// Key-value database interface that needs to be implemented for storing signing keys.
/// Signing key are db values whereas db keys are the time period for which the signing key needs to be used.
pub trait SigKeyDb {
    fn insert_key(&mut self, t: u128, sig_key: Sigkey);

    /// Removes key from database and zeroes it out
    fn remove_key(&mut self, t: u128);

    fn has_key(&self, t: u128) -> bool;

    fn get_key(&self, t: u128) -> Result<&Sigkey, PixelError>;

    /// Returns indices (time periods) for all present keys
    fn get_key_indices(&self) -> HashSet<u128>;
}

/// An in-memory database for storing signing keys. Uses hashmap. Should only be used for testing.
pub struct InMemorySigKeyDb {
    keys: HashMap<u128, Sigkey>,
}

impl SigKeyDb for InMemorySigKeyDb {
    fn insert_key(&mut self, t: u128, sig_key: Sigkey) {
        self.keys.insert(t, sig_key);
    }

    fn remove_key(&mut self, t: u128) {
        let old = self.keys.remove(&t);
        debug_assert!(old.is_some());
        mem::drop(old.unwrap());
    }

    fn has_key(&self, t: u128) -> bool {
        self.keys.contains_key(&t)
    }

    fn get_key(&self, t: u128) -> Result<&Sigkey, PixelError> {
        match self.keys.get(&t) {
            Some(key) => Ok(key),
            None => Err(PixelError::SigkeyNotFound { t }),
        }
    }

    fn get_key_indices(&self) -> HashSet<u128> {
        self.keys.keys().map(|k| *k).collect()
    }
}

impl InMemorySigKeyDb {
    pub fn new() -> Self {
        let keys = HashMap::<u128, Sigkey>::new();
        Self { keys }
    }
}

/// Create master secret, verkey, PoP, SigkeyManager for t = 1, a set with only 1 key and proof of possession.
#[cfg(test)]
pub fn setup<'a, R: RngCore + CryptoRng>(
    T: u128,
    prefix: &str,
    rng: &mut R,
    db: &'a mut dyn SigKeyDb,
) -> Result<(GeneratorSet, Verkey, SigkeyManager<'a>, ProofOfPossession), PixelError> {
    let generators = GeneratorSet::new(T, prefix)?;
    let (keypair, sigkeys) = Keypair::new(T, &generators, rng, db)?;
    Ok((generators, keypair.ver_key, sigkeys, keypair.pop))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;
    // For benchmarking
    use std::time::{Duration, Instant};

    fn fast_forward_and_check<R: RngCore + CryptoRng>(
        set: &mut SigkeyManager,
        t: u128,
        gens: &GeneratorSet,
        mut rng: &mut R,
    ) {
        set.fast_forward_update(t, &gens, &mut rng).unwrap();
        assert_eq!(set.t, t);
        for i in 1..t {
            assert!(!set.has_key(i as u128));
        }
        assert!(set.has_key(t));
    }

    #[test]
    fn test_proof_of_possession() {
        let mut rng = rand::thread_rng();
        let T1 = 7;
        let mut db = InMemorySigKeyDb::new();
        let (gens, verkey, _, PoP) =
            setup::<ThreadRng>(T1, "test_pixel", &mut rng, &mut db).unwrap();
        assert!(Keypair::verify_pop(&PoP, &verkey, &gens.0))
    }

    #[test]
    fn test_setup_with_less_number_of_genertors() {
        let mut rng = rand::thread_rng();
        let T = 7;
        let generators = GeneratorSet::new(T, "test_pixel").unwrap();
        let mut db = InMemorySigKeyDb::new();
        assert!(Keypair::new(3, &generators, &mut rng, &mut db).is_ok());
        assert!(Keypair::new(7, &generators, &mut rng, &mut db).is_ok());
        assert!(Keypair::new(8, &generators, &mut rng, &mut db).is_err());
        assert!(Keypair::new(9, &generators, &mut rng, &mut db).is_err());
    }

    #[test]
    fn test_setup() {
        let mut rng = rand::thread_rng();
        let T1 = 7;
        let l1 = calculate_l(T1).unwrap();
        let mut db1 = InMemorySigKeyDb::new();
        let (_, _, set1, _) = setup::<ThreadRng>(T1, "test_pixel", &mut rng, &mut db1).unwrap();
        let sk1 = set1.get_key(1u128).unwrap();
        assert_eq!(sk1.1.len() as u8, l1 + 1);

        let T2 = 15;
        let l2 = calculate_l(T2).unwrap();
        let mut db2 = InMemorySigKeyDb::new();
        let (_, _, set2, _) = setup::<ThreadRng>(T2, "test_pixel", &mut rng, &mut db2).unwrap();
        let sk2 = set2.get_key(1u128).unwrap();
        assert_eq!(sk2.1.len() as u8, l2 + 1);
    }

    #[test]
    fn test_simple_key_update_7() {
        // Create key and then update time by 1 repeatedly

        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let mut db = InMemorySigKeyDb::new();
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

        // t=2
        set.simple_update(&gens, &mut rng).unwrap();
        let sk_left = set.get_key(2u128).unwrap();
        assert_eq!(sk_left.1.len() as u8, l);
        let sk_right = set.get_key(5u128).unwrap();
        assert_eq!(sk_right.1.len() as u8, l);
        assert_eq!(set.t, 2);
        assert!(!set.has_key(1u128));

        // t=3
        set.simple_update(&gens, &mut rng).unwrap();
        let sk_left = set.get_key(3u128).unwrap();
        assert_eq!(sk_left.1.len() as u8, l - 1);
        let sk_right = set.get_key(4u128).unwrap();
        assert_eq!(sk_right.1.len() as u8, l - 1);
        assert_eq!(set.t, 3);
        assert!(!set.has_key(2u128));
        assert!(set.has_key(5u128));

        // t=4
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 4);
        assert!(!set.has_key(3u128));
        assert!(set.has_key(4u128));
        assert!(set.has_key(5u128));

        // t=5
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 5);
        assert!(!set.has_key(4u128));

        // t=6
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 6);
        assert!(!set.has_key(5u128));
        assert!(set.has_key(6u128));
        assert!(set.has_key(7u128));

        // t=7
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 7);
        assert!(!set.has_key(6u128));
        assert!(set.has_key(7u128));
    }

    #[test]
    fn test_simple_key_update_15() {
        // Create key and then update time by 1 repeatedly

        let mut rng = rand::thread_rng();

        let T = 15;
        let l = calculate_l(T).unwrap();
        let mut db = InMemorySigKeyDb::new();
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

        // t=2
        set.simple_update(&gens, &mut rng).unwrap();
        let sk_left = set.get_key(2u128).unwrap();
        assert_eq!(sk_left.1.len() as u8, l);
        let sk_right = set.get_key(9u128).unwrap();
        assert_eq!(sk_right.1.len() as u8, l);
        assert_eq!(set.t, 2);
        assert!(!set.has_key(1u128));
        assert!(set.has_key(9u128));

        // t=3
        set.simple_update(&gens, &mut rng).unwrap();
        let sk_left = set.get_key(3u128).unwrap();
        assert_eq!(sk_left.1.len() as u8, l - 1);
        let sk_right = set.get_key(6u128).unwrap();
        assert_eq!(sk_right.1.len() as u8, l - 1);
        assert_eq!(set.t, 3);
        assert!(!set.has_key(2u128));
        assert!(set.has_key(9u128));

        // t=4
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 4);
        assert!(!set.has_key(3u128));
        assert!(set.has_key(5u128));
        assert!(set.has_key(6u128));
        assert!(set.has_key(9u128));

        // t=5
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 5);
        assert!(!set.has_key(4u128));
        assert!(set.has_key(6u128));
        assert!(set.has_key(9u128));

        // t=6
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 6);
        assert!(!set.has_key(5u128));
        assert!(set.has_key(6u128));
        assert!(set.has_key(9u128));

        // t=7
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 7);
        assert!(!set.has_key(6u128));
        assert!(set.has_key(8u128));
        assert!(set.has_key(9u128));

        // t=8
        set.simple_update(&gens, &mut rng).unwrap();

        // t=9
        set.simple_update(&gens, &mut rng).unwrap();

        // t=10
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 10);
        assert!(!set.has_key(9u128));
        assert!(set.has_key(13u128));

        // t=11
        set.simple_update(&gens, &mut rng).unwrap();
        assert_eq!(set.t, 11);
        assert!(!set.has_key(10u128));
        assert!(set.has_key(12u128));
        assert!(set.has_key(13u128));
    }

    #[test]
    fn test_fast_forward_key_update_through_simple_key_update_7() {
        // Create key and then fast forward update time

        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let mut db = InMemorySigKeyDb::new();
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();
        assert_eq!(set.t, 1);

        // t=2
        set.fast_forward_update(2u128, &gens, &mut rng).unwrap();
        let sk_left = set.get_key(2u128).unwrap();
        assert_eq!(sk_left.1.len() as u8, l);
        let sk_right = set.get_key(5u128).unwrap();
        assert_eq!(sk_right.1.len() as u8, l);
        assert_eq!(set.t, 2);
        assert!(!set.has_key(1u128));

        // t=3
        set.fast_forward_update(3u128, &gens, &mut rng).unwrap();
        let sk_left = set.get_key(3u128).unwrap();
        assert_eq!(sk_left.1.len() as u8, l - 1);
        let sk_right = set.get_key(4u128).unwrap();
        assert_eq!(sk_right.1.len() as u8, l - 1);
        assert_eq!(set.t, 3);
        assert!(!set.has_key(2u128));
        assert!(set.has_key(5u128));

        // t=4
        set.fast_forward_update(4u128, &gens, &mut rng).unwrap();
        assert_eq!(set.t, 4);
        assert!(!set.has_key(3u128));
        assert!(set.has_key(4u128));
        assert!(set.has_key(5u128));

        // t=5
        set.fast_forward_update(5u128, &gens, &mut rng).unwrap();
        assert_eq!(set.t, 5);
        assert!(!set.has_key(4u128));

        // t=6
        set.fast_forward_update(6u128, &gens, &mut rng).unwrap();
        assert_eq!(set.t, 6);
        assert!(!set.has_key(5u128));
        assert!(set.has_key(6u128));
        assert!(set.has_key(7u128));

        // t=7
        set.fast_forward_update(7u128, &gens, &mut rng).unwrap();
        assert_eq!(set.t, 7);
        assert!(!set.has_key(6u128));
        assert!(set.has_key(7u128));
    }

    #[test]
    fn test_fast_forward_key_update_7() {
        // Create key and then fast forward update

        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();

        let mut t = 1u128;
        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 3;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(4u128));
            assert!(set.has_key(5u128));
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 4;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(4u128));
            assert!(set.has_key(5u128));
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 5;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(5u128));
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 6;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(6u128));
            assert!(set.has_key(7u128));
        }
    }

    #[test]
    fn test_fast_forward_key_update_repeat_7() {
        // Create key and then fast forward update repeatedly

        let mut rng = rand::thread_rng();
        let T = 7;
        let mut t = 1u128;

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 2;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(5u128));

            t = 4;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(5u128));

            t = 6;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(6u128));
            assert!(set.has_key(7u128));
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 3;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(4u128));
            assert!(set.has_key(5u128));

            t = 5;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);

            t = 7;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 4;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(5u128));

            t = 7;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
        }
    }

    #[test]
    fn test_fast_forward_key_update_15() {
        // Create key and then fast forward update

        let mut rng = rand::thread_rng();

        let T = 15;
        let mut t;

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 3;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(6u128));
            assert!(set.has_key(9u128));

            t = 5;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(6u128));
            assert!(set.has_key(9u128));

            t = 9;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            t = 4;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(5u128));
            assert!(set.has_key(6u128));
            assert!(set.has_key(9u128));

            t = 10;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(13u128));

            t = 13;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
        }
    }

    #[test]
    fn timing_simple_key_update_65535() {
        // For tree with l=16, supports 2^16 - 1 = 65535 keys
        let mut rng = rand::thread_rng();

        let T = 65535;
        let l = calculate_l(T).unwrap();
        let mut db = InMemorySigKeyDb::new();
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

        for i in 1..20 {
            let start = Instant::now();
            set.simple_update(&gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t={} to t={} is {:?}",
                l,
                i,
                i + 1,
                start.elapsed()
            );
        }
    }

    #[test]
    fn timing_simple_key_update_1048575() {
        // For tree with l=20, supports 2^20 - 1 = 1048575 keys
        let mut rng = rand::thread_rng();

        let T = 1048575;
        let l = calculate_l(T).unwrap();
        let mut db = InMemorySigKeyDb::new();
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

        for i in 1..40 {
            let start = Instant::now();
            set.simple_update(&gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t={} to t={} is {:?}",
                l,
                i,
                i + 1,
                start.elapsed()
            );
        }
    }

    #[test]
    fn timing_fast_forward_key_update_65535() {
        // For tree with l=16, supports 2^16 - 1 = 65535 keys

        let mut rng = rand::thread_rng();
        let T = 65535;
        let l = calculate_l(T).unwrap();

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            let start = Instant::now();
            set.fast_forward_update(3, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=1 to t=3 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(15, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=3 to t=15 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(35, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=15 to t=35 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(10000, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=35 to t=10000 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(30000, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=10000 to t=30000 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(65535, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=30000 to t=65535 is {:?}",
                l,
                start.elapsed()
            );
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            let start = Instant::now();
            set.fast_forward_update(50000, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=1 to t=50000 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(65535, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=50000 to t=65535 is {:?}",
                l,
                start.elapsed()
            );
        }
    }

    #[test]
    fn timing_fast_forward_key_update_1048575() {
        // For tree with l=20, supports 2^20 - 1 = 1048575 keys
        let mut rng = rand::thread_rng();

        let T = 1048575;
        let l = calculate_l(T).unwrap();

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            let start = Instant::now();
            set.fast_forward_update(3, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=1 to t=3 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(19, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=3 to t=19 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(4096, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=19 to t=4096 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(1048550, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=4096 to t=1048550 is {:?}",
                l,
                start.elapsed()
            );
        }

        {
            let mut db = InMemorySigKeyDb::new();
            let (gens, _, mut set, _) =
                setup::<ThreadRng>(T, "test_pixel", &mut rng, &mut db).unwrap();

            let start = Instant::now();
            set.fast_forward_update(19, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=1 to t=19 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(65535, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=19 to t=65535 is {:?}",
                l,
                start.elapsed()
            );

            let start = Instant::now();
            set.fast_forward_update(1048575, &gens, &mut rng).unwrap();
            println!(
                "For l={}, time to update key from t=65535 to t=1048575 is {:?}",
                l,
                start.elapsed()
            );
        }
    }
    // TODO: More tests with random values using node_successors function.
}
