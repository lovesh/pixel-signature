use rand::{RngCore, CryptoRng};

use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::errors::PixelError;
use std::collections::{HashMap, HashSet};
use crate::util::{calculate_l, from_node_num_to_path, path_to_node_num, calculate_path_factor, node_successor_paths};
use amcl_wrapper::extension_field_gt::GT;

pub struct MasterSecret {
    value: FieldElement
}

impl MasterSecret {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            value: FieldElement::random_using_rng(rng)
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
pub struct Verkey {
    pub value: G2
}

impl Clone for Verkey {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone()
        }
    }
}

impl Verkey {
    pub fn from_master_secret(master_secret: &MasterSecret, generator: &G2) -> Self {
        Self {
            value: generator * &master_secret.value
        }
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

    // add verify PoP function. Use match expression to match on group types and then call the pairing.
}

/// Keypair consisting of a master secret, the corresponding verkey and the proof of possession
/// The public key or proof of possession can be in group G1 or G2.
/// If public key is in G2 then proof of possession is in G1 and vice versa.
/// Type GPrime denotes group for public key and type G denotes group for proof of possession.
pub struct Keypair {
    // Fixme: Probably the master secret does not need to be persisted once the initial signing keys and PoP has been generated.
    // Seems like a bad idea to make it part of struct.
    pub master_secret: MasterSecret,
    pub ver_key: Verkey,
    pub pop: G1     // pop is Proof of Possession
}

const PrefixPoP: &[u8] = b"PoP";

impl Keypair {
    pub fn new<R: RngCore + CryptoRng>(generator: &G2, rng: &mut R) -> Self {
        let master_secret = MasterSecret::new(rng);
        let ver_key = Verkey::from_master_secret(&master_secret, generator);
        let pop = Self::gen_pop(&ver_key, &master_secret);
        Self { master_secret, ver_key, pop }
    }

    /// Generate proof of possession
    fn gen_pop(vk: &Verkey, x: &MasterSecret) -> G1 {
        Self::msg_for_pop(vk) * &x.value
    }

    /// Verify proof of possession
    pub fn verify_pop(pop: &G1, vk: &Verkey, gen: &G2) -> bool {
        let lhs = GT::ate_pairing(pop, &gen);
        let rhs = GT::ate_pairing(&Self::msg_for_pop(vk), &vk.value);
        lhs == rhs
    }

    fn msg_for_pop(vk: &Verkey) -> G1 {
        let mut s = PrefixPoP.to_vec();
        s.extend_from_slice(&vk.to_bytes());
        G1::from_msg_hash(&s)
    }
}

/// second element is a vector with length l+2 and is of form [h, h_0, h_1, h_2, ..., h_l]
pub struct GeneratorSet(pub G2, pub Vec<G1>);

impl GeneratorSet {
    pub fn new(T: u128, prefix: &str) -> Result<Self, PixelError> {
        Ok(GeneratorSet(G2::from_msg_hash(prefix.as_bytes()),  Self::create_generators(T, prefix)?))
    }

    /// Returns generators to be used in the protocol. Takes time period T and a prefix string that is
    /// used to create generators by hashing the prefix string concatenated with integers. T+1 must be a power of 2.
    pub fn create_generators(T: u128, prefix: &str) -> Result<Vec<G1>, PixelError> {
        let l = calculate_l(T)? as usize;
        let mut params = Vec::with_capacity(l+2);
        for i in 0..(l+2) {
            let s: String = prefix.to_string() + &i.to_string();
            params.push(G1::from_msg_hash(s.as_bytes()));
        }
        Ok(params)
    }
}

/// Secret key sk can be seen as (sk', sk'') where sk'' is itself a vector with initial (and max) length l+1
pub struct Sigkey(pub G2, pub Vec<G1>);

impl Sigkey {
    /// Create secret key for the beginning, i.e. t=1
    pub fn initial_secret_key<R: RngCore + CryptoRng>(gen: &G2, gens: &[G1], master_secret: &MasterSecret, rng: &mut R) -> Result<Self, PixelError> {
        if gens.len() < 3 {
            return Err(PixelError::GeneratorsLessThanMinimum {n: 3})
        }
        let r = FieldElement::random_using_rng(rng);
        // g^r
        let sk_prime = gen * &r;
        let mut sk_prime_prime = vec![];
        let h_x = gens[0] * &master_secret.value;
        let h0_r = gens[1] * &r;
        // h^x.h_0^r
        sk_prime_prime.push(h_x + &h0_r);
        for i in 2..gens.len() {
            // h_i^r
            sk_prime_prime.push(gens[i] * &r);
        }
        Ok(Self(sk_prime, sk_prime_prime))
    }
}

/// keys is a hashmap with the hashmap key as the time period for which the key needs to be used.
/// The hashmap will get new entries and remove old entries as time passes. `t` denotes the current time period.
/// This data-structure is to be kept secret.
pub struct SigkeySet {
    l: u8,
    T: u128,
    t: u128,
    keys: HashMap<u128, Sigkey>
}

impl SigkeySet {
    pub fn new(T: u128, l: u8, sigkey: Sigkey) -> Result<Self, PixelError> {
        let mut keys = HashMap::<u128, Sigkey>::new();
        let t = 1;
        keys.insert(t.clone(), sigkey);
        Ok(Self {
            l,
            T,
            t,
            keys
        })
    }

    pub fn has_key(&self, t: u128) -> bool {
        self.keys.contains_key(&t)
    }

    pub fn get_key(&self, t: u128) -> Result<&Sigkey, PixelError> {
        match self.keys.get(&t) {
            Some(key) => Ok(key),
            None => Err(PixelError::SigkeyNotFound {t})
        }
    }

    pub fn get_current_key(&self) -> Result<&Sigkey, PixelError> {
        self.get_key(self.t)
    }

    /// Update time by 1
    pub fn simple_update<R: RngCore + CryptoRng>(&mut self, gens: &GeneratorSet, rng: &mut R) -> Result<(), PixelError> {
        let path = from_node_num_to_path(self.t, self.l)?;
        let path_len = path.len();
        let sk = self.get_current_key()?;
        // sk.1.len() + path_len == l+1
        debug_assert_eq!(self.l as usize + 1, sk.1.len() + path_len);

        if path_len < (self.l as usize - 1) {
            // Create signing keys for left and right child
            let c: G2 = sk.0.clone();
            let d: G1 = sk.1[0].clone();

            // key for left child
            let mut sk_left_prime_prime = vec![d + sk.1[1].clone()];
            for i in 2..sk.1.len() {
                sk_left_prime_prime.push(sk.1[i].clone());
            }

            // key for right child
            let mut path_right = path.clone();
            path_right.push(2);
            let path_right_len = path_right.len();
            let node_num_right = path_to_node_num(&path_right, self.l)?;

            let r = FieldElement::random_using_rng(rng);
            let f2 = FieldElement::from(2u32);       // f2 = 2
            // d * e_j^2
            let mut sk_right_prime_prime = vec![d + (sk.1[1] * f2)];
            // h_0 * h_1^path[0] * h_2^path[1] * ... h_k^path[-1]
            let path_factor = calculate_path_factor(path_right, &gens)?;
            // d * e_j^2 * (h_0 * h_1^path[0] * h_2^path[1] * ... h_k^path[-1])^r
            sk_right_prime_prime[0] += (path_factor * r);

            for i in 2..sk.1.len() {
                let e = sk.1[i] + (gens.1[path_right_len+i] * r);
                sk_right_prime_prime.push(e);
            }

            // Update the set with keys for both children and remove key corresponding to current time period
            self.keys.insert(self.t + 1, Sigkey(c, sk_left_prime_prime));
            self.keys.insert(node_num_right, Sigkey(c + (gens.0 * r), sk_right_prime_prime));
            self.keys.remove(&self.t);
            self.t = self.t + 1;
        } else {
            // Current node is at leaf, so remove current leaf. Already have rest of the keys.
            self.keys.remove(&self.t);
            self.t = self.t + 1;
        }
        Ok(())
    }

    /// Update time to given `t`
    pub fn fast_forward_update<R: RngCore + CryptoRng>(&mut self, t: u128, gens: &GeneratorSet, rng: &mut R) -> Result<(), PixelError> {
        if t > ((1 << self.l) - 1) as u128 {
            return Err(PixelError::InvalidNodeNum {t, l: self.l})
        }

        if t < self.t {
            return Err(PixelError::SigkeyUpdateBackward {old_t: t, current_t: self.t})
        }
        if t == self.t {
            println!("Key already present");
            return Ok(())
        }

        if (t - self.t) == 1 {
            // Simple update is more efficient
            return self.simple_update(gens, rng)
        }

        // Find key for t and all of t's successors
        let t_path = from_node_num_to_path(t, self.l)?;
        let successor_paths = node_successor_paths(t, self.l)?;
        // The set might already have keys for some successors, filter them out.
        let successors_to_update_paths: Vec<_> = successor_paths.iter().filter(|p| {
            let n = path_to_node_num(p, self.l).unwrap();
            !self.has_key(n)
        }).collect();

        match self.get_key(t) {
            Ok(_) => (),     // Key and thus all needed successors already present
            Err(_) => {
                // Key absent. Calculate the highest predecessor path and key to derive necessary children.
                let pred_sk_path: Vec<u8> = if self.has_key(1) {
                    vec![]
                } else {
                    let mut cur_path = vec![];
                    for p in &t_path {
                        cur_path.push(*p);
                        if self.has_key(path_to_node_num(&cur_path, self.l)?) {
                            break
                        }
                    }
                    cur_path
                };
                let pred_node_num = path_to_node_num(&pred_sk_path, self.l)?;
                let pred_sk = {
                    self.get_key(pred_node_num)?.clone()
                };
                let pred_sk_path_len = pred_sk_path.len();

                let keys = {
                    let mut keys = vec![];
                    // Calculate key for time t
                    let sk_t = Self::derive_key(&t_path, pred_sk, pred_sk_path_len, self.l, gens, rng)?;
                    keys.push((t, sk_t));

                    for path in &successors_to_update_paths {
                        let n = path_to_node_num(*path, self.l)?;
                        keys.push((n, Self::derive_key(&path, pred_sk, pred_sk_path_len, self.l, gens, rng)?));
                    }
                    keys
                };

                for (i,k) in keys {
                    self.keys.insert(i, k);
                }
            }
        };

        // Remove all nodes except successors and the node for time t.
        let all_key_node_nums: HashSet<_> = self.keys.keys().map(|k| *k).collect();
        // Keep successors
        let mut node_num_to_keep: HashSet<u128> = successor_paths.iter().map(|p| path_to_node_num(p, self.l).unwrap()).collect();
        // Keep the node for time being forwarded to
        node_num_to_keep.insert(t);
        // Remove all others
        let nodes_to_remove = all_key_node_nums.difference(&node_num_to_keep);
        for n in nodes_to_remove {
            self.keys.remove(n);
        }
        self.t = t;
        Ok(())
    }

    /// Derive signing key denoted by path `key_path` using its predecessor node's signing key `pred_sk`
    fn derive_key<R: RngCore + CryptoRng>(key_path: &[u8], pred_sk: &Sigkey, pred_sk_path_len: usize, l: u8, gens: &GeneratorSet, rng: &mut R) -> Result<Sigkey, PixelError> {
        // TODO: Move to lazy_static
        let f1 = FieldElement::one();               // f1 = 1
        let f2 = FieldElement::from(2u32);       // f2 = 2

        let key_path_len = key_path.len();
        let r = FieldElement::random_using_rng(rng);

        let c: G2 = pred_sk.0.clone();
        let mut d: G1 = pred_sk.1[0].clone();
        for i in pred_sk_path_len..key_path_len {
            if key_path[i] == 1 {
                d += pred_sk.1[i-pred_sk_path_len+1] * &f1;
            } else {
                d += pred_sk.1[i-pred_sk_path_len+1] * &f2;
            }
        }
        let path_factor = calculate_path_factor(key_path.to_vec(), &gens)?;
        d += (path_factor * r);

        let sk_t_prime = c + (&gens.0 * r);
        let mut sk_t_prime_prime = vec![];
        sk_t_prime_prime.push(d);

        let pred_sk_len = pred_sk.1.len();
        let gen_len = gens.1.len();
        for i in (key_path_len+1)..(l as usize + 1) {
            let j = l as usize - i + 1;
            let a = pred_sk.1[pred_sk_len-j];
            let b = (gens.1[gen_len-j] * r);
            let e = a + b;
            sk_t_prime_prime.push(e);
        }

        Ok(Sigkey(sk_t_prime, sk_t_prime_prime))
    }
}

/// Create master secret, verkey, PoP, initial Sigkey for t = 1, Sigkey set with only 1 key, i.e. for t=1 and proof of possession.
pub fn setup<R: RngCore + CryptoRng>(T: u128, prefix: &str, rng: &mut R)
        -> Result<(GeneratorSet, Verkey, SigkeySet, G1), PixelError> {
    let generators = GeneratorSet::new(T, prefix)?;
    let keypair = Keypair::new(&generators.0, rng);
    let sigkey_initial = Sigkey::initial_secret_key(&generators.0, &generators.1.as_slice(), &keypair.master_secret, rng)?;
    let l = calculate_l(T)?;
    let sigkey_set = SigkeySet::new(T, l, sigkey_initial)?;
    Ok(
        (
            generators,
            keypair.ver_key,
            sigkey_set,
            keypair.pop
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;

    fn fast_forward_and_check<R: RngCore + CryptoRng>(set: &mut SigkeySet, t: u128, gens: &GeneratorSet, mut rng: &mut R) {
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
        let (gens, verkey, _, PoP) = setup::<ThreadRng>(T1, "test_pixel", &mut rng).unwrap();
        assert!(Keypair::verify_pop(&PoP, &verkey, &gens.0))
    }

    #[test]
    fn test_setup() {
        let mut rng = rand::thread_rng();
        let T1 = 7;
        let l1 = calculate_l(T1).unwrap();
        let (_, _, set1, _) = setup::<ThreadRng>(T1, "test_pixel", &mut rng).unwrap();
        let sk1 = set1.get_key(1u128).unwrap();
        assert_eq!(sk1.1.len() as u8, l1 + 1);

        let T2 = 15;
        let l2 = calculate_l(T2).unwrap();
        let (_, _, set2, _) = setup::<ThreadRng>(T2, "test_pixel", &mut rng).unwrap();
        let sk2 = set2.get_key(1u128).unwrap();
        assert_eq!(sk2.1.len() as u8, l2 + 1);
    }

    #[test]
    fn test_simple_key_update_7() {
        // Create key and then update time by 1 repeatedly

        let mut rng = rand::thread_rng();
        let T = 7;
        let l = calculate_l(T).unwrap();
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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
        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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

        let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();
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
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 3;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(4u128));
            assert!(set.has_key(5u128));
        }

        {
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 4;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(4u128));
            assert!(set.has_key(5u128));
        }

        {
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

            t = 5;
            fast_forward_and_check(&mut set, t, &gens, &mut rng);
            assert!(set.has_key(5u128));
        }

        {
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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
        let l = calculate_l(T).unwrap();
        let mut t = 1u128;

        {
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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
        let l = calculate_l(T).unwrap();
        let mut t = 1u128;

        {
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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
            let (gens, _, mut set, _) = setup::<ThreadRng>(T, "test_pixel", &mut rng).unwrap();

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

    // TODO: More tests with random values using node_successors function.
}