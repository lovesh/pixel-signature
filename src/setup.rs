use rand::{RngCore, CryptoRng};

use amcl_wrapper::errors::SerzDeserzError;
use amcl_wrapper::field_elem::FieldElement;
use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::G1;
use amcl_wrapper::group_elem_g2::G2;

use super::errors::PixelError;
use std::collections::HashMap;

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
pub struct Verkey<G: GroupElement> {
    pub value: G
}

impl<G: GroupElement> Clone for Verkey<G> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone()
        }
    }
}

impl<G: GroupElement> Verkey<G> {
    pub fn from_master_secret(master_secret: &MasterSecret, generator: &G) -> Self {
        Self {
            value: generator.scalar_mul_const_time(&master_secret.value)
        }
    }

    pub fn from_bytes(vk_bytes: &[u8]) -> Result<Verkey<G>, SerzDeserzError> {
        G::from_bytes(vk_bytes).map(|value| Verkey { value })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes()
    }

    // add verify PoP function. Use match expression to match on group types and then call the pairing.
}

/// Keypair consisting of a master secret, the corresponding verkey and the proof of possession
/// The public key or proof of possession can be in group G1 or G2.
/// If public key is in G2 then proof of possession is in G1 and vice versa.
/// Type GPrime denotes group for public key and type G denotes group for proof of possession.
pub struct Keypair<G: GroupElement, GPrime: GroupElement> {
    // Fixme: Probably the master secret does not need to be persisted once the initial signing keys and PoP has been generated.
    // Seems like a bad idea to make it part of struct.
    master_secret: MasterSecret,
    pub ver_key: Verkey<GPrime>,
    pub pop: G     // pop is Proof of Possession
}

impl<G: GroupElement, G_prime: GroupElement> Keypair<G, G_prime> {
    pub fn new<R: RngCore + CryptoRng>(generator: &G_prime, rng: &mut R) -> Self {
        let master_secret = MasterSecret::new(rng);
        let ver_key = Verkey::from_master_secret(&master_secret, generator);
        let pop = Self::gen_pop(&ver_key, &master_secret);
        Self { master_secret, ver_key, pop }
    }

    /// Generate proof of possession
    fn gen_pop(vk: &Verkey<G_prime>, x: &MasterSecret) -> G {
        let prefix_pop = b"PoP";
        let mut s = prefix_pop.to_vec();
        s.extend_from_slice(&vk.to_bytes());
        let g = G::from_msg_hash(&s);
        g.scalar_mul_const_time(&x.value)
    }
}

/// second element is a vector with length l+2 and is of form [h, h_0, h_1, h_2, ..., h_l]
pub struct GeneratorSet<G: GroupElement, GPrime: GroupElement>(pub GPrime, pub Vec<G>);

impl <G: GroupElement, G_prime: GroupElement> GeneratorSet<G, G_prime> {
    pub fn new(T: u128, prefix: &str) -> Result<Self, PixelError> {
        Ok(GeneratorSet(G_prime::from_msg_hash(prefix.as_bytes()),  Self::create_generators(T, prefix)?))
    }

    /// Returns generators to be used in the protocol. Takes time period T and a prefix string that is
    /// used to create generators by hashing the prefix string concatenated with integers. T+1 must be a power of 2.
    pub fn create_generators(T: u128, prefix: &str) -> Result<Vec<G>, PixelError> {
        let l = calculate_l(T)? as usize;
        let mut params = Vec::with_capacity(l+2);
        for i in 0..(l+2) {
            let s: String = prefix.to_string() + &i.to_string();
            params.push(G::from_msg_hash(s.as_bytes()));
        }
        Ok(params)
    }
}

/// Secret key sk can be seen as (sk', sk'') where sk'' is itself a vector with initial (and max) length l+1
pub struct Sigkey<G: GroupElement, GPrime: GroupElement>(pub GPrime, pub Vec<G>);

impl <G: GroupElement, G_prime: GroupElement> Sigkey<G, G_prime> {
    /// Create secret key for the beginning, i.e. t=1
    pub fn initial_secret_key<R: RngCore + CryptoRng>(gen: &G_prime, gens: &[G], master_secret: &MasterSecret, rng: &mut R) -> Result<Self, PixelError> {
        if gens.len() < 3 {
            return Err(PixelError::GeneratorsLessThanMinimum {n: 3})
        }
        let r = FieldElement::random_using_rng(rng);
        // g^r
        let sk_prime = gen.scalar_mul_const_time(&r);
        let mut sk_prime_prime = vec![];
        let h_x = gens[0].scalar_mul_const_time(&master_secret.value);
        let h0_r = gens[1].scalar_mul_const_time(&r);
        // h^x.h_0^r
        sk_prime_prime.push(h_x.plus(&h0_r));
        for i in 2..gens.len() {
            // h_i^r
            sk_prime_prime.push(gens[i].scalar_mul_const_time(&r));
        }
        Ok(Self(sk_prime, sk_prime_prime))
    }
}

/// keys is a hashmap with the hashmap key as the time period for which the key needs to be used.
/// The hashmap will get new entries and remove old entries as time passes. `t` denotes the current time period.
/// This data-structure is to be kept secret.
pub struct SigkeySet<G: GroupElement, GPrime: GroupElement> {
    l: u8,
    T: u128,
    t: u128,
    keys: HashMap<u128, Sigkey<G, GPrime>>
}

impl <G: GroupElement, G_prime: GroupElement> SigkeySet<G, G_prime> {
    pub fn new(T: u128, l: u8, sigkey: Sigkey<G, G_prime>) -> Result<Self, PixelError> {
        let mut keys = HashMap::<u128, Sigkey<G, G_prime>>::new();
        let t = 1;
        keys.insert(t.clone(), sigkey);
        Ok(Self {
            l,
            T,
            t,
            keys
        })
    }

    pub fn get_key(&self, t: u128) -> Result<&Sigkey<G, G_prime>, PixelError> {
        if self.keys.contains_key(&t) {
            Ok(self.keys.get(&t).unwrap())
        } else {
            Err(PixelError::SigkeyNotFound {t})
        }
    }

    pub fn update_by_1(&mut self) -> Result<(), PixelError> {
        unimplemented!()
    }
}

/// Create master secret, verkey, PoP, initial Sigkey for t = 1, Sigkey set with only 1 key, i.e. for t=1 and proof of possession.
pub fn setup<R: RngCore + CryptoRng, G: GroupElement, GPrime: GroupElement>(T: u128,
                                                                            prefix: &str,
                                                                            rng: &mut R)
        -> Result<(GeneratorSet<G, GPrime>, Verkey<GPrime>, SigkeySet<G, GPrime>, G), PixelError> {
    let generators = GeneratorSet::<G, GPrime>::new(T, prefix)?;
    let keypair = Keypair::<G, GPrime>::new(&generators.0, rng);
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

/// Takes max time period to be supported T. Returns l where 2^l - 1 = T.
pub fn calculate_l(T: u128) -> Result<u8, PixelError> {
    if T >= u128::max_value() {
        return Err(PixelError::MoreThanSupported {T})
    }

    let mut t_plus_1 = T+1;
    if !t_plus_1.is_power_of_two() {
        return Err(PixelError::NonPowerOfTwo {T})
    }

    let mut l = 0;
    while t_plus_1 != 0 {
        t_plus_1 = t_plus_1 >> 1;
        l += 1;
    }

    Ok(l)
}

/// Convert path of node to node number (prefix). Path is from root to the node and
/// `l = depth + 1` where `depth` is the depth of the tree.
/*
    If node is left child of parent then this node's number is 1 more than parent' node number
    If node is right child of parent then this node's number is 1 + parent's node number + half of the number of children of the parent.
    A more verbose form of the code would ne
    if node is left_of(parent) {
        node_num(node) = 1 + node_num(parent)
    } else {
        node_num(node) = 1 + node_num(parent) + (2^ (l - depth(node))) / 2
        node_num(node) = 1 + node_num(parent) + (2^ (l - depth(node) - 1))
    }
*/
pub fn path_to_node_num(path: &[u8], l: u8) -> Result<u128, PixelError> {
    if (path.len() as u8) >= l {
        return Err(PixelError::InvalidPath {path: path.to_vec(), l})
    }
    let mut t = 1u128;
    for i in 1..(path.len()+1) {
        // t += 1 + 2^{l-i-1} * (path[i-1]-1)
        t += 1 + (((1 << (l- i as u8)) - 1) * (path[i-1]-1)) as u128;
    }
    Ok(t)
}

/// Convert node number (prefix) to path of node. Path is from root to the node and
/// `l = depth + 1` where `depth` is the depth of the tree.
pub fn from_node_num_to_path(t: u128, l: u8) -> Result<Vec<u8>, PixelError> {
    if t > ((1 << l) - 1) as u128 {
        return Err(PixelError::InvalidNodeNum {t, l})
    }
    if t == 1 {
        return Ok(vec![])
    } else {
        let two_l_1 = (1 << (l-1)) as u128;     // 2^{l-1}
        if t <= two_l_1 {
            // If node number falls in left half of tree, put a 1 in path and traverse the left subtree
            let mut path = vec![1];
            path.append(&mut from_node_num_to_path(t - 1, l-1)?);
            return Ok(path)
        } else {
            // If node number falls in right half of tree, put a 2 in path and traverse the right subtree.
            // The right subtree will have 2^{l-1} nodes less than the original tree since left subtree had 2^{l-1}-1 nodes.
            let mut path = vec![2];
            path.append(&mut from_node_num_to_path(t - two_l_1, l-1)?);
            return Ok(path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ThreadRng;

    # [test]
    fn test_path_to_node_num() {
        assert_eq!(path_to_node_num(&[], 3).unwrap(), 1);
        assert_eq!(path_to_node_num(&[1], 3).unwrap(), 2);
        assert_eq!(path_to_node_num(&[2], 3).unwrap(), 5);
        assert_eq!(path_to_node_num(&[2, 1], 3).unwrap(), 6);
        assert_eq!(path_to_node_num(&[2, 2], 3).unwrap(), 7);
        assert_eq!(path_to_node_num(&[1, 1], 3).unwrap(), 3);
        assert_eq!(path_to_node_num(&[1, 1, 1], 4).unwrap(), 4);
        assert_eq!(path_to_node_num(&[1, 1, 2], 4).unwrap(), 5);
        assert_eq!(path_to_node_num(&[1, 2], 4).unwrap(), 6);
        assert_eq!(path_to_node_num(&[1, 2, 1], 4).unwrap(), 7);
        assert_eq!(path_to_node_num(&[1, 2, 2], 4).unwrap(), 8);
        assert_eq!(path_to_node_num(&[2], 4).unwrap(), 9);
    }

    # [test]
    fn test_from_node_num_to_path() {
        assert_eq!(from_node_num_to_path(1, 3).unwrap(), vec![]);
        assert_eq!(from_node_num_to_path(2, 3).unwrap(), vec![1]);
        assert_eq!(from_node_num_to_path(3, 3).unwrap(), vec![1, 1]);
        assert_eq!(from_node_num_to_path(4, 3).unwrap(), vec![1, 2]);
        assert_eq!(from_node_num_to_path(5, 3).unwrap(), vec![2]);
        assert_eq!(from_node_num_to_path(6, 3).unwrap(), vec![2, 1]);
        assert_eq!(from_node_num_to_path(7, 3).unwrap(), vec![2, 2]);
        assert_eq!(from_node_num_to_path(15, 4).unwrap(), vec![2, 2, 2]);
        assert_eq!(from_node_num_to_path(14, 4).unwrap(), vec![2, 2, 1]);
        assert_eq!(from_node_num_to_path(13, 4).unwrap(), vec![2, 2]);
        assert_eq!(from_node_num_to_path(10, 4).unwrap(), vec![2, 1]);
        assert_eq!(from_node_num_to_path(11, 4).unwrap(), vec![2, 1, 1]);
        assert_eq!(from_node_num_to_path(12, 4).unwrap(), vec![2, 1, 2]);
        assert_eq!(from_node_num_to_path(8, 4).unwrap(), vec![1, 2, 2]);
    }

    // TODO: Test to and from conversion of path and node number using randoms

    # [test]
    fn test_setup() {
        let mut rng = rand::thread_rng();
        let T1 = 7;
        let l1 = calculate_l(T1).unwrap();
        let (_, _, set1,_) = setup::<ThreadRng, G1, G2>(T1, "test_pixel", &mut rng).unwrap();
        let sk1 = set1.get_key(1u128).unwrap();
        assert_eq!(sk1.1.len() as u8, l1+1);

        let T2 = 15;
        let l2 = calculate_l(T2).unwrap();
        let (_, _, set2,_) = setup::<ThreadRng, G1, G2>(T2, "test_pixel", &mut rng).unwrap();
        let sk2 = set2.get_key(1u128).unwrap();
        assert_eq!(sk2.1.len() as u8, l2+1);
    }
}