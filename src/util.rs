use crate::errors::PixelError;
use crate::keys::GeneratorSet;
use amcl_wrapper::field_elem::FieldElement;
use crate::amcl_wrapper::group_elem::GroupElement;
use amcl_wrapper::group_elem_g1::G1;

// TODO: Abstract left and right in an enum with values 1 and 2 rather than using hardcoded 1 and 2.
// This also helps input validation in lots of places.

/// Takes max time period to be supported T. Returns l where 2^l - 1 = T.
pub fn calculate_l(T: u128) -> Result<u8, PixelError> {
    if (T < 3) || (T == u128::max_value()) {
        return Err(PixelError::InvalidMaxTimePeriod { T });
    }

    if !(T + 1).is_power_of_two() {
        return Err(PixelError::NonPowerOfTwo { T });
    }

    let mut l = 0;
    let mut t = T;
    while t != 0 {
        t = t >> 1;
        l += 1;
    }

    Ok(l)
}

/// Convert path of node to node number (prefix). Path is from root to the node and
/// `l = depth + 1` where `depth` is the depth of the tree.
/*
    // Note: This is different from paper as of 30/6/19. The formula in paper is incorrect.

    If node is left child of parent then this node's number is 1 more than parent's node number
    If node is right child of parent then this node's number is 1 + parent's node number + half of the number of children of the parent.
    A more verbose form of the code would ne
    if node is left_of(parent) {
        node_num(node) = 1 + node_num(parent)
    } else {
        node_num(node) = 1 + node_num(parent) + (2^ (l - depth(node)) - 2) / 2
        node_num(node) = 1 + node_num(parent) + (2^ (l - depth(node) - 1))
    }
*/
pub fn path_to_node_num(path: &[u8], l: u8) -> Result<u128, PixelError> {
    // TODO: Check that path always contains 1 or 2.
    if (path.len() as u8) >= l {
        return Err(PixelError::InvalidPath {
            path: path.to_vec(),
            l,
        });
    }
    let mut t = 1u128;
    for i in 1..(path.len() + 1) {
        // t += 1 + 2^{l-i} * (path[i-1]-1)
        t += 1 + (((1 << (l - i as u8)) as u128 - 1) * (path[i - 1] - 1) as u128) as u128;
    }
    Ok(t)
}

/// Convert node number (prefix) to path of node. Path is from root to the node and
/// `l = depth + 1` where `depth` is the depth of the tree.
pub fn from_node_num_to_path(t: u128, l: u8) -> Result<Vec<u8>, PixelError> {
    if t > ((1 << l) - 1) as u128 {
        return Err(PixelError::InvalidNodeNum { t, l });
    }
    if t == 1 {
        return Ok(vec![]);
    } else {
        let two_l_1 = (1 << (l - 1)) as u128; // 2^{l-1}
        if t <= two_l_1 {
            // If node number falls in left half of tree, put a 1 in path and traverse the left subtree
            let mut path = vec![1];
            path.append(&mut from_node_num_to_path(t - 1, l - 1)?);
            return Ok(path);
        } else {
            // If node number falls in right half of tree, put a 2 in path and traverse the right subtree.
            // The right subtree will have 2^{l-1} nodes less than the original tree since left subtree had 2^{l-1}-1 nodes.
            let mut path = vec![2];
            path.append(&mut from_node_num_to_path(t - two_l_1, l - 1)?);
            return Ok(path);
        }
    }
}

/// Returns path of all successors of the node given by time t. Successors corresponds to the set
/// containing all the right-hand siblings of nodes on the path from t to the root.
/// The siblings are ordered from lowest number to highest.
pub fn node_successor_paths(t: u128, l: u8) -> Result<Vec<Vec<u8>>, PixelError> {
    if t > ((1 << l) - 1) as u128 {
        return Err(PixelError::InvalidNodeNum { t, l });
    }
    if t == 1 {
        return Ok(vec![]);
    } else {
        let mut curr_path = vec![];
        let mut successors = vec![];
        let path = from_node_num_to_path(t, l)?;
        for p in path {
            if p == 1 {
                let mut s = curr_path.clone();
                s.push(2);
                successors.push(s);
            }
            curr_path.push(p)
        }
        successors.reverse();
        return Ok(successors);
    }
}

/// Calculate h_0*h_1^path[0]*h_2^path[2]*......
pub fn calculate_path_factor_using_t_l(
    t: u128,
    l: u8,
    gens: &GeneratorSet,
) -> Result<G1, PixelError> {
    // TODO: Find better name for this function
    let path = from_node_num_to_path(t, l)?;
    calculate_path_factor(path, gens)
}

/// Calculate h_0*h_1^path[0]*h_2^path[2]*......
pub fn calculate_path_factor(path: Vec<u8>, gens: &GeneratorSet) -> Result<G1, PixelError> {
    // TODO: Find better name for this function

    if gens.1.len() < (path.len() + 2) {
        return Err(PixelError::NotEnoughGenerators { n: path.len() + 2 });
    }
    let mut sigma_1_1: G1 = gens.1[1].clone(); // h_0

    // h_0*h_1^path[0]*h_2^path[2]*......
    for (i, p) in path.iter().enumerate() {
        if *p == 1 {
            sigma_1_1 += gens.1[2 + i]
        } else {
            sigma_1_1 += gens.1[2 + i].double()
        }
    }

    Ok(sigma_1_1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::iter::FromIterator;

    #[test]
    fn test_calculate_l() {
        assert!(calculate_l(u128::max_value()).is_err());

        let valid_Ts: HashSet<u128> = HashSet::from_iter(vec![3, 7, 15, 31, 63].iter().cloned());

        assert_eq!(calculate_l(3).unwrap(), 2);
        assert_eq!(calculate_l(7).unwrap(), 3);
        assert_eq!(calculate_l(15).unwrap(), 4);
        assert_eq!(calculate_l(31).unwrap(), 5);

        for i in 1..65 {
            if !valid_Ts.contains(&i) {
                assert!(calculate_l(i).is_err());
            }
        }
    }

    #[test]
    fn test_path_to_node_num() {
        assert!(path_to_node_num(&[1, 2, 1], 3).is_err());
        assert!(path_to_node_num(&[1, 2, 1, 1], 3).is_err());

        assert!(path_to_node_num(&[1, 1, 2, 1], 4).is_err());
        assert!(path_to_node_num(&[2, 1, 2, 1, 1], 4).is_err());

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

    #[test]
    fn test_from_node_num_to_path() {
        assert!(from_node_num_to_path(8, 3).is_err());
        assert!(from_node_num_to_path(9, 3).is_err());
        assert!(from_node_num_to_path(10, 3).is_err());

        assert!(from_node_num_to_path(16, 4).is_err());
        assert!(from_node_num_to_path(17, 4).is_err());
        assert!(from_node_num_to_path(20, 4).is_err());

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

    #[test]
    fn test_node_successors_7() {
        let T = 7;
        let l = calculate_l(T).unwrap();
        let successors = node_successor_paths(1, l).unwrap();
        assert!(successors.is_empty());
        let successors = node_successor_paths(2, l).unwrap();
        assert_eq!(successors, vec![vec![2]]);
        let successors = node_successor_paths(3, l).unwrap();
        assert_eq!(successors, vec![vec![1, 2], vec![2]]);
        let successors = node_successor_paths(4, l).unwrap();
        assert_eq!(successors, vec![vec![2]]);
        let successors = node_successor_paths(5, l).unwrap();
        assert!(successors.is_empty());
        let successors = node_successor_paths(6, l).unwrap();
        assert_eq!(successors, vec![vec![2, 2]]);
        let successors = node_successor_paths(7, l).unwrap();
        assert!(successors.is_empty());
    }

    #[test]
    fn test_node_successors_15() {
        let T = 15;
        let l = calculate_l(T).unwrap();
        let successors = node_successor_paths(1, l).unwrap();
        assert!(successors.is_empty());
        let successors = node_successor_paths(2, l).unwrap();
        assert_eq!(successors, vec![vec![2]]);
        let successors = node_successor_paths(3, l).unwrap();
        assert_eq!(successors, vec![vec![1, 2], vec![2]]);
        let successors = node_successor_paths(4, l).unwrap();
        assert_eq!(successors, vec![vec![1, 1, 2], vec![1, 2], vec![2]]);
        let successors = node_successor_paths(5, l).unwrap();
        assert_eq!(successors, vec![vec![1, 2], vec![2]]);
        let successors = node_successor_paths(6, l).unwrap();
        assert_eq!(successors, vec![vec![2]]);
        let successors = node_successor_paths(7, l).unwrap();
        assert_eq!(successors, vec![vec![1, 2, 2], vec![2]]);
        let successors = node_successor_paths(9, l).unwrap();
        assert!(successors.is_empty());
        let successors = node_successor_paths(10, l).unwrap();
        assert_eq!(successors, vec![vec![2, 2]]);
        let successors = node_successor_paths(11, l).unwrap();
        assert_eq!(successors, vec![vec![2, 1, 2], vec![2, 2]]);
        let successors = node_successor_paths(12, l).unwrap();
        assert_eq!(successors, vec![vec![2, 2]]);
        let successors = node_successor_paths(15, l).unwrap();
        assert!(successors.is_empty());
    }
}
