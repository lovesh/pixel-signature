use amcl_wrapper::field_elem::FieldElement;
use crate::setup::GeneratorSet;
use crate::errors::PixelError;
use amcl_wrapper::group_elem_g1::G1;


/// Takes max time period to be supported T. Returns l where 2^l - 1 = T.
pub fn calculate_l(T: u128) -> Result<u8, PixelError> {
    if T >= u128::max_value() {
        return Err(PixelError::MoreThanSupported {T})
    }

    if !(T+1).is_power_of_two() {
        return Err(PixelError::NonPowerOfTwo {T})
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

/// Calculate h_0*h_1^path[0]*h_2^path[2]*......
pub fn calculate_path_factor_using_t_l(t: u128, l:u8,
                                       gens: &GeneratorSet) -> Result<G1, PixelError> {
    // TODO: Find better name for this function
    let path = from_node_num_to_path(t, l)?;
    calculate_path_factor(path, gens)
}

/// Calculate h_0*h_1^path[0]*h_2^path[2]*......
pub fn calculate_path_factor(path: Vec<u8>, gens: &GeneratorSet) -> Result<G1, PixelError> {
    // TODO: Find better name for this function
    let mut sigma_1_1: G1 = gens.1[1].clone();     // h_0

    // TODO: move them to lazy_static
    let f1 = FieldElement::one();               // f1 = 1
    let f2 = FieldElement::from(2u32);       // f2 = 2

    // h_0*h_1^path[0]*h_2^path[2]*......
    for (i, p) in path.iter().enumerate() {
        if *p == 1 {
            sigma_1_1 += &gens.1[2+i] * &f1
        } else {
            sigma_1_1 += &gens.1[2+i] * &f2
        }
    }

    // h_0*h_1^path[0]*h_2^path[2]*......h_l^m
    Ok(sigma_1_1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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

    #[test]
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
}