#![allow(non_snake_case)]

extern crate rand;
#[macro_use]
extern crate amcl_wrapper;

use amcl_wrapper::extension_field_gt::GT;

#[cfg(all(feature = "VerkeyG1", feature = "VerkeyG2"))]
compile_error!("features `VerkeyG1` and `VerkeyG2` are mutually exclusive");

// For feature VerkeyG2, verification key is in G2 and all but one element of signature are in G1
#[cfg(feature = "VerkeyG2")]
pub type SignatureGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "VerkeyG2")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "VerkeyG2")]
pub type VerkeyGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "VerkeyG2")]
pub type VerkeyGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "VerkeyG2")]
pub fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &VerkeyGroup,
    h1: &SignatureGroup,
    h2: &VerkeyGroup,
) -> GT {
    GT::ate_2_pairing(g1, g2, h1, h2)
}
#[cfg(feature = "VerkeyG2")]
pub fn ate_multi_pairing(elems: Vec<(&SignatureGroup, &VerkeyGroup)>) -> GT {
    GT::ate_multi_pairing(elems)
}

// For feature VerkeyG1, verification key is in G1 and all but one element of signature are in G2
#[cfg(feature = "VerkeyG1")]
pub type SignatureGroup = amcl_wrapper::group_elem_g2::G2;
#[cfg(feature = "VerkeyG1")]
pub type SignatureGroupVec = amcl_wrapper::group_elem_g2::G2Vector;
#[cfg(feature = "VerkeyG1")]
pub type VerkeyGroup = amcl_wrapper::group_elem_g1::G1;
#[cfg(feature = "VerkeyG1")]
pub type VerkeyGroupVec = amcl_wrapper::group_elem_g1::G1Vector;
#[cfg(feature = "VerkeyG1")]
pub fn ate_2_pairing(
    g1: &SignatureGroup,
    g2: &VerkeyGroup,
    h1: &SignatureGroup,
    h2: &VerkeyGroup,
) -> GT {
    GT::ate_2_pairing(g2, g1, h2, h1)
}
#[cfg(feature = "VerkeyG1")]
pub fn ate_multi_pairing(elems: Vec<(&SignatureGroup, &VerkeyGroup)>) -> GT {
    GT::ate_multi_pairing(
        elems
            .into_iter()
            .map(|(s, v)| (v, s))
            .collect::<Vec<(&VerkeyGroup, &SignatureGroup)>>(),
    )
}

#[macro_use]
extern crate failure;

extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod errors;
pub mod keys;
pub mod signature;
pub mod util;
pub mod threshold_sig;

// TODO: Add a high level object that orchestrates key update and signing. Like if the signing has to
// be done for t=x and current time in SigkeyManager is y<x, it should update time to t=x.
