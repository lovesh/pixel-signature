#![allow(non_snake_case)]

extern crate rand;
#[macro_use]
extern crate amcl_wrapper;

#[macro_use]
extern crate failure;

extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod errors;
pub mod keys;
pub mod signature;
pub mod util;

// TODO: Add a high level object that orchestrates key update and signing. Like if the signing has to
// be done for t=x and current time in SigkeyManager is y<x, it should update time to t=x.
