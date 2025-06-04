// Copyright 2022 Aztec
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

mod constants;
pub mod errors;
pub mod key;
pub mod proof;
mod srs;
mod types;
mod utils;

use crate::key::VerificationKey;
use ark_bn254_ext::{Config, CurveHooks};
use ark_models_ext::bn::{BnConfig, G1Prepared, G2Prepared};
use errors::VerifyError;

use proof::ProofType;
pub use types::*;

extern crate alloc;
extern crate core;

pub const PROOF_SIZE: usize = constants::PROOF_SIZE;
pub const ZK_PROOF_SIZE: usize = constants::ZK_PROOF_SIZE;
pub const VK_SIZE: usize = 1760;
pub const PUBS_SIZE: usize = 32;

/// A single public input.
pub type PublicInput = [u8; PUBS_SIZE];
pub type Public = [PublicInput];

pub fn verify<H: CurveHooks + Default>(
    vk_bytes: &[u8],
    proof: &ProofType,
    pubs: &Public,
) -> Result<(), VerifyError> {
    let vk = VerificationKey::<H>::try_from(vk_bytes).map_err(|_| VerifyError::KeyError)?;

    // let proof = Proof::<H>::try_from(raw_proof).map_err(|_| VerifyError::InvalidProofError)?;
    // TODO: Update to support both flavors...
    if !matches!(proof, ProofType::ZK(proof_bytes)) {
        return Err(VerifyError::InvalidProofError);
    }

    // Check the received proof is the expected size where each field element is 32 bytes
    // if (proof.len() != PROOF_SIZE * 32) {
    //         revert ProofLengthWrong();
    // }

    // check_public_input_number(&vk, pubs)?;
    // let public_inputs = &pubs
    //     .iter()
    //     .map(|pi_bytes| pi_bytes.into_u256())
    //     .collect::<Vec<U256>>();

    // verify_with_prepared_vk(&prepared_vk, &proof, public_inputs)

    Ok(())
}

#[cfg(test)]
mod should;
