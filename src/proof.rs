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

use ark_bn254_ext::{CurveHooks, Fq};
use ark_ff::{AdditiveGroup, PrimeField};
use snafu::Snafu;

use crate::{
    constants::{CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES, ZK_BATCHED_RELATION_PARTIAL_LENGTH},
    errors::GroupError,
    utils::read_u256,
    Fr, G1, PROOF_SIZE, U256, ZK_PROOF_SIZE,
};
use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{BitOr, Shl},
};

#[derive(Debug, PartialEq, Snafu)]
pub enum ZKProofError {
    #[snafu(display(
        "Incorrect buffer size. Expected: {}; Got: {}",
        expected_size,
        actual_size
    ))]
    IncorrectBufferSize {
        expected_size: usize,
        actual_size: usize,
    },
    #[snafu(display(
        "Invalid slice size. Expected: {}; Got: {}",
        expected_length,
        actual_length
    ))]
    InvalidSliceLength {
        expected_length: usize,
        actual_length: usize,
    },

    #[snafu(display("Point for field is not on curve"))]
    PointNotOnCurve,

    // // #[snafu(display("Point is not in the correct subgroup"))]
    // // PointNotInCorrectSubgroup,
    // #[snafu(display("Value is not a member of Fq"))]
    // NotMember,
    #[snafu(display("Other error"))]
    OtherError,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProofType {
    Standard([u8; PROOF_SIZE]),
    ZK([u8; ZK_PROOF_SIZE]),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct G1ProofPoint {
    pub x_0: U256,
    pub x_1: U256,
    pub y_0: U256,
    pub y_1: U256,
}

impl Default for G1ProofPoint {
    fn default() -> Self {
        Self {
            x_0: U256::zero(),
            x_1: U256::zero(),
            y_0: U256::zero(),
            y_1: U256::zero(),
        }
    }
}

impl TryFrom<[u8; 128]> for G1ProofPoint {
    type Error = ();

    fn try_from(data: [u8; 128]) -> Result<Self, Self::Error> {
        let x_0 = read_u256(&data[..32])?;
        let x_1 = read_u256(&data[32..64])?;
        let y_0 = read_u256(&data[64..96])?;
        let y_1 = read_u256(&data[96..])?;

        // IMPORTANT: Note that validation is skipped here but
        // is instead performed when we try to convert to G1.

        Ok(Self { x_0, x_1, y_0, y_1 })
    }
}

fn read_g1_proof_point(data: &[u8], offset: &mut usize) -> Result<G1ProofPoint, ZKProofError> {
    let start: usize = *offset;
    let end: usize = *offset + 128;
    if start >= data.len() {
        // Q: Maybe define a new variant for this case?
        return Err(ZKProofError::InvalidSliceLength {
            expected_length: 128,
            actual_length: 0,
        });
    } else if end > data.len() {
        return Err(ZKProofError::InvalidSliceLength {
            expected_length: 128,
            actual_length: data.len() - start,
        });
    }

    let chunk: [u8; 128] = data[start..end]
        .try_into()
        .expect("Not enough bytes for G1ProofPoint");

    G1ProofPoint::try_from(chunk)
        .map_err(|_| ZKProofError::OtherError)
        .inspect(|_| {
            *offset += 128;
        })
}

fn read_fr(data: &[u8], offset: &mut usize) -> Result<Fr, ZKProofError> {
    let start: usize = *offset;
    let end: usize = *offset + 32;
    if start >= data.len() {
        // Q: Maybe define a new variant for this case?
        return Err(ZKProofError::InvalidSliceLength {
            expected_length: 32,
            actual_length: 0,
        });
    } else if end > data.len() {
        return Err(ZKProofError::InvalidSliceLength {
            expected_length: 32,
            actual_length: data.len() - start,
        });
    }

    let chunk: [u8; 32] = data[start..end]
        .try_into()
        .expect("Not enough bytes for field element");
    // TODO: DOUBLE-CHECK
    Ok(Fr::from_be_bytes_mod_order(&chunk)).inspect(|_| {
        *offset += 32;
    })
}

impl<H: CurveHooks> TryFrom<G1ProofPoint> for G1<H> {
    type Error = GroupError;

    fn try_from(g1_proof_point: G1ProofPoint) -> Result<Self, Self::Error> {
        const N: u32 = 136;
        let x = Fq::from_bigint(g1_proof_point.x_0.bitor(g1_proof_point.x_1.shl(N)))
            .expect("Should always succeed");
        let y = Fq::from_bigint(g1_proof_point.y_0.bitor(g1_proof_point.y_1.shl(N)))
            .expect("Should always succeed");

        let point = Self::new_unchecked(x, y);

        // Validate point
        if !point.is_on_curve() {
            return Err(GroupError::NotOnCurve);
        }
        // The following cannot happen for G1 with the BN254 curve.
        // if !point.is_in_correct_subgroup_assuming_on_curve() {...}

        Ok(point)
    }
}

// impl<H: CurveHooks> TryInto<G1<H>> for G1ProofPoint {
//     type Error = GroupError;

//     fn try_into(self) -> Result<G1<H>, Self::Error> {
//         const N: u32 = 136;
//         let x = Fq::from_bigint(self.x_0.bitor(self.x_1.shl(N))).expect("Should always succeed");
//         let y = Fq::from_bigint(self.y_0.bitor(self.y_1.shl(N))).expect("Should always succeed");

//         let point = G1::<H>::new_unchecked(x, y);

//         // Validate point
//         if !point.is_on_curve() {
//             return Err(GroupError::NotOnCurve);
//         }
//         // This cannot happen for G1 with the BN254 curve.
//         // if !point.is_in_correct_subgroup_assuming_on_curve() {...}

//         Ok(point)
//     }
// }

#[derive(Debug, Eq, PartialEq)]
pub struct ZKProof {
    // Commitments to wire polynomials
    pub w1: G1ProofPoint,
    pub w2: G1ProofPoint,
    pub w3: G1ProofPoint,
    pub w4: G1ProofPoint,
    // Commitments to logup witness polynomials
    pub lookup_read_counts: G1ProofPoint,
    pub lookup_read_tags: G1ProofPoint,
    pub lookup_inverses: G1ProofPoint,
    // Commitment to grand permutation polynomial
    pub z_perm: G1ProofPoint,
    pub libra_commitments: [G1ProofPoint; 3],
    // Sumcheck
    pub libra_sum: Fr,
    pub sumcheck_univariates: [[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    pub libra_evaluation: Fr,
    // ZK
    pub gemini_masking_poly: G1ProofPoint,
    pub gemini_masking_eval: Fr,
    // Shplemini
    pub gemini_fold_comms: [G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1],
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub libra_poly_evals: [Fr; 4],
    pub shplonk_q: G1ProofPoint,
    pub kzg_quotient: G1ProofPoint,
}

impl TryFrom<&[u8; ZK_PROOF_SIZE]> for ZKProof {
    type Error = ZKProofError;

    fn try_from(proof_bytes: &[u8; ZK_PROOF_SIZE]) -> Result<Self, Self::Error> {
        // if proof_bytes.len() != ZK_PROOF_SIZE {
        //     return Err(ZKProofError::IncorrectBufferSize {
        //         expected_size: ZK_PROOF_SIZE,
        //         actual_size: proof_bytes.len(),
        //     });
        // }

        let mut offset = 0;

        // Commitments
        let w1 = read_g1_proof_point(proof_bytes, &mut offset)?;
        let w2 = read_g1_proof_point(proof_bytes, &mut offset)?;
        let w3 = read_g1_proof_point(proof_bytes, &mut offset)?;

        // Lookup / Permutation Helper Commitments
        let lookup_read_counts = read_g1_proof_point(proof_bytes, &mut offset)?;
        let lookup_read_tags = read_g1_proof_point(proof_bytes, &mut offset)?;
        let w4 = read_g1_proof_point(proof_bytes, &mut offset)?;
        let lookup_inverses = read_g1_proof_point(proof_bytes, &mut offset)?;
        let z_perm = read_g1_proof_point(proof_bytes, &mut offset)?;

        let mut libra_commitments = [
            G1ProofPoint::default(),
            G1ProofPoint::default(),
            G1ProofPoint::default(),
        ];
        libra_commitments[0] = read_g1_proof_point(proof_bytes, &mut offset)?;

        let libra_sum = read_fr(proof_bytes, &mut offset)?;

        // Sumcheck univariates
        let mut sumcheck_univariates =
            [[Fr::ZERO; ZK_BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];

        for i in 0..CONST_PROOF_SIZE_LOG_N {
            for j in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
                sumcheck_univariates[i][j] = read_fr(proof_bytes, &mut offset)?;
            }
        }

        // Sumcheck evaluations
        let sumcheck_evaluations = (0..NUMBER_OF_ENTITIES)
            .map(|_| {
                read_fr(proof_bytes, &mut offset)
                    .expect("Should always be able to read field element here")
            })
            .collect::<Vec<Fr>>()
            .try_into()
            .expect("Should always be able to convert to array");

        let libra_evaluation = read_fr(proof_bytes, &mut offset)?;

        libra_commitments[1] = read_g1_proof_point(proof_bytes, &mut offset)?;
        libra_commitments[2] = read_g1_proof_point(proof_bytes, &mut offset)?;

        let gemini_masking_poly = read_g1_proof_point(proof_bytes, &mut offset)?;
        let gemini_masking_eval = read_fr(proof_bytes, &mut offset)?;

        // Gemini
        // Read gemini fold univariates
        let gemini_fold_comms = (0..(CONST_PROOF_SIZE_LOG_N - 1))
            .map(|_| {
                read_g1_proof_point(proof_bytes, &mut offset)
                    .expect("Should always be able to read a G1ProofPoint here")
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("Should always be able to convert to array");
        // let mut gemini_fold_comms: [G1ProofPoint<H>; CONST_PROOF_SIZE_LOG_N - 1];
        // for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        //     gemini_fold_comms[i] = read_g1_proof_point::<H>(proof_bytes, &mut offset)?;
        // }

        // Read gemini a evaluations
        let gemini_a_evaluations = (0..CONST_PROOF_SIZE_LOG_N)
            .map(|_| {
                read_fr(proof_bytes, &mut offset)
                    .expect("Should always be able to read field element here")
            })
            .collect::<Vec<Fr>>()
            .try_into()
            .expect("Should always be able to convert to array");
        // let mut gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N];
        // for i in 0..CONST_PROOF_SIZE_LOG_N {
        //     gemini_a_evaluations[i] = read_fr(proof_bytes, &mut offset)?;
        // }

        // let mut libra_poly_evals: [Fr; 4];
        // for i in 0..4 {
        //     libra_poly_evals[i] = read_fr(proof_bytes, &mut offset)?;
        // }
        let libra_poly_evals: [Fr; 4] = (0..4)
            .map(|_| {
                read_fr(proof_bytes, &mut offset)
                    .expect("Should always be able to read field element here")
            })
            .collect::<Vec<Fr>>()
            .try_into()
            .expect("Should always be able to convert to array");

        // Shplonk
        let shplonk_q = read_g1_proof_point(proof_bytes, &mut offset)?;
        // KZG
        let kzg_quotient = read_g1_proof_point(proof_bytes, &mut offset)?;

        Ok(Self {
            w1,
            w2,
            w3,
            w4,
            lookup_read_counts,
            lookup_read_tags,
            lookup_inverses,
            z_perm,
            libra_commitments,
            libra_sum,
            sumcheck_univariates,
            sumcheck_evaluations,
            libra_evaluation,
            gemini_masking_poly,
            gemini_masking_eval,
            gemini_fold_comms,
            gemini_a_evaluations,
            libra_poly_evals,
            shplonk_q,
            kzg_quotient,
        })
    }
}

// #[cfg(test)]
// mod should {
//     use super::*;
//     use rstest::{fixture, rstest};

//     mod reject {
//         use super::*;
//     }
// }
