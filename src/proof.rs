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

extern crate alloc;

use crate::{
    constants::{
        BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N, EVM_WORD_SIZE, LIBRA_COMMITMENTS,
        LIBRA_EVALUATIONS, NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
        ZK_BATCHED_RELATION_PARTIAL_LENGTH,
    },
    errors::GroupError,
    utils::read_u256,
    EVMWord, Fr, G1, PLAIN_PROOF_SIZE, U256, ZK_PROOF_SIZE,
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use ark_bn254_ext::{CurveHooks, Fq};
use ark_ff::{AdditiveGroup, MontFp, PrimeField};
use core::{
    array::from_fn,
    fmt,
    ops::{BitOr, Shl},
};
use snafu::Snafu;

/// Unified enum for handling errors of all flavors.
#[derive(Debug, PartialEq, Snafu)]
pub enum ProofError {
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
    #[snafu(display("Point for proof commitment field '{field:?}' is not on curve"))]
    PointNotOnCurve { field: String },
    // // #[snafu(display("Point is not in the correct subgroup"))]
    // // PointNotInCorrectSubgroup,
    // #[snafu(display("Value is not a member of Fq"))]
    // NotMember,
    #[snafu(display("Other error: {message:?}"))]
    OtherError { message: String },
    #[snafu(display("Shplemini pairing check failed"))]
    ShpleminiPairingCheckFailed,
    #[snafu(display("Consistency check failed. Cause: {message:?}"))]
    ConsistencyCheckFailed { message: &'static str },
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProofType {
    Plain(Box<[u8; PLAIN_PROOF_SIZE]>),
    ZK(Box<[u8; ZK_PROOF_SIZE]>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct G1ProofPoint {
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
        // is instead performed when we try to convert to `G1`.

        Ok(Self { x_0, x_1, y_0, y_1 })
    }
}

// Utility function for parsing `G1ProofPoint` from raw bytes.
fn read_g1_proof_point(data: &mut &[u8]) -> Result<G1ProofPoint, ProofError> {
    const CHUNK_SIZE: usize = 128;
    let chunk: [_; CHUNK_SIZE] = data
        .split_off(..CHUNK_SIZE)
        .ok_or(ProofError::InvalidSliceLength {
            expected_length: CHUNK_SIZE,
            actual_length: data.len(),
        })?
        .try_into()
        .unwrap();

    G1ProofPoint::try_from(chunk).map_err(|_| ProofError::OtherError {
        message: "Failed reading G1 Proof Point".to_string(),
    })
}

// Utility function for parsing `Fr` from raw bytes.
fn read_fr(data: &mut &[u8]) -> Result<Fr, ProofError> {
    const CHUNK_SIZE: usize = 32;
    let chunk = data
        .split_off(..CHUNK_SIZE)
        .ok_or(ProofError::InvalidSliceLength {
            expected_length: CHUNK_SIZE,
            actual_length: data.len(),
        })?;

    Ok(Fr::from_be_bytes_mod_order(chunk))
}

// Utility function for parsing an EVMWord (raw bytes).
fn read_evm_word(data: &mut &[u8]) -> Result<EVMWord, ProofError> {
    const CHUNK_SIZE: usize = EVM_WORD_SIZE;
    let chunk: EVMWord = data
        .split_off(..CHUNK_SIZE)
        .ok_or(ProofError::InvalidSliceLength {
            expected_length: CHUNK_SIZE,
            actual_length: data.len(),
        })?
        .try_into()
        .expect("Conversion should work at this point");

    Ok(chunk)
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum ZKProofCommitmentField {
    SHPLONK_Q,
    GEMINI_MASKING_POLY,
    W_1,
    W_2,
    W_3,
    W_4,
    Z_PERM,
    LOOKUP_INVERSES,
    LOOKUP_READ_COUNTS,
    LOOKUP_READ_TAGS,
    LIBRA_COMMITMENTS(usize),
    GEMINI_FOLD_COMMS(usize),
    KZG_QUOTIENT,
}

impl fmt::Display for ZKProofCommitmentField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZKProofCommitmentField::SHPLONK_Q => write!(f, "SHPLONK_Q"),
            ZKProofCommitmentField::GEMINI_MASKING_POLY => write!(f, "GEMINI_MASKING_POLY"),
            ZKProofCommitmentField::W_1 => write!(f, "W_1"),
            ZKProofCommitmentField::W_2 => write!(f, "W_2"),
            ZKProofCommitmentField::W_3 => write!(f, "W_3"),
            ZKProofCommitmentField::W_4 => write!(f, "W_4"),
            ZKProofCommitmentField::Z_PERM => write!(f, "Z_PERM"),
            ZKProofCommitmentField::LOOKUP_INVERSES => write!(f, "LOOKUP_INVERSES"),
            ZKProofCommitmentField::LOOKUP_READ_COUNTS => write!(f, "LOOKUP_READ_COUNTS"),
            ZKProofCommitmentField::LOOKUP_READ_TAGS => write!(f, "LOOKUP_READ_TAGS"),
            ZKProofCommitmentField::LIBRA_COMMITMENTS(i) => write!(f, "LIBRA_COMMITMENTS_{i}"),
            ZKProofCommitmentField::GEMINI_FOLD_COMMS(i) => write!(f, "GEMINI_FOLD_COMMS_{i}"),
            ZKProofCommitmentField::KZG_QUOTIENT => write!(f, "KZG_QUOTIENT"),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum PlainProofCommitmentField {
    SHPLONK_Q,
    W_1,
    W_2,
    W_3,
    W_4,
    Z_PERM,
    LOOKUP_INVERSES,
    LOOKUP_READ_COUNTS,
    LOOKUP_READ_TAGS,
    GEMINI_FOLD_COMMS(usize),
    KZG_QUOTIENT,
}

impl fmt::Display for PlainProofCommitmentField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlainProofCommitmentField::SHPLONK_Q => write!(f, "SHPLONK_Q"),
            PlainProofCommitmentField::W_1 => write!(f, "W_1"),
            PlainProofCommitmentField::W_2 => write!(f, "W_2"),
            PlainProofCommitmentField::W_3 => write!(f, "W_3"),
            PlainProofCommitmentField::W_4 => write!(f, "W_4"),
            PlainProofCommitmentField::Z_PERM => write!(f, "Z_PERM"),
            PlainProofCommitmentField::LOOKUP_INVERSES => write!(f, "LOOKUP_INVERSES"),
            PlainProofCommitmentField::LOOKUP_READ_COUNTS => write!(f, "LOOKUP_READ_COUNTS"),
            PlainProofCommitmentField::LOOKUP_READ_TAGS => write!(f, "LOOKUP_READ_TAGS"),
            PlainProofCommitmentField::GEMINI_FOLD_COMMS(i) => {
                write!(f, "GEMINI_FOLD_COMMS_{i}")
            }
            PlainProofCommitmentField::KZG_QUOTIENT => write!(f, "KZG_QUOTIENT"),
        }
    }
}

/// Utility function for "reassembling" a `G1ProofPoint` into a `G1`.
pub(crate) fn convert_proof_point<H: CurveHooks>(
    g1_proof_point: G1ProofPoint,
) -> Result<G1<H>, GroupError> {
    const N: u32 = 136;
    let x = Fq::from_bigint(g1_proof_point.x_0.bitor(g1_proof_point.x_1.shl(N)))
        .expect("Should always succeed");
    let y = Fq::from_bigint(g1_proof_point.y_0.bitor(g1_proof_point.y_1.shl(N)))
        .expect("Should always succeed");

    if x == Fq::ZERO && y == Fq::ZERO {
        return Ok(G1::<H>::identity());
    }

    let point = G1::<H>::new_unchecked(x, y);

    if !point.is_on_curve() {
        return Err(GroupError::NotOnCurve);
    }

    // This is always true for G1 with the BN254 curve.
    debug_assert!(point.is_in_correct_subgroup_assuming_on_curve());

    Ok(point)
}

pub(crate) trait CommonProofData {
    // getters
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE];
    fn w1(&self) -> &G1ProofPoint;
    fn w2(&self) -> &G1ProofPoint;
    fn w3(&self) -> &G1ProofPoint;
    fn w4(&self) -> &G1ProofPoint;
    fn lookup_read_counts(&self) -> &G1ProofPoint;
    fn lookup_read_tags(&self) -> &G1ProofPoint;
    fn lookup_inverses(&self) -> &G1ProofPoint;
    fn z_perm(&self) -> &G1ProofPoint;
    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a>;
    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES];
    fn gemini_fold_comms(&self) -> &[G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1];
    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N];
    fn shplonk_q(&self) -> &G1ProofPoint;
    fn kzg_quotient(&self) -> &G1ProofPoint;
}

#[derive(Debug, Eq, PartialEq)]
pub struct ZKProof {
    // Pairing point object
    pub pairing_point_object: [EVMWord; PAIRING_POINTS_SIZE],
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
    pub libra_commitments: [G1ProofPoint; LIBRA_COMMITMENTS],
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
    pub libra_poly_evals: [Fr; LIBRA_EVALUATIONS],
    pub shplonk_q: G1ProofPoint,
    pub kzg_quotient: G1ProofPoint,
}

impl CommonProofData for ZKProof {
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE] {
        &self.pairing_point_object
    }

    fn w1(&self) -> &G1ProofPoint {
        &self.w1
    }

    fn w2(&self) -> &G1ProofPoint {
        &self.w2
    }

    fn w3(&self) -> &G1ProofPoint {
        &self.w3
    }

    fn w4(&self) -> &G1ProofPoint {
        &self.w4
    }

    fn lookup_read_counts(&self) -> &G1ProofPoint {
        &self.lookup_read_counts
    }

    fn lookup_read_tags(&self) -> &G1ProofPoint {
        &self.lookup_read_tags
    }

    fn lookup_inverses(&self) -> &G1ProofPoint {
        &self.lookup_inverses
    }

    fn z_perm(&self) -> &G1ProofPoint {
        &self.z_perm
    }

    fn shplonk_q(&self) -> &G1ProofPoint {
        &self.shplonk_q
    }

    fn kzg_quotient(&self) -> &G1ProofPoint {
        &self.kzg_quotient
    }

    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a> {
        Box::new(self.sumcheck_univariates.iter().map(|row| &row[..]))
    }

    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES] {
        &self.sumcheck_evaluations
    }

    fn gemini_fold_comms(&self) -> &[G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1] {
        &self.gemini_fold_comms
    }

    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.gemini_a_evaluations
    }
}

impl ZKProof {
    pub(crate) fn get_baricentric_lagrange_denominators(&self) -> Box<[Fr]> {
        Box::new([
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000009d80"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
            MontFp!("0x00000000000000000000000000000000000000000000000000000000000005a0"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000240"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
            MontFp!("0x00000000000000000000000000000000000000000000000000000000000005a0"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000009d80"),
        ])
    }

    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        ZK_BATCHED_RELATION_PARTIAL_LENGTH
    }
}

impl TryFrom<&[u8]> for ZKProof {
    type Error = ProofError;

    fn try_from(mut proof_bytes: &[u8]) -> Result<Self, Self::Error> {
        if proof_bytes.len() != ZK_PROOF_SIZE {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: ZK_PROOF_SIZE,
                actual_size: proof_bytes.len(),
            });
        }

        // Pairing Point Object
        let pairing_point_object = from_fn(|_| {
            read_evm_word(&mut proof_bytes).expect("Should always be able to read an EVM word here")
        });

        // Commitments
        let w1 = read_g1_proof_point(&mut proof_bytes)?;
        let w2 = read_g1_proof_point(&mut proof_bytes)?;
        let w3 = read_g1_proof_point(&mut proof_bytes)?;

        // Lookup / Permutation Helper Commitments
        let lookup_read_counts = read_g1_proof_point(&mut proof_bytes)?;
        let lookup_read_tags = read_g1_proof_point(&mut proof_bytes)?;
        let w4 = read_g1_proof_point(&mut proof_bytes)?;
        let lookup_inverses = read_g1_proof_point(&mut proof_bytes)?;
        let z_perm = read_g1_proof_point(&mut proof_bytes)?;

        let mut libra_commitments = [G1ProofPoint::default(); LIBRA_COMMITMENTS];

        libra_commitments[0] = read_g1_proof_point(&mut proof_bytes)?;

        let libra_sum = read_fr(&mut proof_bytes)?;

        // Sumcheck univariates
        let mut sumcheck_univariates =
            [[Fr::ZERO; ZK_BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];

        for sumcheck_univariate in sumcheck_univariates.iter_mut() {
            for su in sumcheck_univariate.iter_mut() {
                *su = read_fr(&mut proof_bytes)?;
            }
        }

        // Sumcheck evaluations
        let sumcheck_evaluations = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        let libra_evaluation = read_fr(&mut proof_bytes)?;

        libra_commitments[1] = read_g1_proof_point(&mut proof_bytes)?;
        libra_commitments[2] = read_g1_proof_point(&mut proof_bytes)?;

        let gemini_masking_poly = read_g1_proof_point(&mut proof_bytes)?;

        let gemini_masking_eval = read_fr(&mut proof_bytes)?;

        // Gemini
        // Read gemini fold univariates
        let gemini_fold_comms = from_fn(|_| {
            read_g1_proof_point(&mut proof_bytes)
                .expect("Should always be able to read a G1ProofPoint here")
        });

        // Read gemini a evaluations
        let gemini_a_evaluations = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        let libra_poly_evals = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        // Shplonk
        let shplonk_q = read_g1_proof_point(&mut proof_bytes)?;
        // KZG
        let kzg_quotient = read_g1_proof_point(&mut proof_bytes)?;

        Ok(Self {
            pairing_point_object,
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

#[derive(Debug, Eq, PartialEq)]
pub struct PlainProof {
    // Pairing point object
    pub pairing_point_object: [EVMWord; PAIRING_POINTS_SIZE],
    // Commitments to wire polynomials
    pub w1: G1ProofPoint,
    pub w2: G1ProofPoint,
    pub w3: G1ProofPoint,
    pub w4: G1ProofPoint,
    // Commitments to logup witness polynomials
    pub lookup_read_counts: G1ProofPoint,
    pub lookup_read_tags: G1ProofPoint,
    pub lookup_inverses: G1ProofPoint,
    // Lookup helpers - Permutations
    pub z_perm: G1ProofPoint,
    // Sumcheck
    pub sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    // Shplemini
    pub gemini_fold_comms: [G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1],
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub shplonk_q: G1ProofPoint,
    pub kzg_quotient: G1ProofPoint,
}

impl CommonProofData for PlainProof {
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE] {
        &self.pairing_point_object
    }

    fn w1(&self) -> &G1ProofPoint {
        &self.w1
    }

    fn w2(&self) -> &G1ProofPoint {
        &self.w2
    }

    fn w3(&self) -> &G1ProofPoint {
        &self.w3
    }

    fn w4(&self) -> &G1ProofPoint {
        &self.w4
    }

    fn lookup_read_counts(&self) -> &G1ProofPoint {
        &self.lookup_read_counts
    }

    fn lookup_read_tags(&self) -> &G1ProofPoint {
        &self.lookup_read_tags
    }

    fn lookup_inverses(&self) -> &G1ProofPoint {
        &self.lookup_inverses
    }

    fn z_perm(&self) -> &G1ProofPoint {
        &self.z_perm
    }

    fn shplonk_q(&self) -> &G1ProofPoint {
        &self.shplonk_q
    }

    fn kzg_quotient(&self) -> &G1ProofPoint {
        &self.kzg_quotient
    }

    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a> {
        Box::new(self.sumcheck_univariates.iter().map(|row| &row[..]))
    }

    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES] {
        &self.sumcheck_evaluations
    }

    fn gemini_fold_comms(&self) -> &[G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1] {
        &self.gemini_fold_comms
    }

    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.gemini_a_evaluations
    }
}

impl PlainProof {
    pub(crate) fn get_baricentric_lagrange_denominators(&self) -> Box<[Fr]> {
        Box::new([
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
            MontFp!("0x00000000000000000000000000000000000000000000000000000000000002d0"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11"),
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000090"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71"),
            MontFp!("0x00000000000000000000000000000000000000000000000000000000000000f0"),
            MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
            MontFp!("0x00000000000000000000000000000000000000000000000000000000000013b0"),
        ])
    }

    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        BATCHED_RELATION_PARTIAL_LENGTH
    }
}

impl TryFrom<&[u8]> for PlainProof {
    type Error = ProofError;

    fn try_from(mut proof_bytes: &[u8]) -> Result<Self, Self::Error> {
        if proof_bytes.len() != PLAIN_PROOF_SIZE {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: PLAIN_PROOF_SIZE,
                actual_size: proof_bytes.len(),
            });
        }

        // Pairing Point Object
        let pairing_point_object = from_fn(|_| {
            read_evm_word(&mut proof_bytes).expect("Should always be able to read an EVM word here")
        });

        // Commitments
        let w1 = read_g1_proof_point(&mut proof_bytes)?;
        let w2 = read_g1_proof_point(&mut proof_bytes)?;
        let w3 = read_g1_proof_point(&mut proof_bytes)?;

        // Lookup / Permutation Helper Commitments
        let lookup_read_counts = read_g1_proof_point(&mut proof_bytes)?;
        let lookup_read_tags = read_g1_proof_point(&mut proof_bytes)?;
        let w4 = read_g1_proof_point(&mut proof_bytes)?;
        let lookup_inverses = read_g1_proof_point(&mut proof_bytes)?;
        let z_perm = read_g1_proof_point(&mut proof_bytes)?;

        // Sumcheck univariates
        let mut sumcheck_univariates =
            [[Fr::ZERO; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];

        for sumcheck_univariate in sumcheck_univariates.iter_mut() {
            for su in sumcheck_univariate.iter_mut() {
                *su = read_fr(&mut proof_bytes)?;
            }
        }

        // Sumcheck evaluations
        let sumcheck_evaluations = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        // Gemini
        // Read gemini fold univariates
        let gemini_fold_comms = from_fn(|_| {
            read_g1_proof_point(&mut proof_bytes)
                .expect("Should always be able to read a G1ProofPoint here")
        });

        // Read gemini a evaluations
        let gemini_a_evaluations = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        // Shplonk
        let shplonk_q = read_g1_proof_point(&mut proof_bytes)?;

        // KZG
        let kzg_quotient = read_g1_proof_point(&mut proof_bytes)?;

        Ok(Self {
            pairing_point_object,
            w1,
            w2,
            w3,
            w4,
            lookup_read_counts,
            lookup_read_tags,
            lookup_inverses,
            z_perm,
            sumcheck_univariates,
            sumcheck_evaluations,
            gemini_fold_comms,
            gemini_a_evaluations,
            shplonk_q,
            kzg_quotient,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ParsedProof {
    Plain(Box<PlainProof>),
    ZK(Box<ZKProof>),
}

impl ParsedProof {
    pub(crate) fn get_baricentric_lagrange_denominators(&self) -> Box<[Fr]> {
        match self {
            ParsedProof::ZK(zkp) => zkp.get_baricentric_lagrange_denominators(),
            ParsedProof::Plain(p) => p.get_baricentric_lagrange_denominators(),
        }
    }

    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        match self {
            ParsedProof::ZK(zkp) => zkp.get_batched_relation_partial_length(),
            ParsedProof::Plain(p) => p.get_batched_relation_partial_length(),
        }
    }
}

impl CommonProofData for ParsedProof {
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE] {
        match self {
            Self::ZK(p) => p.pairing_point_object(),
            Self::Plain(p) => p.pairing_point_object(),
        }
    }

    fn w1(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.w1(),
            Self::Plain(p) => p.w1(),
        }
    }

    fn w2(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.w2(),
            Self::Plain(p) => p.w2(),
        }
    }

    fn w3(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.w3(),
            Self::Plain(p) => p.w3(),
        }
    }

    fn w4(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.w4(),
            Self::Plain(p) => p.w4(),
        }
    }

    fn lookup_read_counts(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.lookup_read_counts(),
            Self::Plain(p) => p.lookup_read_counts(),
        }
    }

    fn lookup_read_tags(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.lookup_read_tags(),
            Self::Plain(p) => p.lookup_read_tags(),
        }
    }

    fn lookup_inverses(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.lookup_inverses(),
            Self::Plain(p) => p.lookup_inverses(),
        }
    }

    fn z_perm(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.z_perm(),
            Self::Plain(p) => p.z_perm(),
        }
    }

    fn shplonk_q(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.shplonk_q(),
            Self::Plain(p) => p.shplonk_q(),
        }
    }

    fn kzg_quotient(&self) -> &G1ProofPoint {
        match self {
            Self::ZK(p) => p.kzg_quotient(),
            Self::Plain(p) => p.kzg_quotient(),
        }
    }

    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a> {
        match self {
            Self::ZK(p) => p.sumcheck_univariates(),
            Self::Plain(p) => p.sumcheck_univariates(),
        }
    }

    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES] {
        match self {
            Self::ZK(p) => p.sumcheck_evaluations(),
            Self::Plain(p) => p.sumcheck_evaluations(),
        }
    }

    fn gemini_fold_comms(&self) -> &[G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1] {
        match self {
            Self::ZK(p) => p.gemini_fold_comms(),
            Self::Plain(p) => p.gemini_fold_comms(),
        }
    }

    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        match self {
            Self::ZK(p) => p.gemini_a_evaluations(),
            Self::Plain(p) => p.gemini_a_evaluations(),
        }
    }
}

#[cfg(test)]
mod should {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_zk_proof() -> [u8; ZK_PROOF_SIZE] {
        hex_literal::hex!("0000000000000000000000000000000000000000000000042ab5d6d1986846cf00000000000000000000000000000000000000000000000b75c020998797da780000000000000000000000000000000000000000000000005a107acb64952eca000000000000000000000000000000000000000000000000000031e97a575e9d00000000000000000000000000000000000000000000000b5666547acf8bd5a400000000000000000000000000000000000000000000000c410db10a01750aeb00000000000000000000000000000000000000000000000d722669117f9758a4000000000000000000000000000000000000000000000000000178cbf4206471000000000000000000000000000000000000000000000000e91b8a11e7842c38000000000000000000000000000000000000000000000007fd51009034b3357f000000000000000000000000000000000000000000000009889939f81e9c74020000000000000000000000000000000000000000000000000000f94656a2ca48000000000000000000000000000000000000000000000006fb128b46c1ddb67f0000000000000000000000000000000000000000000000093fe27776f50224bd000000000000000000000000000000000000000000000004a0c80c0da527a0810000000000000000000000000000000000000000000000000001b52c2020d74600000000000000000000000000000022a3e3f9d9f4578802110dc14ad1448296000000000000000000000000000000000024b8d1d30f054f6e9414b35e661a6000000000000000000000000000000039bdf1631dcc9690c23dbde1300fb0a3c600000000000000000000000000000000000b262bf72a88173042c484ca9c47ac0000000000000000000000000000009e11a437a391b7b5e0f161e88ea64ea1cd00000000000000000000000000000000000c85d46e8c477f32edbddb7e66578200000000000000000000000000000026da0a1ebbb927a51fe939c3a6929b17df00000000000000000000000000000000002caf8b95fef178a04249835fe8e000000000000000000000000000000000d5aee6b90b56ebe4cc957636d26fb11cde0000000000000000000000000000000000035fbd13e477c6d5d22daf4cc357e8000000000000000000000000000000832520e1ae67b30105692f473e5e0b5768000000000000000000000000000000000023cf270b8438a07fc2c3168ded7077000000000000000000000000000000db3619a26bd70352828e4c10025bf74ae10000000000000000000000000000000000148c14f54222fc09258bd606fe23c8000000000000000000000000000000f804719e3f31851a710234501121b363c100000000000000000000000000000000002d89c70bc3fe059170e11131dbb987000000000000000000000000000000dc517ebcf703b773e3c83f24891eca85ac00000000000000000000000000000000000d999dea3e18a842399eb1073ce6f10000000000000000000000000000005a22affdf5ba8c96eed1dced89552ad9fe00000000000000000000000000000000001c14fe30349108f79a755fa1d8a5fd000000000000000000000000000000a0e53741cb49407d5f140a883944524d3700000000000000000000000000000000001fc171791a2dd628a1d23af70fb444000000000000000000000000000000b655050f9059d2f6357f8d9ff252c4fdca0000000000000000000000000000000000155450289caf82a6f1d698ac4efb38000000000000000000000000000000589f3a15ca292bcee79d8c7b5263ffb0b0000000000000000000000000000000000002afdf51b1a56f44f0f536a1fd230f000000000000000000000000000000d050c9664103b630334f5760988f5fe93a00000000000000000000000000000000001cc61ce56aa787d2f5932d0d82cf8d00000000000000000000000000000011231af4fb4b201814bd2057d8afb21ca2000000000000000000000000000000000008f0214c9845f3d0506499e61e2a2e000000000000000000000000000000651d06b64da4f0e9fff05cf66386b5de8c0000000000000000000000000000000000295c3fa9e91ace5f8453b2c39c9247000000000000000000000000000000b3fc83ce10298d8995ea09f6c60d2b385700000000000000000000000000000000002e0c525516245732a4894716b98354000000000000000000000000000000ba62a4233986f3db036e82d308b4c1dc020000000000000000000000000000000000291ef1b3206767dd718045827cb804112a68eb76e2bd150743604664a5e53f33b19a1cddf0e486898501344a4804031ab4b32ef25fdac6d67add419d01516f5461af4a8cb570d27acb9f107fc6716e125964327ec65663efc3beb12760b2a0b3568206fe877728c3ba8fc4cfed16c520155c008bef8af00c37e823d982234208e22fca20f860b188675d55dc1b494c0511f4a14bbfaa8a41416b78939ca47cf6c2a44719186754636ad8d74adc49c22a57aa494654d26c7523cd5c99758f2f0a82b908809056720ecf2d46cf6a44490bd6e51f482a1a01cec299d9eb1ec0f29565aecf37df4388d5795580e4a925580e0c851942f41f7204e15f5d27421306d731cfffb6b7a1c8a39b7e54c12c70e30f2a974dd9fa8d649b0f24677e162356342508fac31fc2cd850bae6a935c0d042e64779d5ffb1c3c796e3f18c3481b8a316b78659f191bf522374005978034082420828ea8c38c05bbe97fd1aac5e6ae55ed2ef19910c836b2251a568e28572822542eea57fb2e02aa6c464510baf403f7a6ee4384ceea00e2e91e38bdcb2eaf149dab6602c4e88e8f283d312602edcc8883b58af595f30ab635c120b5fc61c2280176965200f3b4c0ef8a731b9c332870b418785a810beada5161e373db23c416ac5d4adf90101be0df63a503f730a416ae09c99c7f4f91c98536e4ac4bc4f3192353ef87ab78f08a2b49272c393355a9ea03ac9e9b3e3cd7a0ff47300f7b840d39996eb3d96c06ba6af91924908913bb1c0ff8b3fad7b26d4a9ecd5bc768230436164c933b0a2405b52d1ee1d4d9bd866e7f68c286b15aeba2a389a73b95380c2fc7ef58d8fcc2f1575d1926c60601ac9ea8d5f4d9037405cd396a7f3c67d62b66e5371edafe0a025b4dc43cff858f987408189a86dc52e84018d4d2cb0b222ac2cf57a8f2f21369857926ceb680aa45972bb8a33f93a32c7a6223bb9fa791220f0f969353b75d43f9b03ba70b0a4a66c3cc336a0c3e3e3a17e9a8397922201b3b856cee33b6a9dd8b030ee1e45a85dba8fb55a6c4b3ebc3e72df9f6c7aae60915e6db9366928fb0604cae1806490db9ab68a41650f67b047b1f6e20135fc11976f2e3865a3c33bfb6b76bdc809eb64043229817d77388c49f9ec5e2573b8719858cdbe8fd65014af2a521298cfe9e5d1a8a94a172fdf8791f095f7a3e0d110f6c87ce8b0c5e38d84bdf30c4e1e490a0ec1379ed118a5ae8ab69b7e883f10727d8a7ea0d98e2f8d461164b83f21c988a1ed9c229d83fb91694534ee8d6c8a80be9f0f4befee2bfdc1f2e272069a6a29c6a56d77859b3a439f8fc46ad8260510be607434adbd22ee5ab98eda8b3df84938dacaad0f42aca2cf694cc9aa82e7c1761972c89d2afc6544312e0d2767d5e1b561e6572bb31e0a104592dd419b54b2053ab1e57ac40e6159fed1c1bd5892b6a59364ff3be9174e209744ae1f0c7e30da580e5ee1b77383b54810889ce7641d7b24d98426153eb41fd3c4054c2932e17976324a76ceb65073fa50f3475ad727294cf2711540d42ac87ae1d97d864362197ea0b48991d2702d07c96efde65a1f9bce47f83db18c26015fe6a485392a0072625f86d4a8d6bb2ff5674f15f2ac9caa9fabf14f0f039c6f2667d59cde93f0f1e28442d4c997c622e17eb24dbf92e95ed6703b34ae11470cde2fceb69837402b4ba5f68d19ad3d286975508573509fd19e51511db7a86cc3821d4796a624522e5340c42a3780be7b3b26eeb993e9fa762eeef06b30a8068ac5b6038fd8b9b13c6587ad36104e5b8b94dbecaa4eec7612ae6ec5c3f694bd823d6b6478c732b049acd64e0b941e1a11231fac8c58cb487ead0ac2c75c14e1afa33a8122fefac20fd1ad64ce87eca389d0afa558329cd4e019bb88b126129dcd970e9e88b3370271f600d04dc2232e44cf67b772d2d4f531cbcfdcd5507f716820e6b5a1529890cc620cfc2f80ec29791c8d8fc2b632da542bc929275009fa20448b15aaf5cd2305eb42bd5c7160b9219a4824e25367a323aa37b30568594c048a95ac1b101050b55eac1053da61ddb183d983a093d77c916376fffb3ea2fefb2dd00a5d6e712271a98bda8728c61b117c325459e89adf94a26e646b368ea08f6175ed76fc06d02dda470e4993c3e2e27f187d718c938d7b45302597dbdea5a53c85edbdbf9fa06d9d2d6376086df3344881aa61eda2ce99a31556a2df46927882d62cc5ee7442d355ae972d90398e33531eceeb31bf79f5178153b5be33b3adb9b756432973a1cc0b391297b7d1c97c7240e8da181acd741752cfe37a0fd37df42aaa853e8ad1a16fca4bb2ac17bd3d1f8b0461c57f1fe4598754fe9c7d8b1a90a7a480370eb1e6aa1e9f5d93f687d30307d1b0d17e8a68c5f8926d5098c800bacce42fd7c3b2cf24c9b5d8250a7ae115e8776ecbdc4da30311606719123a9829af374aced972a413380c81779ea2d9931f0df7124de8f8a9b162e0f3ec8f50e2b23d42188911b134e8e933cfdf496797e96de630dec495e707ebdc7d1dfc7eb96ede0557cb123182685a114ceee437c95c6a687eb1457bf0ab5bd9e62aeaaa235f8c6c643360054dc812162037d765be3f07ad1692f48cb62a86fa3ed2059f39821e80341c719f7d0285f381337e68001ba976f1190f968ac48ccb827feb6a990a2ddad33cb258bef76487a454845edc9a76ab973ec4c0a82771b327b8e9931811ab86be7351b07d743990f686c10afaa9cf0a0317fc8d52919bed03f9fffe238066293eb0f0a41587ccd2f2a34cffc0a694fc81932cc26e03fb3045b4f72b74e24f29a4693273e281db6ebf3f726b792f9955e9252722e26261db8851a5d9a5d2339e90f732dbb325b5015c41ddebd76d21a3237bdb360380e95beeafa578a25c6eb1fe5562cb188d003623ef7905c9c572fed0b5914e76394e6df332e1e2114041a5e54a215fb1613c3a2eb694b867cb998c90a24746a333c95f8ba99371c9eb570534f632b3878b570fe2149acaa8f5703bfc860daebc3e788021cd808e47a1aac4e848211d8646a90e3946dd47f07ac2468c5e3805b362ee336d6da5f9c2ccd6e29ff6c129269c9b546efbf2d30b46ae807c90dc33ce9b972d39514a94545886ed34f22065492dd5e5f2417b7d99e932ee6dabac64db6e1070c9ed2ef34917097366a4c228de877eab242c6e44b8f2af51df40b056aaf9add3888edacf6f9af36d0bb2d0b6b7f97e99c182c388be37082d9069eee951e3aead007979adeb7f2c758d2b2102c22e20f981c257b06277e910ccdd6287ee188dd23db598386c4c9848bd20f0c251f90d43b4ae8e155987b7b3f7a9fe95efa04bcc835b139eee40a0886a55411cde35d69c686e41bd3d770fb667f407a83c00a88b7af1e18278c0c863419af0a6f92d28c300dc88562738c7e667c759167bf1d53326861970fb46c75dbd702088ba8ee63c6a6c324781a2fffa452811c42055ca21dfdee7de77d743188fadc0b5e589ec281af0eb0774c5cc8f64b92dfb7ad784597621e7131f051787c40772e6e8a25b2215aabd3999c5700b66262a2591264e8d379cf6a16da04522e0d7418d5d7601403d73663e19b99dfac1009560602cb342bc82259421fae2db0468b2690d6336bc1b69471929428729f38ef91abf96daa3699962633f80a6dde879516fed5f6df5ab4065abdb6f09277efc410bec6ae690fa10acd697f17667ef12016db2926f713334ffda7a38bc7e49e0f61fc902376ca6ddd6b6f99d855e956ff300f06cb39664a58b2cb51a41fd7b1f2840c6eb48342ddea35bd8786ae55665e2dd043a463f2db2e31f3cfe18031db8f7f82274f3449cba48f727aeb365c949c26c576d84c2d7c98b06b671d8b267cf80d3a645583d64138043e1c5fe3adbbd614b6cbff4269e68cc330bcecb13ca11b927b406133325ed95d9ba7bfb7978a5d2b1699eef8f488a6406587b047d663245111b12e9fd2767777b4a35eac492c4d0a1016639e19c8c584c3c687e3e991fb3c446ff779026f703383654fe578266e043c6bc0fce9e50fcadfbaa1f461beaf26c84a919e22375b7ea44d7cc6f4c39019734f3ac6df2bddb704ea3e90757ef3d17d3c61d394bb317eadb5706b296c5e22fb74dad5000ad7da3c3a92bca8e496d69e02f38fb0af9d4026476b176054fb15620c892fb1fdef8b06890effde37d6abe2d416e4d2dc188707a69146e2c5ec195a491c8a488eb012be8ee0b62859380e19085666e300120b2a06a3f3bc066427cc249e92ff98378e2a14208b220022801c128dd1043c50b2ab955c20dbc1a80bf47eb63f581cb9b6602397f2df50fead721247a1c1288a74542407f271c0e829740b3dbf235bcb12ae4a2afa5b25c91e9de2814ffab6c8c3b94887f96b805d2778c2010f84f3d26660a95d6fcedcc6d5bd6daf6b586b2ef62e98d700ff875f14ee3990eb242792f81a3c9986d3685abcea9cca77c6285fa4c980f5abe8754d03a105a76371644aa58e9000e9d085cbdbf9b1ca4e7790b942ceda449f1c99f228175c26e4e2268f29d793ef4a87efab32ae95b11e06e006af3f1166624bafc5062490e955ad7d570573a64be0f31a01b65fe4ed6d6bad8919d78dd41c6e01dd23117adcf0473dd4d34052b6be31bd48d3532256e3546f075958dbd2d9a8ec602c543b44c5abe7c8dfb1207d98e05d3cd46666715979380bef74fb49b6337194279e5ab18beffdc6ffd43d0c5b3b27ad8113c121b8b5f733682361811460f5a11089eb49eb43719362a0c8c43270cbad1a1c8ea61b6751882b8a696f8959cccb0111ce09571c7bc1d4ce430962377acf509385e93374ffdd525014f02a80fb381889168ffce6bc98e129dd76dee7c351015fe14da2af13627f1cedb10c83b4cb0cbaf2be770a15d2228846d9d20870e9ac8c8f9e214eaa3c695cd4d098671715000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000252b6da2d9825828e979e4d027390e13149ad23fb4c2d33aed20b7299c97933c00fe8b1aead774127f971391eee0cdea6fff8ec309295acb81da5db179b28c9c256547dfbc51c989f27e0ef1c00739505f095da9fbb9695d8bea997dd7b8c0ac179b97e602e2ea27f6204922e8435f3032b466bba960f8ecf7df2fcfce12e26507615a0116239bf37fe340b5eaa76a47480060ecbfc4c8bf463db83560473bcb1fa3a8d25adbf1391d39e729b93a0cc5ae79a2e6aa29668943b7c12c85fcf6f004fc2c4bc10e3e4bbdf47169d23b13540839f7bf52e437d41c332f7c3c20d95219fa446b7b8aba49b3e624b93a00cd8e15bbb212d3c33efdca2a733dc527819b2b460ac82a53e5a2222a371bf74399a9f5f6f7ca3121e5cdf25dd66a2cb064ec25822bd45a8e5b5eadd4851fa0915c6f9399140f150549827040e043b37d3176140c6a9391acd8e4c12cd4c1689a8adbd8b8178e316d220857019a8d06e968de29557aa58bde65e296df820d22da1ea5c8308f4d551ac691bd458124f0798b7b1005a4b51633fc8a2be4560fa68ad34cb73e9d7b7d0c653ce7d8b0422be01fe40cd4155f22cd3ee344e53282ce9b1884c94c84352ce6b9fcdc163b930c3580091f387feb7001d6ccf032913f34d7ac613adadf49421f2fc7969b8814c43cd05826ddaebaa1c1acf107ebfb29d7b5bc946a33ee87de56ed33112da48edcc860ec0348e0cc6afe01bb739971f2f6a4784d298113ab992bae0ad63e7c7f31e632c41d71924e436e985ac85f747f6b227d28d3586937c14e42eef3a40b62c26aabc7159a2e07498b5574fa40675c33354d090cfbaf74f139e81819137b179b4bc8082d9ca459767ac38cee7e35b76db4804802317f56cd1a7a443c35feba30ebdcbc047f3840de1fbb5536babaf6b5d7017b987596f9f9b1ff30f55ce55b0d9086df1cc6b31e99c2fb14360976fe97221548b99377675a1577ddb72c68cd5cc59098148b3058314f7eaf5acd74fb37f3f2a0396f740bd89d69527fa1e115d946aed22945925066b2bfa85b9fd57e5fcc7325572793543468966592625c994ca8d22d20e358b47664ec192448f7ed4b4613fcb17c9b3749c2676234eb7dca351dbeae22d6e2f19adae66bcae7c686591cab54ba2bcfea806a51f22f4a162083f56f9706764f4d9f31f39ed4d66ce1caf1180b3bd74f8f2a7c0177e904dfd4316fbee70cd1ac2b1be6d9570f301d4c90d2d043e23161d607c9c63a44d9a49650be0519031b07649893ffb96f7be2507d9339665fd8ed5eff3b71293b5ac44af6665c0f0336b77cb1bd3e591d7293510b218957a42f9b4e0e1d36ce2d5d1f13e25a88a21667f16fc13b1f1616a0b72d75f8b4f49c094315f8e27c863a0b2ef14c30034c018f8086407b31fb528362ceb89ae991cd27128f6dd099ed4776ff97d88c187f09d6b3d6ae3341e8464fb6f445a3b1a2ea810b5f3c40738e79d69cda5c4e4b1202dbecad21b2f3b4f215d83c2896f46cf83391ead880bb11c84604bd2ffb9ffe1b585ecfc49b05f4c9cb6e29c999b1db3d07a46f203aa041b62839f68841880b2d6ee2b25b2d3a1fe44635ac9807064735adf89d0f994d59446bf81f44dc78431dfd4b69e09e641510ea4ddee3fa1b6194a25d04593df20d5d8e91ef5ab756522f57b1932f873053fccdc6dcd806694c1fb0e75432dbe33099ec39b7da7606690e343906b918a0ade402d3ebcc337557124ef41def476a54c5928ce15961408d2f5033cf431142cad404ae56a86cef14a157503f57e652a4b8c4c564cf22eadc14a8e29dcb6db33eda779cf5baf2fb1495198a1b6bdd01fce7b50d29a5a9d987000000000000000000000000000000cc3f9432f153f72eeb8e2884724a1d38b4000000000000000000000000000000000026cbbe8b721e03feac6cb43e61350e0000000000000000000000000000000f16dfb0a30005a7e21ea2c1d7209c22b90000000000000000000000000000000000118846e1d0b43150f3d0f8803c3fd60000000000000000000000000000005bef13a3102fc6d0529307ab1349d581fc00000000000000000000000000000000000cf0d4f71be52ab268cb2e7a2b01cb000000000000000000000000000000f4026508c714e287f9f303b8f4f0ffbc8700000000000000000000000000000000001c0d61ea6a1853dbfc51b6dc1539e70000000000000000000000000000004b94657b26efb13cb4825dc9d03b1ef250000000000000000000000000000000000002ad9b282eaaa06f6225139dfd4022000000000000000000000000000000c4ccb15cc57e546283eed71600bdc0f5a2000000000000000000000000000000000024919983a8080c3d74b358be232cb11b8c7ddbb050734f5c351460671b640ce5209d6ec67075c79eaa3928e7aa71d6000000000000000000000000000000a64b2dc43b19aaaf7f5934201069e733550000000000000000000000000000000000022f72275b5a079763ea6be056b4220000000000000000000000000000008a71698cbc4644f8709b064f9936dde63700000000000000000000000000000000000541bac5abde082c43d3947e97df780000000000000000000000000000005b541955f155a1a2b351c86b07b623636800000000000000000000000000000000000007e73d9a46e7726d3e82ce25f709000000000000000000000000000000aa65958cdc950a1f8127dce76fd8c6fad300000000000000000000000000000000001ab776b218bf0f6a653ad071edb94400000000000000000000000000000075f6322dd4577c99f31078a9f8c191cbc800000000000000000000000000000000001f3c17b504fbf01c93c5063cc3ec21000000000000000000000000000000a58a6e73b9642a59731f9325bd0bbb58dd000000000000000000000000000000000029e20eebafc8a9c39be77990e64c760000000000000000000000000000000a98b53bd29e01fbc45334b9dd55416306000000000000000000000000000000000026e8cd6dfa9032d4fc3733cc61437f000000000000000000000000000000b8a0d7bdd979901cdd6eb17911f00c66400000000000000000000000000000000000151f3b6e744ddcafb528ad1b3f989d000000000000000000000000000000ac9125f69a3f30e21575f719dce86517360000000000000000000000000000000000158d5f1564476e1a6b4dfea31a7231000000000000000000000000000000e3b6cd07be69c003fd96ce3c7d95378ee400000000000000000000000000000000001ae07068350de64430ae095049283800000000000000000000000000000054ce6ac72b7a95cbca6a4fecb5a05f4153000000000000000000000000000000000002ef730adb2e06e8ee9015f29f3d590000000000000000000000000000007566820b04945460f8490a229a9fa3028200000000000000000000000000000000000730ae8674c7eb0fe05a351a5f52d60000000000000000000000000000007ad002d6be17fa5b4cd1ac158aaad82e33000000000000000000000000000000000027bfb15f22ae35f635969eaa041dbe0000000000000000000000000000004c72c23fae10d70a88b95024e1ff4c6c6700000000000000000000000000000000002fd7f8033b36e66cfe8518d3f16fd80000000000000000000000000000004fae2c2cf7349f0560ef8384464fab382300000000000000000000000000000000001277b42530edc0505dd8bdd48d163e000000000000000000000000000000208ccaf152b87fda4a28625c9be6d35c1f0000000000000000000000000000000000228f6390b9f767c2abaa25f3ffb47700000000000000000000000000000001dfa210bf75a1838ad7ab69eb670c5c5c00000000000000000000000000000000001341527cfd8c746a4d6de794fc0f400000000000000000000000000000009abd2884d2c6f4cbb2bcbd04a3c9e6df6c0000000000000000000000000000000000149cd35d397d9eb9e335d96c99d9e4000000000000000000000000000000adf1c0b3c902e10aac74f489a749dc78ea00000000000000000000000000000000000aa295435a0d6112ecd87b8a62a01600000000000000000000000000000012889dccbee6ac3b7dba97bdaa2730cf86000000000000000000000000000000000013ca6282e1189e47590d43faff739a00000000000000000000000000000099f6a525095b2ec62ca30f680379395f1e00000000000000000000000000000000002a1dbef49181a657670f4f0bd7c78a000000000000000000000000000000effbbcffb18f0cd4fc06f7a105cc57dcf800000000000000000000000000000000002dad27c0ae641aa6bd0a3a8bcceed8000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000014604aaebb109902092ae3f8db6b73dd20e7908241c5f0b5705a8aef06823b4e20d7d952c46c54d392c19b6e18f1d612812161983eacf05341d5ab9d9aa868d72a6563faecae0e4e52f03afe1b0ffdb8d2cd5f5f050aee9beb5f14a14fcff39b1c3ecf7b4db64cc70f916afa75692006025340ebb4c767c6c5959108147d92261f6c964f09da6648881884f0efe1c498308fd635e2ed874eeda1218ffa668714031f34c8047e074aa8dd310e06c3f9ac0e2fe7ef8dc23be3580c95f03f3dd3872d4a3fdec7f489d7b6951a50525a18a007751cd367c3ef1160db6210426f6e721d82574fd8caf67c2d6df505310ff75b9390e514fd535924bef5c2b1fe9604010e94b83d78b1177a926f59128fd58c6272df9a2481615f8356e394b9bb410b7516b3630a940d899315e1d45ad0ee9dbd95f0e5d5f76a02c7cd66d7c3932cdff925890a7b27e6c89f86000d9b081e2332c009f5d17fffbeff4d996e0006430cf41ce8ebfffc1c13c27d8bab29a85bef313aafa1a1f9f72fea27933bea5ef357f200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000312466914f31ed77986482accc3004c15a88063ba6c79848e6f6b4990d19a5b2a4ad0f5171fb5a7afc00384c280c6d58380da7424eaf2d261e11339f6c33e2527d7de594b4f2d93b01b9611d4b77f32c5529a34e9cd9ae1659bd8d705a418521379c4a9027db0b6c7802ebdf995592959afaa0fbb71cd90d0ce443467d16d540000000000000000000000000000004f66b5c90e6a316714faac8fb917a22eab00000000000000000000000000000000001a16cf78e4ad73260994b0f7b9047e0000000000000000000000000000003e764de9fca22752122b8e2333a70c19f8000000000000000000000000000000000018637f43f93ba519da98522d149cf600000000000000000000000000000016ecad61bc4abacd835daf9969f10b08a9000000000000000000000000000000000012d92021a51570af40b2f46432137b00000000000000000000000000000020175c705dc8aefce3907d34cf2e8b14a7000000000000000000000000000000000004909303820435a6c958c7b6eb48f9")
    }

    #[fixture]
    fn valid_plain_proof() -> [u8; PLAIN_PROOF_SIZE] {
        hex_literal::hex!("0000000000000000000000000000000000000000000000042ab5d6d1986846cf00000000000000000000000000000000000000000000000b75c020998797da780000000000000000000000000000000000000000000000005a107acb64952eca000000000000000000000000000000000000000000000000000031e97a575e9d00000000000000000000000000000000000000000000000b5666547acf8bd5a400000000000000000000000000000000000000000000000c410db10a01750aeb00000000000000000000000000000000000000000000000d722669117f9758a4000000000000000000000000000000000000000000000000000178cbf4206471000000000000000000000000000000000000000000000000e91b8a11e7842c38000000000000000000000000000000000000000000000007fd51009034b3357f000000000000000000000000000000000000000000000009889939f81e9c74020000000000000000000000000000000000000000000000000000f94656a2ca48000000000000000000000000000000000000000000000006fb128b46c1ddb67f0000000000000000000000000000000000000000000000093fe27776f50224bd000000000000000000000000000000000000000000000004a0c80c0da527a0810000000000000000000000000000000000000000000000000001b52c2020d746000000000000000000000000000000f922bc2bb6d64b3ea896f2a25f6bcb33ca00000000000000000000000000000000000aefe3388e9345add9533b99ee5141000000000000000000000000000000f8b4639e5e81a976bfb34c46a9ee1ffa3d00000000000000000000000000000000001fc0568b50bf309bc489ad1f77587a000000000000000000000000000000e3063254026308c879f692df3af9affd2b00000000000000000000000000000000001392ef862232f14351e0fbd9ba66bf000000000000000000000000000000f9ff93951d06cf4add8c7e9c06365d210d00000000000000000000000000000000000dc198502f75d2a85a584e118c631a000000000000000000000000000000f2bf208a6ff86dc8bfa1fc8cbe961ccd5400000000000000000000000000000000001ea606ad62d644b59069c7c4178b8b000000000000000000000000000000cbfaba5da7c3b8693a59440919a384126a00000000000000000000000000000000002f3c20c330325a277376ff0caba57900000000000000000000000000000079cf93b804469cfd1aed183baaeae73de800000000000000000000000000000000000e59187557f6855bde567cb35ede860000000000000000000000000000008bd253f9ec6d2aa0aa50326c8365f4771f0000000000000000000000000000000000094ed7be0bdab40ba71f0b5a713f4600000000000000000000000000000079cf93b804469cfd1aed183baaeae73de800000000000000000000000000000000000e59187557f6855bde567cb35ede860000000000000000000000000000008bd253f9ec6d2aa0aa50326c8365f4771f0000000000000000000000000000000000094ed7be0bdab40ba71f0b5a713f460000000000000000000000000000003d4c9640bbf63988772976fc65f857114d000000000000000000000000000000000016c29167ff562fdee5fec91ec05b5600000000000000000000000000000073d7e2b6919a97865580f4ef04f6c87c2000000000000000000000000000000000001043b1c40b3e844b4c2bccb626a052000000000000000000000000000000fa4fdebf97093f5a274ceb329d5a6ac63f000000000000000000000000000000000019bc803bb3f905b8255201e596cd0f000000000000000000000000000000f633b0fabd5908dff23a6ec79ba2e8db190000000000000000000000000000000000072e7c7579a79dc6f492331ff212c600000000000000000000000000000049e7ba255ad5c8d042109f82015b35cc1000000000000000000000000000000000002ef307b1333f215003619917bca1de0000000000000000000000000000001ec461bc585faef4d131e19ec1ec6f24ce00000000000000000000000000000000002f2eeb521ab1c2067d982c15338bd61c7b8ecd48e7f62faa8492fc376d16d7dc096aa68b554c9730672ea6773d062f13e8bfa59849a9fa0dcbb2ba4a1441854c2a7da1ee6423fa137ac6ed78c2f9d22c2bcebcde2ce7600c653e8c66411a8eab46c13eb6ecbb10477fe8907f5dc243166b3077dcb7961859e514d80ff98039277c9dabff8a54445a5564e92d08bb6825121fe4548b3fa3f4a3b864f5d4affe5fe243c08f96739fdb04a24acbabcb9e0810b925cdbb2763096567d70aa130d1d65e223d2f38f6a88556602702bc81f1087291c3ea6247f21b529cbfd731f29c1ce332cafdea3f554c501f108977ee78098025a2450091bc706b23745eb101d2d0ff6fa1e84b73eba289312965b534bc2363eca3ad5e4645ca72b643d3a1326163691ffa14aef4c1c7e47e23e47c0b160fe98f2b3d19532b2eb22dcc4ef751666c552033465e733f567090efd60baa6f0e8268c5cb953746d1066bd2414010b675c64f6c908dd6aebbe11c9f16000e5a1c4b9fcd9aac0d8bfed2728ab9b42f7d3873dea5381e76b715760d2a27f1d6950d05bbdcdd7a77fc688a6b5b3f0cf759fae44092ba9a94ad536345c700461c870c565fb81d8629a372518df1bf8ccfbc6ba38ac9db523a3facc984069eab8fdd039d29854a400226989cf74340bacbc5dbe943fce7b53289671f9458ec39538f078c31aef50cde0623dcb5a9a81145c861ceaa3ec1822f8a038a4e4ad0977c1719fb82e82385233aee67c4b3e68b7e540e49e1e654ddef520714c3a42c0b169e049fb4620b510f6a9f76dd3eb304c878a417298995659a5c1e4620e0c853d0701dd3c602db8265d977cca6f20c05a9287b57166a14e9194e8f7a6159e81aa7f006ce52e511aad3b28b12d1925ad60f0d590df87d5cd0d9874a76ebc55854812d303e889b581df5fcca09ecb99635e79e828864de7da62c3012be72bbc72b6d3c100c81767c45f8372f8eecba96ac1dd4d06fb7e9e9ba00962fff0d5e427efd761ded91c6415c4fe439421675e9b7baf86be5ee2a52b678d2eb7305f4f1adeccf10c0fa7a0bff1a3a579f572da676872ca372621e0258801777b3bb47807fbea70aa919acfc76d8cbde514e4b675520fcca42e5f6a16a611d9c1bb41dd503f003293c2f046dda56d94694894d979db7e503a7b235299ba175c0a8d00e3aedd7a41cc168733ec6e5bc476ef6dc02345c3ad008dbf608cf8914de74cc4b01b777a52bc42adde1b34c29ad76579ae7aeb04ea3d9f38c18fb6cd5dc862e18463f4fa5180c5d72faa4ad7c46ab183ad80284eac23f178d66117e7afecec24d0c0654f30585639a7a2a759231d06e92853d4d4dfdbd507ffcc2fa82012fb95153e30f32293d23f3f096baef837166f6b8d17d4d515ac9d5dd34854f71f51e541e5c7a06190a33dfd03d73f44a96c2806343777a10d898b34b1e74991da2dfcd606d32062c8f4301525d60766be503de1ff69588b955c8670aeb21af91e181e9a4c6b4663057cc106b42cdd54567c758b021fead6115bcf2352341c6b94e806df12f05a42eb0b38bfeff57695bc5d881ac900ae17f37e15c59517ab0700a83e13280b75a273715b58ee0f48039beb6911eaa120714e793358a7af6293286f1d40f15d88b1a569e7ca26fec0e8263078e819d4bb0eb6d0ce485c67540b6463a1d0f813cbd100aee76768a260d5bd7ab2bf93a483cc3d31a9acb31247aaf598e002b81139d073bd58b466d6b9d8e4cf7bf032efbfbcdc576f158de5ebce3e750911394ed711e802b2044ad2c68107154e823c64ffe987f2daf7e3ac42a5e89e977ef4427f708506daabfb516a1e2d402a4c53f663dda8694037bd794bf3767cdcdb3d0e41d164f5ed218d48ce9758c350bd2fb89a32ef5b2efb1c6a946747b21a51ec0b2f22922d396afa5042ff7b1bf739c171c7719ef1e37799a4faa343df0b93bab8901020ece52d22d589a7bc02335de1da2681bdabc8902c46e29e22e6ef4ec9ccf6c16601b4e6cdb1663210497999a95779c51bd0a2c0265f80585c20d23558b9022162d48ed1c25f7a223225cfdbbc35dfd1a990d6fe64be39645ff6b2335a3656b16811d9c6bd8329271d8502d17138c49fe75504582c323c0822bd79c90a762ca2484188f9ad63487ce70c3720484774de605a002c8272dee89d4684ee1e8abbd2ab010436e746b2cf15e7fb82e92a599b714b363fe5174c3c89512b4e3f3bf3509cbb3f26579460e5df8381fcce723ecb9c404cbb42c016822d6d8e5f3a4ba72141fc2e6e5c760c6ccb3064154821c53b21f5b946701f5c303a67abcfea9ed9a029a3c652a38c1fb98f3c8bb4e82720353208e3e7909363a8f7ce837eb52ec2e0a7355e97b35b145b318f0e58bc802fa2e3ea3dc9422c13551ad898ddfa5198a25bec411f874e6f6f07a090c2830fbc958903f24d56e44023d9fb2b0f2f0310f0e110b829c72f6ea01d5d05d952c5f24c11c4f943cd9f3ed6b913677ee15010b0a40966c9c6b65b93f90674ffb3bd368454045564b2d3dd137656d2173f314e52a4b0bcae0babfd35677bd74c2dfa4a6973a8b83de5f979e7c0f903d18d060a10ae00331f55326600d1d8d8ce3325d4d690e4aa175ef35f8568237fddc1564872dfc1c75cc1f2bf849efe2b3170d6ea551c4d30973176019aa00aecabec3177d267b1e41fc884983d03ce3549b7feead2e5cb767655e7deab5b9d16d6502ea66194b91d709ad461dbe9ff4bdd87b1a3291b6759615efca0792492595c2c7e77612791ae3f79531c4920e899d1fe966b81e1b80a7e73cf1e9470d1319d1522e5102dfc037162a487c7fc94faec37d3670d22987cc9ee7de53f1535350d7e4040d1d0c5cfd0657384e23ac9de7c7aae1bee12f423a8219cc3e3b39886d14a2bd0424bad78a033e4f2e77b46eb92ddabed3661b800acacefef2f98411d9c9f9ab970cf024af0169e17b80cc966b6c10e0160365afea88d33303704a97e8bdd7072209f21d2a9584ebddee2a994bb8c02a0187df74d672437cd3b0dd653dcb1bf8dd2dc5538c6a15d8c77b19eb30f873060b6b086b19d505d07f49974f77e298463e16fe3db47abe88636aa96cc7dd6d92314fa191b07f83dde226e56efa06ebfc510a092e6ba4ab25d0c980b648bee506f9b44086f35fb1e756c909911f925ad4ea2a00f399f804ead93ea281f847bf4e208f6cfaf00b8ba64252a2765bc52b9c1f09c7b5040fdb10bd47a881044db8e0fd2efa8aca51230c005eb2a44339f36fe211686075aa9d4a88777c92e94e9d5401b909b89667316d289261497f3c82267e12ee421853a448179e10c1442e1624c25218fa85f5ed3ec3265be04207dabbca1bb428f6ea6c02dd1a26b62723e446169927edf23b048f2e4d125c35a40b0f9005c3495b95a7c57e14a065cdd25ae4595aadf21db5410699ae8cdc68000f4a031bdfccf5ca6179d45c7755a3d5ba1ce524d2fd66b5128918bc2c723a0d436c8e1b1e2b2970a4517945fc8f220ce458cc4cc3a332126fee45a90d150c4bf10de3094ffbc153fcaefb10a192ca008d22dd0abd24284b21689980f730e1900d35ba2300e420dbffdc668a8181653c5171378331972f02edcf1ffee05104e6db0294163bf60365348f7f742d5c5e441776fef1a989839cb603b9f19b44681977eefd00e51de977edac9c9be05ef1b5f472c14308a42ecc4da4c7aab7bfc4bfa54e692ebe3912955c5528d4a78f2edc85ee8876f6f20f1ec66454901ed7838071f8970a092043721c13cecbe40c726c62a8f3b98eb65a19af0538078713e5a2a081421315bd7dc39e8bd90aed2f9756140f51b4a1363ef9ec1a55c6424c42e06951c20584c31a091c6b585f3c591cf20ecceff93cf8b574938316fad46838b47331970631328bce002cee759b0f4680b9ee53e5ae35839c257588b4de204a3ef902fb10b07027ad032d8a4ae1a4802855ec6982a8e73fae4da5d84b891af94aa6b0df1696477dd3e52cafc2e17ac8d2a32152922a56bf31d3edc361fbea0c5abd9cac298033125a190b02834bdacd186e506d1c5dee739da33442710700e06c9655912096693a0f63a16ff39293b3ff41232af72ff2dba251ca96969177c7c01a1f6122b4dbfb6f28ef13151c43acc2c25d913b4bfabacfeb548916719adce59f74bc09fde8c9937572ff4e59f5c75b92574fe89b7507fe981067deef942b28f2e27c17e0f57cf41b97c0a0255ebf28694c85295ad5defcb415f70b6a06c68966c6c7248afb30169e494a38bc7d17fea2fedb62cc3d6ea9044fadebb5f022209548ea0b1cb773aab1df169f86216727f6ab60a1a5256948488a71799b2dd9eb8da1ee0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f419f5fea4225513eb455ad02329f7f6aae23acba26c51a921d59c37773fc0226fde1b9cf4769244ccb3abd73459fb86c8741a963b978d578f22ff30c345192ea7cee331eb596f529812488c6e1f9fe3693782a845ce94f234670a61a33fe72f2c618b3151ae7fec750362d697218177711aebc3fa368a6edef299789f6290233535cb7727c0e6bd68e9f4b201e53c968ce150eac8e8c7c1e2766cba6c46a80d3a5f217d0e6fddf75ef1b294d04440ca8df792f4e5435c489f6f549522401d166cde370480484d2de4240e1d5a729ace27e0db73c5791498833e5948d0630e15ec8a14174432cb727ff3a0c9c00bd44e5351b1065032bdc8a67922045347a023dc7fda24925a3dc7b43564ed73d4251397f2a1893486824e16e2ae2210ca191ced56248e4cae05d18877c5bc0c86606df699b1bcd9070cfd7870b1bbcd7d3623fdc7c175b80d56806cc84e514eac54163644cd5d90917a1523d92e22476ef20ddd382b3e4b4a25610791cb7cb72e80dc9c379f2bb0be1103e8f9b88705548f17d434e9adb3077bbb370d59794259a9e047c130dd8247f23fc7144c3b2434022466b3793d6b700a48ac7dea4a306c20294864e103c343c1439ea7a9673634ab23e4ce6b720007e58d7958b335e0638877d793e3626fcf01a3951a46c7f884a3160379399a2c70847fbec97ead3a8af8bf08fef52cdc21471f3999ec09513cec2330b826d797acd3531bfaf705ac1fb5a1125da17bd6322eea3e883c660d795211dd5178a0a84b147ca591d54f587c045f8a270be27918c2932351729e96ae2f158aaa4370e4f6c6a31d8cd2ad9055e2724bda39ef6cb4d83937fa766fa163b205f319c43be092fc88df04ffb9ac5deaa45af14aedd83dd2366413a67773b9e52ef9660a745e5bbc2996d73095b165ec9398225bb03a9988f8005739a81f6efc01a40252869d674cd046c26e9d89365426ef9dad55f4a0ce4da77cf587d77d6114f51a0053a6d19c238eb3624b225fab60850d189801d1b6dcd96c30a893ef502f6e31392308ecbf97d162cdbcaa16cf659b6b9a0740590e4e0557f971fcdece1d9958675fab47900f868565b9f4ed54d344719abc0c2ebfd5c7d86fa147cf7e0331db3fcf35627b2ed813e600c89eb85dd76753abf4160ac6451eb41337de4f1548754281e669efb8bc434db73e86dcc0fd3713410c56cdd750ed866af380370d7409953700e69586b8493a70cda7110061489976c31e307d756f7c9995651f2bc03e9029ee0ccdf3f1962a5f14967c0d3bcb8071765752004bc98bed9eace42677d73a2371005ec8cddbc36b9da73da278b7f9251c30f838aba0215ef818980c7037424f08340d6ea6732563a0cf9a1705d86a186d96e82a5e5fdb899c8a0815b013263d4baa72feb4862dcd4efaeee1e5205409f4b694eb0faf8285a417ff1ad33259893ecd5a848d396ca393312c04e4741fa29f26279d26fbc7abf8f1140aaa0bd49a5eb9099763aa200abfe455e90705a62f8a1d44d2a52645103257c30aaa0bd49a5eb9099763aa200abfe455e90705a62f8a1d44d2a52645103257c32f2fc3e036a1e92e8dc04b68ec6984cf1adf7688ecb6a700b3fd603683d001d70b48f62b8d585fe9dd1b75b924129b3ecc98ddc05c0538624908adb9fbcbe7760be48f4c691c84882818ccc4c3fe45a13b1f584709a0a9d9eb677df36f93ac4909e7239f927da122cfa9ec2704f65371d5853c5c751a623c7c42ab09ce86542b2eb9d9245fd93c8a6fdb51443b1e3be4a15babbbed14c171f3e9691e0bd0218c000000000000000000000000000000dc56ba1e5023753d07d46e6bb1cbfd628600000000000000000000000000000000002e82884c3ec8ae689c915d38d9d93c00000000000000000000000000000039786d01a1ecc5fff9931c83ca6412b2cc00000000000000000000000000000000001e1f7a92efe9beff68b8855c9f7c3f0000000000000000000000000000006c49a591cf6c5cb40281826b3aa00d3dfc000000000000000000000000000000000011abb089b73fc31d1c7e39876d2095000000000000000000000000000000333907f8e0cfaccfc114b0a275c8dcbcb800000000000000000000000000000000001582781c18a4b5b8995fb75beea1490000000000000000000000000000002e3de34e1058aebae55a58a41d06a84fb300000000000000000000000000000000001de17b03be82b87b592230356c21fa000000000000000000000000000000e57ba3fab4602113148b171b4e0a9466d200000000000000000000000000000000002f54d6d04ee1ac8fa7e39128d1c320000000000000000000000000000000badf513c0cc571a8a1f8ce24abfbab81e1000000000000000000000000000000000022c914af8c4fa2e1edd290df51131a000000000000000000000000000000e5e3ca44f19347c9a617e5df93f038f34a0000000000000000000000000000000000194a75ef65392dab290920610598f6000000000000000000000000000000dde59a126566ff820fdbc547c90037743d00000000000000000000000000000000002c19525ba8806a94f057a180b60ba1000000000000000000000000000000bfca7673c606a159245318ae2479f86cd200000000000000000000000000000000001354d965304348fb99d944b52e0d88000000000000000000000000000000dffe47fb62e9db973bf14feb64ff0fb51d000000000000000000000000000000000010c417e6b1ce4b1b5f61a97204f9320000000000000000000000000000007a842f5a4c5326a8cf432a50a404535849000000000000000000000000000000000011a12996d793c91a30134bb599828a00000000000000000000000000000048818ea7ea10d2284c0af86ac9c6bf91d3000000000000000000000000000000000007fa1f11e254cdda0f1a1ed9958f58000000000000000000000000000000d6cf46dfa0592f0713833a9fed087236970000000000000000000000000000000000235f1936c0d11bc1adf83b3a1af3940000000000000000000000000000008550f63abbbf3601387bcc3889666b24d80000000000000000000000000000000000032ed7501bb04ea97139d33bcc665d000000000000000000000000000000699e6b88d2921437715533bc8532b60cc300000000000000000000000000000000000a2a46981ff07db0d2ec03247b764c000000000000000000000000000000f35c92b9bf64baafa8a72fd870336144920000000000000000000000000000000000100ad4e035953fb2120922e9083687000000000000000000000000000000e0b5cfafe104353b1021409661b77268dc00000000000000000000000000000000000954bcd35200579f7b581e2db909c4000000000000000000000000000000a3486db95cb3af0114eacfd78ccd38011b00000000000000000000000000000000000e5a0d78cfab7149da747b8ab0767f000000000000000000000000000000e34e9f12e1e8bc73abfaef46cd72c3042600000000000000000000000000000000001796d9e42513140b570b60f4933da1000000000000000000000000000000592d746beaab4c9b3ac58e0ac434b896cd00000000000000000000000000000000001bdd199ef258fe95cd0e72a7e9b71d0000000000000000000000000000002d9ad27124a9236686cefb0b9ed4b0255f000000000000000000000000000000000017f119f7af695f19e7bc2f39049a78000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000004cbdea4b62a5540042125ec8d0a91c1d9434689500ae864eb96038b8b745c68299a2c767a64a9f2d75573012b90784e2c1c2fd32057e9093008682ad48955392d551a2e1a767693d91633bc4320fa02d2d992e638be63812c94893c84b825592a1bf48da509760b4b1cff561e7b8c60a7636fc48ba81068b8eaaf62e7c5d80004e88f1d56f09579fabf3be94b1c61bbfa67bc45d1554a44dc72ad4284926b580dc18bb1f793d737fc61c0ee6bb4dcfde8e0fa6d7d9f3dd8d24fc29c9da9e6cd1b85ce39901472ea3aa5b54a6ed53a9cfebcdc24233286c29d9d2552ef1de6a012f1ce485425278ce6eff51c11ba887742b9a364c7950bbba3be55ac916b7c8817f653ccc3b71e5f0b8914a9806baa3aff651e5363223704f801efa35f33fd2b2b7c860bc63336d6b1bb8478772eb30893a885adc6210048a4aaf0cfe32a8297276e65fa960a87347d2296955b7d2101dc7d8f3c132518216c4193e98df052b726d008c962b5f38cdd0470d07c3caf35f6fbff20ea060ef6fbc20096ad231f74000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069b3f375e9be79c449f6d6ec50979b24df00000000000000000000000000000000002b339f7063c6bd1e9882f4481e28040000000000000000000000000000004dd784de31192d115a27286c825836301000000000000000000000000000000000002ac260042545956bbafebdb4e164ba0000000000000000000000000000004d83be85ff75d87780b1ad11742db1adf30000000000000000000000000000000000037cceaa0c4698af2fb6c492cb58d80000000000000000000000000000008d91c29ac44f946712cc191e15968427f100000000000000000000000000000000000ee7b2760f6456f2b7727d70f53c5c")
    }

    #[rstest]
    fn parse_valid_zk_proof(valid_zk_proof: [u8; ZK_PROOF_SIZE]) {
        assert!(ZKProof::try_from(&valid_zk_proof[..]).is_ok());
    }

    #[rstest]
    fn parse_valid_plain_proof(valid_plain_proof: [u8; PLAIN_PROOF_SIZE]) {
        assert!(PlainProof::try_from(&valid_plain_proof[..]).is_ok());
    }

    mod reject {
        use super::*;

        #[rstest]
        fn a_zk_proof_from_a_short_buffer(valid_zk_proof: [u8; ZK_PROOF_SIZE]) {
            let invalid_zk_proof = &valid_zk_proof[..ZK_PROOF_SIZE - 1];
            assert_eq!(
                ZKProof::try_from(invalid_zk_proof),
                Err(ProofError::IncorrectBufferSize {
                    expected_size: ZK_PROOF_SIZE,
                    actual_size: invalid_zk_proof.len()
                })
            );
        }

        #[rstest]
        fn a_plain_proof_from_a_short_buffer(valid_plain_proof: [u8; PLAIN_PROOF_SIZE]) {
            let invalid_proof = &valid_plain_proof[..PLAIN_PROOF_SIZE - 1];
            assert_eq!(
                PlainProof::try_from(invalid_proof),
                Err(ProofError::IncorrectBufferSize {
                    expected_size: PLAIN_PROOF_SIZE,
                    actual_size: invalid_proof.len()
                })
            );
        }
    }
}
