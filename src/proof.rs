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
        BATCHED_RELATION_PARTIAL_LENGTH, CONST_PROOF_SIZE_LOG_N, EVM_WORD_SIZE, FIELD_ELEMENT_SIZE,
        NUMBER_OF_ENTITIES, NUM_ELEMENTS_COMM, NUM_ELEMENTS_FR, NUM_LIBRA_COMMITMENTS,
        NUM_LIBRA_EVALUATIONS, NUM_WITNESS_ENTITIES, PAIRING_POINTS_SIZE,
        ZK_BATCHED_RELATION_PARTIAL_LENGTH,
    },
    errors::{ConversionError, GroupError},
    utils::{read_g1_by_splitting, IntoBEBytes32, IntoU256},
    EVMWord, Fr, G1,
};
use alloc::{boxed::Box, string::ToString};
use ark_bn254_ext::{CurveHooks, Fq};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, MontFp, PrimeField};
use core::{array::from_fn, fmt};
use sha3::{Digest, Keccak256};
use snafu::Snafu;

/// Unified enum for handling errors of all flavors.
#[derive(Debug, PartialEq, Snafu)]
pub enum ProofError {
    #[snafu(display("Incorrect buffer size. Expected: {expected_size}; Got: {actual_size}",))]
    IncorrectBufferSize {
        expected_size: usize,
        actual_size: usize,
    },
    #[snafu(display("Group element conversion error: {conv_error}"))]
    GroupConversionError { conv_error: ConversionError },
    #[snafu(display("Shplemini pairing check failed"))]
    ShpleminiPairingCheckFailed,
    #[snafu(display("Consistency check failed. Cause: {message}"))]
    ConsistencyCheckFailed { message: &'static str },
    #[snafu(display("Other error: {message}"))]
    OtherError { message: String },
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProofType {
    Plain(Box<[u8]>),
    ZK(Box<[u8]>),
}

// Utility function for parsing `Fr` from raw bytes.
fn read_fr(data: &mut &[u8]) -> Result<Fr, ProofError> {
    const CHUNK_SIZE: usize = FIELD_ELEMENT_SIZE;
    let chunk = data.split_off(..CHUNK_SIZE).ok_or(ProofError::OtherError {
        message: "Unable to read field element from data".to_string(),
    })?;

    Ok(Fr::from_be_bytes_mod_order(chunk)) // Q: Do we want verification to fail if value >= r?
}

// Utility function for parsing an EVMWord (raw bytes).
fn read_evm_word(data: &mut &[u8]) -> Result<EVMWord, ProofError> {
    const CHUNK_SIZE: usize = EVM_WORD_SIZE;
    let chunk: EVMWord = data
        .split_off(..CHUNK_SIZE)
        .ok_or(ProofError::OtherError {
            message: "Unable to read EVM word from data".to_string(),
        })?
        .try_into()
        .expect("Conversion should work at this point");

    Ok(chunk)
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum ProofCommitmentField {
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

impl fmt::Display for ProofCommitmentField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofCommitmentField::SHPLONK_Q => write!(f, "SHPLONK_Q"),
            ProofCommitmentField::GEMINI_MASKING_POLY => write!(f, "GEMINI_MASKING_POLY"),
            ProofCommitmentField::W_1 => write!(f, "W_1"),
            ProofCommitmentField::W_2 => write!(f, "W_2"),
            ProofCommitmentField::W_3 => write!(f, "W_3"),
            ProofCommitmentField::W_4 => write!(f, "W_4"),
            ProofCommitmentField::Z_PERM => write!(f, "Z_PERM"),
            ProofCommitmentField::LOOKUP_INVERSES => write!(f, "LOOKUP_INVERSES"),
            ProofCommitmentField::LOOKUP_READ_COUNTS => write!(f, "LOOKUP_READ_COUNTS"),
            ProofCommitmentField::LOOKUP_READ_TAGS => write!(f, "LOOKUP_READ_TAGS"),
            ProofCommitmentField::LIBRA_COMMITMENTS(i) => write!(f, "LIBRA_COMMITMENTS_{i}"),
            ProofCommitmentField::GEMINI_FOLD_COMMS(i) => write!(f, "GEMINI_FOLD_COMMS_{i}"),
            ProofCommitmentField::KZG_QUOTIENT => write!(f, "KZG_QUOTIENT"),
        }
    }
}

pub(crate) trait CommonProofData<H: CurveHooks> {
    // getters
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE];
    fn w1(&self) -> &G1<H>;
    fn w2(&self) -> &G1<H>;
    fn w3(&self) -> &G1<H>;
    fn w4(&self) -> &G1<H>;
    fn lookup_read_counts(&self) -> &G1<H>;
    fn lookup_read_tags(&self) -> &G1<H>;
    fn lookup_inverses(&self) -> &G1<H>;
    fn z_perm(&self) -> &G1<H>;
    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a>;
    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES];
    fn gemini_fold_comms(&self) -> &Vec<G1<H>>;
    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N];
    fn shplonk_q(&self) -> &G1<H>;
    fn kzg_quotient(&self) -> &G1<H>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct ZKProof<H: CurveHooks> {
    // Pairing point object
    pub pairing_point_object: [EVMWord; PAIRING_POINTS_SIZE],
    // Commitments to wire polynomials
    pub w1: G1<H>,
    pub w2: G1<H>,
    pub w3: G1<H>,
    pub w4: G1<H>,
    // Commitments to logup witness polynomials
    pub lookup_read_counts: G1<H>,
    pub lookup_read_tags: G1<H>,
    pub lookup_inverses: G1<H>,
    // Commitment to grand permutation polynomial
    pub z_perm: G1<H>,
    pub libra_commitments: [G1<H>; NUM_LIBRA_COMMITMENTS],
    // Sumcheck
    pub libra_sum: Fr,
    pub sumcheck_univariates: Vec<Vec<Fr>>,
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    pub libra_evaluation: Fr,
    // ZK
    pub gemini_masking_poly: G1<H>,
    pub gemini_masking_eval: Fr,
    // Shplemini
    pub gemini_fold_comms: Vec<G1<H>>,
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub libra_poly_evals: [Fr; NUM_LIBRA_EVALUATIONS],
    pub shplonk_q: G1<H>,
    pub kzg_quotient: G1<H>,
}

impl<H: CurveHooks> CommonProofData<H> for ZKProof<H> {
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE] {
        &self.pairing_point_object
    }

    fn w1(&self) -> &G1<H> {
        &self.w1
    }

    fn w2(&self) -> &G1<H> {
        &self.w2
    }

    fn w3(&self) -> &G1<H> {
        &self.w3
    }

    fn w4(&self) -> &G1<H> {
        &self.w4
    }

    fn lookup_read_counts(&self) -> &G1<H> {
        &self.lookup_read_counts
    }

    fn lookup_read_tags(&self) -> &G1<H> {
        &self.lookup_read_tags
    }

    fn lookup_inverses(&self) -> &G1<H> {
        &self.lookup_inverses
    }

    fn z_perm(&self) -> &G1<H> {
        &self.z_perm
    }

    fn shplonk_q(&self) -> &G1<H> {
        &self.shplonk_q
    }

    fn kzg_quotient(&self) -> &G1<H> {
        &self.kzg_quotient
    }

    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a> {
        Box::new(self.sumcheck_univariates.iter().map(|row| &row[..]))
    }

    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES] {
        &self.sumcheck_evaluations
    }

    fn gemini_fold_comms(&self) -> &Vec<G1<H>> {
        &self.gemini_fold_comms
    }

    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.gemini_a_evaluations
    }
}

impl<H: CurveHooks> ZKProof<H> {
    // Get the baricentric lagrange denominators for the proof structure.
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

    // Get the length of batched relation partials in the proof structure.
    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        ZK_BATCHED_RELATION_PARTIAL_LENGTH
    }

    // Get the starting index of shifted commitments in the proof structure.
    pub(crate) fn get_shifted_commitments_start(&self) -> usize {
        30
    }

    // Calculate proof size in EVM words based on log_n (matching UltraKeccakZKFlavor formula)
    pub(crate) fn calculate_proof_size(log_n: u64) -> usize {
        // Witness and Libra commitments
        let mut proof_length = NUM_WITNESS_ENTITIES * NUM_ELEMENTS_COMM; // witness commitments

        proof_length += NUM_ELEMENTS_COMM * 4; // Libra concat, grand sum, quotient comms + Gemini masking

        // Sumcheck
        proof_length += (log_n as usize) * ZK_BATCHED_RELATION_PARTIAL_LENGTH * NUM_ELEMENTS_FR; // sumcheck univariates

        proof_length += NUMBER_OF_ENTITIES * NUM_ELEMENTS_FR; // sumcheck evaluations

        // Libra and Gemini
        proof_length += NUM_ELEMENTS_FR * 3; // Libra sum, claimed eval, Gemini masking eval

        proof_length += (log_n as usize) * NUM_ELEMENTS_FR; // Gemini a evaluations

        proof_length += NUM_LIBRA_EVALUATIONS * NUM_ELEMENTS_FR; // libra evaluations

        // PCS commitments
        proof_length += (log_n as usize - 1) * NUM_ELEMENTS_COMM; // Gemini Fold commitments

        proof_length += NUM_ELEMENTS_COMM * 2; // Shplonk Q and KZG W commitments

        // Pairing points
        proof_length += PAIRING_POINTS_SIZE; // pairing inputs carried on public inputs

        proof_length
    }

    // Calculate proof size in bytes based on log_n.
    pub(crate) fn calculate_proof_byte_size(log_n: u64) -> usize {
        Self::calculate_proof_size(log_n) * EVM_WORD_SIZE
    }

    // Constructs a `ZKProof` from a byte slice and a required log_n parameter.
    pub fn from_bytes(mut proof_bytes: &[u8], log_n: u64) -> Result<Self, ProofError> {
        let expected_byte_size = Self::calculate_proof_byte_size(log_n);
        if proof_bytes.len() != expected_byte_size {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: expected_byte_size,
                actual_size: proof_bytes.len(),
            });
        }

        // Pairing Point Object
        let pairing_point_object = from_fn(|_| {
            read_evm_word(&mut proof_bytes).expect("Should always be able to read an EVM word here")
        });

        // Commitments
        let w1 = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_1.into()),
                },
            }
        })?;
        let w2 = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_2.into()),
                },
            }
        })?;
        let w3 = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_3.into()),
                },
            }
        })?;
        // Lookup / Permutation Helper Commitments
        let lookup_read_counts = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LOOKUP_READ_COUNTS.into()),
                },
            }
        })?;
        let lookup_read_tags = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LOOKUP_READ_TAGS.into()),
                },
            }
        })?;
        let w4 = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_4.into()),
                },
            }
        })?;
        let lookup_inverses = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LOOKUP_INVERSES.into()),
                },
            }
        })?;
        let z_perm = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::Z_PERM.into()),
                },
            }
        })?;

        let mut libra_commitments = [G1::<H>::default(); NUM_LIBRA_COMMITMENTS];

        libra_commitments[0] = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LIBRA_COMMITMENTS(0).into()),
                },
            }
        })?;

        let libra_sum = read_fr(&mut proof_bytes)?;

        // Sumcheck univariates
        let mut sumcheck_univariates: Vec<Vec<Fr>> = Vec::with_capacity(log_n as usize);

        for _ in 0..log_n {
            let mut sumcheck_univariate: Vec<Fr> =
                Vec::with_capacity(ZK_BATCHED_RELATION_PARTIAL_LENGTH);
            for _ in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
                let su = read_fr(&mut proof_bytes)?;
                sumcheck_univariate.push(su);
            }
            sumcheck_univariates.push(sumcheck_univariate);
        }

        // Sumcheck evaluations
        let sumcheck_evaluations = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        let libra_evaluation = read_fr(&mut proof_bytes)?;

        libra_commitments[1] = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LIBRA_COMMITMENTS(1).into()),
                },
            }
        })?;
        libra_commitments[2] = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LIBRA_COMMITMENTS(2).into()),
                },
            }
        })?;

        let gemini_masking_poly = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::GEMINI_MASKING_POLY.into()),
                },
            }
        })?;

        let gemini_masking_eval = read_fr(&mut proof_bytes)?;

        // Gemini
        // Read gemini fold univariates
        let mut gemini_fold_comms = Vec::with_capacity(log_n as usize - 1);

        for i in 0..(log_n as usize - 1) {
            gemini_fold_comms.push(read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
                ProofError::GroupConversionError {
                    conv_error: ConversionError {
                        group: e,
                        field: Some(ProofCommitmentField::GEMINI_FOLD_COMMS(i).into()),
                    },
                }
            })?);
        }

        // Read gemini a evaluations
        let gemini_a_evaluations = from_fn(|i| {
            if i < log_n as usize {
                read_fr(&mut proof_bytes)
                    .expect("Should always be able to read a field element here")
            } else {
                Fr::ZERO
            }
        });

        let libra_poly_evals = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        // Shplonk
        let shplonk_q = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::SHPLONK_Q.into()),
                },
            }
        })?;

        // KZG
        let kzg_quotient = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::KZG_QUOTIENT.into()),
                },
            }
        })?;

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
pub struct PlainProof<H: CurveHooks> {
    // Pairing point object
    pub pairing_point_object: [EVMWord; PAIRING_POINTS_SIZE],
    // Commitments to wire polynomials
    pub w1: G1<H>,
    pub w2: G1<H>,
    pub w3: G1<H>,
    pub w4: G1<H>,
    // Commitments to logup witness polynomials
    pub lookup_read_counts: G1<H>,
    pub lookup_read_tags: G1<H>,
    pub lookup_inverses: G1<H>,
    // Lookup helpers - Permutations
    pub z_perm: G1<H>,
    // Sumcheck
    pub sumcheck_univariates: Vec<Vec<Fr>>,
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    // Shplemini
    pub gemini_fold_comms: Vec<G1<H>>,
    pub gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    pub shplonk_q: G1<H>,
    pub kzg_quotient: G1<H>,
}

impl<H: CurveHooks> CommonProofData<H> for PlainProof<H> {
    // getters
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE] {
        &self.pairing_point_object
    }

    fn w1(&self) -> &G1<H> {
        &self.w1
    }

    fn w2(&self) -> &G1<H> {
        &self.w2
    }

    fn w3(&self) -> &G1<H> {
        &self.w3
    }

    fn w4(&self) -> &G1<H> {
        &self.w4
    }

    fn lookup_read_counts(&self) -> &G1<H> {
        &self.lookup_read_counts
    }

    fn lookup_read_tags(&self) -> &G1<H> {
        &self.lookup_read_tags
    }

    fn lookup_inverses(&self) -> &G1<H> {
        &self.lookup_inverses
    }

    fn z_perm(&self) -> &G1<H> {
        &self.z_perm
    }

    fn shplonk_q(&self) -> &G1<H> {
        &self.shplonk_q
    }

    fn kzg_quotient(&self) -> &G1<H> {
        &self.kzg_quotient
    }

    fn sumcheck_univariates<'a>(&'a self) -> Box<dyn Iterator<Item = &'a [Fr]> + 'a> {
        Box::new(self.sumcheck_univariates.iter().map(|row| &row[..]))
    }

    fn sumcheck_evaluations(&self) -> &[Fr; NUMBER_OF_ENTITIES] {
        &self.sumcheck_evaluations
    }

    fn gemini_fold_comms(&self) -> &Vec<G1<H>> {
        &self.gemini_fold_comms
    }

    fn gemini_a_evaluations(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.gemini_a_evaluations
    }
}

impl<H: CurveHooks> PlainProof<H> {
    // Get the baricentric lagrange denominators for the proof structure.
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

    // Get the length of batched relation partials in the proof structure.
    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        BATCHED_RELATION_PARTIAL_LENGTH
    }

    // Get the starting index of shifted commitments in the proof structure.
    pub(crate) fn get_shifted_commitments_start(&self) -> usize {
        29
    }

    // Calculate proof size in EVM words based on log_n (matching UltraKeccakFlavor formula)
    pub(crate) fn calculate_proof_size(log_n: u64) -> usize {
        // Witness commitments
        let mut proof_length = NUM_WITNESS_ENTITIES * NUM_ELEMENTS_COMM; // witness commitments

        // Sumcheck
        proof_length += (log_n as usize) * BATCHED_RELATION_PARTIAL_LENGTH * NUM_ELEMENTS_FR; // sumcheck univariates
        proof_length += NUMBER_OF_ENTITIES * NUM_ELEMENTS_FR; // sumcheck evaluations

        // Gemini
        proof_length += (log_n as usize - 1) * NUM_ELEMENTS_COMM; // Gemini Fold commitments
        proof_length += (log_n as usize) * NUM_ELEMENTS_FR; // Gemini evaluations

        // Shplonk and KZG commitments
        proof_length += NUM_ELEMENTS_COMM * 2; // Shplonk Q and KZG W commitments

        // Pairing points
        proof_length += PAIRING_POINTS_SIZE; // pairing inputs carried on public inputs

        proof_length
    }

    // Calculate proof size in bytes based on log_n.
    pub(crate) fn calculate_proof_byte_size(log_n: u64) -> usize {
        Self::calculate_proof_size(log_n) * EVM_WORD_SIZE
    }

    // Constructs a `PlainProof` from a byte slice and a required log_n parameter.
    pub fn from_bytes(mut proof_bytes: &[u8], log_n: u64) -> Result<Self, ProofError> {
        let expected_byte_size = Self::calculate_proof_byte_size(log_n);
        if proof_bytes.len() != expected_byte_size {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: expected_byte_size,
                actual_size: proof_bytes.len(),
            });
        }

        // Pairing Point Object
        let pairing_point_object = from_fn(|_| {
            read_evm_word(&mut proof_bytes).expect("Should always be able to read an EVM word here")
        });

        // Commitments
        let w1 = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_1.into()),
                },
            }
        })?;
        let w2 = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_2.into()),
                },
            }
        })?;
        let w3 = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_3.into()),
                },
            }
        })?;

        // Lookup / Permutation Helper Commitments
        let lookup_read_counts = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LOOKUP_READ_COUNTS.into()),
                },
            }
        })?;
        let lookup_read_tags = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LOOKUP_READ_TAGS.into()),
                },
            }
        })?;
        let w4 = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::W_4.into()),
                },
            }
        })?;
        let lookup_inverses = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::LOOKUP_INVERSES.into()),
                },
            }
        })?;
        let z_perm = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::Z_PERM.into()),
                },
            }
        })?;

        // Sumcheck univariates
        let mut sumcheck_univariates: Vec<Vec<Fr>> = Vec::with_capacity(log_n as usize);

        for _ in 0..log_n {
            let mut sumcheck_univariate: Vec<Fr> =
                Vec::with_capacity(BATCHED_RELATION_PARTIAL_LENGTH);
            for _ in 0..BATCHED_RELATION_PARTIAL_LENGTH {
                let su = read_fr(&mut proof_bytes)?;
                sumcheck_univariate.push(su);
            }
            sumcheck_univariates.push(sumcheck_univariate);
        }

        // Sumcheck evaluations
        let sumcheck_evaluations = from_fn(|_| {
            read_fr(&mut proof_bytes).expect("Should always be able to read a field element here")
        });

        // Gemini
        // Read gemini fold univariates
        let mut gemini_fold_comms = Vec::with_capacity(log_n as usize - 1);

        for i in 0..(log_n as usize - 1) {
            gemini_fold_comms.push(read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
                ProofError::GroupConversionError {
                    conv_error: ConversionError {
                        group: e,
                        field: Some(ProofCommitmentField::GEMINI_FOLD_COMMS(i).into()),
                    },
                }
            })?);
        }

        // Read gemini a evaluations
        let gemini_a_evaluations = from_fn(|i| {
            if i < log_n as usize {
                read_fr(&mut proof_bytes)
                    .expect("Should always be able to read a field element here")
            } else {
                Fr::ZERO
            }
        });

        // Shplonk
        let shplonk_q = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::SHPLONK_Q.into()),
                },
            }
        })?;

        // KZG
        let kzg_quotient = read_g1_by_splitting(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::KZG_QUOTIENT.into()),
                },
            }
        })?;

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
pub(crate) enum ParsedProof<H: CurveHooks> {
    Plain(Box<PlainProof<H>>),
    ZK(Box<ZKProof<H>>),
}

impl<H: CurveHooks> ParsedProof<H> {
    // Get the baricentric lagrange denominators for the proof structure.
    pub(crate) fn get_baricentric_lagrange_denominators(&self) -> Box<[Fr]> {
        match self {
            ParsedProof::ZK(zkp) => zkp.get_baricentric_lagrange_denominators(),
            ParsedProof::Plain(p) => p.get_baricentric_lagrange_denominators(),
        }
    }

    // Get the length of batched relation partials in the proof structure.
    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        match self {
            ParsedProof::ZK(zkp) => zkp.get_batched_relation_partial_length(),
            ParsedProof::Plain(p) => p.get_batched_relation_partial_length(),
        }
    }

    // Get the starting index of shifted commitments in the proof structure.
    pub(crate) fn get_shifted_commitments_start(&self) -> usize {
        match self {
            ParsedProof::ZK(zkp) => zkp.get_shifted_commitments_start(),
            ParsedProof::Plain(p) => p.get_shifted_commitments_start(),
        }
    }
}

impl<H: CurveHooks> CommonProofData<H> for ParsedProof<H> {
    // getters
    fn pairing_point_object(&self) -> &[EVMWord; PAIRING_POINTS_SIZE] {
        match self {
            Self::ZK(p) => p.pairing_point_object(),
            Self::Plain(p) => p.pairing_point_object(),
        }
    }

    fn w1(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.w1(),
            Self::Plain(p) => p.w1(),
        }
    }

    fn w2(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.w2(),
            Self::Plain(p) => p.w2(),
        }
    }

    fn w3(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.w3(),
            Self::Plain(p) => p.w3(),
        }
    }

    fn w4(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.w4(),
            Self::Plain(p) => p.w4(),
        }
    }

    fn lookup_read_counts(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.lookup_read_counts(),
            Self::Plain(p) => p.lookup_read_counts(),
        }
    }

    fn lookup_read_tags(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.lookup_read_tags(),
            Self::Plain(p) => p.lookup_read_tags(),
        }
    }

    fn lookup_inverses(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.lookup_inverses(),
            Self::Plain(p) => p.lookup_inverses(),
        }
    }

    fn z_perm(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.z_perm(),
            Self::Plain(p) => p.z_perm(),
        }
    }

    fn shplonk_q(&self) -> &G1<H> {
        match self {
            Self::ZK(p) => p.shplonk_q(),
            Self::Plain(p) => p.shplonk_q(),
        }
    }

    fn kzg_quotient(&self) -> &G1<H> {
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

    fn gemini_fold_comms(&self) -> &Vec<G1<H>> {
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

// Convert pairing points from EVM words to G1 points.
// The first 8 EVM words correspond to the x and y coordinates of the first G1 point,
// and the next 8 EVM words correspond to the x and y coordinates of the second G1 point.
pub(crate) fn convert_pairing_points_to_g1<H: CurveHooks>(
    pairing_points: &[EVMWord; PAIRING_POINTS_SIZE],
) -> Result<(G1<H>, G1<H>), ProofError> {
    let p0;
    let p1;

    let mut lhs_x = pairing_points[0].into_u256();
    lhs_x |= pairing_points[1].into_u256() << 68;
    lhs_x |= pairing_points[2].into_u256() << 136;
    lhs_x |= pairing_points[3].into_u256() << 204;

    let mut lhs_y = pairing_points[4].into_u256();
    lhs_y |= pairing_points[5].into_u256() << 68;
    lhs_y |= pairing_points[6].into_u256() << 136;
    lhs_y |= pairing_points[7].into_u256() << 204;

    let lhs_x = Fq::from_bigint(lhs_x)
        .ok_or(())
        .map_err(|_| ProofError::GroupConversionError {
            conv_error: ConversionError {
                group: GroupError::CoordinateExceedsModulus {
                    coordinate_value: lhs_x,
                    modulus: Fq::MODULUS,
                },
                field: None,
            },
        })?;
    let lhs_y = Fq::from_bigint(lhs_y)
        .ok_or(())
        .map_err(|_| ProofError::GroupConversionError {
            conv_error: ConversionError {
                group: GroupError::CoordinateExceedsModulus {
                    coordinate_value: lhs_y,
                    modulus: Fq::MODULUS,
                },
                field: None,
            },
        })?;

    // If (0, 0) is given, we interpret this as the point at infinity:
    // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
    if lhs_x == Fq::ZERO && lhs_y == Fq::ZERO {
        p0 = G1::zero();
    } else {
        p0 = G1::new_unchecked(lhs_x, lhs_y);

        // Validate point
        if !p0.is_on_curve() {
            return Err(ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: GroupError::NotOnCurve,
                    field: None,
                },
            });
        }
        // This is always true for G1 with the BN254 curve.
        debug_assert!(p0.is_in_correct_subgroup_assuming_on_curve());
    }

    let mut rhs_x = pairing_points[8].into_u256();
    rhs_x |= pairing_points[9].into_u256() << 68;
    rhs_x |= pairing_points[10].into_u256() << 136;
    rhs_x |= pairing_points[11].into_u256() << 204;

    let mut rhs_y = pairing_points[12].into_u256();
    rhs_y |= pairing_points[13].into_u256() << 68;
    rhs_y |= pairing_points[14].into_u256() << 136;
    rhs_y |= pairing_points[15].into_u256() << 204;

    let rhs_x = Fq::from_bigint(rhs_x)
        .ok_or(())
        .map_err(|_| ProofError::GroupConversionError {
            conv_error: ConversionError {
                group: GroupError::CoordinateExceedsModulus {
                    coordinate_value: rhs_x,
                    modulus: Fq::MODULUS,
                },
                field: None,
            },
        })?;
    let rhs_y = Fq::from_bigint(rhs_y)
        .ok_or(())
        .map_err(|_| ProofError::GroupConversionError {
            conv_error: ConversionError {
                group: GroupError::CoordinateExceedsModulus {
                    coordinate_value: rhs_y,
                    modulus: Fq::MODULUS,
                },
                field: None,
            },
        })?;

    // If (0, 0) is given, we interpret this as the point at infinity:
    // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
    if rhs_x == Fq::ZERO && rhs_y == Fq::ZERO {
        p1 = G1::zero();
    } else {
        p1 = G1::new_unchecked(rhs_x, rhs_y);

        // Validate point
        if !p1.is_on_curve() {
            return Err(ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: GroupError::NotOnCurve,
                    field: None,
                },
            });
        }
        // This is always true for G1 with the BN254 curve.
        debug_assert!(p1.is_in_correct_subgroup_assuming_on_curve());
    }

    Ok((p0, p1))
}

/// Generate the recursion separator by hashing the proof and accumulator points.
/// # Arguments
/// * `acc_lhs` - The left accumulator point.
/// * `acc_rhs` - The right accumulator point.
/// * `proof_lhs` - The left proof point.
/// * `proof_rhs` - The right proof point.
/// # Returns
/// * `Fr` - The generated recursion separator as a field element.
pub(crate) fn generate_recursion_separator<H: CurveHooks>(
    acc_lhs: &G1<H>,
    acc_rhs: &G1<H>,
    proof_lhs: &G1<H>,
    proof_rhs: &G1<H>,
) -> Fr {
    // hash the proof aggregated X
    // hash the proof aggregated Y
    // hash the accum X
    // hash the accum Y
    let hash: EVMWord = Keccak256::new()
        // Proof points
        .chain_update(
            proof_lhs
                .x()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .chain_update(
            proof_lhs
                .y()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .chain_update(
            proof_rhs
                .x()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .chain_update(
            proof_rhs
                .y()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        // Accumulator points
        .chain_update(
            acc_lhs
                .x()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .chain_update(
            acc_lhs
                .y()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .chain_update(
            acc_rhs
                .x()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .chain_update(
            acc_rhs
                .y()
                .expect("Point is parsed at this point")
                .into_be_bytes32(),
        )
        .finalize()
        .into();

    Fr::from_be_bytes_mod_order(&hash)
}

#[cfg(test)]
mod should {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_zk_proof() -> Box<[u8]> {
        Box::new(hex_literal::hex!(
            "
            0000000000000000000000000000000000000000000000042ab5d6d1986846cf
            00000000000000000000000000000000000000000000000b75c020998797da78
            0000000000000000000000000000000000000000000000005a107acb64952eca
            000000000000000000000000000000000000000000000000000031e97a575e9d
            00000000000000000000000000000000000000000000000b5666547acf8bd5a4
            00000000000000000000000000000000000000000000000c410db10a01750aeb
            00000000000000000000000000000000000000000000000d722669117f9758a4
            000000000000000000000000000000000000000000000000000178cbf4206471
            000000000000000000000000000000000000000000000000e91b8a11e7842c38
            000000000000000000000000000000000000000000000007fd51009034b3357f
            000000000000000000000000000000000000000000000009889939f81e9c7402
            0000000000000000000000000000000000000000000000000000f94656a2ca48
            000000000000000000000000000000000000000000000006fb128b46c1ddb67f
            0000000000000000000000000000000000000000000000093fe27776f50224bd
            000000000000000000000000000000000000000000000004a0c80c0da527a081
            0000000000000000000000000000000000000000000000000001b52c2020d746
            20dbd39855da0aa548efa88e9121c530a646b3ca56596742a69218cb4bff670a
            29326f97cc3576a3c23cd4ad5f23986b5d524a995cad2d34a9d0ca74591cba5d
            16652c79cc682038a0006b6f68d3d70f3f577125b5c714fafb9e9f6ef661310c
            0951fc2f821c85fb14ca27f5a32b19122e740045ca70f261cedf622c07e756f4
            20725f498951a13bbc857a2b71cc149689fcad27c9580e16c5bf2d665da69699
            21dc363d97ce40779ed836753433894b9d5915699b8452c14683da36c92f63bf
            254892d851dc1b87abde9382e2645314f200907e4433e11d4fe1c51c29dd4537
            229f24a429b1594eb19810e6af69e0606d11570db1170da181d400af7abb8b28
            0ee6a5bd135a17dff958fb78d97c1203653798c08baf86078941421f26a29387
            134b54989843b1d3627bc1fcf82f37b493316789a14c3883c62bc4855166317b
            13ee0b4fc9ecca5e8817912f6a91bcbe19a582849a6b1b1cba534226b97762a9
            0801ab18a97fbad5577e56536354628708a6e51880f29eeaa4bc25c5944353a5
            16faf00cd7dda6bf9ef9634d772ab29a9d50961c4a3e745ecd81436fdf66c06f
            2646325454cea518ebfa2f3cc4547e45dbf554addb1443cba9e489ddbc455c99
            258bff351061fc5d4e0553f63cd470933832112025a3290080fa96d846a7b291
            0b4368734ebec662d5e5dbfc1c2b9b3c83d0d0a3e6a7685b3a4c299840735885
            17880ff944921f65ddda1248d9ba177fc6f47b7ef624eebfbda447ee42199d75
            212e373ffa96c2a36841b2b0428c367a091166e5bf5fb9e400f1c073a554bb2a
            2f4abaca1d27b556f61ab045a7cbaa869d5332a28daace4f63a5000619fe12d7
            171e6ee5827b7d79bc893f7aa649138a9f3f343dcf56905c4aed9363e5f9dc96
            267880c1ca908505e734f7bd99ea71306ef21c985b513a22523ecfa5c1f612f1
            098b44b1507ba8db1d47e3125b281679d510972a84ddb88f57b679c2f69e6b8d
            268d0d8ffb1424f581378c4f07d9a709ccf6c5be13b8c99c4343886a0e51078a
            2edc537901834205f25b503c00aeabab11a2fe6b65b3647dff86027b9703c60d
            081b9ddeee3769f98d5f26e615e3cfba0d4a1a82d9d8ef356c6a74a7ff98f83d
            2e87e5b2b38b5fc5aded646157e1f89870f05421547a6776fa03afc00d5d093c
            03a7289456608694119f146c7a5cc5a662974dc04aaffeca44fa8b943dcf726a
            18a72fcb13b0fc5a70f570c43dd9764695919e8edaea9b6fbe6a9b74b3f9e379
            127e71676bca8980e2778cdc7a19fea79dcaf2f478f1d063b95889c7531da305
            1219c1a8ae910a0600b12c117c6864622e20c858cdd8ab2b163959c69d3c074b
            236b773bd38c15c98764ef57c0111f460d9d2c00777b3d05fdfa4716a7f798d1
            29e112bbf1e66e828187c083d7cb847b8434d43ed02a63ffa5c9904a833031e4
            0bf2110d7d458accaa14041b73e081dd7eec04ba804e1110632f1ca23444f88b
            2a02593dc3dbc57728f648b892c47227fa518d4dc68eb73a526d62468c64aac7
            221f9c92482f97948829168b4363ae03a4afad292adaab43fb48ed8cf88cc880
            13ff4b98fb2c1d79825a786d19d934bb1b1e22c4851d70a0214670debc9c0693
            2894cd723607484505ab3040c04b86559db78a0d687a07a2a3fd20e5c3ff6094
            124f65fbbaaac103a605919deabb61f3f513dcfa50ab83edf422def51f6822cf
            1f46f0d081d14fed06f08636d9917074df1cc4209110140d55c2ad8133bffb79
            09a7763cfcdf85ec164f3ec40550f7f66e6b720ed670362fcc78c52c169d9a83
            0f159b6cbecc00b2a1e7684b6e1c8da154367d3655de3941b14f14fb0b574926
            2d52975dd8517dc9d78256df9c8cda062fb8f12fc9f89d8fcb819962d0b41e70
            1753ea823dc76ef98ca91b22f2f2c0f40fd4efa57384d030678f358c998c2742
            17c8a0d3a0842ff07f2224b7b1394fb89ff5e5d352c4baf19be6ceaeecfce8f7
            1c637ec0cb94ef3226216029f20be59776f815ad4e17416198b2e06b5145a36a
            130b1177666bb661e6553679ca980ae9dd39c861027b40b65183bd626c9a06d0
            0a57c38debceff4e193cbea664a7fa0471d5d672d07609a5e53824035ad21f42
            2be5f909819636ad4d8ff9a45983c6ee0bc6504f60f269855befe09eef842623
            0cb8d9ef9507048a70e210d26fbc82d1e2c6150ba7e12f29d1d65797e79fba68
            1cd31ea298974bcdd66476230d4d56ef5ffc7813c4c8dc88a9396f08dd954503
            141c775cbe89141dcf9d21990ae5cc54fc0392a9164a6e57daafff48576ecd4b
            138f1fa72392f850a6c490a32d1487f38b78cf42b9d3d307e7206dc81a092963
            189d8c38a00b40a439278f86813dcc6dde7b18f3442e819304a72f489b0ccdb9
            106ca2de23064fad6b947c21bdb25a0e76f471afcc4e2727e5e8abee354c34da
            0f7cdef80041f8ce3222941e6e0d69646d9985b23ad3b76188c5086a0691c290
            0eac63911f622d709d02f1e64d3e0ec3fbee17e5b99b8b82a369a37fc1638455
            29c29c1c2e5cf40953daba85ec793f41145ef7d7bc4e0cf87860df7cd98763b4
            27e23fcf4ab3e97a21d524ea8b141a2d3a6476a44768e5c956a187036e3f5c37
            1b68da77a0d8ae97761d4ca3ebd2ca1013ec60dfe9feda8190f077ae16541352
            19ce5c5a4cd9c5917e763541ff839942f3152d1ba1c7032a54bb829b123e72fa
            2366c13dd5096a74fe23f6b47f7d7e75781780646758be27ff4246c30bfef525
            0ebf028e8a1633463eb4cc4fe7e300d34ce8ca798115aceba14e0f2e7b579489
            19f43754f45052b8a2206e63c03645ea295e190c241f5bf32e7e066870e2e341
            0e49a82a18b0f22629f06d145bcbe05bfe18fcfd7ec405f3315dc6b8c5862b76
            13146a77b47a13bc203a69b2f5f7edf4dd4ab01d79fca800fdc2b0df80104d12
            2ef16764145bf25c47e69399e44b966117db9b7bae7b05543b54b48176bad8e0
            2fcdca252b870ed3bc2552db7a962808cfb250a7eb3fcb8e0404159f728cdbf0
            1c1c48a1ddb3de7e9150985d30cacea7ddc5d2bed2eda6683b2d5b754adf576c
            267cb00d9a401a574b856eae4800dc220308226b3c4279599a42b5e7f8900a4a
            0694d05cfeec672ba9fe4b6bc92b68cd160e2bf2413d84263bbb4ab38e815e19
            0686c1cffd21f48adadd7d7e71b40055d77b7ceab2d10dd745f9f79f2eead781
            1f6afffa14601b518b153a94f95f8213a96f8640c874d7da0f3b336b2ec9d524
            1feaa74f3320acffaf5314abdee72fed4d86b041a3d7f87be3e554464bfb6e49
            0eef37a267576c275aa773e6b3fcbd552c026f1e281ada2f672748b4a471e480
            11ebf66cbb95b6ad369f008ec711a4340280b40871335d8d534f2377299f2114
            2020085a94e6d8cd59d40a1e9e449f36479fca5cb83683041cc15251c77d7f63
            3025c8f3ec0a17c8c0bc00a7ee33ac803301be230dab47d29b017c9664523b27
            1682c3ec7727ada14a9c0e58464ca8b0222a2f527c39bcf2498bc174b3b385b5
            15791367a8eb9b83cf99b571c17afebeee5f208568b8f404c1c8219a71840954
            1e4d27bd8dbb7ca40fb99bdd420afb585bf65045a383c7ebabb9d555065b5f5c
            1051774645d46cf8cbd127905f2c698f097eeee0b939e67bd48a21300ce8007c
            0097f20d2ba79da9790e49cad048c59e9d9a47050aeca9598304d3390d43ace6
            24927e4acf7c86a512b9483c744a51c729bc9a1338158d79a8251c0b604afe51
            2ee8ad3000735cc423cbf2efab5f7abe6b90741085688b8231e3e9189f39dc4f
            00a8c021b4751fd7e54ed748d4c69f0bab9cec6e79c0e83e8fa0ec79b11af113
            0198a39cde78865e58b40f70578afb6f7e6bba88aae287eee79e62b25c8fb39e
            0459d56963ae60c915c979ed583a65f3d36618f959cf718496b64d2a992cc7ce
            2a98aeccdc1de79a075b82d40b735e7831538f5c5707faef67a1e1a4c5934d6a
            0881f2b17de0279fbbf8aa28f214ba850fabc55e41b327a85f8c123cee4a1dae
            079f730b47dd22154fa412a13e5c7d35d8f81e53b0c53d852b96bc02a25abee5
            14da085d2f32c56ae58bafb6c87fddaca20d5ef93e41186f0af167b66376e822
            2ea02e8776f250c4ddef43eb4683ae749ceb9baa203edf0dac6fee35a1a77e86
            2dc74d2a9b76c3f7fe3bfb07ddad1686d3d4d32cd1c42b6ed3bb9930172c8b4a
            0db0cf48daa06b403b89e9862416955d10bce0b7091d510dc3b6e2333928b698
            1e24a79d3a4f3b2d27725238db6fbfcde325ceec4c76037401497b366984e354
            234b6afd1182f664f5e6b79cbba9e037b783a40d2c9eb2908b2d7511050e7108
            00070b79fab1e11c9117e6a34f511877bc7f6bc2fb7b749d6e7f0e798ebe65d6
            2ac3e3025c58ee93656e34f8b4f1a7a4a322e52348ce7a6a698e7140bd415bd3
            102a26f46b2e3c881397d52ca12b5ad5bde5557c6dc19b98e97cd1b76e7add31
            281bdc7b429bc1570133fa673276e7dee225ef8c08352895b7962860b7dbe8da
            237a96bb061658d70845461043a43ad28e7800bbf2b67cdf734c4c457e92ebb9
            0cdd29dfa452d03e0ba1819091fb09ffcb4510838a283cbb64c526d1c0b5ef6e
            0ba06bf8638f3859d74fe0afab82e061624ac81e3ba2787d341e12b9819df59a
            102055ba1dcf8bff926c369f4d4f684559c3c5152bca8d9aecc9cb26b7dea2fc
            164c5a3a3e74a305c6b10283e18496a728b94815ed1ded71f012e7bcca683ed8
            1cd14c9817efb4bbc7d11d1bfd7203ee8560814f4672d7c817d50dd856a5929b
            1ec151828c0a96d613101f9c21cd7120f99308638ec109e8a2ed708533fa7992
            2afe65cf4a9a43f98131560ef5fcccd5558150ced128a3085ef233293701798b
            280a7a119d1d0a7d111f88828d8f505a9c80202b742bb4d6fbc1693014905729
            13a4f0d54a08d3e55266d8ad7d4f0fd5ede71291f751626df30438b669f3ee2f
            0dae8b1c149697d68c533f0d49887277a855515992b5f1aecc1af53aeb8b4f43
            1a8cc5526e1e2287a20ebc481a2b6c737810a1cd83e0854a4a2d2875403ba97a
            15dc6a9e8d0718041de773a8752ec7d4f90df7e63214604ffea061a1b01fa1be
            142718c392de9ea81680132c510292b83c082f833ae744431fb418f4ff5e9d3a
            0cd53d54207960e0a2b796328a6a4f4b4cc2a42f9caa63f645c0a7f290554802
            0773cfa3852ae065b2251f4c21dfe728d3f8dba1059c6af24357a53cf3a930fe
            14d7b8f8e648ce4b2910aafd7949dcf160e479d3ee1c3e80ff2ead0ee14aedda
            2435d653f32e291c1ef99e3162f62edcc603b4093f2c7b4756f22c1aaff1dc26
            1575693706894c96a2d380f508a1b31057e5b06341d1b97470d5271af86bb36e
            2ec2e3e8c10f62c3f72ab421d9a4173d363cc428edc8a79884266077c3c2fd3c
            2e04bf55eeeb3c9a51f1f742ecc1b9cd83c31f6abb0f94a529dff160ec0e2fe2
            2f3af2f3a83d91a6a27a11b2ae94ef535e2ce830ae6ed2a1ad212bbc99b9fb9e
            04c46816056c9908273a5344ac082e016f654484171265fbeb06018b94747ba5
            26119f022efc7734a54dd8c05280d1cfde84fa98845bd5293d0d9af7b337823d
            06607eb57658f40e839c48fd96a60a73d15465fc2d82f27b9a19b5844df13eb1
            1c42e6eda894cab333f4f1038cd1f6550975db5209a78c7988d543334fcb26be
            04dbf865b3a63015630a9b49d58c0a9cfacae6c4e73e89df964c343c74b4ce56
            03945a36c21210b61362905e696afd26a99bb53c6e445dd7a382476d9e1a4583
            2c4ad47d8fafe3778e645c9bd2400dc4da14071b96bd4986d48448edea22b631
            19d224f555dff26e48fe7009e947517952b095688632a7272ffe42efbd8b429e
            29d4684ea9ce4812b1c14dfd1fd11af40553982e98b164fb8e0e1a997fbe8aeb
            06d420ae8d5020c377dede1a01f2dcbe86b878e27a664fe7825acd1090b7fec2
            0fc9d6f20276a25bc7b1e51cdf3422013ee0d73323c1f312b0935cb31c099ba7
            1d72f328cab864a9f9541c070dc4a1994c8fa60b4b5f88bf75761d6a463c0e90
            22c4873f1a6da20eee0aacee3abc1ac2815e2560fd02e7619482868acbdaab69
            07be0912afd969e44b71d223cb9d04162848a2dfd5413c37349a3edbd4c56964
            01c78cbe6d93caad7e9ab76018a11f47d46b1210aadef72b04d282a3a5808f98
            0c9b0aeb9d6cea5e0815d11b9f9a60e1e874896b504b221399403259e89cfe7d
            1a6ec7a3633260596c4425b3071658bd86e4ed1a73acccd7e2ae0e7fab2ed904
            0fc90db411671e1f54324e9ba1140f30ee12d89265d335147a1993aec7a8387c
            031953cb03c6f4000a60d7d0b7dd45751c221c832ed3afe2676a2b72a37d12d6
            0df84b7d7478c34911745f1ea44af560bd8f61dbce4e5fdad9e1237632190116
            2cfe38b63098dd7a5038312f598b053d3308f9427135365800a47a0e7c63b650
            1ce4b58f3ee7be1f31317ac553f8cd73024c3d06bc27af13db3bd1f898a88b90
            048282ff3f8d70fb0c802852dd10d812de1822a756b349c9428a88215be9c3fd
            2dde1228cd03ce9ab75a15e187ca3b372ff5df4695718679c8bd033178d44279
            08cfca96786e5659f533fe71cbe30f1da4bc8137b3e41b41f514a4bc73997f93
            1dd64833fdcdd71f8f38c43abbd152a2c1e07bcd72908d99d5ac5c2ddea227ad
            159a64eeaac62924d5310e38269934d0142067fcd187fd9d8cf61d8272733918
            2de31f01fb9f48e4b2aefedbcef61e350f15d2d87af2b4ba8d79613ba7a801e7
            01cadd955b70d4ff4975eefa3847426183771e9ca6ef38999c2b424e2b550e5d
            27f4f7c09f0f3704ab462611d3ab596281799e2c7e651537394f07070425551a
            3062d6f4776d163aec62a99223cfb27922f57401398610ce37b701ef7a46415c
            0cc02f8c745167b158c9de83c0ce85a14ab4d3fe3029c91453af591b54cbe467
            2b90ea245c637ec4199a995b856f37aa0fe5444f91732759410a4a42cfd30f32
            12753f2321936b70d2096460d694056a721b8cb9087e1c59d289889a9075e95c
            09415923eb019b4f1dba1a0e0ea067fb2bd51739b71102af7b4186e75b055b0d
            27a1874f197ce2af4e45edf6082df90dfdc06ffeaccc5d01cbd4db7376c823e4
            116752ef8c1c961e341e3810dfe55d6376bc549d51d91e3767eb9c0e1cce29d1
            02d04e6d9cc49c8f0a5352d1c95d3fc683b2038a7c0899482fd306837985b13d
            2e686d35e70ebcb7e42c3181d03660d0301704984c33bcafe48ed7c7a9b5879a
            17e2ee4675850841dcd1570d120c3cf82f61a767d6bde76df42db23f9997c46f
            1c277530f248373e3349da9b67f56337110c455aac008e88befc0282d31cd0cf
            24d015c61ad0f9336cdb2b7de62e4a5d5c9d5e91f78a701919bb3297ec012a8e
            0a8f2dd141ca49cd88cb996a3da2b1c08d089f6920746912616493c14e61fba0
            205556a3765d14168725d0f89d2dbd6aad946c4f898839587ed2a342383e0472
            1f5e1f0c5d42f20e6876b3cd6b77b488e825052f5782bb4cc8b240ecedd2c67b
            152986d7f49b37be20e0b6697bbb4925bc50dd240f26a8f0c37ae58478adf455
            1a0f68e87177100f9e0d4e541bbb9e297e86aa6cfaf27ee3c09610f1d0fcded0
            1353b2568ba1e991a158838823d69fd2e86b5776be6c89d518422d3fffc898cb
            1c2e1166255e1c30e5dd349ec009c9a8c6b060f1eb386b0694d53035d8c6b7ee
            0b970de9ec55ec0438a31a57a863bb3010d1511536c918915d68a1a7858d9f05
            18d55ca82771ffcedb56759e127950591167e63c13ec88200a4a3a80ac66fdff
            07c67faa5c2cf0086a45dfb75a978fecd0cb9db5f6f82bd3c75b493f990fa0a1
            065399b861eb6b466e0454406e30de4fa8815657c329adb5648ce1f3be4e9b56
            02253b4b10d74c5d8a1c5169f65a2134b13ae35c0695a3daecbc4f8c5534464e
            1a39a2cf2ba6eca2898adcad39f42aae4f4a4f1a4ee15a414b0bee15fee5073c
            0a881f52836a19d7f22befced8518dcb09f3227d4bb5bab014c6abb015b7c97a
            011ec33a66539c630125f27d23e74f7b02a578ae9f8336337e1bfa8aa605d42f
            172a74ac558e19dc83d059b69fc77be8fe33f015430a5dd988e2c8883b3f0440
            252a96a1a0a9fcd20d337d78d63ad7bfb16133e3848f8deff78fea4b35a6d2fd
            1a2326c5d94ba5fd1c443a52df52f3ad02b4039b0dcfb3a10810c0badef612b5
            2bdc511f1a582b529e8dd9c03406d09168a170647cd0f63eca191db1b8f33ae0
            23556570c3d67113b58d095df1e7df43fa1147d6f431f587ac2fde328f305885
            1e512ef9ac7657de0ddf3e0a850e4f081ce2383f46f53c87dbcf6f20dd9edb19
            06715dcdbf4b36bbb8d5cea54d6ee15d3422b2101b4487616fe4fa0f61e7402d
            08e1343690d98fb3e2af8ffad5ecd8f03589c42f46c2d87833dc50d879f05aba
            202d6cfc4175ae5dfd3e8f68450b4ff600d384b593b4d23da2de5b207bdff968
            1f0f5c8a3ec9e80502473a031e152bfec0ff24e3c72db067f2b4e8c4a9c6cd65
            29ee156c415d799f02985b486259074eb228db1206bb58f6d34bd45f25e56680
            176381a12a2396ebb027d6c567a7d9c4e8a0525d6144e36237ae902d54bf97ae
            1dc14ab63362584fc58516429069bded05d7b01f0a993b8ee76cbc3b693df575
            159a53f645316fbc87d4dcd69aa771230accd0261d9951e1d2c2727be5ee972a
            1ab1a5781091dc6fcadc168a17355532d6862cccb2fc29863f0d2d4d5277aa94
            183a27258a8df3df8d40b509032ea07f4d6c10a203bfd026f18c5d14f04cccff
            24d9653c234ede4bc71421ba4d5afca34dcf37d13c05f2b0e588557eb542ebf5
            29e9af3289356559e9b48682bb9e2552421deba4349c02513c9e759f4c1ef45d
            123e7f0f251178a617c85709051460b829963475a2cd13d9a0d45ad25ec55805
            17aa8e3056ca0cfbce7a5427fe4b7195993e029a811eb0b7d9bfec78b8a50599
            2194c4e294056dd4eec140e98d8f7a729a3095b99d8b13f5a725dd803b90a77c
            23eb009bf475a1f79dc55f6756d52509799442bec852c9568dcf40da21db4064
            2a775d5093e988c0eb085fcddcab067fc8f8ab235bdf586b41ffa5341e8633f5
            156d328fb54f6cf94b5220cebe30f17d71886354e2369bac901549c03e59c9a8
            215cdbe7199af0a71dd07116ec10e263703751888746b9075ddc88bd71f45d18
            0c4ed78687209e627b31275f993dc9cf84ae5fcbf4b94ea58ca2a29102931f92
            28dd460ffc20a1677bdc1e3c3de65f3fbe6aad32b3ac638b9116db078b75ebd9
            2455bfc4cbaef5ddad43951a04627a0477d0bef940cb8a91b0b298597d9cbeac
            0bf965ffe5b177c70752e175d534a3a7bf94b6ee8e67826b3f07372d2586f715
            0c3625369fc749ed41935464f2fe05a48001315f148d56004423526735a5e7a8
            1bc278f24141c994809bea87cfcb4635c0564735831a32d1ff079d512f289143
            0130d84512705f0a69dbccfd222ee49c16c6b0197c44e7f80c60985bc43b5708
            006071459478b6822b3df3d942e236da79dba2dddc9d4283d4da189139ae3556
            23d5595b9e28abb659d38c0e0c58b4ce2e2ade11914ebd35a74537d965b9e727
            21e194544065ef8e6aee58cf8b6469f119ecb60c47d079e9e1e70bc3b3875754
            0eea9d5dfd19df934e1102c0705a4ebb321f013386fda8bc9e8102b49ed32f2c
            204f23e54a35896f471a4f9bc3b002d0b413e00bfc83bbea9b7f311067996d69
            17c1e0edde3648ccad3ba37944337a340ef82ccf8a583d37414381dc8bced939
            0c66ff9f9240afadb9892dfd09a37acb9891a1b79c1107e155bdd338a380b80c
            "
        ))
    }

    #[fixture]
    fn valid_plain_proof() -> Box<[u8]> {
        Box::new(hex_literal::hex!(
            "
            0000000000000000000000000000000000000000000000042ab5d6d1986846cf
            00000000000000000000000000000000000000000000000b75c020998797da78
            0000000000000000000000000000000000000000000000005a107acb64952eca
            000000000000000000000000000000000000000000000000000031e97a575e9d
            00000000000000000000000000000000000000000000000b5666547acf8bd5a4
            00000000000000000000000000000000000000000000000c410db10a01750aeb
            00000000000000000000000000000000000000000000000d722669117f9758a4
            000000000000000000000000000000000000000000000000000178cbf4206471
            000000000000000000000000000000000000000000000000e91b8a11e7842c38
            000000000000000000000000000000000000000000000007fd51009034b3357f
            000000000000000000000000000000000000000000000009889939f81e9c7402
            0000000000000000000000000000000000000000000000000000f94656a2ca48
            000000000000000000000000000000000000000000000006fb128b46c1ddb67f
            0000000000000000000000000000000000000000000000093fe27776f50224bd
            000000000000000000000000000000000000000000000004a0c80c0da527a081
            0000000000000000000000000000000000000000000000000001b52c2020d746
            2e387d31be1806682bd9795d4a8ae3506c19e907e4d72018624f7c3dbebcefa1
            2f3bcfbe2ebf68ac234cb22ef053bfcd90544804e01e74be9b619f359d3d942d
            10384baa634aab94925080d29c88c8378b47a63f3662742e85618a626aba9dec
            1a4f90011ff7b8ab0ca22c961dfe0853d142b604bac3309ad97bb589983b4456
            17c5bce3cce5b0980c14fcbcf5839fb9199a8233fed3fb960a205c8c92bf64c6
            1a199a87afc59f9838c4c8b02f35840d6d0d157e001a4e54aff42834cd03054a
            0e59187557f6855bde567cb35ede8679cf93b804469cfd1aed183baaeae73de8
            094ed7be0bdab40ba71f0b5a713f468bd253f9ec6d2aa0aa50326c8365f4771f
            0e59187557f6855bde567cb35ede8679cf93b804469cfd1aed183baaeae73de8
            094ed7be0bdab40ba71f0b5a713f468bd253f9ec6d2aa0aa50326c8365f4771f
            0aa1378eefed989342b96e2a668c4a8aa4c595937f079d18cfb736aeb835a3ce
            0cb10931fdf0585655917646fd1ea925362077daa57170b461f9f0309d5aaa3b
            0fc7467b1aff327e148f2994594e0ced7925d979e0ae969d78f1a00dc81ac2c2
            189f2e18a3da3d0554ab959c76bd89e287fe9cd7c959240d7534a91909c6feea
            24074f6b36d6abc6b25a2b4dd39b01a3a21bf07a3965555c0649cbb1a4476351
            01761b96675d453dcbec88a2ed8f65c4d6e0bbe6654155e915c58a05a0222059
            236df6b800c9d6b1ab82a3c5f421e10f246cdba4e1b527955474da8de688e96c
            0cf657bae067c9780ccda1f08d5f774e03c70ca3980448fbef6d1b0609771695
            0c82505c62b40d34a7157579fa5d1f0ec3d084af1c52ad745fbb8bbab117772f
            1c4b3ec7f13e22ee2a8f0553da0e2af963fdf87c3e5b33c24f9cc4a705b224bb
            12b26e95009817a1198848673de021c79c1c48919a4fe0f485dcb8af6f840be2
            0ee5f955b4b17784dfe4105c3b2ca8798d9b6d8e16a1402a106ef4c605e74801
            2c8c446f1f56363c37db1635e6c1da4bb61537a1e5ed55e2bacda525a67ba73d
            0fa30793bc666c6e04f319e63f0517859bab9a137a42788e9bc5415f844f5722
            0e5c7e43bfdd091851923ecaa7c71c4e32fad9c9da56f5599c532d452dc09d7d
            2e49dbc6dd376920ca935a91e4c43007cc0e1b89b919245e44e79c6b800d477a
            05979a0984330b0885047bdef9ada0cf801b3dad711532f019c4049672d76dfb
            238765655da7949dc7d5c1f7a258ac046cddb2ec49fa3a1ab54aab270f1665ab
            1b651c214c4f7378125412523417bea62b89bd2ed138850bc5a49fce15fa7dcd
            2e609202a36f0a3bba78cf79f98455abcbd3f0917b89acda1af4923e9d0e3aaa
            1677a85989f577d631257e5f491538ca881ca1d6c1a9a2814f7528ca7fff5392
            0d0500a64a52dd195cc2b452ff25617f7038bfed8ecf86643257be82f80f748b
            1b906e920dc8b58afa4c704d9df06644823c73aa4e938b70b70945cdf3b7fa1d
            2efa506314bcc284b698d1e158fb9447ef993ece70f22b1aedac2f2c8785a99d
            26dadcd21d2ffebc79d090583ddc38314f6c50ee56b21f6b0c515b3ca304bda3
            2add25bc4336ea8cbf48ef02cb95f6543ee6aee8414768eb104976cc36813eaf
            0a433cdc9cbf8aed6d2e67be4d8bffbf496540fef8a3754e994005bba7382286
            10e1ae909343887b8657c22c8c49d4b00aa082aa41f6c0bc9cfcdc2a3310d793
            1d0ec54e041dfdec8ed4c80682eba06e8eb21066ea7e6af555a84fb0e3778807
            2d2ecb6c1bd098b2e08d37a8b2bd0cbf9b6280567bae39f9ec936f7eff5814c9
            22692592696138e7fd49fed4a06ee13c60b998511f863e170e391aacbc530073
            237ed6e5133e455dbdd76262f3edfdfff12595e48ba68aad80b36438b023f283
            1c2a6c55a1360e2d47a48956b432555f6cae4384d90ae82c147997c48430fb1e
            2b2fd91e981b12061a0bf3d0e249dd9cafdc133af4ebcf84c0fc89f916aa6cfb
            1087869506b05288247b101d00576bcb17ce671081c06fa7a44252da190c8a32
            0462554ed80369625304f9eadf56bafe79f1db8991f3ba9a1f017640191f0a5e
            1b903fd9bb99d3d3eb01da52180643f2285111139e88c0c76f20fa0a055ff6c8
            19050ccd6595dfb7d6e81908dbab73dd307d15f2beb4c38096ce7bfa63c1714d
            02c5ab9cc6aaa728778d8f35e01f09ca01fb5d86e1034bf60f2e5f019582c64a
            27ee1c8be988be8dcff01969a64fa2389d744ea86f082fee17228539f837c253
            0925234379d34675e4518b440d2468397876848cf47d9ff1a4927f003f035021
            2367fa2f0f629b6ca6a9f661d2fed0d5382fb6d93912d64e5e44795f41c168b5
            1595e610684aef5e9c0a08c0072eef82fe28711eb3881da385a5ed545ae69d59
            22050f7a869f65e9edcffec288db9261a187f8ff95d3af00f577ec65bd77bbda
            0e3ab3d105868a1129a986598eb960db7cf0e6b0efb2a88ba736cdb0b4307e7b
            0451612c31730f9d68228c7b051833451e9fab06e268ae96f05b36a5cd0a6657
            1f3d569e46d7324c3392d1a668c44333a7d0f6e1dbae040e1d30421301449e4e
            1b44458d76be69821d1a0a19a6c4ccd0183964ffca1e451aa67c696993f9b2e4
            02afc8ed078270f722b12331e3ee520666a61af0c1f44570b1b352e112bb50c7
            2fbb20342055fb3c9b2cbe3e19df5cf5ebd3613bc8e56b377ba4323ca62c7aa0
            2e599aea7e89991af3e0b39e03bc78bd2ab2c814e209cc736d49e0a1eb2d8b03
            280849e6f6640d2815f7e24bd151f455a034d1ca8f212ddda5e40ebe5c35127d
            2d36503b2635b6f12306f202b6f81a349a4188842e72655ca125206c032c720e
            0c8140be80168ca50bb8322d5d86cfddd02eb9f5f01bc3a385e3cde870f3ec17
            034de30bda6cd0fa5a44a1dc62af51a3943182f2cf6d5106f440aeee2dd006ec
            26f62033280c3fe00180785333ff0e7333285b3729d88b0ec02f4dfca237c8a1
            06673a27d7cd7ccc156da589834f535f62d7b8e4d652c78757624d5ce00f9ce8
            1a49f4c86b0371f023ddcbddb8d605f6e14b8fe90444e9613eb5d05dab390811
            23876842b42ef2d901cfba0db420322a6ab35cf8c9088c5ebfd0d0bacea81827
            00a1797dff71ed5761583446835dd23323cbdd1a09e124394c1de0aa0218e7e5
            0a75e5cf708dd856f677c05dd46c28d0fa1231b3c7185f9402d70ed719f8f9ea
            2eda40e1f1ecb1b7dc68e1d45458a2bbf2da496aefb7601d6f5a08337f8e4718
            1c01691ef142aec7ce99d98ea25bffccc0e67db7de950b6b4d2347c3c8b43869
            249aaffd62806f9725442f8aeabf853d8aab32b999d8d42edda50945491b2a75
            0aa1dbadffe37b27d5749a504287f8eefa37e839245cb63667085042b0da5ff0
            1d7728708cda601901ad1bba65b42b04cb9c8700ab052f1458197c3db2784331
            0a763687cff02252b67be544952c2b4a00a40f15cba52d0e129a691d2e70277f
            13cdfaa76b43314316d33cb6050da6241050c1c9046437c0f2a974ea8899071d
            1a9433ca3e43bc6ff4e9f061942fec36c4d363364e2bdc78fee60928de4b6f97
            0b51fb029ac19df3fa9064d68266b6c3937c497334c57a40a870ddb67fca046a
            185b14488dbf8f7dffd9d0d0be756d63708152bd0577fe45fd237d9958d26a70
            003bd05d0732263da4d6ce35b5c76be38d29a9ca190a4fe5af2d4adfbdb6d3c7
            11730e8bc016792e3706b7cf930960cc91617ec7fda3ad7a78caeccc4140a6af
            15a34850553f6ecfe0cdbbd05ab72776af5e37815b1b81bd239d7adb1690b799
            0d628a85420c8c9921923d310a762525b9e76f21a593eb61653c3a565be02e56
            22a0691f3c163476dd6b30b87ad7eb599517b19afd545a225e1e647c8bea04d7
            26f1d83f11f3fbc749365d1c691fa594ae7079a1bd6e60c93dda1d99ca1c9ec6
            2138f78eb78048a1be54c05b632800f8ad5916c8859700e67e6b5c4775877c31
            044e2534a4a926a20c59ee8e4b68c5874755d41a63b425fcd1b0f215fb696193
            2f69b032f75e4b716703761f0f194132f18ee05d5a8c0e9591b78f62c7dddb36
            26d4f0a8a4af071155c469b801bf726d83a32be8dcdad602dfc78bdf2ce9c9ba
            1ef34c14aa282dee8a8f38b4735e39d38b6d2fb383d599eb77e197399dbc55ee
            0a6e6bb1cb97a2adb62ccb451049ff83af94b2eb8b3fd89f0be031f489d3028e
            2632758e4f42cdf65a752a830a85078fdb791569d63c47ac0abfa32238fd63ea
            08b49a658139bf69c1d61355fcffd6a2c231ff3790e3a39cfc959e70e65b822a
            06bcf4c3ea79ee73ed7aec62eadd35f7b41a7a16c304ff6ad7aaa341e11f3381
            14733437bdd09fae2063238036ce8cb686c583ec174fc7ed11c2bce60407ce03
            1e2fd7b30348e9e7247bb737cec0ad491ec45092d41803fd229142a8b94bd601
            1593e2b479300da560022baeee1cc3f317f4241e52241818321714ada95d5c80
            1e1e4647c4ec50166d77648c2860ee48d76c8038d0fb30b81ea736089d0676d1
            0791a01be197b3cee6aea1cb61c05deaac265fc355d532f2036b6d628a3d3947
            1309646be4816c3b11460712980b7f59eca54c865d99ec77d8544202d56fb9bb
            104caf5cb5e36d205d66939e3fa4a6dca092c7037c4d8cb37fe2e2ba5c80f286
            0cb0f216b425da521faeacdc5baeffb8275cf775fb97b741b7f4a811ab06c810
            24841236427badf5bb277e1c03537b6af0c1e6a1eeecf0dffb6e131b980c942e
            20c402c8883c5d4282afd097e4c34aaf7098864afb8f8d8a634385e3e61107dc
            136ae55c85dcdb7cffd0c17e960f01aefca9b181871d178247021a5c5ed4dc67
            0531ebc26c1ce3112d778eb69409ef3f62276655f1d2ffae755fdef902a544a0
            1777b5ed1ac13553ab2e2eadda10c442bbdaddc3b9a171fa9747d3a1d819d15d
            194715b07b7a52c98ffa3bc668229e1f7354335ab074a9ce72cc20bf3ae7a9ad
            03486509b2b9ec5d25d4a9d933a4b1734b9255037a840c37945e598883918602
            0442d45f1e8a2a56af728f9739fff9911cda52858122592d7ba9afcca18ed145
            0c22b2f24ec12cc3bc30f2706e43dd8e03278ece7f043e0532b1df27c84de525
            265d69ef29ecee3ae63a7e500b325ab4b04aabeb81ed7a48476a2792029aecae
            1211cd85bd836c9355b80c0f28e4e3c2aa9367b67e9c981b43b4e1e684455ff8
            1ec99df5e72aec2a28b0ec343a6976744148ffac94abe1bdb38f717af7672da7
            1717c7f0e86ea4a6b4e6502eab3552c5855c12da212e7d47b99c827baa262a94
            199d90d8c8ed54566757cad771f16d9e0a6e47e7b50eb2cc6e40191295921e06
            12e7798e78aba28c14a6675484de5e4f3d605e04eec39cc6ffd933ed6f8fd829
            0f56a8a37bc4d2240b44263c7bd9bc9ef660b1a2c459e5565faeecdf580b046f
            0c36d38a56bc7ebeebbe35097350f9fbc77d032649f37c59a917f5c11d843282
            204c1e470af141086658b53873a7536adca86cc8a573eaa376750c2fcd6ec211
            2a2d5d104f13e876d7969b672240107bd685fde23af0e6887fe80454b6f99fe2
            01e88f628622cd133f637dada58b864a50cdcd3923ce5317200942705cfe74c9
            256203e8f8c89a05610648fdc30f4b33924209905c339fd9df4ffb8f1cf02172
            200e0f61e1190c33d7c318b20a989da314141ee74ef46d7c529a4e18c0377062
            20fb7fdf91fe4d8275e392d932bee1ba35315cc1e2e790bd205394de98b3413a
            27f17ef493a2494d337ff1ef151c6d7ed3f55d0dada19dabac560aa9a454266c
            0f42ce971303bb4411cae6405a31a41c45a3980c80c191664cc9b043a2f095df
            2e3099768a31a4c4886c713492bc83d401c5374a1457f2fa409bb1566041b1d3
            29d2ce5d6b33c5ee0b2210b1e4670071e10854ba902d682ea4b39d41cab90aac
            229e722dcbc5625412a260e40bbaf240d3761dc86cf254e48ef1a509f8dc88c9
            305e65bb2194d3e3f47bc18d9a871b156593f036dde477f090dce1fb5f5c67f7
            15bc348e5e4347146b1b7a44e7a76db0d6531c6a3dfcf36eb073664d20b2b35a
            0740149b124a9bb522c8bd0f6defe47314ea81fde587995561296e9d255d6adf
            1b15afdb4833aca8e876055a6a6ea01a18b75d2970eba96eac936788491ef892
            2ee8bf5c8cc6ecc41112bf66ad096ad5fc1df73ba391a494f1b158cfae31da8d
            0ea0ea4b7b574955a8a7a9eb7a49ce9e7bdc80ebae091cb91b96cc60fe4377d9
            26261e5f0601d35fbd58ec7e3c29986581c64811b4bf892c08d6b8ca0c9f343f
            036f2dd85aa094edd42f434293581da9f1d4318c4d9dfc084527e3642382aa00
            2681f581bac8e3526f5e3dc78319119257b13b9958aeeb1e3d68949f9c4ff932
            13daf91febc60682047410f88a3e54ce651e39c8fd1ff80a6c3718705966721d
            1d4d5e171a6fb9c6251cb5806d7cb114c7e56801cf988ffdb0e61c1f08eebb8a
            0785959caf6d3c2e1f37f89470332c0f4b3dce7145c679b4cb7abba6863c28c6
            18b89d45f71c985f7b29a7b6618766a597d4479b1c4459d16730f6cbba926932
            1585cc797f84078c4ab56def6ae470a16ac96b65a6578e49d9f6b50df2bb912d
            250537fc34ed6879ee293c5d7e57eac4e02a7ecaa840a1d1947313c6eb714544
            250537fc34ed6879ee293c5d7e57eac4e02a7ecaa840a1d1947313c6eb714544
            0432653a930a284387763576b56c9c21b1864f08b4e5bf4674b68f77f83be44e
            1552f8151a66d351b8d242e25605611496191b7de8415293d6ce621561180e41
            1ada9b6035dec39f23e782aaa01e96b86a53226555d929a16ea41844a6d1181c
            04c89d855e8ca5a85446fb59a94cb03e30745917f1ecda38e23f7fe6d53b3a23
            018328afb446168356331f667873ff74e27a51664f4b181983c598382ab10e59
            271d80780f82b22c71c2ccf6fdf3781bbaac93160708e305635317a3a1d50968
            0a98f25d81ed72ac9a1cabecca15286cd902e856fa78f473ee5a32dda2044143
            1915595294d64458a2d4899e10ce70e18ed0f3f815b11ea4d967584cab843c9e
            289a59c829c90c6441b135f0f9513b85a1724905a541b30e0594303b80cefc4b
            302bd2f7a456341a9f025a300f5ed911633fea25986a2d3026457cb57f513d92
            1bbf92a074524545f7d074c55c2eba8a9539d1e65b2a8328422d853437ef773f
            0d4bed12e7ab65a8bf50cf310d3f3eaf16fcce4989b9bc0e6694c1c933e4e934
            1a06e5e560285e317cc6dd2d9a4b24a4a601914f39d7bed331482dba0d11c165
            0f72c206b73685a108fd8931e0782580a60b5dccd6704ab20bce196bc4f48041
            2b79c45133143dd270c91918eab1776913f62f09377557a91d119060904afc8b
            063c07bf5d449748a09605305534b30fc1fdc88db2111be46401e21f7680e0ec
            24d0f60f356a5c5da0cf2bffd9405b25d75189f4ad85731656f1f921cac5cf21
            2cccd040070942c1411ebbe2715a5dd225318e23b657e5f5716a8b37864aba81
            00ef248a7c8c28208ba12b6401c4a22588957c1e5e699be61597da8744508a16
            11cfb8660e281bdf5c9a70d2f4edd245863af978c020245007ace82c61b2d737
            12d29f500e825bd8887d9361b0d8a58a19e579a84fd25415f25140541aa1a4c4
            25fc38f6e7fdb8406a1be0dc82a15d675bd836fc3a50d9ed38449810e20caf63
            0a2c101cb33d7e0e26becd47adbdd22f4b1c58d2fecaa8320a09eeedac2ce99c
            17c2563272e1cc32327365f10fd26f1b00dfb019a0652e9f81954ac95730322c
            170ab572275d5fffa1576b28863ffac40458e2fa5bef6bb4b145495755b3d90a
            07a21467b0d0b41d36e558e6e8e4f1364616d17eeb327113e120bb7fd1711d11
            1fe8836a2dcd26ebd9ee77b404c93f3d9340dfed48ebbcf44b2c59e649892102
            1b50cdcd7a3c96895ebd9aa33c4f400808ff89de2d6af93836743baf8d51a818
            224044de1a9fd64d53a609af96390d8693470a565af59fb7aea8a3046d97f803
            2b81c11b02127fb8f33fe0e22c920c797e8334a427319e20b78ba75c25c38506
            181f8378c284a0b34680b9ed6570e905d8d7e61343dcf947b7f3a30702e7083b
            2f47a3233c777e9d4d3006a5a7d209696370c1556b2af4a3e0dd7740db2ae385
            2ce4f978b715f04d1cd4fdf153fde9690858f3ce5bb89a015a55817b1194f4e1
            1ae484bd1ff3120693a43b6048d7ecf97e644711a3c30f6e3f882a823db08972
            06daf3d82e9e1e3cff9394e921309be1a5692d7a1b4d265c51e0c7165b98f138
            302b9d7eb3377cd1cbf2aaab133f22f385a26e7f104e9a64517f6dd8ff32dc1c
            1e431106016f8f531ba22a759bfd8f21e7e3751635322d468a0dfa312be711b4
            0e0caad29639db3fba648ae6662e0ee62bfbc2a75ecd65082e23b192282a6b3c
            2b212cff34f0949a810c8c5ad3e40ccc79ae926a264cec1d01353d444f3c81a2
            262ab6050ccfc4da8647c44fe7261fc22d42a738c7f5c504c825702d013f5c84
            1d97711979bdde13bf6a392f4bbcfffff3895c8da08079beef982923e73bf3d7
            0608d60337dc9feefbc313bb4df926b07a7472313df38d2ec4f2493715a0ee7e
            105a608cb1aefe667b1f1f84830edd0c64430b810b8d6d5793a227eb9e260bc4
            "
        ))
    }

    // This is normally extracted from the vk and is needed for parsing the proof.
    #[fixture]
    fn logn() -> u64 {
        0x0c
    }

    #[rstest]
    fn parse_valid_zk_proof(valid_zk_proof: Box<[u8]>, logn: u64) {
        assert!(ZKProof::<()>::from_bytes(&valid_zk_proof[..], logn).is_ok());
    }

    #[rstest]
    fn parse_valid_plain_proof(valid_plain_proof: Box<[u8]>, logn: u64) {
        assert!(PlainProof::<()>::from_bytes(&valid_plain_proof[..], logn).is_ok());
    }

    mod reject {
        use crate::constants::GROUP_ELEMENT_SIZE;

        use super::*;

        #[rstest]
        fn a_zk_proof_from_a_short_buffer(valid_zk_proof: Box<[u8]>, logn: u64) {
            let invalid_zk_proof = &valid_zk_proof[..valid_zk_proof.len() - 1];
            assert_eq!(
                ZKProof::<()>::from_bytes(&invalid_zk_proof[..], logn),
                Err(ProofError::IncorrectBufferSize {
                    expected_size: ZKProof::<()>::calculate_proof_byte_size(logn),
                    actual_size: invalid_zk_proof.len()
                })
            );
        }

        #[rstest]
        fn a_plain_proof_from_a_short_buffer(valid_plain_proof: Box<[u8]>, logn: u64) {
            let invalid_proof = &valid_plain_proof[..valid_plain_proof.len() - 1];
            assert_eq!(
                PlainProof::<()>::from_bytes(invalid_proof, logn),
                Err(ProofError::IncorrectBufferSize {
                    expected_size: PlainProof::<()>::calculate_proof_byte_size(logn),
                    actual_size: invalid_proof.len()
                })
            );
        }

        #[rstest]
        fn a_zk_proof_containing_points_not_on_curve(valid_zk_proof: Box<[u8]>) {
            let log_n = logn() as usize;
            let w_1_offset = PAIRING_POINTS_SIZE * EVM_WORD_SIZE;
            let libra_commitments_1_offset: usize = w_1_offset
                + NUM_WITNESS_ENTITIES * GROUP_ELEMENT_SIZE
                + 2 * EVM_WORD_SIZE
                + log_n * ZK_BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES * EVM_WORD_SIZE
                + GROUP_ELEMENT_SIZE;
            let gemini_fold_comms_0_offset: usize = libra_commitments_1_offset
                + (NUM_LIBRA_COMMITMENTS - 1) * GROUP_ELEMENT_SIZE
                + GROUP_ELEMENT_SIZE
                + EVM_WORD_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n + NUM_LIBRA_EVALUATIONS) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUM_WITNESS_ENTITIES] = [
                (ProofCommitmentField::W_1, w_1_offset),
                (ProofCommitmentField::W_2, w_1_offset + GROUP_ELEMENT_SIZE),
                (
                    ProofCommitmentField::W_3,
                    w_1_offset + 2 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_COUNTS,
                    w_1_offset + 3 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_TAGS,
                    w_1_offset + 4 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_4,
                    w_1_offset + 5 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_INVERSES,
                    w_1_offset + 6 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::Z_PERM,
                    w_1_offset + 7 * GROUP_ELEMENT_SIZE,
                ),
            ];

            let libra_fields: Vec<(ProofCommitmentField, usize)> = (0..NUM_LIBRA_COMMITMENTS)
                .map(|i| match i {
                    0 => (
                        ProofCommitmentField::LIBRA_COMMITMENTS(0),
                        w_1_offset + 8 * GROUP_ELEMENT_SIZE,
                    ),
                    _ => (
                        ProofCommitmentField::LIBRA_COMMITMENTS(i),
                        libra_commitments_1_offset + (i - 1) * GROUP_ELEMENT_SIZE,
                    ),
                })
                .collect();

            let gemini_fields: Vec<(ProofCommitmentField, usize)> = (0..log_n - 1)
                .map(|i| {
                    (
                        ProofCommitmentField::GEMINI_FOLD_COMMS(i),
                        gemini_fold_comms_0_offset + i * GROUP_ELEMENT_SIZE,
                    )
                })
                .collect();

            let final_fields: [(ProofCommitmentField, usize); 2] = [
                (ProofCommitmentField::SHPLONK_Q, shplonk_q_offset),
                (
                    ProofCommitmentField::KZG_QUOTIENT,
                    shplonk_q_offset + GROUP_ELEMENT_SIZE,
                ),
            ];

            let mut field_offset_vec: Vec<(ProofCommitmentField, usize)> = fixed_fields.to_vec();
            field_offset_vec.extend(gemini_fields);
            field_offset_vec.extend(libra_fields);
            field_offset_vec.extend(final_fields.to_vec());

            let field_offset = field_offset_vec.to_owned();

            for (field, offset) in field_offset {
                let mut invalid_zk_proof = valid_zk_proof.to_vec();
                // Alter current field; notice that (1, 3) ∉ G1
                invalid_zk_proof[offset..offset + GROUP_ELEMENT_SIZE].fill(0);
                invalid_zk_proof[offset + EVM_WORD_SIZE - 1] = 1;
                invalid_zk_proof[offset + GROUP_ELEMENT_SIZE - 1] = 3;

                assert_eq!(
                    ZKProof::<()>::from_bytes(&invalid_zk_proof[..], logn()),
                    Err(ProofError::GroupConversionError {
                        conv_error: ConversionError {
                            group: GroupError::NotOnCurve,
                            field: Some(field.into())
                        }
                    })
                );
            }
        }

        #[rstest]
        fn a_zk_proof_containing_points_with_coordinates_outside_fq(valid_zk_proof: Box<[u8]>) {
            let log_n = logn() as usize;
            let w_1_offset = PAIRING_POINTS_SIZE * EVM_WORD_SIZE;
            let libra_commitments_1_offset: usize = w_1_offset
                + NUM_WITNESS_ENTITIES * GROUP_ELEMENT_SIZE
                + 2 * EVM_WORD_SIZE
                + log_n * ZK_BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES * EVM_WORD_SIZE
                + GROUP_ELEMENT_SIZE;
            let gemini_fold_comms_0_offset: usize = libra_commitments_1_offset
                + (NUM_LIBRA_COMMITMENTS - 1) * GROUP_ELEMENT_SIZE
                + GROUP_ELEMENT_SIZE
                + EVM_WORD_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n + NUM_LIBRA_EVALUATIONS) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUM_WITNESS_ENTITIES] = [
                (ProofCommitmentField::W_1, w_1_offset),
                (ProofCommitmentField::W_2, w_1_offset + GROUP_ELEMENT_SIZE),
                (
                    ProofCommitmentField::W_3,
                    w_1_offset + 2 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_COUNTS,
                    w_1_offset + 3 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_TAGS,
                    w_1_offset + 4 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_4,
                    w_1_offset + 5 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_INVERSES,
                    w_1_offset + 6 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::Z_PERM,
                    w_1_offset + 7 * GROUP_ELEMENT_SIZE,
                ),
            ];

            let libra_fields: Vec<(ProofCommitmentField, usize)> = (0..NUM_LIBRA_COMMITMENTS)
                .map(|i| match i {
                    0 => (
                        ProofCommitmentField::LIBRA_COMMITMENTS(0),
                        w_1_offset + 8 * GROUP_ELEMENT_SIZE,
                    ),
                    _ => (
                        ProofCommitmentField::LIBRA_COMMITMENTS(i),
                        libra_commitments_1_offset + (i - 1) * GROUP_ELEMENT_SIZE,
                    ),
                })
                .collect();

            let gemini_fields: Vec<(ProofCommitmentField, usize)> = (0..log_n - 1)
                .map(|i| {
                    (
                        ProofCommitmentField::GEMINI_FOLD_COMMS(i),
                        gemini_fold_comms_0_offset + i * GROUP_ELEMENT_SIZE,
                    )
                })
                .collect();

            let final_fields: [(ProofCommitmentField, usize); 2] = [
                (ProofCommitmentField::SHPLONK_Q, shplonk_q_offset),
                (
                    ProofCommitmentField::KZG_QUOTIENT,
                    shplonk_q_offset + GROUP_ELEMENT_SIZE,
                ),
            ];

            let mut field_offset_vec: Vec<(ProofCommitmentField, usize)> = fixed_fields.to_vec();
            field_offset_vec.extend(gemini_fields);
            field_offset_vec.extend(libra_fields);
            field_offset_vec.extend(final_fields.to_vec());

            let field_offset = field_offset_vec.to_owned();

            let invalid_bytes = Fq::MODULUS.into_be_bytes32();
            for (field, offset) in field_offset {
                let mut invalid_zk_proof = valid_zk_proof.to_vec();
                // Copy the base field modulus bytes into the coordinate position to
                // simulate an out-of-bounds coordinate.
                invalid_zk_proof[offset..offset + EVM_WORD_SIZE].copy_from_slice(&invalid_bytes);

                assert_eq!(
                    ZKProof::<()>::from_bytes(&invalid_zk_proof[..], logn()),
                    Err(ProofError::GroupConversionError {
                        conv_error: ConversionError {
                            group: GroupError::CoordinateExceedsModulus {
                                coordinate_value: Fq::MODULUS,
                                modulus: Fq::MODULUS,
                            },
                            field: Some(field.into())
                        }
                    })
                );
            }
        }

        #[rstest]
        fn a_plain_proof_containing_points_not_on_curve(valid_plain_proof: Box<[u8]>) {
            let log_n = logn() as usize;
            let w_1_offset = PAIRING_POINTS_SIZE * EVM_WORD_SIZE;
            let gemini_fold_comms_0_offset: usize = w_1_offset
                + NUM_WITNESS_ENTITIES * GROUP_ELEMENT_SIZE
                + log_n * BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES * EVM_WORD_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUM_WITNESS_ENTITIES] = [
                (ProofCommitmentField::W_1, w_1_offset),
                (ProofCommitmentField::W_2, w_1_offset + GROUP_ELEMENT_SIZE),
                (
                    ProofCommitmentField::W_3,
                    w_1_offset + 2 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_COUNTS,
                    w_1_offset + 3 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_TAGS,
                    w_1_offset + 4 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_4,
                    w_1_offset + 5 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_INVERSES,
                    w_1_offset + 6 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::Z_PERM,
                    w_1_offset + 7 * GROUP_ELEMENT_SIZE,
                ),
            ];

            let gemini_fields: Vec<(ProofCommitmentField, usize)> = (0..log_n - 1)
                .map(|i| {
                    (
                        ProofCommitmentField::GEMINI_FOLD_COMMS(i),
                        gemini_fold_comms_0_offset + i * GROUP_ELEMENT_SIZE,
                    )
                })
                .collect();

            let final_fields: [(ProofCommitmentField, usize); 2] = [
                (ProofCommitmentField::SHPLONK_Q, shplonk_q_offset),
                (
                    ProofCommitmentField::KZG_QUOTIENT,
                    shplonk_q_offset + GROUP_ELEMENT_SIZE,
                ),
            ];

            let mut field_offset_vec: Vec<(ProofCommitmentField, usize)> = fixed_fields.to_vec();
            field_offset_vec.extend(gemini_fields);
            field_offset_vec.extend(final_fields.to_vec());

            let field_offset = field_offset_vec.to_owned();

            for (field, offset) in field_offset {
                let mut invalid_plain_proof = valid_plain_proof.to_vec();
                // Alter current field; notice that (1, 3) ∉ G1
                invalid_plain_proof[offset..offset + GROUP_ELEMENT_SIZE].fill(0);
                invalid_plain_proof[offset + EVM_WORD_SIZE - 1] = 1;
                invalid_plain_proof[offset + GROUP_ELEMENT_SIZE - 1] = 3;

                assert_eq!(
                    PlainProof::<()>::from_bytes(&invalid_plain_proof[..], logn()),
                    Err(ProofError::GroupConversionError {
                        conv_error: ConversionError {
                            group: GroupError::NotOnCurve,
                            field: Some(field.into())
                        }
                    })
                );
            }
        }

        #[rstest]
        fn a_plain_proof_containing_points_with_coordinates_outside_fq(
            valid_plain_proof: Box<[u8]>,
        ) {
            let log_n = logn() as usize;
            let w_1_offset = PAIRING_POINTS_SIZE * EVM_WORD_SIZE;
            let gemini_fold_comms_0_offset: usize = w_1_offset
                + NUM_WITNESS_ENTITIES * GROUP_ELEMENT_SIZE
                + log_n * BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES * EVM_WORD_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUM_WITNESS_ENTITIES] = [
                (ProofCommitmentField::W_1, w_1_offset),
                (ProofCommitmentField::W_2, w_1_offset + GROUP_ELEMENT_SIZE),
                (
                    ProofCommitmentField::W_3,
                    w_1_offset + 2 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_COUNTS,
                    w_1_offset + 3 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_TAGS,
                    w_1_offset + 4 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_4,
                    w_1_offset + 5 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_INVERSES,
                    w_1_offset + 6 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::Z_PERM,
                    w_1_offset + 7 * GROUP_ELEMENT_SIZE,
                ),
            ];

            let gemini_fields: Vec<(ProofCommitmentField, usize)> = (0..log_n - 1)
                .map(|i| {
                    (
                        ProofCommitmentField::GEMINI_FOLD_COMMS(i),
                        gemini_fold_comms_0_offset + i * GROUP_ELEMENT_SIZE,
                    )
                })
                .collect();

            let final_fields: [(ProofCommitmentField, usize); 2] = [
                (ProofCommitmentField::SHPLONK_Q, shplonk_q_offset),
                (
                    ProofCommitmentField::KZG_QUOTIENT,
                    shplonk_q_offset + GROUP_ELEMENT_SIZE,
                ),
            ];

            let mut field_offset_vec: Vec<(ProofCommitmentField, usize)> = fixed_fields.to_vec();
            field_offset_vec.extend(gemini_fields);
            field_offset_vec.extend(final_fields.to_vec());

            let field_offset = field_offset_vec.to_owned();

            let invalid_bytes = Fq::MODULUS.into_be_bytes32();
            for (field, offset) in field_offset {
                let mut invalid_plain_proof = valid_plain_proof.to_vec();
                // Copy the base field modulus bytes into the coordinate position to
                // simulate an out-of-bounds coordinate.
                invalid_plain_proof[offset..offset + EVM_WORD_SIZE].copy_from_slice(&invalid_bytes);

                assert_eq!(
                    PlainProof::<()>::from_bytes(&invalid_plain_proof[..], logn()),
                    Err(ProofError::GroupConversionError {
                        conv_error: ConversionError {
                            group: GroupError::CoordinateExceedsModulus {
                                coordinate_value: Fq::MODULUS,
                                modulus: Fq::MODULUS,
                            },
                            field: Some(field.into())
                        }
                    })
                );
            }
        }
    }
}
