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
        NUMBER_OF_ENTITIES, NUMBER_OF_ENTITIES_ZK, NUMBER_OF_WITNESS_ENTITIES,
        NUMBER_OF_WITNESS_ENTITIES_ZK, NUMBER_UNSHIFTED, NUMBER_UNSHIFTED_ZK, NUM_ELEMENTS_COMM,
        NUM_ELEMENTS_FR, NUM_LIBRA_COMMITMENTS, NUM_LIBRA_EVALUATIONS, PAIRING_POINTS_SIZE,
        ZK_BATCHED_RELATION_PARTIAL_LENGTH,
    },
    errors::{ConversionError, GroupError},
    utils::{read_g1_by_splitting, IntoBEBytes32, IntoU256},
    EVMWord, Fr, G1,
};
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
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

impl ProofType {
    /// Derives `log_n` from the proof byte length.
    ///
    /// Since the proof length is a linear function of `log_n` for both ZK and Plain
    /// proofs, this computes the inverse to recover `log_n`.
    /// It is important to note that this does not guarantee that the derived `log_n`
    /// value matches the actual value of `log_n` in the vk.
    pub fn log_n(&self) -> Result<u64, ProofError> {
        let byte_len = match self {
            ProofType::ZK(b) | ProofType::Plain(b) => b.len(),
        };

        if byte_len & (EVM_WORD_SIZE - 1) != 0 {
            return Err(ProofError::OtherError {
                message: format!("Proof byte length {byte_len} is not a multiple of EVM word size"),
            });
        }

        let word_len = byte_len / EVM_WORD_SIZE;

        // Compute slope and word_len_at_1 for each variant using the same constants
        // as the corresponding calculate_proof_word_len functions.
        let (slope, word_len_at_1) = match self {
            ProofType::ZK(_) => {
                let slope = proof_word_len_slope(ZK_BATCHED_RELATION_PARTIAL_LENGTH);
                // ZKProof::calculate_proof_word_len(1), expanded inline:
                let at_1 = NUMBER_OF_WITNESS_ENTITIES_ZK * NUM_ELEMENTS_COMM
                    + NUM_ELEMENTS_COMM * 3 // Libra concat, grand sum, quotient comms + Gemini masking
                    + ZK_BATCHED_RELATION_PARTIAL_LENGTH * NUM_ELEMENTS_FR // sumcheck univariates (log_n=1)
                    + NUMBER_OF_ENTITIES_ZK * NUM_ELEMENTS_FR // sumcheck evaluations
                    + NUM_ELEMENTS_FR * 2 // Libra sum, claimed eval
                    + NUM_ELEMENTS_FR // Gemini a evaluations (log_n=1)
                    + NUM_LIBRA_EVALUATIONS * NUM_ELEMENTS_FR // libra evaluations
                    + NUM_ELEMENTS_COMM * 2 // Shplonk Q and KZG W
                    + PAIRING_POINTS_SIZE;
                (slope, at_1)
            }
            ProofType::Plain(_) => {
                let slope = proof_word_len_slope(BATCHED_RELATION_PARTIAL_LENGTH);
                // PlainProof::calculate_proof_word_len(1), expanded inline:
                let at_1 = NUMBER_OF_WITNESS_ENTITIES * NUM_ELEMENTS_COMM
                    + BATCHED_RELATION_PARTIAL_LENGTH * NUM_ELEMENTS_FR // sumcheck univariates (log_n=1)
                    + NUMBER_OF_ENTITIES * NUM_ELEMENTS_FR // sumcheck evaluations
                    + NUM_ELEMENTS_FR // Gemini evaluations (log_n=1)
                    + NUM_ELEMENTS_COMM * 2 // Shplonk Q and KZG W
                    + PAIRING_POINTS_SIZE;
                (slope, at_1)
            }
        };

        derive_log_n(word_len, slope, word_len_at_1)
    }
}

// Trait defining shared constants with differing values per type.
pub(crate) trait ProofSpec {
    const SHIFTED_COMMITMENTS_START: usize;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize;
    const NUMBER_UNSHIFTED: usize;
    const NUMBER_OF_ENTITIES: usize;
    const NUMBER_OF_WITNESS_ENTITIES: usize;
    const LAGRANGE_DENOMINATORS: &'static [Fr];
}

impl<H: CurveHooks> ProofSpec for ZKProof<H> {
    const SHIFTED_COMMITMENTS_START: usize = 30;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = ZK_BATCHED_RELATION_PARTIAL_LENGTH;
    const NUMBER_UNSHIFTED: usize = NUMBER_UNSHIFTED_ZK;
    const NUMBER_OF_ENTITIES: usize = NUMBER_OF_ENTITIES_ZK;
    const NUMBER_OF_WITNESS_ENTITIES: usize = NUMBER_OF_WITNESS_ENTITIES_ZK;
    const LAGRANGE_DENOMINATORS: &'static [Fr] = &[
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000009d80"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
        MontFp!("0x00000000000000000000000000000000000000000000000000000000000005a0"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000240"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
        MontFp!("0x00000000000000000000000000000000000000000000000000000000000005a0"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000009d80"),
    ];
}

impl<H: CurveHooks> ProofSpec for PlainProof<H> {
    const SHIFTED_COMMITMENTS_START: usize = 29;
    const BATCHED_RELATION_PARTIAL_LENGTH: usize = BATCHED_RELATION_PARTIAL_LENGTH;
    const NUMBER_UNSHIFTED: usize = NUMBER_UNSHIFTED;
    const NUMBER_OF_ENTITIES: usize = NUMBER_OF_ENTITIES;
    const NUMBER_OF_WITNESS_ENTITIES: usize = NUMBER_OF_WITNESS_ENTITIES;
    const LAGRANGE_DENOMINATORS: &'static [Fr] = &[
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
        MontFp!("0x00000000000000000000000000000000000000000000000000000000000002d0"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11"),
        MontFp!("0x0000000000000000000000000000000000000000000000000000000000000090"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71"),
        MontFp!("0x00000000000000000000000000000000000000000000000000000000000000f0"),
        MontFp!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
        MontFp!("0x00000000000000000000000000000000000000000000000000000000000013b0"),
    ];
}

/// Derives `log_n` from a proof word length, given the per-proof-type slope
/// (the coefficient of `log_n` in the word-length formula) and the word length
/// at `log_n = 1` (used to compute the constant offset).
///
/// The proof word length is a linear function of `log_n`:
///   `proof_word_len = offset + log_n * slope`
/// where `offset = word_len_at_1 - slope`.
fn derive_log_n(
    proof_word_len: usize,
    slope: usize,
    word_len_at_1: usize,
) -> Result<u64, ProofError> {
    let offset = word_len_at_1 - slope;

    if proof_word_len <= offset || (proof_word_len - offset) % slope != 0 {
        return Err(ProofError::OtherError {
            message: format!("Cannot derive log_n from proof word length {proof_word_len}"),
        });
    }

    Ok(((proof_word_len - offset) / slope) as u64)
}

/// Computes the per-`log_n` slope in the proof word-length formula.
///
/// Both `ZKProof` and `PlainProof` share the same slope structure:
///   `BATCHED_RELATION_PARTIAL_LENGTH * NUM_ELEMENTS_FR` (sumcheck univariates)
///   + `NUM_ELEMENTS_FR` (Gemini evaluations)
///   + `NUM_ELEMENTS_COMM` (Gemini fold commitments)
const fn proof_word_len_slope(batched_relation_partial_length: usize) -> usize {
    batched_relation_partial_length * NUM_ELEMENTS_FR + NUM_ELEMENTS_FR + NUM_ELEMENTS_COMM
}

// Utility function for parsing `Fr` from raw bytes.
fn read_fr(data: &mut &[u8]) -> Result<Fr, ProofError> {
    const CHUNK_SIZE: usize = FIELD_ELEMENT_SIZE;
    let chunk = data.split_off(..CHUNK_SIZE).ok_or(ProofError::OtherError {
        message: "Unable to read field element from data".to_string(),
    })?;

    Ok(Fr::from_be_bytes_mod_order(chunk))
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
    fn sumcheck_evaluations(&self) -> &[Fr];
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
    pub sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES_ZK], // sumcheck_evaluations[0] == gemini_masking_eval
    pub libra_evaluation: Fr,
    // ZK
    pub gemini_masking_poly: G1<H>,
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

    fn sumcheck_evaluations(&self) -> &[Fr] {
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
    // Calculate proof length in EVM words based on log_n (matching UltraKeccakZKFlavor formula)
    pub(crate) fn calculate_proof_word_len(log_n: u64) -> usize {
        // Witness and Libra commitments
        let mut proof_length = <Self as ProofSpec>::NUMBER_OF_WITNESS_ENTITIES * NUM_ELEMENTS_COMM;

        proof_length += NUM_ELEMENTS_COMM * 3; // Libra concat, grand sum, quotient comms + Gemini masking

        // Sumcheck
        proof_length += (log_n as usize)
            * <Self as ProofSpec>::BATCHED_RELATION_PARTIAL_LENGTH
            * NUM_ELEMENTS_FR; // sumcheck univariates

        proof_length += <Self as ProofSpec>::NUMBER_OF_ENTITIES * NUM_ELEMENTS_FR; // sumcheck evaluations

        // Libra and Gemini
        proof_length += NUM_ELEMENTS_FR * 2; // Libra sum, claimed eval

        proof_length += (log_n as usize) * NUM_ELEMENTS_FR; // Gemini a evaluations

        proof_length += NUM_LIBRA_EVALUATIONS * NUM_ELEMENTS_FR; // libra evaluations

        // PCS commitments
        proof_length += (log_n as usize - 1) * NUM_ELEMENTS_COMM; // Gemini Fold commitments

        proof_length += NUM_ELEMENTS_COMM * 2; // Shplonk Q and KZG W commitments

        // Pairing points
        proof_length += PAIRING_POINTS_SIZE; // pairing inputs carried on public inputs

        proof_length
    }

    // Calculate proof length in bytes based on log_n.
    pub(crate) fn calculate_proof_byte_len(log_n: u64) -> usize {
        Self::calculate_proof_word_len(log_n) * EVM_WORD_SIZE
    }

    /// Derives `log_n` from a proof length in EVM words.
    ///
    /// This is the inverse of [`Self::calculate_proof_word_len`]. Returns an error
    /// if the given word length does not correspond to a valid `log_n` value.
    pub fn log_n_from_proof_word_len(proof_word_len: usize) -> Result<u64, ProofError> {
        let slope = proof_word_len_slope(<Self as ProofSpec>::BATCHED_RELATION_PARTIAL_LENGTH);
        derive_log_n(proof_word_len, slope, Self::calculate_proof_word_len(1))
    }

    /// Derives `log_n` from a proof length in bytes.
    ///
    /// This is the inverse of [`Self::calculate_proof_byte_len`]. Returns an error
    /// if the given byte length does not correspond to a valid `log_n` value.
    pub fn log_n_from_proof_byte_len(proof_byte_len: usize) -> Result<u64, ProofError> {
        if proof_byte_len & (EVM_WORD_SIZE - 1) != 0 {
            return Err(ProofError::OtherError {
                message: format!(
                    "Proof byte length {proof_byte_len} is not a multiple of EVM word size"
                ),
            });
        }
        Self::log_n_from_proof_word_len(proof_byte_len / EVM_WORD_SIZE)
    }

    // Constructs a `ZKProof` from a byte slice and a required log_n parameter.
    pub fn from_bytes(mut proof_bytes: &[u8], log_n: u64) -> Result<Self, ProofError> {
        let expected_byte_len = Self::calculate_proof_byte_len(log_n);
        if proof_bytes.len() != expected_byte_len {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: expected_byte_len,
                actual_size: proof_bytes.len(),
            });
        }

        // Pairing Point Object
        let pairing_point_object = from_fn(|_| {
            read_evm_word(&mut proof_bytes).expect("Should always be able to read an EVM word here")
        });

        // Gemini masking polynomial commitment (sent first in ZK flavors, right after pairing points)
        let gemini_masking_poly = read_g1_by_splitting::<H>(&mut proof_bytes).map_err(|e| {
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(ProofCommitmentField::GEMINI_MASKING_POLY.into()),
                },
            }
        })?;

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

        // Sumcheck evaluations (includes gemini_masking_poly eval at index 0 for ZK flavors)
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

    fn sumcheck_evaluations(&self) -> &[Fr] {
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
    // Calculate proof length in EVM words based on log_n (matching UltraKeccakFlavor formula)
    pub(crate) fn calculate_proof_word_len(log_n: u64) -> usize {
        // Witness commitments
        let mut proof_length = <Self as ProofSpec>::NUMBER_OF_WITNESS_ENTITIES * NUM_ELEMENTS_COMM;

        // Sumcheck
        proof_length += (log_n as usize)
            * <Self as ProofSpec>::BATCHED_RELATION_PARTIAL_LENGTH
            * NUM_ELEMENTS_FR; // sumcheck univariates
        proof_length += <Self as ProofSpec>::NUMBER_OF_ENTITIES * NUM_ELEMENTS_FR; // sumcheck evaluations

        // Gemini
        proof_length += (log_n as usize - 1) * NUM_ELEMENTS_COMM; // Gemini Fold commitments
        proof_length += (log_n as usize) * NUM_ELEMENTS_FR; // Gemini evaluations

        // Shplonk and KZG commitments
        proof_length += NUM_ELEMENTS_COMM * 2; // Shplonk Q and KZG W commitments

        // Pairing points
        proof_length += PAIRING_POINTS_SIZE; // pairing inputs carried on public inputs

        proof_length
    }

    // Calculate proof length in bytes based on log_n.
    pub(crate) fn calculate_proof_byte_len(log_n: u64) -> usize {
        Self::calculate_proof_word_len(log_n) * EVM_WORD_SIZE
    }

    /// Derives `log_n` from a proof length in EVM words.
    ///
    /// This is the inverse of [`Self::calculate_proof_word_len`]. Returns an error
    /// if the given word length does not correspond to a valid `log_n` value.
    pub fn log_n_from_proof_word_len(proof_word_len: usize) -> Result<u64, ProofError> {
        let slope = proof_word_len_slope(<Self as ProofSpec>::BATCHED_RELATION_PARTIAL_LENGTH);
        derive_log_n(proof_word_len, slope, Self::calculate_proof_word_len(1))
    }

    /// Derives `log_n` from a proof length in bytes.
    ///
    /// This is the inverse of [`Self::calculate_proof_byte_len`]. Returns an error
    /// if the given byte length does not correspond to a valid `log_n` value.
    pub fn log_n_from_proof_byte_len(proof_byte_len: usize) -> Result<u64, ProofError> {
        if proof_byte_len & (EVM_WORD_SIZE - 1) != 0 {
            return Err(ProofError::OtherError {
                message: alloc::format!(
                    "Proof byte length {proof_byte_len} is not a multiple of EVM word size"
                ),
            });
        }
        Self::log_n_from_proof_word_len(proof_byte_len / EVM_WORD_SIZE)
    }

    // Constructs a `PlainProof` from a byte slice and a required log_n parameter.
    pub fn from_bytes(mut proof_bytes: &[u8], log_n: u64) -> Result<Self, ProofError> {
        let expected_byte_len = Self::calculate_proof_byte_len(log_n);
        if proof_bytes.len() != expected_byte_len {
            return Err(ProofError::IncorrectBufferSize {
                expected_size: expected_byte_len,
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
    pub(crate) fn get_baricentric_lagrange_denominators(&self) -> &'static [Fr] {
        match self {
            ParsedProof::ZK(_) => ZKProof::<H>::LAGRANGE_DENOMINATORS,
            ParsedProof::Plain(_) => PlainProof::<H>::LAGRANGE_DENOMINATORS,
        }
    }

    // Get the length of batched relation partials in the proof structure.
    pub(crate) fn get_batched_relation_partial_length(&self) -> usize {
        match self {
            ParsedProof::ZK(_) => ZKProof::<H>::BATCHED_RELATION_PARTIAL_LENGTH,
            ParsedProof::Plain(_) => PlainProof::<H>::BATCHED_RELATION_PARTIAL_LENGTH,
        }
    }

    // Get the starting index of shifted commitments in the proof structure.
    pub(crate) fn get_shifted_commitments_start(&self) -> usize {
        match self {
            ParsedProof::ZK(_) => ZKProof::<H>::SHIFTED_COMMITMENTS_START,
            ParsedProof::Plain(_) => PlainProof::<H>::SHIFTED_COMMITMENTS_START,
        }
    }

    // Get the number of unshifted elements.
    pub(crate) fn get_number_of_unshifted(&self) -> usize {
        match self {
            ParsedProof::ZK(_) => ZKProof::<H>::NUMBER_UNSHIFTED,
            ParsedProof::Plain(_) => PlainProof::<H>::NUMBER_UNSHIFTED,
        }
    }

    // Get the number of entities.
    pub(crate) fn get_number_of_entities(&self) -> usize {
        match self {
            ParsedProof::ZK(_) => ZKProof::<H>::NUMBER_OF_ENTITIES,
            ParsedProof::Plain(_) => PlainProof::<H>::NUMBER_OF_ENTITIES,
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

    fn sumcheck_evaluations(&self) -> &[Fr] {
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

// Convert a single G1 point from 8 EVM words.
fn convert_g1_point_from_words<H: CurveHooks>(
    words: &[EVMWord], // words must be an 8-element slice
) -> Result<G1<H>, ProofError> {
    // Combine 4 words for the x-coordinate
    let mut x_coord = words[0].into_u256();
    x_coord |= words[1].into_u256() << 68;
    x_coord |= words[2].into_u256() << 136;
    x_coord |= words[3].into_u256() << 204;

    // Combine 4 words for the y-coordinate
    let mut y_coord = words[4].into_u256();
    y_coord |= words[5].into_u256() << 68;
    y_coord |= words[6].into_u256() << 136;
    y_coord |= words[7].into_u256() << 204;

    // Convert x to Fq (check modulus)
    let x_coord =
        Fq::from_bigint(x_coord)
            .ok_or(())
            .map_err(|_| ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: GroupError::CoordinateExceedsModulus {
                        coordinate_value: x_coord,
                        modulus: Fq::MODULUS,
                    },
                    field: None,
                },
            })?;

    // Convert y to Fq (check modulus)
    let y_coord =
        Fq::from_bigint(y_coord)
            .ok_or(())
            .map_err(|_| ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: GroupError::CoordinateExceedsModulus {
                        coordinate_value: y_coord,
                        modulus: Fq::MODULUS,
                    },
                    field: None,
                },
            })?;

    // Construct and validate the G1 point
    let p;
    if x_coord == Fq::ZERO && y_coord == Fq::ZERO {
        // (0, 0) is the point at infinity
        p = G1::zero();
    } else {
        p = G1::new_unchecked(x_coord, y_coord);

        // Validate point
        if !p.is_on_curve() {
            return Err(ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: GroupError::NotOnCurve,
                    field: None,
                },
            });
        }
        // This is always true for G1 with the BN254 curve.
        debug_assert!(p.is_in_correct_subgroup_assuming_on_curve());
    }

    Ok(p)
}

// Convert pairing points from EVM words to G1 points.
// The first 8 EVM words correspond to the x and y coordinates of the first G1 point,
// and the next 8 EVM words correspond to the x and y coordinates of the second G1 point.
pub(crate) fn convert_pairing_points_to_g1<H: CurveHooks>(
    pairing_points: &[EVMWord; PAIRING_POINTS_SIZE],
) -> Result<(G1<H>, G1<H>), ProofError> {
    let p0 = convert_g1_point_from_words(&pairing_points[0..8])?;
    let p1 = convert_g1_point_from_words(&pairing_points[8..16])?;
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
            0884875880e2fc2005ac18d1ff81e53d11ab416c5db3f6d57016e01495b96858
            0626602fe849125e6b74fa489c248f3bcdc542c114aab59e354ebd7b090a7e12
            12b62359013f7a767c1e7563ff0ad6a83583abbfbbfac731a8faadfa0493cbea
            1868c0f0b388fe68e5c6ac61255e400769efca98797d0d8493ba47bb365aa0e6
            112785a3d84dc70ac139ff3b1cb5840cd0455fc72f463b565fb32b97d02b49bc
            0666c8927d7873b31edd717bab6a7298397b888592cea926fd4408dd432a2b66
            0dde2e7829709560904bb0a98b73e94211fb6c8e12a6cecd8eb285a59ac4ac0b
            0403c2583f26a44e000e2bb58b0df823132f0246b3ba5c06d82965c7346a75bb
            1dc5bf03a91058131e553b8858ede7ecb4dc1bf591379dbbc54d382c8ae1b6cc
            0367ee37b8cd4277d7b56cb83a18945f0800d435e21175f9e837b71287d62524
            14c371e6c5e2194bfd195ef16a8912d68f701923c9ca23b19dc9c0475629fb33
            2dad8e78840829d8e823864d8513358b2ab97a9b0aeee93ae68c323847e84256
            115121955a3c3311634f7221c4ce895823a2a8734ca74a1091e84454a834bcc0
            298ce4130851ccc5514d9daf393ce6d2228c30e877e7a10091e7913036ef24ae
            22ad190342648a01149534e966e593376f6a7973e37d27066e7948f71a770916
            09be868da845ea25d3efe1d9906973b6624b41c93627cf84c0b3beae328a09b6
            057599fa14004ba7255bb1d2178d0fbffc93e74ca718221909a71cc46f35dd1b
            2aac1f43b270b4925bdc8d5bb54c42f7ed8cff6ffebf2f8ccf04167e6bf8b557
            2d5dfe4a64011d6474f8d4102f1611a11685f6f98555cd5ea184d697b87308af
            1f538553ac75c34e5184edd3787137ce7ec4979b84ab0e560dc79cc53b2f43cb
            1bad3982e9ec49a1731ed5ebbe865c31806879feaa94d38cb6021c6c418a11c7
            0f34352fe637a99fffeba3ab89107f53eab56dbfad7fef79859279128ee30448
            167a20693bca9374e41794d19cf91efbef58c19632b5f9b84eec4455279ef15b
            00f6558de8d9999dac31785aaa9a511621257fb8c311996480b518b4df8d05ed
            1800159180c589d29050e257031ea0ad6452fb5cd063bbb9a7422ec8ad3316dc
            25bdfba9bf4e8cf5ecc104e65c4ea4ba1ba2457a3b3482e35779f3a00c497328
            21c41d1cba83bf98f6387e6b914c244dee3832d392d0d62b1146fffcfdc1a078
            20d11ec9f89e7e43cb36a7651dc29a687525b92765daee0c57b17ade17b68d31
            17b39f77368a9b815440fc345394d7729cf56a4df021e850c8cca4914bf3d1fc
            0949a204cb3a7a33bb3062a33b572d1c637548bf59d8ca0dad8396c52ad2cb5a
            251b2e2e4adfaa039b89885721375f50620727b044b8531d2685db6edef3349e
            1b1b416340890c46decffe6a4810d56a83fd04c7489dfadcd2618db0feba8c06
            159fa028fe337f66f57a359a3d0cecf1239bcbcfb8391f10e69b3b37698f93a8
            1ddbd0976e9aba4ef99a849fc3caac2c03643cf11d97cc6670f7f70cb4783777
            0827a28052dcbb4858e231d84b494044933e140a6529c35532b8b86ec42710ad
            29bafaba82e3357188d87d366aa6b4e78a501ffb5ac353a9e678887b97102655
            245f7c962753da1e9cbd492c8bc54f56d6b5891486401f2cc05bda374a13251e
            1fb3ebb37b2aa9b17acab93f491085f43d96dd0354d87d0472f82b56ebfec48e
            05b5a63104a605ad99d396c504e38d40f9ba39cd9de994d369a9d88ce568b5e5
            29c2d996fa8915065442c780b6b5da4a8ec2bfbd748a5776cbaedf098564e917
            177283324941cd858214f4dfcf0cf5d2e3ae54326a260d4af9b58a8f0a36266b
            14f38ea0b2aab3da0847bd75cf325cd9eb8f807c6744c136c4e56b2603fd0ca4
            1942cc6e9faaa5f6a41e484c2c82d0d7eb38ebede7ad467e5a350ce19823af1f
            0ee1f8d7276f758128597cf9d1781fd412eb919e968e248349a4b18bcf13a063
            1edabac1156beb4eb277b8bda43df70888425e79028918d063f5840d42fc81f2
            141e3c2785c0503ac8b9af09a9fa93855e5fa6f99c8aa0e41f26266c22478499
            1b5366f81bcf948840e01aacf866a9c7b09347ae397b59e5b77fc9dd76d2048c
            07aa3b77df27d73e0ec407716ffc36c467b72a0520f8185198091d962a3f2421
            1f54ce7379c7efbfd1dff1f60b6f6d0b06a7c2f75952ec2aa51e23131825fb34
            1f7b4b488a5d7b65655979bb651d3d54fe2db4bac25c268a55e58c99f3b3d0f0
            2c8f2162ed537477b61b40c8ac51109091fa545e7ac3ff7b3e7c77ee0ed034fd
            187407061bc4300a433439c8f484c16d1e6e72c6baac88b7148d0d677e7f02c7
            2ef97aa6a16aec41964255e4f0a2746ecfed9f7a32290f265749f188fc6a4974
            092ee16b5930a7be5d17b9f38239f37c3d9161ad23c2eb21531e3a9044df3600
            2fa480d7a986f3f356e196bc2517bb23d38a4761930196708a5450ae50470e72
            29c640e42e3439ab35242f2545735dbdb060c8177c4e6d8b2e276efb9b4750ce
            2cbbe3b897ee0e830b247f97407271d237e7b98395406fb2814eadeca14f33ae
            0682fb65b15b181d53ba7775b385a33340bd5016e03847f83b0af5b10f4fb53e
            0013cf6f1aebcac8ad09a48e41e0801183e97ec85e9c052ee431b535b87c77ec
            28a118de51af9edddb928b0296bb670e0e0e6883a258aeea9275d6194dfe6631
            243b466d7e8469a98b5e235c9ffc924ce0fc2f3125f25d16e3d362d169442f64
            2d03f5fa0d5db8557f099e98e25b5e58f7c935053cb90e09302c4aa6479035d1
            22a36d340c81377a2d361cc56f3460960f763daced7ad9ac967813418c48c147
            0b3f21f5cd01f79eb8d1e7ec02c4fcc13f257af005195cd14aba5b5da6ca175d
            2c19ed296b8de59ec2acaaf8a7c5e0177302551d010ccfccbf51b28dea36f894
            2cad59e0cccc6b75d2ea3da445542710ce8cfee838813e2223646b0af0dff99e
            2328f66c17a8fffb31b739b4e14f9cd38733124c9f0324f4e3323d455213b45d
            21128038141becdd43d594221f9b56426f95364e2f1ecfd93f033cf4fe460fdc
            2861c16677681256046799921c79b66723b375cc99e702444539317566d6a8ac
            01072b7fa31425b4c7017d2734d00fac8b708878b38e564461c5f96461c1a2ce
            017a65ebb359566547eb5e06d9a2d4ef685261955028ae2db17ebb72b2de521c
            1d5b53de948286cbb8a69fdd2371dafee1218e35d1cab45ba30e6de0f3eeb8c3
            088d1b20bcb15a5f7dab1ba87723cf703ed781d85956823e5fe92f10632f90b6
            0b32d5313d422d85a1fc8bcc35d31dfd404eb98cbdfebbc7f0ad3a1b04826f8e
            18fac26f1b16dd62f1e466ec762db781e6dce6703246730b6458a8e78619f479
            021b930370cdeaaf42448793e1d055e578ef0d59b3fe884e8a1e0363baf6379a
            0b5e66c247c0729482ce89fede733f45c0165fa809242c0a558a93aaa3ccfd74
            2b5b634af347aff54490ad10c25db4b4fe16fdba49666cfe9bcf806cd875248b
            095758747a739f602d02cbf595108924f1fb4f5b9b478256fc21702820f9bf8c
            21f1cce32e98bccaf956313c2ec71697dd9f452e2061eec86583cbe29126e599
            1dc03ca2cab3bac1b6b6048d900a7027c6f1ffa50572169ec89265c74bde10a9
            22fc30d0b524c3f71dc0d950ad91821e28eeafa844ea64d8d32a02734627afff
            18c0d2e55234bdb8dae8f73fe948a92310eaadbcaf5e6e9e88c07f4bc66a1da4
            2282816b818235c56baa4aa7fc1cab993f3647798ae977305e715a5ec7284e9a
            23e4fe78077e48f291a38ec77522c281fef3ae5a81e55d281aab769e7d250ea5
            04d5e4810cfcfe6ea5334c9d36f46b3e3db35748c0362478ebc5363dfa049746
            0a7e82df2bd4fc9b4d83a925e6c56190e253bd8d6897a4e2a1011b1833d22261
            27fe9f44358a7a369a0c556f295bcbb11b46e6fff5b3255a5deb4677d8bcbd83
            24d6ef7048985af931c24a9a91b4b12f5c5106c9b0057d72044d5c759e377c43
            0ba468464dff9a2cc7792201013f7ddb28175c8461814fbf9791e7a294739bad
            176e534139f4379f01b1910fc6dcf8f419d3cde6378911ebf58bfb4034131a6f
            144af59b5f1b2404e7fa58d496049489bddcbfab4070a92482d35421dce04495
            14721bd0cedb74e6b82e3f34f39fc0531778f1d3cb3ddabfddb5ca3f8e7667b8
            2402ca2eec463f6aa6eec4592b78891a8b7b0c5f4577c5db329737288b833e15
            258635178686e9f16151c8f175b75ec30cd705b94180e794276416af0549cae2
            0fe1fcd2987fd1f5167c5095dd2c2dea70bb9ef75a082436d894758dbbf2dbe6
            0d07144d236da0e0461c8f50005d7f88073cbc7fc109820493375cbf91de8a72
            264a07cff7c296257f38337b03ea0ce9191fdb3b0220e31738e4f53596b55190
            0702a05eab41515e9df49c56dce19dab4c1833f5d8e701c56c67e63e73629307
            067fbe85d949c0f070561e5a5e7fae37bfd5bc0856b5da95f94afd77cf76dd8f
            286049c0c8264f54f36d75dfc19992be76ca59c110e71d68fff7928d9275dbeb
            059da2967573ba087314687f1be281fa3d185e37e5376687cf99329527febb9b
            11b1b5fdea39351bcfcf86d1466c5514bd3f52249cd8343df55f9ac6c24b135c
            29c2b8bf967bac1607c29812ebb98a010061c84ce70045856b0b29c5c75d6869
            2ce5875746deaf104fcf492ebeeea3236a505d8369cc9822ba6390933fcc3a5f
            1adbe23fb6f7923c120176bc7e6d1a24483688ef2d8060e52c77009383ef0db7
            137de1093d7a9a2fbac830b5c2acbb62d3db5bfcd82e55632781a74d56d24f4f
            0406910ef97b5d3cdad2452140f96358b67608131622fd7dab589240d758974c
            1382f6ef4400a74f360a41b6d1a7ac79a831192327c57b305b0a7e5c9fbf3227
            18d3864b7a359c0d20874fd3ddc2846408d782842fac6f05a23d0e383abfa6e0
            144f348f796672ce12f81f1dced49d011a4e4f4fbafde76d224436786868c964
            2efbbe2c0809933755be71d89063a584ed14fafca46827c9fb01ecf2107ced80
            1a6c11c2264b23720955391dbade19baba1878f3585fa39db6b23e1c32941f64
            1b06db73d17dbfb0c831abb7850fa0514e581d3e3415a42253bcaf03e315c0eb
            01b2365903d61c9d34ecc7ac0c5ec60515e88e8d1aec8b087480ef288953b100
            2c6d044f499492e9cc95cba19314502cee95b6fcf523092419e85bdd39a2208a
            08c1870ad804174c1dc7db62b7f2afb6406bc2af2b54f227818b757009a2eff8
            2b7cb158953ee7fdb55d38885e59dc72aa319e98c8d88665d5f84a9095642115
            010ba0f1f0e4fe36f140ef8e5d96492f58e296816dcbdc83c052a9380d2c69d0
            07595e50b2815dde63eb5a5ffacaaf4f429fc141aa853050307a25d0cd64188f
            2c51fafcad2a67a2cff11cfff7da4e7244d3e726938d98f778ee788ded2edd86
            05c1e05e9fa77a42924c45578e39e8c5312f06d72035880725531c782362af14
            26ebb22815c6897062cdc226ce37cfcbcfba8563f81a9d094c092e62cb7e1031
            0a4a658a5c85980fe0b77cf460e47bdd0dd0bcf798925db52a52420a1d208afc
            24a8d199aba5f323267ddc17f17fc49695f8ea57bb522d4a85274c13ac8ccb21
            01f916a64cc03b54bf12dad48d4d3d879e52449218f679849e5feccdf2045af4
            22ed4a0d2aba6cdb9ce0115781421319a54bc7056a547d0877b1c5cbe00fb726
            163c0a0092feedd65a2337cccc367f390511d662306cf7994b8e096a3bfba17d
            18a5a10df5f601a9a7a955a6a495cd6cdc4ebc5040bae9cd5ec683c0979e2174
            281114ebacf44187050a47473fe128034653fb712432c418110ef5b2f40ffdae
            082daf818f93474ad50c3e805cc24b896d15445b6cdcf5a41b30560d20b1e967
            08772e0a36b1a2c1475a499e1da3d42e58a4645e5299b78d3166e9f886d06843
            20d430844654418836656f42afa3a15c50af98a03afef636312f46fe4f173ada
            1d8d228b1a36190ed7ff147bcef0a7e59eb37d11266a7a7b6b1672e23c476c5f
            25cbb5eebf008d306656b17353e3e42982c5a47bfb0929a33ffab0e11ac99b60
            00bbcf9c14880bc671651ed1fa2707d1daa904558079378916a13022585b11dd
            14800e8ba3023f5b71511ed4a20d96d8e5583da85e71d62b2a15fe4719879aef
            08de6c8633ac65b8e286bfc8a8ed5182dde68c37873167a4b140ef2c065fb6fe
            200affe894a9bc11105ec2bdf0b8ca0ac75385cefd4c1b47cff7f80f3f32a695
            2a02d36fd283a1a5e016c93d712fcc8da76552446ea549d1127fdb994aea42bc
            09d20fa4d79430cc25bb65a257523817d6a0743107dcbbeb087f6452101b7653
            1e83b76651ccfb9c7f5c6be98cf07b95a7100cae4558acdb7aec25a52e6f5c9d
            2c251d9c0cd6cf2bae8adb448011c52bd39ecda462a1400f7f82331e8dd437e4
            21c23628ace5db864460794d1560f5e10bcc651320dcab735f3c8eaf8c59b4c1
            0a668bbeaacf20030f91f881c4ecd3dd31164a47851bc2f09a307c5fabeb45e5
            1e1bd023c5f7d83d13d29096c1205eab4c8eeb7e5b992d8eea3d2f4c73c6d93e
            1d977ca3193318b0e0924919a567fc5965ede538a873d0f1610667ef754a3ca5
            015f1a593a851d43e3684b830a43f32cf2772338fb2664c1ce159fe26640f00e
            1a6f6c4fd9fd509324ccb92bf7b3ab4437d538771eae2291fc5cb989f5d7b789
            276271c8b4f6475aee34dd5da2acf5c775eedd1ac0d5ab3c7b2baca6c59585eb
            016eb28aae43a597937ce502155ea337498668311ee1ad768418c93809839b48
            0f06b6718e2702b972e9ad122a97d8cc88b68e740a0c2b376a920ab39162da2c
            1b5c82cada4c22b3c115bb8936a3c671a7e1d49ed8b53508dc2573f440bfe50d
            23912d6b5547e8ac27b6162a7f7e42aaa58cdf951c2447f64dc56f74ca8a5669
            27b0901030f2c18b58b2e9e969045b925529d01c3116ebad90157820f9b72be7
            235a77bc59e0a7f20432e79c7bc778f1dd0689e5e6e4a5e9115bd2816c3bc4ab
            2d2cfb5c56d2e95837e1240f3f41abb27e605f97ba9dabe2ee421d99de0acc12
            24a60660690d853b1fe2f64b8b2c23740ee0e77422f1beb07895203f838cabca
            291c269a201f1cf6f39d9f3c2544ca83fde903d11e97b1456bc3396540dc8ba7
            305212de25cf6776f35b26a42a7e26a42017705c3ab78cb78672f6ac62933297
            1310efd40c9065963ccaf617dee94665eb7a0a2412c546b0915b1b0897b24178
            1d383a0f6a5986835df401a1257bc908a59eb304c7cad2f278f4bccc03984672
            01fcf0ad52d557f8df7c1001576a403674348664b2e51840e8b41410b6f8de01
            22e46ac82ae91945a1db20298dbc2e56b9cb4a141d61e03b89b2743d6fb45da0
            0d49ddf30a8bdfeab95203bc800e6bd55cf3d24c3228575ccfddb3a355b67999
            11bcbe8e1726d60da4796f0ed2407da168cebcf50297b43cd9bfdf65241bf946
            160d8f6a1380a8a40621a52f0339fa962c29d48f66e0744f0c83ecd19b374328
            0d6a00b9ab8210411d0cc98f14bc80047ec7c99b11522276035a85fa4489325e
            0e5716b0c75b38e65f94cf6a89ca706cb47d3e9312507fdda2790742bba9e016
            1b3ac56ddcdfb10aee0dafec5c1e7e2d759daf49af1c0c0e1ede04b752cbfb7f
            05db6a205af30728bb9b2ffad5055eb421debb95d8af2fa350ccf802d107a6d8
            0c7bbc0b40f72760bc91ce80ef18c588c520d535e40e9cafaef48e883d52e7b6
            0fbe7e7a5681c1cbaf65de56cfac37f0318cd6247a0c7dc2abc11c4d2792b1f2
            2a2130c843097af04cf3d6c7f252387a0d617efddc0ce7082e55cd462339e509
            0e8a044d5685ebb22bdf5fb5fcbfd6215540c2aea55873adb6b18424f37e5b08
            18683bc96f5de8860a8a28074bbff5b19eeb729d1c36c214091f9f727026c4f4
            2a9294e57959f8aae633a6c796ffe68c9330d7ef8b7a801f0f7158736119521f
            03de24b2667b5aa7ff530aac05e57025ff01354a66c483286887fc5baaaef0a4
            19919cc04027fcbcc6578081345294cd9d6e9b01cb3d1473444c4e501b71259d
            2a94788f7ea3784202c9cb5f0cc517e81027ca599a9323686c74766b9d25aa6b
            1cbaa49dd9b4acc6ea418060232dfe55cdfe9e3858c8f8913a8655473318614e
            0e31e2adbf2c4e3ceec188b20c9a79b29e20f207f9e7724ee9d3cbbe94b5ce5d
            093a4857e0e32df68500bfca00cb8e19a18c63dd5c9c309540ed331d7ec53484
            291b96dbbfdcf6912298e9b43482b075812fbe5e106f0787c49a571f6473f240
            2c117b388e9d4662f819f87fa0c4b00a2ab50bc2602a1b698726ebc6899adbf9
            1c000972bfec6e388b72920e65e3b36851e4a997b725991a7563e6ade093c44f
            29954f65495854bd53ab233a8e8edb16066bb90133be791d2c7d4593e370da8f
            2b44a0c75f26ca412e11b6688590337ab4413a971a7194371a2eb8204e833794
            148d83f9cd4626af7d702be6702471d1c1c24155134eac607560b4a1c84b79b8
            0aa45a2026df4f0b21cac187f481a394742e24df917dabf4abff5b586067afc8
            1e7b673cea9ad25a547de5057a5fa3e9542501f27a6d76a4f7c335d0cb91836e
            10cf27adfaa101b301e361705c4ae46f1dba1129c27a9f8a3b4d0bce29b1cba4
            2384be56986c346ad2ad3bcb1e378e2cd3e9bbc57e25ca89b96c49bfa5e68397
            04ca509d8a866efe3153010cc545f969e5375408b74f849c64ce90d44ad043e7
            28a9aaf99804770fc8e1e748699db473237e428c472d7ab6ed83429837901240
            216c56decd4d53cc21030677f2c9b266bf88939b5f8246fdd1b47a8dc879d35a
            2088439f2b7a612012d2134550a6542ace0a47e020f583f2a81d4d1a78eef69f
            22a9e6063e79274d44258817daeef9382923c9f6d63d0a406a1f6b57dba9b92f
            2174e4fcc24b4535ce5e5e41dd3c644e34b228cda345aa915283c16bd1eadc75
            0a4e69cb62e44e21a35f00bffe6e79d533ea3c9b279c47919988c12ebdd41514
            0f37cfe00939f80723618c7b2aa5fa92e577f5a70c97c3dbc90dc53a2e5b6ffa
            2c2783f9ae22e90712591b36f31175eba0e03c509c18a539f45ee0fd3e8e8d6b
            1c2affac0b0ed01464d412a31956d33f8890bd4cbdcf876f0c7c9ba466f9f99a
            082a95f236647fa15df33c837df6eb6560ab58ff234249fe80872b6399afde62
            0259f1155924d4c1b9a66dfa3f250714c9589e2ed5a40b34f4882d5d9fddfec2
            2b69066fa8c2b254023a69161e4e588f33d1713be5e13a5a1897d541bb216f4e
            0013e6007f7b2d71119ffb00a7b37832891a155cdcb9466d48288bc2c054e563
            10edcc6c3225716949b750da00b6a7557e9b16789188ae58268f1659b793ecc1
            2fe29329a34a2d3e1f8dd57af517979105d06f95385ac3b69ce7e8835dd5ed9c
            024514c81a52af768cafbec8acdff8cabfbe210f32a1d512678c880f327afa30
            1256c94363b4d2ea3397b54185a24bae106c5254ff0975281ed4da38e672487f
            17f21edb9fc528d649927ce8d19b3547e66c637c5b20cb2fb61e4e1ab7d70d9f
            125c77b9fef572f3074ff1eee7f7b1d8d8c7b13832cb44fe331583dd055507ec
            0268a9d66f2ee63e37eec1fec4d8ea74fe2618dfe9d74582367ba666d2dc28e8
            1b5b35c93c774796ea433920984c64952a1267759c2301a7d34f32b3585978cc
            28936b66b335ac2b14360156e7c2e25094d764f6357c37a253c517cc03add135
            25f9aecc50b6ccd76e9027729c13ab52e28a1a400d04559ddd73f77f4b0ac1a0
            20920ede016886ec7ac65a0a3848025d7728bd15f04ac7da3960eb883ccd7938
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
            28d9c504b9a349137fe0295586f268ba2201790f3502328384d7dfa3c1b766ea
            011d97f5e302d16430e07347789afcd9d3c24cd6a87d20a2554e563d6809fd56
            09de4c0ce293ba3b96cbad52ea2027630b0d8ff43d9ef999a83cc1cd66bbf03c
            117dbcfeb68ed48d23660581568ebe7f66fab0bd8e7254d8848b80222ba7cf71
            09de4c0ce293ba3b96cbad52ea2027630b0d8ff43d9ef999a83cc1cd66bbf03c
            117dbcfeb68ed48d23660581568ebe7f66fab0bd8e7254d8848b80222ba7cf71
            2f3d337096c4dbd308167ac9964d5f5a23a92384c6ac2552eec57abcca17faa5
            23aef04ebf4e63a0039c3800bf95c29c62a4f344c38f7fea7263e00a7d045d24
            15503b722e5cf9746baa74b56dbcb1f0b1803b348f8af0f642bc109eccd7eb18
            202745ae3b1e01e039f0b3dd928178200f6ab303676bcc0572f73f80ece589c2
            263750e83dd936b53796e33f4ba0d77fc60a51111b247296bbf8213321559f97
            2b792847e46fda8ec91a734f46ab4b5c10fa156c961cea474aff761f212de89a
            186af8efa28773679f2f66e036a3abf415371df012017bc0ff867a7ad0c42be1
            17f955833eaa2cc21920ded64addac6912fcca5867b7f4d0445b7b191f3bd420
            17eb65dd48732dab4998eab27175d0e612b9faf491468fb2d55928b122c34cf1
            0a2945444f3fedd66d78f7066347aa6d478564b4fe27b86b3c2f6e547532bfdb
            07fecfd43a11bd49dcc28e205b80d17e697a2323d94386f5e1992dcd514cec11
            0d574e82aa8abfdff8e34a4221fb0cf038c6fa3cc7b52a772e513380deec3526
            2ac78f0d8ffe1ac1afbc64dc43c0b8e9dc853720622f988082bef91a00a34a8c
            0c0c9122a36992e04184408670b35bcd2c1fbdf08ea8dd046e0f758502d167d8
            2cb1ce621c238d494d7ec3982d630f45d9dc527e41650be60665fd7355929779
            0999c2fe11c0a64a5d1de1867358db773785f8cab579b897c0278c8c9fdc82fa
            29e13bd30c6d1a66c1b3e5df4c4a73e592a3aab4e9861d88373126fcccc013a4
            28be1f3adf86b95c5e65d4f3bf8fa13f41d8abf26e71c311448f1a20313355ee
            1431c08ffc197efcc61848b0eed4689682a0fd4bc85479b28f6ccd8f40ea54ad
            017baf61083884631efe908748d538895ed6b613823006f9336caad6483a8f45
            16cca64cb6787b5c3c174c5c62eab4bb305f77e4de2eab21297cdd9c13ec59f9
            1844114777939330530525f6f1de65cdf9fe733fc1c74c9a1fbf2053d6fa2855
            0fac55798434266af43a432e29cad5403769f8d29d10980984fea54375d64790
            1d18632e3938949e95d41282b4cd48b5cd3dfc876534ad25198605c74a3ff026
            2f60a921a5e79c4d0cba8e90be3f4edb68110c578962966c106796697849bdfa
            0e4ac720105fc685e379c7521688b2fe66b58f7ec6a87a1416475098700f7921
            2343f1776b83a304586cc7a001f1011cada240f06679b37b19dbdbb669de433c
            072672487c4637a51566b698301f48075a60fd8f302f671ca376c2dffc3785be
            22b72b3f75cc4eb3fe6409705f50a8746ad5f1ae5505b617e9c79fa43e8269c1
            24ecfae504fcfeb154eac931f9994cfd29ae3483a5ae0e8ce3b9919c886bd949
            0586c1d15f3b93731ca43fdd0ed8875f28d707a2e12200a1dc8b92489ed3059d
            10eb7e11a917b7f69198a71549e2b7e259745f786630ce8bd2b16ee1eaad7f0f
            0f28845aa9abf7d0da9d41fbc30c2d7084fcd09b669be2d519fad3f40f31673c
            012f2e3cdbe532c5409aeb296182f1df5350aefd1f886db20ef8460eab547f0e
            12380ecfa984a1cb1863a811b2de7c28fb52bf746ea0e4701f24ec2d31208edf
            1f98a559c03ca53af4e32270f0c93e8c2bf548a7eb1c3526ebbd6f8e2be041b4
            06daeb384a0ddc603c8617568f18965128347e0eca83cdbb57f56ff9205ba75e
            1ea288eff79c94217b98fdfef4ac0c2baa6c7e2737c6d169acc76b755430385b
            11586d5b7523bdb4ac1d165af037807ea03a3fe97f0ee794c9b074d62d0129d1
            2f940e35890d5b8c7bc3c4565bd8d076bc5419deb195906ca414de420dc08002
            188ada4d1970a98690bfab5f39e70c96b9519868349c3ce0fee3d19379d50bfc
            00aa7fa19c81177034858e623df3f6f3e2a51eb29da27da59d011fd8b8cb5c83
            2058620196411d5d08130150711abf9baae631361aa4a54f3b5e7f34bf229da9
            12f51a29e41c06f5e769eb4457b54486ca1c922c64d3af010a45171f2b4bca8f
            1d9a94e0b15dbc24de8752c3b982c226471a78a39e6095a0eface11fedacd706
            0e672c6133a8626c21b31b6c682a9025d79971607c2ed74f89d9f4e7361cb645
            10015925bfbb80642e1a63a3236d710ffb8ea1ba19b2b05a8bef9ae413aef012
            0d90c5fe86ebf131140c86c5af28e3a33d897381d6869b8df6a8a49a7986eacd
            14f0924e72ca03e8ea1a99fa9b968d38d6ef94034f15b1cac65a4f86dba40e53
            0fb95d1bdc11b4b0347fb4256e2c3efdc5232e185ecb3ad02800b5ab8ca45090
            2f73f2815228bf208ef328dfac7e35269d15ee1e96de42793b56b7bfee31d45e
            0021d203853367c253530081b5e384c84371a883852a600d7c61fa752600963e
            1d6a452fa5e153e3fb16dc42c1317d5c70981c36d407ad10f98fc7752d1d488e
            0dc29b2eee2e70925fdaa1ce625bfe3eb62dd3020d1cdbe1aec039c939c69575
            173963002447d2da224eded55f592e7d6c82a4d32b85215f426dee2aff8e5fac
            2c4be219f0525c74de04aebca6cc227bd97e278f5bd9fac4ecb39061f719f948
            0d49bfe1d99a852761f6b749f380997edbc1a482e8712ada8a492f4b635ff9c5
            14892b3db95d8dea5929fd9922a160328454ca508e611e77b543e01bc7e66781
            03ba0a46e6fad7d2ed3bcff8ebd60990ac122fbeef7706d8f0af31afdfbe17d7
            08dd1340d9cccb96f78088ea6ad3f800dbd7b8728d435e3e151705da01738132
            2467177059074c651952a9c73c64a666b3f1bc215429aadf948fe688ab181b6a
            156a4b7d2d2579827808bb419448c8f6630235ba9f06b911d597c41467222dc4
            2660860fc66b41aa7f7b5286e4c452d2a1a5e6c8a2f0eadcd148f9318d3dbbe2
            235d44de438c5bdb1d9360756a87593cd3aaf6251db475fd48dd22b87c8d44b4
            0b8bfd9223adf5f895994baf58e8f3db694dfb41b21732993a2605e74c020143
            120d093eb32018b1824d80c63c65eae04d0032e9e35fb5aaffae732e39ba0ebf
            2788dac29eb7f58b5bcb349bd783e9f202f17c4ff4478d6c2833f68c3f8e6cdf
            2a05f74c50b8edc7c62d683aaaa284afea164c9fc5529dd3afffc38b16434e41
            0b90157212df28c7318ddbccd2e444927e40dee48e3f9c903c39e68825c13107
            08ac3272d1796ae7b43e657da5ad935d411a8b3514910048604439071eb6e716
            1ea13b56a7c9d1366b0f7c1dfc3527fc857b56b767ceafb10393ac47070d5a61
            0287a8fd7299f5a673daefd61a8097cf35a165ed60ada6dd5a32ed312a714021
            12a1a8725bbcf73957cd89b8f3c4f484caf02a791ea5e5c727351f31beb3a186
            1ad6e13187b786522ba66cb9c5faead068b008e2c37d06d897ab733b9b1cf10c
            2c823c5936babb195db22833318900c1c4097458755cfea909e8ef32ac8431e7
            257e379c59e09bae22bcfbca89e9ecb869b1b6d61b88a1ed2199e2edb4c36b3a
            292333b7d706ee3c0614208f90874cb9e8813187166665d2ca9afd1722a77e90
            176522a2c85a3d9d3d863a2a6b1375501fe393739db43df538d1e48bde0014ba
            0517af3dd9e8520f7921e4fd3af129f685eae54621075e1321fc65d42a99b425
            25abb89c31f26d25bbe4469ec93d751bc001698254aab2244d671d1a06aef5ea
            26c53333a1bc8339f783c0c630cd59dea53bb0133d26be599cb67b2b66f2a77e
            2113eb6960c0c624926a39945cb53cc8ada5c04f2cf51e2cf568ec4da36e1496
            12e39599c11db3c81c575bcaa0f4208f6bea01e6b516ae9b6554e7d28091f6f3
            23dbff07e78ac78071470a7bf1615c0cfbd47b966c9545c9e0209e2bd1ef9aa9
            1a25f34bc5eef45ee8fcd3f1e021d82ebd5c7d6dd1411cbceea41d58b5d59110
            13e13b71cf1a96a7a414610ee4049016277d3f9ca565821f5a1ea473e85960fe
            001cb30c62a111740f33fc003b4b220ab2a0a3989e34f7e08500ce3a1a0f2117
            0eb864a56e0eb706bee1745dda66c8b10da4a653248353e5817cbd0085873472
            18e7cb126f4b6ae03b76aec7c052b779f62ca986fad798d07c24f254db00fea5
            2252b864dedcac5b7193259a2ce4f028c4f722b96c18f666e5fbaa2a7211c687
            0a45200b925492ec8f2a3232650ce18506dd58f26362007946dca3f71fe757b6
            15510de2831aec5f17a33c6ed2730c360fd00ba8099f73fa80f0ca828fcc9d13
            2eeab8949b3d473335de7251ebb69b5e4bcbb7d569887b8a98e3e27233bc42ac
            23ff0a44191e763f63a1c8043aa03fdd1dadfdab1a02ea47c4c337f339fa5374
            3010e779bdc50364f03567eea315e84ff5053511acb8d260101b984dceddfe4b
            2331b6c7303f7b695d6ba9f568e8ccb6b574c26bb36880de95684b437ad5d5ba
            1593fafe05f87d36e32ff43c7c07e69d919bed350d3421e62660a4702c181370
            1aebb5043714fd3af053b8267e194ce69ab27e347bd60d6d60578b991cce757d
            142cd42b528d58f9639bdb807ddfd17bc443b290e6d3c697a09b3e1fcf400ffa
            0303aa30a8ba0ccab66c8d965614e84fae37104e2c1bb7fecfb09567bb7ae5b1
            268a8ace306fd9cbe701b1e5e622612657c7cb851d0ebd58570c976b2a11d1f6
            25edd8aeefd9442da00e63cc9f89e334d0619be5e7571a25cb13123ca5e8d855
            28ac5383f4a4674dbccbb5c20f0f4821d2b2fb8d0c79d69a41f037c4e7e12020
            0977ca15e933830add9e0943031abed062ba45147fe1560e49ad46625052d8a6
            0697ef7a5a0f9d451c4abcabd71a2482133ebfa2a5d29d8b35da9f92a3ef4e32
            273fd0de49bf1478807b437db93ff7dc8c99ed04d51e7ff37cb52420d9d8f1f5
            0ce7a75994b572cbbc6f56d8279923bee1c553d5f04168e1f0ccdea049339b52
            05902cb2b6abf15c80dcced2e5454f482dcb821ee47d8eb67f488482bb682e1d
            040345ea71a9871788cb32124e5165d72e9ee046081a90a89c9b7d6fa3bacf40
            23f1ce1bee5e10551de3e29c8c2d2883218c52b9a8deaf9797d5d59ccee6f1e9
            16ef77df6b4a2d039b81ed405816ace95babff0b75a00d9427336dc1327ad06a
            2982a7624e16cff3dd63a7dc985ae380b34ace55133904dc68054b0bd6689c8d
            093eff5899f316e182efeb0a622d928bbcc2a175945036492f1759405d449ff2
            0552f21fa9ed22540e6d9c48b793f8940e5eef8a3ff2370d4bb21c7b6fcfa8c1
            147f479420f623f8891798c99fd434b68e458ac13c9c5b072f9eb7e9aec21acc
            2dfc7db588626f37fe38777fb410c9f88322486c268f5b99cf84109bf9918d2c
            2e9e234b2e836b43016e7381264ccd1090934807600cf178ff238a982b0725b2
            11edcf5d005f26bfb4d305aa9b333fc6076633e065dcef17c604043c143ae9f2
            00054cbb4eaac4c35b386e16f133ed40bcb4312d73e5f850f0119b827b84ba8d
            263c0163a2b4ef9dd79e3d3865ee3368c807cbba777c6d3299b95d0e8c1ef435
            0772dc33a765d694e78163925e699445fd6e22ba6a72cfd5ee3d45dfd7662891
            0b9d7a859fe7ad01fd32cbd367f88116f4bc907f6e25a42768b5e95dc7932937
            073d31c08ccdcf82eb20eefae29af4a31a97513172d01856906b28e5b605deda
            206a43631d7a0a2d5705138606e8ebf8a1a5fe4cde9c40eb8c7c4e79b744bc48
            2199d19935a0d0de790c82384d4e83fe322826589bd726cebf0a76f00eca4e47
            189edf4f6f2431ce8b588d3116a7f446e77222ee8d68b1a9d9ca483a25eff2a9
            23730c7b285d858c2950441d2078799f8f1e34df6004e50e32afeca0ca744d10
            227c5fb4627feb427c573c59bacee95147dc291eb49255de62bfb132a5c83cfa
            2452d95586e3fd46cc99fe7162c025e374d65e7b255ece1debabbca5299300c7
            03a05b55aea206e7629631d6c76fc7003bee0855ccd28b6b949bc842e6fa96c9
            171988476b163cf8f2ccda220320efc882069fd1eaeeec8863b057d3d86ed948
            2a00c2a21445132d35003d9be0e8f252db327cca16f9a4f0908c0ab176047dfb
            1016759bf7f9e0689c6fec89e28ddf944569d1711eb9ed0cdbe89efc7017c777
            18dc6d1c32774e66e5a339745e01898dbcc13381d77daf0d0c40d3aec3c59822
            1d52d06a37e118060b796730a4f53d74f44ad167865a64ef5a07eb0ee1dfd747
            2ebc91cdeaaa325c9f6fc942d1fba73f0c21e099039f8268ecaa82b00dfe0987
            206516b2cac5b7bf28f9a8ae57bab1bfef81ba443df9c7fdbf6259d04f3bc2f0
            206516b2cac5b7bf28f9a8ae57bab1bfef81ba443df9c7fdbf6259d04f3bc2f0
            122b645b4d7f5853ca7e4cf70010593817f2f3df6d4e2e112ec98228d807e501
            0e53cb8598542e71490715a40983ac1c86710499e5611ea4e077660653752ac8
            21e8623d16a7e688d16f2266843701648d76a95cce2530650d83adabd24ea76b
            0d9f882633601a615f7f4d6fc55bce47e9531a9c85ff803e31c94355e4fe33a3
            021719eeee23be3bb0ceaf9b0c8fb39896cdd684115f04a0cf063add3d54e4c4
            0a3d00f5085158d6490b85813a99f83ca9aeb197856245b1177560da0e4ec695
            278aba6e25054d8888aaef915150842367d22b4a1f49061f0b2a25657ac64778
            05b0cb70a63b503a2e48af382d4e73e07a3102e65a2c1dd96e3de2cb17fadd97
            0aca6a6fac9aa2340b3249224b696282973d331f929e484b3f98fcb4ca2b3e67
            2b41bc77473edf34c686fad184e539022f9567521db9c5bde71246d340847928
            2b502225463dc2201d4c9276fae01c543bace6e139f44f4fa718b2caa9c5fd60
            0050ad60c29f3f12da5a69a605fe95c873e26de05bb9a52ccab5c29354f1dbed
            24804039fa8d5520f3b0bf4526057f2f30328d2ae6c2137368095ba98d71229c
            03d105d862daeeffa7c0c78a3b2d98193c06f38ab936bce5819234289af92d64
            2620f1f447562afbf1608d106baf4382a3237a59e4cd18495816bfe8e6508e77
            26cdbfb46b5e48019851694b7a0b04ea40d99da1cc0bbb4be6d7d505852b5ff6
            0fd045acef45c1bf981fd9ff87ae9e103fe699b3887d43f525a908e56d35931b
            2286eaf3dc95cfb05e469dd5be999ec6451ed7dfd6d8210ab9c5fffd5f004a4c
            24a118b435e726ab69e9544cd3f1432ffe8ade60c75f7f1261c14bad63050955
            30341a14e7aa7cdb984b4f70e26be113b8fd99607b3b8f7a76aee9d127d38ab3
            1f5d3cc5540d6e5cc9166ed02a8458ab73e31f5291fbe29c55d9eac9956fb5b6
            1683122424c9749361de6ba69b31e315a363762db5d89048a06967895d3a94b4
            1693bd45c80e2b7a1315fbe13035572c03d6be6cd012a5499c3134e7ac4526d1
            2b64e6d55f3702e93992495645b9376902b505bf0eef63b4148ab93ad9029428
            1fd19a0c49a3a2f3942804a8c3cddc5973e8d49a36f73ff5f79175a23a195b30
            26845c2ae42db83d2962e7e89152edaecca0a6dd7c2edd63a354c26b493c3481
            06de0011d27f541b7c104d8269495c630332ad113fb7bbd9aa1ce84191a47442
            0b1f33c291e3d3f79c7485eab5ac4153ba467d519dcd4fab9f58e701911d192a
            17c68d617b1df0ba129d121448dde82ee1df09a8a8c548d22b295c111eaad361
            0420cc2ef121f62750bd58145d466a21cc270a5d4f1da437cb5448fcff8edb86
            28cd8dd8e083528c0ec9c78b4d705741935eccbd50b99899e00c2a099b3b70b5
            0de9ca0226d7c42571a526c9227508535cb1647c67399ca3d053067d15b38769
            1724f85e57dbc37c4eec9340d4a9a99c401a822f5d4ae41ef2e2e06d61a26dd3
            26718dd41b0e6cde48a08d34dbadcfed6dd985e8cc270599d4aecbc7562f0a9c
            00b07c0f5f7db7ef184fe5c769881928c968eec6355e233e938404445b28ec5e
            30597c2afb9ffd9c1fae35007689d9fc4e0f021b97fba488d10e47f9c49d55f1
            029668aa123aeb7ed6630112d22ac8ce03f31e10892e926e0dbfb1380818733d
            08129cc15a750dbf4a24115ad6b0ffdd2c8632293fecd4feac11df9109f0afdf
            2409eb162e4427721c9cdae3a0805667dfa69e678ecc39ab3fcc72af92013cb9
            13dccb841aa8d20bcf80816f01424c20c2986b01bf946dac089212ef6aa72bde
            2841faf37cbbb27d311a5da45d6cd1cb107a91722022ab70fd0b20a548bd78c7
            2fb3d68844d822b53d18facad6ecda43f94a2ad968ac3856e105085be9d39407
            1afe98edc91550a8436e95a5dec62bdbf1a10565cde95e1a531b5371f0f66c63
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
                    expected_size: ZKProof::<()>::calculate_proof_byte_len(logn),
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
                    expected_size: PlainProof::<()>::calculate_proof_byte_len(logn),
                    actual_size: invalid_proof.len()
                })
            );
        }

        #[rstest]
        fn a_zk_proof_containing_points_not_on_curve(valid_zk_proof: Box<[u8]>) {
            let log_n = logn() as usize;
            let gemini_masking_poly_offset = PAIRING_POINTS_SIZE * EVM_WORD_SIZE;
            let libra_commitments_1_offset: usize = gemini_masking_poly_offset
                + NUMBER_OF_WITNESS_ENTITIES_ZK * GROUP_ELEMENT_SIZE
                + 2 * EVM_WORD_SIZE // libra_sum & libra_evaluation
                + log_n * ZK_BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES_ZK * EVM_WORD_SIZE
                + GROUP_ELEMENT_SIZE; // libra_commitments[0]
            let gemini_fold_comms_0_offset: usize =
                libra_commitments_1_offset + (NUM_LIBRA_COMMITMENTS - 1) * GROUP_ELEMENT_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n + NUM_LIBRA_EVALUATIONS) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUMBER_OF_WITNESS_ENTITIES_ZK] = [
                (
                    ProofCommitmentField::GEMINI_MASKING_POLY,
                    gemini_masking_poly_offset,
                ),
                (
                    ProofCommitmentField::W_1,
                    gemini_masking_poly_offset + GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_2,
                    gemini_masking_poly_offset + 2 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_3,
                    gemini_masking_poly_offset + 3 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_COUNTS,
                    gemini_masking_poly_offset + 4 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_TAGS,
                    gemini_masking_poly_offset + 5 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_4,
                    gemini_masking_poly_offset + 6 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_INVERSES,
                    gemini_masking_poly_offset + 7 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::Z_PERM,
                    gemini_masking_poly_offset + 8 * GROUP_ELEMENT_SIZE,
                ),
            ];

            let libra_fields: Vec<(ProofCommitmentField, usize)> = (0..NUM_LIBRA_COMMITMENTS)
                .map(|i| match i {
                    0 => (
                        ProofCommitmentField::LIBRA_COMMITMENTS(0),
                        gemini_masking_poly_offset + fixed_fields.len() * GROUP_ELEMENT_SIZE,
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
            let gemini_masking_poly_offset = PAIRING_POINTS_SIZE * EVM_WORD_SIZE;
            let libra_commitments_1_offset: usize = gemini_masking_poly_offset
                + NUMBER_OF_WITNESS_ENTITIES_ZK * GROUP_ELEMENT_SIZE
                + 2 * EVM_WORD_SIZE // libra_sum & libra_evaluation
                + log_n * ZK_BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES_ZK * EVM_WORD_SIZE
                + GROUP_ELEMENT_SIZE; // libra_commitments[0]
            let gemini_fold_comms_0_offset: usize =
                libra_commitments_1_offset + (NUM_LIBRA_COMMITMENTS - 1) * GROUP_ELEMENT_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n + NUM_LIBRA_EVALUATIONS) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUMBER_OF_WITNESS_ENTITIES_ZK] = [
                (
                    ProofCommitmentField::GEMINI_MASKING_POLY,
                    gemini_masking_poly_offset,
                ),
                (
                    ProofCommitmentField::W_1,
                    gemini_masking_poly_offset + GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_2,
                    gemini_masking_poly_offset + 2 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_3,
                    gemini_masking_poly_offset + 3 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_COUNTS,
                    gemini_masking_poly_offset + 4 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_READ_TAGS,
                    gemini_masking_poly_offset + 5 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::W_4,
                    gemini_masking_poly_offset + 6 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::LOOKUP_INVERSES,
                    gemini_masking_poly_offset + 7 * GROUP_ELEMENT_SIZE,
                ),
                (
                    ProofCommitmentField::Z_PERM,
                    gemini_masking_poly_offset + 8 * GROUP_ELEMENT_SIZE,
                ),
            ];

            let libra_fields: Vec<(ProofCommitmentField, usize)> = (0..NUM_LIBRA_COMMITMENTS)
                .map(|i| match i {
                    0 => (
                        ProofCommitmentField::LIBRA_COMMITMENTS(0),
                        gemini_masking_poly_offset + fixed_fields.len() * GROUP_ELEMENT_SIZE,
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
                + NUMBER_OF_WITNESS_ENTITIES * GROUP_ELEMENT_SIZE
                + log_n * BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES * EVM_WORD_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUMBER_OF_WITNESS_ENTITIES] = [
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
                + NUMBER_OF_WITNESS_ENTITIES * GROUP_ELEMENT_SIZE
                + log_n * BATCHED_RELATION_PARTIAL_LENGTH * EVM_WORD_SIZE
                + NUMBER_OF_ENTITIES * EVM_WORD_SIZE;
            let shplonk_q_offset: usize = gemini_fold_comms_0_offset
                + (log_n - 1) * GROUP_ELEMENT_SIZE
                + (log_n) * EVM_WORD_SIZE;

            let fixed_fields: [(ProofCommitmentField, usize); NUMBER_OF_WITNESS_ENTITIES] = [
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

#[cfg(test)]
mod log_n_derivation {
    use super::*;
    use rstest::rstest;

    mod should {
        use super::*;

        #[rstest]
        fn derive_log_n_for_zk_proofs_of_valid_word_length() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let word_len = ZKProof::<()>::calculate_proof_word_len(log_n);
                let derived = ZKProof::<()>::log_n_from_proof_word_len(word_len);
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "ZK word-len roundtrip failed for log_n={log_n}"
                );
            }
        }

        #[rstest]
        fn derive_log_n_for_plain_proofs_of_valid_word_length() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let word_len = PlainProof::<()>::calculate_proof_word_len(log_n);
                let derived = PlainProof::<()>::log_n_from_proof_word_len(word_len);
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "Plain word-len roundtrip failed for log_n={log_n}"
                );
            }
        }

        #[rstest]
        fn derive_log_n_for_zk_proofs_of_valid_byte_length() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let byte_len = ZKProof::<()>::calculate_proof_byte_len(log_n);
                let derived = ZKProof::<()>::log_n_from_proof_byte_len(byte_len);
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "ZK byte-len roundtrip failed for log_n={log_n}"
                );
            }
        }

        #[rstest]
        fn derive_log_n_for_plain_proofs_of_valid_byte_length() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let byte_len = PlainProof::<()>::calculate_proof_byte_len(log_n);
                let derived = PlainProof::<()>::log_n_from_proof_byte_len(byte_len);
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "Plain byte-len roundtrip failed for log_n={log_n}"
                );
            }
        }

        #[rstest]
        fn derive_log_n_for_a_valid_zk_proof_type() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let byte_len = ZKProof::<()>::calculate_proof_byte_len(log_n);
                let proof = ProofType::ZK(vec![0u8; byte_len].into_boxed_slice());
                let derived = proof.log_n();
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "ProofType::ZK log_n failed for log_n={log_n}"
                );
            }
        }

        #[rstest]
        fn derive_log_n_for_a_valid_plain_proof_type() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let byte_len = PlainProof::<()>::calculate_proof_byte_len(log_n);
                let proof = ProofType::Plain(vec![0u8; byte_len].into_boxed_slice());
                let derived = proof.log_n().unwrap();
                assert_eq!(
                    derived, log_n,
                    "ProofType::Plain log_n failed for log_n={log_n}"
                );
            }
        }

        mod reject {
            use super::*;

            #[rstest]
            fn a_zk_proof_with_non_aligned_byte_length() {
                const LOG_N: u64 = 25;
                let invalid_length = ZKProof::<()>::calculate_proof_byte_len(LOG_N) + 1;
                assert_eq!(
                    ZKProof::<()>::log_n_from_proof_byte_len(invalid_length),
                    Err(ProofError::OtherError {
                        message: format!(
                            "Proof byte length {invalid_length} is not a multiple of EVM word size"
                        )
                    })
                );
            }

            #[rstest]
            fn a_plain_proof_with_non_aligned_byte_length() {
                const LOG_N: u64 = 25;
                let invalid_length = PlainProof::<()>::calculate_proof_byte_len(LOG_N) + 1;
                assert_eq!(
                    PlainProof::<()>::log_n_from_proof_byte_len(invalid_length),
                    Err(ProofError::OtherError {
                        message: format!(
                            "Proof byte length {invalid_length} is not a multiple of EVM word size"
                        )
                    })
                );
            }

            #[rstest]
            fn a_prooftype_with_non_aligned_byte_length() {
                const LOG_N: u64 = 25;
                // A byte length that falls between two valid log_n values
                let invalid_length = ZKProof::<()>::calculate_proof_byte_len(LOG_N) + 1;
                // ProofType with non-aligned byte length
                let proof = ProofType::ZK(vec![0u8; invalid_length].into_boxed_slice());
                assert_eq!(
                    proof.log_n(),
                    Err(ProofError::OtherError {
                        message: format!(
                            "Proof byte length {invalid_length} is not a multiple of EVM word size"
                        ),
                    })
                );
            }

            #[rstest]
            fn a_prooftype_containing_an_empty_proof() {
                // ProofType containing an empty proof
                let proof = ProofType::ZK(vec![].into_boxed_slice());
                assert_eq!(
                    proof.log_n(),
                    Err(ProofError::OtherError {
                        message: format!("Cannot derive log_n from proof word length 0"),
                    })
                );
            }
        }
    }
}
