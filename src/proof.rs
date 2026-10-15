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
    utils::{read_g1_by_splitting, read_u256, G1Coordinates, IntoU256},
    EVMWord, Fr, G1,
};
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use ark_bn254_ext::{CurveHooks, Fq};
use ark_ff::{AdditiveGroup, MontFp, PrimeField};
use core::fmt;
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
    #[snafu(display("Field element is not canonical (>= r)"))]
    FieldElementExceedsModulus,
    #[snafu(display("Pairing point limb {index} exceeds its maximum bit length"))]
    PairingPointLimbExceedsMax { index: usize },
    #[snafu(display("Pairing point is the point at infinity"))]
    PairingPointAtInfinity,
    #[snafu(display("Other error: {message}"))]
    OtherError { message: String },
}

/// Proof-type discriminant without the associated proof bytes.
///
/// Used to derive `log_n` from a proof byte length when the actual
/// proof bytes themselves are not needed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProofVariant {
    Plain,
    ZK,
}

impl ProofVariant {
    /// Derives `log_n` from the proof byte length.
    ///
    /// Since the proof length is a linear function of `log_n` for both ZK and Plain
    /// proofs, this computes the inverse to recover `log_n`.
    /// It is important to note that this does not guarantee that the derived `log_n`
    /// value matches the actual value of `log_n` in the vk.
    pub fn log_n_from_byte_len(&self, byte_len: usize) -> Result<u64, ProofError> {
        if byte_len & (EVM_WORD_SIZE - 1) != 0 {
            return Err(ProofError::OtherError {
                message: format!("Proof byte length {byte_len} is not a multiple of EVM word size"),
            });
        }

        let word_len = byte_len / EVM_WORD_SIZE;

        // Compute slope and word_len_at_1 for each variant using the same constants
        // as the corresponding calculate_proof_word_len functions.
        let (slope, word_len_at_1) = match self {
            ProofVariant::ZK => {
                let slope = proof_word_len_slope(ZK_BATCHED_RELATION_PARTIAL_LENGTH);
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
            ProofVariant::Plain => {
                let slope = proof_word_len_slope(BATCHED_RELATION_PARTIAL_LENGTH);
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

#[derive(Debug, Eq, PartialEq)]
pub enum ProofType {
    Plain(Box<[u8]>),
    ZK(Box<[u8]>),
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

    if proof_word_len <= offset || !(proof_word_len - offset).is_multiple_of(slope) {
        return Err(ProofError::OtherError {
            message: format!("Cannot derive log_n from proof word length {proof_word_len}"),
        });
    }

    Ok(((proof_word_len - offset) / slope) as u64)
}

/// Computes the per-`log_n` slope in the proof word-length formula.
///
/// Both `ZK` and `Plain` share the same slope structure:
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

    // Reject non-canonical encodings (>= r) rather than reducing them, matching bb v5.0.0's
    // `FrLib.fromBytes32`: a reduced value would let several byte strings map to one element.
    let value = read_u256(chunk).map_err(|_| ProofError::OtherError {
        message: "Unable to read field element from data".to_string(),
    })?;
    Fr::from_bigint(value).ok_or(ProofError::FieldElementExceedsModulus)
}

// Utility function for parsing `len` field elements into an array, zero-padding the rest.
fn read_fr_array<const N: usize>(data: &mut &[u8], len: usize) -> Result<[Fr; N], ProofError> {
    let mut out = [Fr::ZERO; N];
    for elem in out.iter_mut().take(len) {
        *elem = read_fr(data)?;
    }
    Ok(out)
}

// Utility function for parsing exactly N field elements into an array.
fn read_full_fr_array<const N: usize>(data: &mut &[u8]) -> Result<[Fr; N], ProofError> {
    read_fr_array(data, N)
}

// Bit lengths of the pairing point limbs: even indices are low limbs (< 2^136), odd indices
// are high limbs (< 2^120). Matches bb v5.0.0's `loadProof`.
const PAIRING_POINT_LO_LIMB_BITS: usize = 136;
const PAIRING_POINT_HI_LIMB_BITS: usize = 120;

// Utility function for parsing the pairing point object, rejecting oversized limbs.
fn read_pairing_point_object(
    data: &mut &[u8],
) -> Result<[EVMWord; PAIRING_POINTS_SIZE], ProofError> {
    let mut limbs = [[0u8; EVM_WORD_SIZE]; PAIRING_POINTS_SIZE];
    for (index, limb) in limbs.iter_mut().enumerate() {
        *limb = read_evm_word(data)?;
        let max_bits = if index % 2 == 0 {
            PAIRING_POINT_LO_LIMB_BITS
        } else {
            PAIRING_POINT_HI_LIMB_BITS
        };
        // A big-endian word is < 2^max_bits iff its leading (256 - max_bits) / 8 bytes are zero.
        let zero_prefix_len = EVM_WORD_SIZE - max_bits / 8;
        if limb[..zero_prefix_len].iter().any(|b| *b != 0) {
            return Err(ProofError::PairingPointLimbExceedsMax { index });
        }
    }
    Ok(limbs)
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
        let pairing_point_object = read_pairing_point_object(&mut proof_bytes)?;

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
        let sumcheck_evaluations = read_full_fr_array(&mut proof_bytes)?;

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
        let gemini_a_evaluations = read_fr_array(&mut proof_bytes, log_n as usize)?;

        let libra_poly_evals = read_full_fr_array(&mut proof_bytes)?;

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
        let pairing_point_object = read_pairing_point_object(&mut proof_bytes)?;

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
        let sumcheck_evaluations = read_full_fr_array(&mut proof_bytes)?;

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
        let gemini_a_evaluations = read_fr_array(&mut proof_bytes, log_n as usize)?;

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

// Convert a single G1 point from 4 EVM words: x = w[0] | (w[1] << 136), y = w[2] | (w[3] << 136).
// The point at infinity is rejected: callers only convert non-default pairing points, matching
// bb v5.0.0's `rejectPointAtInfinity`.
fn convert_g1_point_from_words<H: CurveHooks>(
    words: &[EVMWord], // words must be a 4-element slice
) -> Result<G1<H>, ProofError> {
    let to_fq = |lo: &EVMWord, hi: &EVMWord| {
        let coord = lo.into_u256() | (hi.into_u256() << PAIRING_POINT_LO_LIMB_BITS as u32);
        // Reconstructed coordinates must be < q, otherwise two limb encodings could denote one
        // point while hashing differently into the transcript.
        Fq::from_bigint(coord).ok_or(ProofError::GroupConversionError {
            conv_error: ConversionError {
                group: GroupError::CoordinateExceedsModulus {
                    coordinate_value: coord,
                    modulus: Fq::MODULUS,
                },
                field: None,
            },
        })
    };
    let x_coord = to_fq(&words[0], &words[1])?;
    let y_coord = to_fq(&words[2], &words[3])?;

    if x_coord == Fq::ZERO && y_coord == Fq::ZERO {
        return Err(ProofError::PairingPointAtInfinity);
    }

    let p = G1::new_unchecked(x_coord, y_coord);
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

    Ok(p)
}

/// Returns `true` if every pairing point limb is zero, i.e. no recursive verification occurred
/// and the points must not be aggregated (bb v5.0.0's `arePairingPointsDefault`).
pub(crate) fn are_pairing_points_default(pairing_points: &[EVMWord; PAIRING_POINTS_SIZE]) -> bool {
    pairing_points.iter().flatten().all(|b| *b == 0)
}

// Convert pairing points from EVM words to G1 points.
// The first 4 EVM words are the (lo, hi) limbs of the x and y coordinates of the first G1 point,
// and the next 4 EVM words are those of the second G1 point.
pub(crate) fn convert_pairing_points_to_g1<H: CurveHooks>(
    pairing_points: &[EVMWord; PAIRING_POINTS_SIZE],
) -> Result<(G1<H>, G1<H>), ProofError> {
    let p0 = convert_g1_point_from_words(&pairing_points[0..4])?;
    let p1 = convert_g1_point_from_words(&pairing_points[4..8])?;
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
    let mut hasher = Keccak256::new();
    for point in [proof_lhs, proof_rhs, acc_lhs, acc_rhs] {
        hasher.update(point.x_be_bytes32());
        hasher.update(point.y_be_bytes32());
    }
    let hash: EVMWord = hasher.finalize().into();

    Fr::from_be_bytes_mod_order(&hash)
}

#[cfg(test)]
mod should {
    use super::*;
    use crate::utils::IntoBEBytes32;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_zk_proof() -> Box<[u8]> {
        Box::new(hex_literal::hex!(
            "
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            17817012e17e58e005519052f074bad14c96b8859cf5027c18c21b151d45abc3
            0e6d4164b6f13a6e36abe2b536c3fbd8a4123e9472166600d7d18ca4e53ee819
            038d25df1ea592c8f4951968df111647e37a0365608e8e9d60f1a77dcfc07bbd
            123bf33946b270e980fb177ca6a068d6536e181d409800b05eb1cea2b7fb4d47
            2e17eecbcba2a316339f3f4ca761e8a64c3019c9a4cc6c81200867ecc511fb95
            028dab042194d95117ca6ded2367227f2fd747bbcbf320db04f00a4bee948f9b
            1de38a43b5439aa1be38d612fe71e62934bf462b7fc9adba33aa6c775e9f1c04
            2e4d32e88ead2b59a77497a3cb389c0a61b16f0e59538bb3cdb278a4fed55050
            014a49299f326199cac2e5f128ea109e23bb6d1105cda82b0d49adc4de6a0678
            2e4cac24c9bdceeab2bfad96f13212ebea24ec9952c98438c47dd0a58616f425
            2badd18d5f9e2b55be136a3d09314bf9f4ee6706c425f04ea493b02a7b85033f
            105380a9962380c857bcaa67c8d28d2fe2f67d66922c1e40178a522d9494badd
            09c191c94c103647747e4e458c13fe11993cee7cca68e4c939b3c26042aa8609
            21122a0c71136e41dd47305424c00c9131494e44cafb9e4769bf1c81dd91a250
            120587bebe5c80b88eb2db24b36c2c26947ad8240d7cb443cd0b01a40cc6fff7
            2f869d9b11e458dc4425970a868386bb40269f7bd313ae6f399e8fd7fd9330cc
            1e0e28dcb28c3baa3df78947b14e1f738f1407b34e6d08b23d6787b2b18e2d05
            11037eca53f47508b4679bc6b8f476debeac0922f908f72c5bffad1fedcdb6ff
            2027dc5796cf6cb9a862d51ac6a58c1144d16b20452d9539eb28f03e28cdd2c3
            23ed47466fb5f3b62a9a97386b5fc69824067c5e11e9920a7e85370ed13b9f17
            07b2ef19e03e26b289705eeec028c9243be589ee7c1c373c74d0dec41d1e4890
            2a5a66538f643486a13c28d3c634d85a55574ed5d1f222dac7cac9e6d2be71f8
            236c5eff39d3592ec3f891a5c47e2ce4d787bc382ec4fe394dfac63d3d1822d9
            02b276ac7790aa15b3a3f1de368f261614109f67cc29f708d5c34fdece01b856
            24c7459668fdd9cc941f410ef370abd1e3551865abe98445405d255b12d12926
            1c86a079eb2ec2f64d7c46bffbabca2cf7890e908d8fa9a0349526265cd2d499
            04269cb0515cc0e614a99a83867ab610da5a0ec2723581388a5fc75c046d29a4
            125e1232e267a6fcf4fc4e1e99d40e57a7f73624de3f504f10af455abfb364c0
            21ca92002c281c0e280871a857783c90295cb0d515ba4fec208127704ce381b1
            1018f5c042858a74bb899953b0d876470a3632e74fd4c18300e1a639bca9c0de
            0d8de61a305210d15e0263d3b03897813b03437d2ebc5f9ec810e47f40ee6427
            2dedcc2b513820779e2e0c2543ad06e8dc39628f58ac63e3550aa91c23a1f2a4
            2bcb3732947d42eec61917cfa4c73567205ad316c7b7ae8a771c8b199576c76d
            167aae20c919d0456afb701fee47f4d8936ea8760ff6062f213f097364c4c090
            00a553b51d92cbf0d3e478ac301b5dfba32a1b1a133f3283877f6577e324b7b8
            1e85de42ca33500646494a195bcd4e406c4e7598184855e65c8e6498265021bb
            28d3427537a0a78cf4425cf68c220f123c4687b81a27c8fa337f643f51f9d5ef
            00a165ac6ddcadefe9a8a3fdd9609b8cd27ada07656c12c4ccb18f93e0c9826c
            154be090c1ed1234258a5b3cc550c19a9cffee8dcf1a70a701a234fb34bb0c69
            073b806d11182f0889788be6f1f8d429bf60dc809ed2a87145c848040debad27
            1463dfbec135239d7d77758b8de217d2c7ece8e06a9239f9465a4d13a09dd8ee
            18103ea4acb35bd5e1968e4d3de9f4993fa48d16553c8fbdebabefc8495e46d8
            2a8bce2b03736c0d383126807fb7ac8492713a8b1fcba09b7ea85f58961ce63e
            1f25735f661a5e3eb43adc8a8076ecfd392f227aba42a70993e8dc5ae293d5d3
            2fb5bee5eb33b6b8b127a8dc2f9103451fc1826850c9e4eb12c9dac51585fac5
            15a5fcb804b1df7b579fbe7902d67d8d074a78a4103283921ece9eb80e383132
            1186cfd074e1ba529737111a133141dfc546fbd2103ce6ccd7addc2dd9d4bd10
            09ad069e5b951436d47fe02f99df0c424ae8b02476a61bce901a29c8a6c49784
            18c100fdcb24728e4d04523e08fa982c3ac78f7eb43f70619fee6d189708924e
            2cb6a0464a6fda46d46ed17f3cceb819b0022dd807ebd6d0950780b078c109d5
            2e71547370b6ca8577c8714897b4ffb310c829ae20ff94f6edaa4fbe648d50ea
            2981248c79a2ee5dfc9e6f36f508ca4121e7b36184e12d9480f27ded7dd0aa0e
            186272a4f4d3fe3f15e6c85c39f633cdeb660bfc7991b770161c696db62d5a78
            02ddd45bad695e0fa3f8f841154c9ff56ab830af2ac4461ac2e5f8bfdbfd4feb
            00fc4211779fe52df94c5d67ee57919739633d70ef73572f9e9c87db25439992
            04cb64bf5980e3a970a67bbc7fe4e0ee44b17fb755d78661f9379b033ce62779
            18f151ca77565d9a48bc00f592c276bc1a3926a97807fd24369f846da6182dba
            2f7f7edd7678db2ebbe99d746073f639b12c70a9a8519129ea24f20fa8f71e3d
            1a3ecffb44450edb10a163aa649fd378cb02285f8d2f1fec2e1b96ccc0d617ff
            138ab0bdd82819d03fe7b8e70921431b832cabc878ce42aad9bcf3e73f80dfa8
            0af8c667bfea4fbe12f35dbc681912487a6667232a158d1ccbd4ed89f4e75798
            2c7c5dcd66f7db2ed961e800e6f93a299938c77219990cc8f1d66178a594bf60
            02bc41707d9ce548162a529fc043564469d5137c5c8708050257001df10535b5
            26530c61a621c3b3c361cb81a897f2976c9457831be627bfb1bfdbfc6bb12e15
            20a7d68bd63a2e0daa8035022d168eb5f1466fcb13335fc43fbb36cf21f7b876
            2cc707525313ac785ce62db84abc9cf1bc52fe69471ba08816b0aaa6a00cbf54
            110c10ce97529d4fb6a158ca952ca4f74d691464a50e6e6ab3e18fef07a4abb0
            11c91d6f2d3df2aa3ced94f1ca17602aa10f57916b7f39b2f208665c93588d7a
            1ec21fb59c00f2c78830a3f7520278f657f2c98f866a120a9cf2f60195802c2a
            2fef74b9abc6bf8fd71297165ffc270c02ce7302e32d0ddabdd9b26be37ede71
            1ec2a27507c08a0170cf38408976df8eccac1d390f8d99d1f69caf8e6d9d6ec4
            044902e651b29c577dcdd850b8e159a41a052e85c3bca48730833be77ff88d8c
            0dd46043b0ea89adbd96dae38860a6eb89c9c63ff2fe0336fabbba9292c61fc7
            104c0bd5d0f3eb88a0a9ca4c9804953f96acea62ebeeb9da3999da4360a23b76
            213d6c34b481de0b0496e70d4e229533ed35d96b863e73ff099f498e9127083e
            1b0d5887ec0f96822024db48a878b96bf39ae78c03aa399ed65784f7bdc38826
            089b1e3929c5ba8af3dd5ddf5317e78d0bf6addfe7f590dc715f7cf3900f9fc7
            12e5f94a6629ad0e71cf358eec7c5ea087c4721b10cd887b7103e30e54b7bac3
            0c592793df3aa80379fa8d084f07480307afef48a4ec9935b4948e3e0d583e10
            2ac9cfdcf09009bf8580930b051948513a8eb3a3701c0bfc56de894f4dead3ab
            21d40243ce4f9127d4ff1aafd411921eae3ec57aca679f1d291b4b3dec5f94e3
            26620d5b211b7756b0dce39a3d4bc3b8e49f9d55dbeec3664efe6e8a3c37316d
            046d61a7646259b934f5b84dfd7d6151ff5af077e5984c21513def888c2c02b0
            1f92fb325608c22d300efdc713a605cf739039977f9eb67fa9a7ae522de05aca
            1ebe52212c7c29ebd401d97738a8becb633c87bedd4b68ffa26cd0b9311a4619
            25778ea3071a5b8ab5b7f273050dde3710a0a385c5690aea9727e136fe8ec992
            1c92de141f62fb8f07a5b69253eec4e714ab4f2f04dcf2f5635171cf6a275e38
            21b2e6bd40e6be9f01444b8b8fe93894cab60cef2185aee1769ed036243a11be
            0778f73a96e662411c5e44f90eb9971a02e7c5f9b7f1110c666b776ea858cfea
            0f1c07d591dbc613ce999088d00d719dba33fe3d149ad5397185725285d1733e
            023880d6e04187cd73f360f0e152b81ff29fe3e9b68928c41199a7e6b7f2ddf8
            012513bcd9f1eb27e7fe36a05274855f15892e96bd9941045d8ae2204b2c8043
            079659f6dbfa89416960a2c19f92ce2913bb8d9521de90b988b2ebc5618fb0a8
            2dd8a91ed48d8a2a50484e8898bff884bd71f9a9ddf3d7cbdafab1abf1eca522
            1a5c913db9877022611115a4b349378a994448197309eb07597d3ca3fe404c3e
            303cce72e1132c3266bb477d9ee16db2e1a7071b9ba50c3501e9eeb59528196e
            011c34b717be5886fdfd1323bb9a16be5780d6152609bd4f9d014ecd84943722
            1e523cb39baa812c5869ae99ef4ae8ee21c7a18c5225f77d919a5cfe0f31531d
            1d1c28aa7f303659493aa21b977983577f1c0e08e5bca0c2b91ba12e1995b5dc
            04b22ecbe037e340a911913fac2733b50d2158bde363f68810b319f5b63fa755
            279278413e8f0a324056c018f8db98be27f8f2e223a8f001c6e7ac1cf98f6db0
            022d764263c9ac366feed8271bfff3b63b9039eb67d4ce6d92cab2119234c745
            1253b78361dcdc19b0cf145868bb55809bff10c270d13bf85e917e29f2d1fc16
            0b33dfc9263b4db4fce1256cb60228e7e40a034fb4f8d663dc2f99ddd9577deb
            0778a26edffd6008995929b4e3f0f769454482ef8a610a60813e5d823e9f2ce9
            096e580a10a4cfec6c0e02ac624027c4a1eb4a8ffb925e454d8d477e8676163a
            1639cd04778b23d8d584e183e17500284809ecdaf90effe1c0f5696d72489817
            22112d245f01966393114e42fb5ef9440fd3b0d6b1e57490dce7d13a050ad01c
            12b7531ba17b84618d825f1bc009bcc64c85304f6c09363a811fbaf8c9c705ef
            12519f914a058de74ccc0701e41cd91861ece4ce6bcaa8f934c985f46339b913
            0e936b05f7b22174946013578907631d9ef7956a256f9f7ba4e5dfc701613762
            0e60ba8f57d00a5d57a310de3f5d8ad837faf8b3811c2a59e7914e6e58204874
            26a7d5fd9f974cb8b3d6758fe56bbb285c37ef685aded79431141d3bf6eea87d
            2420a722105932e9c33cf003c16cc0996473086d9c32e9b03a0ae6f658fedc07
            17203466230db7a39aec41379f9db943d0136f5a91732aeb52b869b788fd4e37
            0c9d3f5dde68ef79daebc99a34fe69c750be4e52c9f4b82868fa9250646692e7
            252d0d98b1a80d1eed663d3e80f3cf0191ca18cc418cc1ac12619021522ff996
            2c6f6e7676dd370dd4331da183353318e2d5131604a822bc390c11acf0c107c9
            09236872d6af1f4f759273d5ab2548bde52c61204c316f2c14cddae84949e192
            23164338fb5e12d8cd546df9dcddb8bd08fffd1d838da4f4cdf5c0b5547b634d
            203aacda7e7a0b196d5cee6bbe2c367a48ee4f23521595eaa660ea63fd2ea1e7
            17e5d81087e1fd60e57229c5dda8775ef56b5da6f28f7803ffa3a013cd753dc6
            21b72bdb0877d0b6df8bec3a9a254e317492eb411d1625cc12e7ba5ce322e69a
            0bb1ed10922ce24bf8e77ac1e0d38741dffacd1699bd7049a5d996621f4da78a
            1ede12770f83581208786a59656ebc6610633e0e7acb1feda956109e7831a4c9
            2879ebef788eab052db05c551a2d6c3afad9552a8047147e68f542d7a3d49c5a
            062e0fde647740f316dcf738d5375ccbaa0e8eaac2907493696b5220771d038b
            0e27cfa5129231eab9fd1a3baffdc1e649ca34c23b7a3920636752a0d0fc8add
            22f02ae09299ff4a1cc2f31eae1efa48df3e290c767d328a23720f9e9ab43d9e
            21db97016ff658e572ab991be7dea38c84fd643b8bb464eae2ddcad0458b5845
            1e550c844bf9bc052b8d40c976b4359692d8efb543195366ea8005326ad26662
            1875613b61fe8fc4f3ba742faf341e9c3bfba5add3d09131d625f49b0294d592
            207e55dcaba87829a9c0a6b7b9de3b5b293f8374ac97ba07ef42c6ea329c9702
            21af43eb442391e11f05b64828a48166bded6bf23235af7808d1302faeb92636
            070ba6cf916fffa59b77541ce6668787fb1c1caa393d3588b149402710d49fc0
            2156fc51affd8ce8f4b04082c5545efca2d8e4c1f350beb58d8feb495acf87be
            16b4dbb7993241d60b0cac66af2b157f7e1d80eb1ac9e702b75c38e2f58be571
            148d6d3146c561a35dc0386623cb4282c3fab6539bb6958521a5036a019c3b13
            16fd04b922b3b9d24d2f6caa4c12209f9b511a2cc4f92e987634114bdf5dd629
            1b41f91cb136f65d7df6c7de5e7935a2513187d3b2d42a6d2455aa303b006cd2
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0b0690c26bc64443d067d66e85ce98f9b1331d3f888c6fe6f5cc5e7797c44513
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0b0690c26bc64443d067d66e85ce98f9b1331d3f888c6fe6f5cc5e7797c44513
            1b0427f76b85663329114e93e8e2d2a37c7f041b0460aee04a45fafe01d9fcf7
            0000000000000000000000000000000000000000000000000000000000000000
            0ffd9734ffbf21ef58a97825631439a9cb4be6db7bd43ef954799c866a15b7e4
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            1d0b7624c9a29bebbabb61c34826b66e63798588822a0852ad18d3d020d0f609
            1859e1c2f08cb16173dbdeb587b13fdcc865baf26f3d799eda72548f8ddea731
            138bfcbcc7ec9d4282685f34bbb83dc71a4e6504dd5e1494c7441833ada5dc11
            2561423d68e57c7e8a864544bba7367408421c6b7c8346b0619947b3ed636f8e
            1350b822896ec228cdc46ab4987e8b775df39ba54a871b0f4f649cf09c22f60a
            09257d5546b2c6b478786bd386f0b0c4e2448960cfd1e4b65985640f5fa8e454
            08b66da60b7dd92b093c8d018cc30a6ab0c23a96de33771d50c93b4a64e90f92
            1708e34126ba790b61e528993a5830469404114579bebded38dc93a8f3314012
            2740a7f338bb5680cdf0fa3ea3e44581aedb9bee9f78a9a7b28227baf71ea361
            02916efb4bc90b00e909089ae7f80f4ff9b73a349afba9984b7e285491f319a3
            056a0ee4d49f3ce31b46711880715b28cdb4fdb3bc047b0689a2cd3500292da5
            0b983d5a853fbbac6da6fb50eda2c666c16d28be0363858a175fb8b049ae9dd3
            096799a3ce9c277b5bb02dcc67d82193fcae905fd613ef0ede31fcda25335d5d
            017ac52f4e828c110c936f193ddceba9becdc1bcc674a4f212d9b1f0ecac924e
            0fec96552dd14bd0b9f824db8f64c4d088fe87bd0ab8f94d72e9cc5838939d6b
            2fc26acabdfd67ddf90dcadbc017c7893918b0e736791208d6d2181ad9fd7063
            2502abd8d7175b78fcc83ffaef674b5e0eee3d1de625040f3a9b92726a8c0e3b
            199d61bc850ed665c584d53ccf5273d2d605ef771c26353e451be585b9adaa1b
            0461ce92f595f1e17eb15914b8837927dd06e7e7bc012880fc3cfb1771fc264a
            21d87a780ad7260796cbabcb058aaa136c2488947679e6ea1fac681a1a4a32f1
            24b97ae1c4cae42a8e3bb6abef9e21e627106bca81011685e80e981399047219
            0a425e442b5b911bb10b6e2976e4c915509cee911e2d94ae65469d294e8eddbb
            03c2b942b6efb2ee2e59f60d8a19cb065242cdeb599a270989e8eee5bb2c13f1
            10b5c2cc3a608e0e5717c1f1d43da020ef0ee5a1a4dd9bf0844a719577e11789
            0b47b9aebb497d32cd4f62e322a9c62b804c503cfec4a59d71c63b2207dc31fc
            01fe5a8fab2f21a125f6e9baa9de4d62c7a62f22c99e2419ee08dcf421fc2053
            17bc500544092bea769e477ef9122739833e9c1c88b55191a191dc6af7bc9e0c
            1ed4c88611379509b2695e993ae4c4f3d527b9e18a2a5895d595c1367573c3e6
            0094fa8bef7e8174f558a731a0edc6e02e8a2bf500e1abadf256eb6c36a9f7f0
            1781839c2cfe7f5baedcd1b3b57f7bf93122652bf9c83f97b1410c95755c918b
            015d6616ccb1d32b154bcce765f5c4428a768f8c693ea9097af18957d3870641
            067df43074e4768a73e6dfd46d4969b507c658e1ade3b9ffa2538a8715957fab
            1fa20f0ca75acdd16ddcddebc1e621540c03528cf0cf62b44834c2ce65688977
            1ec58128a8f9615d2719484429d03adbcf7a9bc4ddbc747c90e81d90825eae16
            2c99379c15c92d5a8def0831a8bc1d1010cfd394f8581ab5bd53aa287c909d34
            17b4e8ae3cbded6d5d37dd89cf41c846183c5012aaafec34d7914cedaf948338
            2b75c2f9c94ac971920671100a38d325d48353f0370b68f0ab9e6fd05eecb787
            092b966b64df9374b7b77dc56628309ac56be7719c3f4987b943fb6ad0019543
            0a5bf915282dd8f4c98192e6856cbccb9314248d28a24d92421ce4cf6c1d8f32
            2fd4f1df945cd46d6e950c20b887d39cab9dd599f956b991232daccdb2f64892
            04f871ccc1fdc14935018bae2723acacbdd2b06d3bd8c7dd97d7876f1707c89a
            19ab888cf7204141289abc0cf843ccbabc3af2b0bbc36f31f07f738f9c43d9a7
            23a37be638ed233b3bbba91e05a47dd6f6a380a45c532edbe634ae7b5ebad274
            19728af0aa4eb600c16ec9a4b52172865958e296a651df916b0169c5b8b535c8
            23038360d4919b1793908a04a84ad998ee49cc34920d1676c37e0702f78470ce
            0212cc0bb70893c60a0c714bac9ec853196dcfe7fccb01dd3b1f54704fc6f6d2
            0d0bdefd960fcb931c9c5bd127aba330e3633d6a469c6b9227f94050805a6de4
            0e31cb210716500a098c57e67e4365587f1153a7321e8b62ca147d5598ed46a6
            281a4a687c6f0a05beb87262e3bbece510038d5fce7687ecbfcbe69a5cbea84f
            192750f64cde7805431b96fa036843ae5866f201e1fb60cdeb3b8180b3b9b9b8
            0baed9623a96ed9c3de31cff70eb6506649c7ec57e81996d604f0b696976b307
            178ca376116ba7cc383735a96b346bc1c18b0b7e3d63e2df3d610390137b82e8
            08e0000881ae92e883847bfdf0e9c355e16f3c133df78a44c3c3f27a99f3b3e5
            28ce729f24605461448245a8f4cf428f7855cf329b90a2fcd8ae2b3cfddf9b3b
            0509d4704daab9dc5adaaf63c69536c26d7fdc00328bbe08bb8cb23d47948c4f
            2b55876bec702106fbdbe2cea50699469e63b34dfac561bf66fc69f43fdd8aef
            07bdfaffb76d5fdeedb0baeae2f0dadaa761d504b619490b1f811b21ec274d58
            195998ceae2681431a8acb3ab4b18a4b93e73bd832e9a40bbbc14d0537ff3868
            0b18fdcb2bc101d04dfe9a89ee17c4a87b73f13c5243399bb32659d92a081b71
            0147e96def1cf87bc73a1e0673a06a3bac6c1f1ff28910c8dacb963e046c8e3c
            "
        ))
    }

    #[fixture]
    fn valid_plain_proof() -> Box<[u8]> {
        Box::new(hex_literal::hex!(
            "
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            14bf37623bc20daaaa1b5f24d638ef6d435b52851fdaad30b34c670552f66e6b
            1e03868fbb08235a60b51fdfa9e713c1c3ac538bd867053ade415cc88770fc42
            28d8b9ce435306a1a303da077b10c38fc57d593c9cf1347294880339e08588cb
            04dfb5582f5c4494550e4b60c0b7ed6db5e0c87be19d5193e85803ec5f6450d2
            1469006b8b61c8d79301dfeeed1b752548d2ebff7ed60a3cda0c7db10c955c8a
            19c2b11ddeff8ffe68ab919e345670ab029bcbce4a91df6570722995d636f037
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            1469006b8b61c8d79301dfeeed1b752548d2ebff7ed60a3cda0c7db10c955c8a
            19c2b11ddeff8ffe68ab919e345670ab029bcbce4a91df6570722995d636f037
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0c69f06ce415c563a7082dacfc46093339d3093c732d5fa0e5825d53c1863da5
            0dd9288a079ffa14667d353eba253839df2e0bd45b56c28e8ac49046ec5dede9
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            1d9ff083a6e3730d3cd206c71cb3680b3337c32300007a42e35e0b8dbea16153
            00941eebeb6802493b8dbef9b638920a731c31ae980cdd0ad021a5e5f91fb7b5
            1784681184436533d350eda6f1514ccd51c945e8f24ad544f98b4ec0e70db1b2
            07b8859fff63339c44482cb52aff1b8981335845c1597b767fd400e02a0d4f39
            165a060b2dcdb75c0f1ce2ff2c50f5e911a4ae0b8cbeb2727e4c28674c3a1f2f
            0fef0c1b61849921abb0947572bb8619f9a5fa3b8960f76497413f3c9d4583e5
            27dba6f6e2c7654b4d35492eb59a915e81c4d886f65ebc7f33efa873cb0a4a23
            1fc201df1e223ed355acbc7dd52ba8fc86bdf9b96496607c3e1e196fc156bb82
            1b44caa7e2b6e4ff18b8b42929e0e2ca5ede7ade452efff22b72aebd96a5122d
            098fb1afd782efe45abf6256156fc39b0fc0af19f6a600a2231c24d399283540
            058e59aabde7584a4aa261f66404e84ef7e792def6840535ca0d86d1cb0c3278
            09942afa866a5b990a8105dd86f1c8a6fddd819b1adfa0e5748b618eb86e84e9
            02140a563a2b50977ccecb7c63bbc04ca328855972448fc520cfe29dd6163709
            0f03a44bd7d6cccd9d6dab8d360b05b1d2e0581050460326f6e3edbb78ebe00f
            2edb11706f1cc00dd67d8861bde1971a94913436649e3e0c2080dbf7efad893f
            0d7549ad88b83c876cf598749d1f3875f62a33fb42132ec666d0e0f983e2ea4b
            056bf473bab10a0eec9daa44542252b6fed958b90408023c58b8a41880108c20
            04bbd40b75d272400ca2aa05b68bea53ef03dedf331b62bceca9f69732c67204
            037c1d62aecfafc9c9349d081008b946f0175bf603cbea6f7edf3d12d1fd148a
            22981f369b4d53e57898fbbc963d83faf91ad95c8fe58e67103f67b56351f7b2
            178dc7d44a91ac56d044c165dea53da7cb36383fd0aa48d22ba6de4387d7ac37
            29e4b6d2a82fabe97dc175fd6a71207ae89ec2300e674916a02ce2f56b793c17
            1b7bdd082d712de882bfa4e5edf7c794fb97e6277756d71cf0c1dbada0aa8226
            0e863ce1fed3d75631bc53daab3bab76c3a2c26ba9e07229ef9ccbd0283df18e
            2e3fab2d5345b4b1518baf49183ee035443c61fc72809d4f1e020521f7009620
            077fcc30b587e8aae26256f89994dda7b5a3b4cd10313b5312aec0d6a1edbb96
            1c85b10c8e67e56a21f5407c3b36b087f1d2fbc3a774a177d1add7f7e98466d6
            1e19f51c62462f55c36157226414c28ed562cf5540c08772a8eb2d6a0de0ff8c
            20bb940d41e2c964bb09777f1521f474d1859426c6e64e52755354cf403f8b4d
            140bcf717096a6e39e93f7be0e3668bdc209ae9f225ca024af6e7ad7c1e67a2a
            18cc940b58c062dfbfdc59f5d09d7bc568b22e250d0d447bca0af1300a43b959
            0b52531013069c66cacacd194bd0f1492a37231f2d1b58c0cec462a04b4b9c1a
            263365715b6259aa5b0c876b64a1e017b63615eb34bd35002aa9a42588ddbf8a
            0647d3d94f91787332534df0acd94d20d5de318289f744e81ef6c709a977c788
            2e1d50c801ca27aa7206833cf7d93652b0cec8071f1fd581b0ed37d64cd7eb4e
            154bf59dfc7d2f3e2a5a84533bcb67d5114e9a2948c1a4b54717cac1ef6d1294
            3003e53821f76cd70e7188c117ecefdfb0b6d48b41d9bf1be3a031db8d09f023
            2ec343b6d6efdeb0c8aadbbb423f0a401bc18f86dfbda4d91c85884352db19af
            0c21fd97e6fdebaa2042a023b2d1a30ae2c460e405353598401ba719c47595e2
            20ac615a8fdd4e207df21ba416d63e76078ea5fef9b851bc84c9aa372cf54d80
            0df734a46b5c5c6b00b41c42cad0dd02a86abd74c3637b689b36012d3958c8ee
            238e73346095620dab26e9ea2fdd50113cd0a9c9d62881daf7ac28b3fcb1b577
            23a7882d42aaad7ea2626a1e0eb05d867b5bafe9c4713aa65e659d780d72c170
            16d4aa748e992aa4a2e73e587b9dde9ec2e53b6bd690d5c0f10423388fbfb655
            0e3a12628209c97fa24c912051297c861867e78cb419e2034bceb4e258a13aa4
            27032de7b37d121fa7de79d6cbab7540d31606d8732b16108dded4b3ba1c3b7d
            1e8a366f1031c1961dba7e0b3446d371eee93b368a06f17c311dd2416355a4f3
            22248504701a49d03264d8bbefb32f16a5e961daccc6cd82615c325d7c9821ba
            1f6032293ca7be2b0413a09687ba16277c04309ef092f24aecf3b19af4904ace
            22374e43d89e98750efe501d92a7453edb4a4acc58f2acc91012233723d8e15d
            062543dfad3ea6c65f0191f765925def5f09a28f35e2116a35e0ecd0aadf2867
            0b772a40eab9b8d10d3536c921d942448847f835e52e5b30449995936680207d
            095ba566d199e396493737885f711081f488c5968f240c612883584d6cdf0391
            1292ec37b6ffbdf1badfd9f50aa1ec9671e931da206c694e98171c18227500e6
            0b26eced88536297dd45b806b03d5aa73477416f5343d3c6212568c307d1bdf5
            034446ac4940ca72a4beab94a7eecf3f776152efd29b95e892d45afda52e3f4d
            0bf1d47af45deb043f03ca2bdb821fe0cefe219356c17d05afc96b2a8a11cc88
            287cf845d26424bd8a13f9cbc9d66ee3752af17c3224a99b77b3e2338cdfb3d4
            27e2db526690217e32193bcc692361c5187a51b63e6d97aeac056cc7ea263370
            1d5ca4d855b7e720482557d28db6956fcc56d4daa764126b3f1f9af6a8a320dc
            002d0e7449b4f663cc154b0a32ab3b90117b9cca419b7a28a56fb81eb66ff590
            2636187ebbe117b1a46def113227fc406095e40ab46a51ed6b6a9d682f554143
            29b8326ea626cf6456a44e303c69b8f6b176c308e8e04b920c7e85dc5387654a
            079dadf5f8e5f9ae4b0bb81a823b371f4a6b8663b450e2748c3281a7bdc888e6
            139429027a48b031b04099311bf28f75fd7bc7454f48518e2276c1e4ed7b1cea
            22b7689bbb26d60c0c4120ca1cbf4fa323e869b0eaa5f79b566bfff05f6fa247
            255f0e6932c66721516d6b2b7085405ac0d590b4bbc67de2b14b4a038e9e4821
            1832df4f9b598547c433724f652545808ab1c1a4a6a1e5bfc417b46ade654bcf
            22c4790e94e95db671e2f04eb6122f858042cdd345c2e00263adcbc6f6bd07aa
            221d3d1309e7660f57681c96142c1c8a6888e1a76931abdd0ba8f209d261b0a7
            1677388d38fb7687a6dfec8b54f6875f6adcdfeaa9ddcfb35955254e4595c905
            11782460a4f1712a8cc705703f73b0d3069d70eadc86829a1cbaef12d15966a2
            2c35ecde8584bdcce7b4d26cac2381c59edc30758166be2ded429ac08de120c2
            25689154ec6848372aded0d8228baa301e228b430a1c889341acc159bbd2439f
            030fa7b94b5c05a6685c7b4ffc64889ea7795c046a8a0fa8181596bd429ea4ad
            23fe2f0e208571e3225e75a0d84de554f4d13faa7236e3e094589820a8f56212
            17f30efed7fe37a10a39ec82a8f0ab476fc1cdc04f714983a4c336d0c4853efa
            061465ab7a79876a138d9b697ea8863028adda82beac6ba0fabdaec7e1109cdb
            20b982c5baefce053304f2a9a5c33a67cf415112f7dafe54e9f0137a3eb0c69f
            1e087eb7efee62cabd4399a7ae0e29014353b699c6a62584ca0ab9bc45a774c5
            0b8a66ea538bf0dd02744b0b227bea696c958788ed609098f0aa5dfb97f45a9d
            1f1645cfde7537b15d89be810e5c226389e6637e85e11ff25a416401e794df48
            2dfe058a2c85a27bb65bf778e36c298322320152b36b006448d58c5b5579ef36
            2e09f4109621d55b55c2ff6565c642cc0df8ea5e082500f405270af84bc38e1d
            24947b87ced4c81b92e412d6021f4b4c955784da35212c874418c542d7dde770
            14f2fa22acc44f0582a2128c12d6ecc91b2726367220f934fbff9863547fdd59
            064a49cc3d0a1b4a61a064e2e9e6762c3a224e06c0b2de46573c7a494338c110
            147ed438208c9f38f4b2520341fbcaf9d6c2fb4ec9f8f947efcde0e08eeab041
            0d6183093cc7640485057744132c1f9ab57fe754f0e7b0ec2508d34a3cd237f2
            01311c23c7a7963cc2be4dae7f5b737184ec27179e3e6b54f8c464f9c05aab3b
            0d916cd97d8a1c925ccec2147d2e75dff23b6254141f8fa0b96eed987ed5cf8c
            061f9e12ba89046d590b3e45cdfd312faef5d6aa3faf2fc1747c03843d829500
            1acbb4134634beb66f33cc0de4337c3348ac793df1f7a5eba2c79b87d24516cb
            06df3e0562340ab50addc7b6268db5e3c80a6b2751a96e3b9c74d54ae70fe3b6
            2aff5ece051e08c1cd69b1badad8a3fba74192efdfaf6c6f0117228cdc30a62d
            153271196399e72f090b9c5573eb1654dd193e9ca064bc85db4350b82c8e2aa0
            00fb000b0d825a8e426680508fe8c235c850ccd12fadfa2233cc1068dd7af7bd
            12dd0a89b1d1e914cf5ac25ac5d95b0089c3ede328057bf7db198dafea9457e4
            172d8ade1860fa309334b0a7f89d9625e3e62f4d23a1af464011b0c32b33f56c
            099d88907be6d06a58e2561f72e8091243d5631ee7056f32dd9cdcc0f19d8c07
            0c2d28eeac116e658927cd3a68afacc96ad0b0bfbb85ceef08627fc1ca52a279
            08cba55c679d7099b01bf6ede48043a6d79a6d9e2184d18594ce7eaa4fa68129
            09a81d1551c17e55de23c6f9de39ee1f3304b113d8047c401d47112ab1f37604
            21fbe115bde8d983e2c5ac8a36ff44c9bd98b3a83ea33f161ea7ac499d5d4334
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            11a20515c0af87c045fd8b5d38899b62b8259d8a6c6eb04dd29ab0de3d19fccf
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            11a20515c0af87c045fd8b5d38899b62b8259d8a6c6eb04dd29ab0de3d19fccf
            118647ce4de7a7a74474f235836c033597d37a7f02c0fa401927e726e041ddc5
            0000000000000000000000000000000000000000000000000000000000000000
            3048912b6e69c010b6c7ac8ecc63c03007e1c53d100bba838a6f2bdc9327e0f7
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            18b2c51769922073d60015f7ee3a9531f250aa00e53207eef978fb1030dbb06b
            042b7ee7a28f073fefbbdce38cc9073dbf26061a188202641b02e862526d1f03
            0668b1e16db28901313f249701e278eb3ecfd2a94a1d658453fa8df04d49e633
            0668b1e16db28901313f249701e278eb3ecfd2a94a1d658453fa8df04d49e633
            293339eac4968b53262900d0d55c5bff0561dc7c5ca4747a8ff47f4b3d75e314
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            10ee2f7a09a0af42b942aeab5375a44bee174642361e2553ca4d164084a3afae
            1061a22d89c91f9b9dc69c4cd472847574ed54bb8e91db8d0f10fbe7a88a62e1
            1843c9f22f93f5be7e648740941f8a6f734ad074ad36ff91b232a123bf2fb97f
            1843c9f22f93f5be7e648740941f8a6f734ad074ad36ff91b232a123bf2fb97f
            204d2ce543be3bfc6c6511a9a5ee12b5a939aee0144e2cb6f8a1195637f920e0
            0aa0cb65782c6c4680735ac338ad66c4c160067b226bc31164934d1e376ca5c6
            1d792f0c23a333b11d58d35e5941b24395db196ee112c5861fdecb090b79c81e
            09cc65aa620782d150410e2bb73cd6aa3b2c4130a51d82d9892b2e138095a904
            2c85de5417bb6fec0d92c3c06c16d4dbd583012e26de1d03eda9aca5b2f1c398
            226d26d4d8c02a1319b558412a734e278ec24e7b5c44da5205a740d1b7a480f1
            2f70ff62c417a3822ecef9110d5dd85b677ac0fa7221a19168b4f3f61d7ccf30
            0e9ea4a556af7daea45c7c671bc9294a2e791968c2497b299c820745f4840778
            0217a3a3739d81669d04fce061c453e524a9132c4f355448285f501d430602ff
            09a8bdc18f817b72cb567e57ff8a1e0a118e11f415c1495cf25eff222aa4b5c6
            20d04a01f537e7d52d0be94b11460b723c503685d6ffd5e9d9cffe6f82d5c04b
            30532addb56c8b975e8bf1ca59e34145e2edea04480145a62978e2641c2fd466
            301f485550a022679227ca9852df152c2090b69127304780e43af4765da7b3d9
            1828330cebb289e26fb38100af50aeb7ed71161e1782179646185cab1700bb83
            2f81f6c44fd914e2866fe3e6288f597115046928e9090f78747de5669862bc6f
            2bde41a88dc68a11ca1be5a35c72c1e185bb2064e219d359c0b83aa67c46f5a4
            09b20cc39becb80e659c261cf814c8d9f80ccae4859fd2c1ad4baef01a0429ea
            1f7f4139e249b899216b5c1cc50c3f956633d1d2756b4adae73cc733696e45eb
            2dec739e1c16d617f4ac5396c4d23463d37183689690ff81793c5ca2f75c1330
            076be8f7d6dd6940d704ee64be90f16843b5dcbb75e47bf13af0d4efde0031b2
            28b3f64274720bd0c526777ab02ff888920a2647422804cb77749f60bf4efb1e
            2ad070216642dc1bff63c4a7dc254a4c3dd795d14893164fb6ca8a14724bc5d0
            1bcfa9482e6b333f60eb1f24b573ec5d781e2bfdc0a6b7c97fc50001661fb536
            2604da921df52492b9f194acc3b824ad4aa6066009b6eee9a8595f6be800fa63
            20708cc430eec457e51b357365ee1873ef7355aa7fc611c35465e5e42d1e3e9c
            03ff38a63c06f5f3d04fe98d4c1564a2348d35d21d62751f80927e0043c92807
            1890d8faeb1edce7f373f3549145dd048fded0873ef03f34196ea0f94b22569c
            0f43c28f18c9d1b0fa373ecbac3a3f540f585fb5da0b94da6e819efd4afe1e19
            0f5929c0d4f98fd7e9d9e0a9e13a2ddc22401c7053de89ead8c8a2baa1b2db9d
            0c60a7afe5ad8f96e0335128d16146fa578fc5d7c123e0d391a44f34d69eb65c
            2ad893771540bb4dd4d2354d23c7b97bc5614763ba706747f9ec1248c5cdeb49
            0ae4651b52051679235d83265fc52ba7cfb5a5f9f42a0f67a7de8317dc57fa2d
            09ace9ae49f96456f53a2861a2128cfc83a0658ada2d64b0b3979c6ebdc47205
            1f2f94d59ebb822e2d4a81d1a82f8ef8e5aa66ef8ba39c6073d420cd668d09a4
            0b69c435deb9727e0527f8c84518a237530ff4daab14b0d74f60b771504a2a05
            2cc14f36a8e9317e1baed420dc005a862c3e253bc864d0f03cfb849db8bd735f
            2584c041f6696eeaf267bc0a6f5b7c1dbb6077902ee665acc92ae11e2ec7be70
            2f3d828715517d4947a7285404f91fb503457238934c03914645431c797002a4
            2889dc2323071a7d184d3addfea32f1a2a6a8557d87c206f7b5b8f3d3f5f7922
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

    mod should {
        use super::*;

        #[test]
        fn derive_log_n_for_a_valid_zk_proof_variant() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let byte_len = ZKProof::<()>::calculate_proof_byte_len(log_n);
                let derived = ProofVariant::ZK.log_n_from_byte_len(byte_len);
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "ProofVariant::ZK log_n_from_byte_len failed for log_n={log_n}"
                );
            }
        }

        #[test]
        fn derive_log_n_for_a_valid_plain_proof_variant() {
            for log_n in 1..=CONST_PROOF_SIZE_LOG_N as u64 {
                let byte_len = PlainProof::<()>::calculate_proof_byte_len(log_n);
                let derived = ProofVariant::Plain.log_n_from_byte_len(byte_len);
                assert_eq!(
                    derived,
                    Ok(log_n),
                    "ProofVariant::Plain log_n_from_byte_len failed for log_n={log_n}"
                );
            }
        }

        mod reject {
            use super::*;

            #[test]
            fn a_proof_variant_with_non_aligned_byte_length() {
                const LOG_N: u64 = 25;
                let invalid_length = ZKProof::<()>::calculate_proof_byte_len(LOG_N) + 1;
                assert_eq!(
                    ProofVariant::ZK.log_n_from_byte_len(invalid_length),
                    Err(ProofError::OtherError {
                        message: format!(
                            "Proof byte length {invalid_length} is not a multiple of EVM word size"
                        ),
                    })
                );
            }

            #[test]
            fn a_proof_variant_with_empty_byte_length() {
                assert_eq!(
                    ProofVariant::ZK.log_n_from_byte_len(0),
                    Err(ProofError::OtherError {
                        message: format!("Cannot derive log_n from proof word length 0"),
                    })
                );
            }
        }
    }
}

#[cfg(test)]
mod pairing_points {
    use super::*;

    #[test]
    fn treat_all_zero_limbs_as_default() {
        assert!(are_pairing_points_default(
            &[[0u8; EVM_WORD_SIZE]; PAIRING_POINTS_SIZE]
        ));
    }

    #[test]
    fn reject_a_point_at_infinity() {
        // Non-default (limb 4 is set) but the first point is (0, 0).
        let mut pairing_points = [[0u8; EVM_WORD_SIZE]; PAIRING_POINTS_SIZE];
        pairing_points[4][EVM_WORD_SIZE - 1] = 1;

        assert!(!are_pairing_points_default(&pairing_points));
        assert_eq!(
            convert_pairing_points_to_g1::<()>(&pairing_points).unwrap_err(),
            ProofError::PairingPointAtInfinity
        );
    }

    #[test]
    fn reject_a_coordinate_outside_fq() {
        // x = lo | (hi << 136) with every limb bit set exceeds q.
        let mut pairing_points = [[0u8; EVM_WORD_SIZE]; PAIRING_POINTS_SIZE];
        pairing_points[0][EVM_WORD_SIZE - 17..].fill(0xff);
        pairing_points[1][EVM_WORD_SIZE - 15..].fill(0xff);

        assert!(matches!(
            convert_pairing_points_to_g1::<()>(&pairing_points).unwrap_err(),
            ProofError::GroupConversionError {
                conv_error: ConversionError {
                    group: GroupError::CoordinateExceedsModulus { .. },
                    ..
                }
            }
        ));
    }
}
