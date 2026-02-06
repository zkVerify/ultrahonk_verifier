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

use ark_bn254::Fr;
use ark_ff::MontFp;

pub const CONST_PROOF_SIZE_LOG_N: usize = 28;
pub const NUMBER_OF_SUBRELATIONS: usize = 28;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8; // for Plain case (i.e., non-ZK)
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = 9; // for ZK case
pub const NUMBER_OF_ENTITIES: usize = 41;
// The number of entities added for ZK (gemini_masking_poly)
pub const NUM_MASKING_POLYNOMIALS: usize = 1;
pub const NUMBER_OF_ENTITIES_ZK: usize = NUMBER_OF_ENTITIES + NUM_MASKING_POLYNOMIALS;

pub const NUMBER_UNSHIFTED: usize = 36;
pub const NUMBER_UNSHIFTED_ZK: usize = NUMBER_UNSHIFTED + NUM_MASKING_POLYNOMIALS;
pub const NUMBER_TO_BE_SHIFTED: usize = NUMBER_OF_ENTITIES - NUMBER_UNSHIFTED;

pub const NUMBER_OF_WITNESS_ENTITIES: usize = 8;
pub const NUMBER_OF_WITNESS_ENTITIES_ZK: usize = 8 + NUM_MASKING_POLYNOMIALS;

// Powers of alpha used to batch subrelations (alpha, alpha^2, ..., alpha^(NUM_SUBRELATIONS-1))
pub const NUMBER_OF_ALPHAS: usize = NUMBER_OF_SUBRELATIONS - 1;

pub const NUM_LIBRA_COMMITMENTS: usize = 3;
pub const NUM_LIBRA_EVALUATIONS: usize = 4;
pub const LIBRA_UNIVARIATES_LENGTH: usize = 9;

// Scalar size (in bytes)
pub const FIELD_ELEMENT_SIZE: usize = 32;
// G1 Point Size (in bytes)
pub const GROUP_ELEMENT_SIZE: usize = 64;
// EVM words are 32 bytes long
pub const EVM_WORD_SIZE: usize = 32;
// Number of entries in the Pairing Point Object array
pub const PAIRING_POINTS_SIZE: usize = 16;

pub const NUM_ELEMENTS_COMM: usize = 2; // U256 elements for curve points
pub const NUM_ELEMENTS_FR: usize = 1; // U256 elements for field elements

pub const VK_SIZE: usize = 28 * GROUP_ELEMENT_SIZE + 3 * EVM_WORD_SIZE;

pub const PUB_SIZE: usize = 32;

pub const SUBGROUP_SIZE: u32 = 256;
pub const SUBGROUP_GENERATOR: Fr =
    MontFp!("0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76");
pub const SUBGROUP_GENERATOR_INVERSE: Fr =
    MontFp!("0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6");

pub const PERMUTATION_ARGUMENT_VALUE_SEPARATOR: u64 = 1 << 28;
