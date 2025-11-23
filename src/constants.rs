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
pub const NUMBER_OF_SUBRELATIONS: usize = 27;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8; // for Plain case (i.e., non-ZK)
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = 9; // for ZK case
pub const NUMBER_OF_ENTITIES: usize = 40;
pub const NUMBER_UNSHIFTED: usize = 35;
// pub const NUMBER_TO_BE_SHIFTED: usize = 5;

// Alphas are used as relation separators so there should be NUMBER_OF_SUBRELATIONS - 1
pub const NUMBER_OF_ALPHAS: usize = NUMBER_OF_SUBRELATIONS - 1;

pub const LIBRA_COMMITMENTS: usize = 3;
pub const LIBRA_EVALUATIONS: usize = 4;
pub const LIBRA_UNIVARIATES_LENGTH: usize = 9;

// Scalar size (in bytes)
pub(crate) const SCALAR_SIZE: usize = 32;
// G1ProofPoint size (in bytes)
const G1_PROOF_POINT_SIZE: usize = 32 * 4;
// G1 Point Size
const G1_POINT_SIZE: usize = 64;

pub(crate) const EVM_WORD_SIZE: usize = 32;

pub const PAIRING_POINTS_SIZE: usize = 16;

// ZK Proof size in bytes
pub const ZK_PROOF_SIZE: usize = 4 * G1_PROOF_POINT_SIZE   // 1. Commitments to wire polynomials
    + 3 * G1_PROOF_POINT_SIZE // 2. Commitments to logup witness polynomials
    + 4 * G1_PROOF_POINT_SIZE // 3. Commitment to grand permutation polynomial
    + (2 + NUMBER_OF_ENTITIES + ZK_BATCHED_RELATION_PARTIAL_LENGTH * CONST_PROOF_SIZE_LOG_N) * SCALAR_SIZE // 4. Sumcheck
    + G1_PROOF_POINT_SIZE + SCALAR_SIZE // 5. ZK
    + (2 + CONST_PROOF_SIZE_LOG_N - 1) * G1_PROOF_POINT_SIZE + (CONST_PROOF_SIZE_LOG_N + 4) * SCALAR_SIZE // 6. Shplemini
    + PAIRING_POINTS_SIZE * SCALAR_SIZE; // 7. Pairing Point Object

// Plain Proof size in bytes
pub const PLAIN_PROOF_SIZE: usize = 4 * G1_PROOF_POINT_SIZE   // 1. Commitments to wire polynomials
    + G1_PROOF_POINT_SIZE // 2. Lookup helpers - Permutations
    + 3 * G1_PROOF_POINT_SIZE // 3. Lookup helpers - logup
    + (NUMBER_OF_ENTITIES + BATCHED_RELATION_PARTIAL_LENGTH * CONST_PROOF_SIZE_LOG_N) * SCALAR_SIZE  // 4. Sumcheck
    + (CONST_PROOF_SIZE_LOG_N - 1 + 2) * G1_PROOF_POINT_SIZE + CONST_PROOF_SIZE_LOG_N * SCALAR_SIZE // 5. Shplemini
    + PAIRING_POINTS_SIZE * SCALAR_SIZE; // 6. Pairing Point Object

pub const VK_SIZE: usize = 27 * G1_POINT_SIZE + EVM_WORD_SIZE;

pub const PUB_SIZE: usize = 32;

pub(crate) const SUBGROUP_SIZE: u32 = 256;
pub(crate) const SUBGROUP_GENERATOR: Fr =
    MontFp!("0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76");
pub(crate) const SUBGROUP_GENERATOR_INVERSE: Fr =
    MontFp!("0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6");
