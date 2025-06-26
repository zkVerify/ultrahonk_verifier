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
pub const NUMBER_OF_SUBRELATIONS: usize = 26;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8; // for non-ZK case
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;
pub const NUMBER_OF_ENTITIES: usize = 40;
pub const NUMBER_UNSHIFTED: usize = 35;
pub const NUMBER_TO_BE_SHIFTED: usize = 5;
pub const PAIRING_POINTS_SIZE: usize = 16;
// Alphas are used as relation separators so there should be NUMBER_OF_SUBRELATIONS - 1
pub const NUMBER_OF_ALPHAS: usize = 25;

pub const LIBRA_POLY_EVALS_LENGTH: usize = 4;
pub const LIBRA_COMMITMENTS_LENGTH: usize = 3;

// Scalar size (in bytes)
const SCALAR_SIZE: usize = 32;
// G1ProofPoint size (in bytes)
const G1_PROOF_POINT_SIZE: usize = 32 * 4;

pub(crate) const ZK_PROOF_SIZE: usize = 4 * G1_PROOF_POINT_SIZE   // 1. Commitments to wire polynomials
    + 3 * G1_PROOF_POINT_SIZE // 2. Commitments to logup witness polynomials
    + 4 * G1_PROOF_POINT_SIZE // 3. Commitment to grand permutation polynomial
    + (2 + NUMBER_OF_ENTITIES + ZK_BATCHED_RELATION_PARTIAL_LENGTH * CONST_PROOF_SIZE_LOG_N) * SCALAR_SIZE // 4. Sumcheck
    + G1_PROOF_POINT_SIZE + SCALAR_SIZE // 5. ZK
    + (2 + CONST_PROOF_SIZE_LOG_N - 1) * G1_PROOF_POINT_SIZE + (CONST_PROOF_SIZE_LOG_N + 4) * SCALAR_SIZE; // 6. Shplemini

pub(crate) const PROOF_SIZE: usize = 4 * G1_PROOF_POINT_SIZE   // 1. Commitments to wire polynomials
    + G1_PROOF_POINT_SIZE // 2. Lookup helpers - Permutations
    + 3 * G1_PROOF_POINT_SIZE // 3. Lookup helpers - logup
    + (NUMBER_OF_ENTITIES + BATCHED_RELATION_PARTIAL_LENGTH * CONST_PROOF_SIZE_LOG_N) * SCALAR_SIZE  // 4. Sumcheck
    + (CONST_PROOF_SIZE_LOG_N - 1 + 2) * G1_PROOF_POINT_SIZE + CONST_PROOF_SIZE_LOG_N * SCALAR_SIZE; // 5. Shplemini

pub(crate) const SUBGROUP_SIZE: u64 = 256;
pub(crate) const SUBGROUP_GENERATOR: Fr =
    MontFp!("0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76");
pub(crate) const SUBGROUP_GENERATOR_INVERSE: Fr =
    MontFp!("0x204bd3277422fad364751ad938e2b5e6a54cf8c68712848a692c553d0329f5d6");
