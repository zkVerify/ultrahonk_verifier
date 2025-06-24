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

use ark_bn254_ext::Fr;
use ark_ff::Field;

use crate::constants::CONST_PROOF_SIZE_LOG_N;

// POSSIBLY REDUNDANT...
struct ShpleminiIntermediates {
    unshifted_scalar: Fr,
    shifted_scalar: Fr,
    // Scalar to be multiplied by [1]₁
    constant_term_accumulator: Fr,
    // Accumulator for powers of rho
    batching_challenge: Fr,
    // Linear combination of multilinear (sumcheck) evaluations and powers of rho
    batched_evaluation: Fr,
    denominators: [Fr; 4],
    batching_scalars: [Fr; 4],
    // 1/(z - r^{2^i}) for i = 0, ..., logSize, dynamically updated
    pos_inverted_denominator: Fr,
    // 1/(z + r^{2^i}) for i = 0, ..., logSize, dynamically updated
    neg_inverted_denominator: Fr,
    // v^{2i} * 1/(z - r^{2^i})
    scaling_factor_pos: Fr,
    // v^{2i+1} * 1/(z + r^{2^i})
    scalingfactor_neg: Fr,
}

fn compute_squares(r: Fr) -> [Fr; CONST_PROOF_SIZE_LOG_N] {
    let mut squares = [r; CONST_PROOF_SIZE_LOG_N];

    for i in 1..CONST_PROOF_SIZE_LOG_N {
        squares[i] = squares[i - 1].square();
    }

    squares
}

// The following seem to still be unused by UltraHonk at the moment...

// fn compute_inverted_gemini_denominators(
//     shplonk_z: Fr,
//     eval_challenge_powers: &[Fr; CONST_PROOF_SIZE_LOG_N],
//     uint256 logSize
// ) -> [Fr; CONST_PROOF_SIZE_LOG_N + 1] inverse_vanishing_evals {
//     inverse_vanishing_evals[0] = (shplonkZ- eval_challenge_powers[0]).invert();

//     for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; ++i) {
//         Fr round_inverted_denominator = ZERO;
//         if (i <= logSize + 1) {
//             round_inverted_denominator = (shplonkZ+ eval_challenge_powers[i]).invert();
//         }
//         inverse_vanishing_evals[i + 1] = round_inverted_denominator;
//     }
// }

// // Compute the evaluations  Aₗ(r^{2ˡ}) for l = 0, ..., m-1
// fn compute_fold_pos_evaluations(
//     Fr[CONST_PROOF_SIZE_LOG_N] memory sumcheckUChallenges,
//     Fr batchedEvalAccumulator,
//     Fr[CONST_PROOF_SIZE_LOG_N] memory geminiEvaluations,
//     Fr[CONST_PROOF_SIZE_LOG_N] memory geminiEvalChallengePowers,
//     uint256 logSize
// ) internal view returns (Fr[CONST_PROOF_SIZE_LOG_N] memory foldPosEvaluations) {
//     for (uint256 i = CONST_PROOF_SIZE_LOG_N; i > 0; --i) {
//         Fr challengePower = geminiEvalChallengePowers[i - 1];
//         Fr u = sumcheckUChallenges[i - 1];

//         Fr batchedEvalRoundAcc = (
//             (challengePower * batchedEvalAccumulator * Fr.wrap(2))
//                 - geminiEvaluations[i - 1] * (challengePower * (Fr.wrap(1) - u) - u)
//         );
//         // Divide by the denominator
//         batchedEvalRoundAcc = batchedEvalRoundAcc * (challengePower * (Fr.wrap(1) - u) + u).invert();
//         if (i <= logSize) {
//             batchedEvalAccumulator = batchedEvalRoundAcc;
//             foldPosEvaluations[i - 1] = batchedEvalRoundAcc;
//         }
//     }
// }
