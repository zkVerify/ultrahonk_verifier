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
use ark_ff::{AdditiveGroup, Field, MontFp};

use crate::constants::CONST_PROOF_SIZE_LOG_N;

const TWO: Fr = MontFp!("2");

pub(crate) fn compute_squares(r: Fr) -> [Fr; CONST_PROOF_SIZE_LOG_N] {
    let mut squares = [r; CONST_PROOF_SIZE_LOG_N];

    for i in 1..CONST_PROOF_SIZE_LOG_N {
        squares[i] = squares[i - 1].square();
    }

    squares
}

// UNUSED
// pub(crate) fn compute_inverted_gemini_denominators(
//     shplonk_z: Fr,
//     eval_challenge_powers: &[Fr; CONST_PROOF_SIZE_LOG_N],
//     log_size: u64,
// ) -> [Fr; CONST_PROOF_SIZE_LOG_N + 1] {
//     let mut inverse_vanishing_evals = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N + 1];
//     inverse_vanishing_evals[0] = (shplonk_z - eval_challenge_powers[0])
//         .inverse()
//         .expect("shplonk_z - eval_challenge_powers[0] should be invertible w.h.p.");

//     for i in 0..CONST_PROOF_SIZE_LOG_N {
//         let mut round_inverted_denominator = Fr::ZERO;
//         if i as u64 <= log_size + 1 {
//             round_inverted_denominator = (shplonk_z + eval_challenge_powers[i])
//                 .inverse()
//                 .expect("shplonk_z + eval_challenge_powers[i] should be invertible w.h.p.");
//         }
//         inverse_vanishing_evals[i + 1] = round_inverted_denominator;
//     }

//     inverse_vanishing_evals
// }

// Compute the evaluations  Aₗ(r^{2ˡ}) for l = 0, ..., m-1.
pub(crate) fn compute_fold_pos_evaluations(
    sumcheck_u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    batched_eval_accumulator: &mut Fr, // !!!
    gemini_evaluations: &[Fr; CONST_PROOF_SIZE_LOG_N],
    gemini_eval_challenge_powers: &[Fr; CONST_PROOF_SIZE_LOG_N],
    log_size: u64,
) -> [Fr; CONST_PROOF_SIZE_LOG_N] {
    let mut fold_pos_evaluations = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N];

    for i in (1..=CONST_PROOF_SIZE_LOG_N).rev() {
        let challenge_power = gemini_eval_challenge_powers[i - 1];
        let u = sumcheck_u_challenges[i - 1];

        let mut batched_eval_round_acc = challenge_power * (*batched_eval_accumulator) * TWO
            - gemini_evaluations[i - 1] * (challenge_power * (Fr::ONE - u) - u);
        // Divide by the denominator
        batched_eval_round_acc *= (challenge_power * (Fr::ONE - u) + u)
            .inverse()
            .expect("challenge_power * (Fr::ONE - u) + u should be invertible w.h.p.");
        if i as u64 <= log_size {
            *batched_eval_accumulator = batched_eval_round_acc;
            fold_pos_evaluations[i - 1] = batched_eval_round_acc;
        }
    }

    fold_pos_evaluations
}
