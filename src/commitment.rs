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

use crate::constants::CONST_PROOF_SIZE_LOG_N;
use ark_bn254_ext::Fr;
use ark_ff::{batch_inversion, AdditiveGroup, Field, MontFp};

const TWO: Fr = MontFp!("2");

// Compute an array containing r raised to powers of two:
// [r, r^2, r^4, ..., r^(2^(log_n-1))].
pub(crate) fn compute_squares(r: Fr, log_n: u64) -> Vec<Fr> {
    let mut squares = Vec::<Fr>::with_capacity(log_n as usize);

    squares.push(r);
    for i in 1..log_n as usize {
        squares.push(squares[i - 1].square());
    }

    squares
}

// Compute the evaluations  Aₗ(r^{2ˡ}) for l = 0, 1, ..., m-1.
pub(crate) fn compute_fold_pos_evaluations(
    sumcheck_u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    batched_eval_accumulator: &mut Fr,
    gemini_evaluations: &[Fr; CONST_PROOF_SIZE_LOG_N],
    gemini_eval_challenge_powers: &[Fr],
    log_size: u64,
) -> Vec<Fr> {
    let mut fold_pos_evaluations = Vec::<Fr>::with_capacity(log_size as usize);
    fold_pos_evaluations.resize(log_size as usize, Fr::ZERO);

    let mut inverted_denominators = Vec::with_capacity(log_size as usize);
    inverted_denominators.extend((0..log_size).map(|i| {
        let j = (log_size - 1 - i) as usize;
        gemini_eval_challenge_powers[j] * (Fr::ONE - sumcheck_u_challenges[j])
            + sumcheck_u_challenges[j] // invertible w.h.p.
    }));

    batch_inversion(&mut inverted_denominators);

    for i in (1..=log_size as usize).rev() {
        let challenge_power = gemini_eval_challenge_powers[i - 1];
        let u = sumcheck_u_challenges[i - 1];

        let mut batched_eval_round_acc = challenge_power * (*batched_eval_accumulator) * TWO
            - gemini_evaluations[i - 1] * (challenge_power * (Fr::ONE - u) - u);
        // Divide by the denominator
        batched_eval_round_acc *= inverted_denominators[log_size as usize - i];

        *batched_eval_accumulator = batched_eval_round_acc;
        fold_pos_evaluations[i - 1] = batched_eval_round_acc;
    }

    fold_pos_evaluations
}
