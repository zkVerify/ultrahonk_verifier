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

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![allow(non_camel_case_types)]

mod commitment;
mod constants;
pub mod errors;
pub mod key;
pub mod proof;
mod relations;
mod srs;
mod transcript;
mod types;
mod utils;

use crate::{
    commitment::{compute_fold_pos_evaluations, compute_squares},
    constants::{
        CONST_PROOF_SIZE_LOG_N, LIBRA_COMMITMENTS, LIBRA_EVALUATIONS, NUMBER_OF_ENTITIES,
        NUMBER_UNSHIFTED, SUBGROUP_SIZE, ZK_BATCHED_RELATION_PARTIAL_LENGTH,
    },
    key::VerificationKey,
    proof::{
        convert_proof_point, ProofCommitmentField, ProofError, ZKProof, ZKProofCommitmentField,
    },
    relations::accumulate_relation_evaluations,
    srs::{SRS_G2, SRS_G2_VK},
    transcript::{generate_transcript, ZKTranscript},
    utils::read_g2,
};
use alloc::{format, string::ToString};
use ark_bn254_ext::CurveHooks;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{batch_inversion, AdditiveGroup, Field, MontFp, One};
use ark_models_ext::bn::{G1Prepared, G2Prepared};
use core::array::from_fn;
use errors::VerifyError;
use proof::ProofType;

pub use types::*;

extern crate alloc;
extern crate core;

use constants::{SUBGROUP_GENERATOR, SUBGROUP_GENERATOR_INVERSE};

pub const VK_SIZE: usize = 1760;
pub const PUB_SIZE: usize = 32;
pub const PROOF_SIZE: usize = constants::PROOF_SIZE;
pub const ZK_PROOF_SIZE: usize = constants::ZK_PROOF_SIZE;

/// A single public input.
pub type PublicInput = [u8; PUB_SIZE];
pub type Pubs = [PublicInput];

pub fn verify<H: CurveHooks + Default>(
    vk_bytes: &[u8],
    proof_type: &ProofType,
    pubs: &Pubs,
) -> Result<(), VerifyError> {
    let vk = VerificationKey::<H>::try_from(vk_bytes).map_err(|_| VerifyError::KeyError)?;

    // TODO: Update to support both flavors...
    if let ProofType::ZK(proof_bytes) = proof_type {
        let proof =
            ZKProof::try_from(&proof_bytes[..]).map_err(|_| VerifyError::InvalidProofError)?;

        check_public_input_number(&vk, pubs)?;

        verify_inner(&vk, &proof, pubs)
    } else {
        unimplemented!();
    }
}

fn verify_inner<H: CurveHooks>(
    vk: &VerificationKey<H>,
    proof: &ZKProof,
    public_inputs: &Pubs,
) -> Result<(), VerifyError> {
    // Generate the Fiat-Shamir challenges for the whole protocol and derive public inputs delta
    let t: ZKTranscript = generate_transcript(
        proof,
        public_inputs,
        vk.circuit_size,
        public_inputs.len() as u64,
        /*pubInputsOffset=*/ 1,
    );

    let public_inputs_delta = t.relation_parameters_challenges.public_inputs_delta(
        public_inputs,
        vk.circuit_size,
        vk.pub_inputs_offset,
    );

    // Sumcheck
    verify_sumcheck(proof, &t, vk.log_circuit_size, public_inputs_delta).map_err(|cause| {
        VerifyError::VerificationError {
            message: format!("Sumcheck Failed. Cause: {cause}"),
        }
    })?;

    // Shplemini
    verify_shplemini(proof, vk, &t).map_err(|cause| VerifyError::VerificationError {
        message: format!("Shplemini Failed. Cause: {cause}"),
    })?;

    Ok(())
}

// Checks that number of public inputs in the vk, matches the actual length of the PI list.
fn check_public_input_number<H: CurveHooks>(
    vk: &VerificationKey<H>,
    pubs: &Pubs,
) -> Result<(), VerifyError> {
    if vk.num_public_inputs != pubs.len() as u64 {
        Err(VerifyError::PublicInputError {
            message: format!(
                "Provided public inputs length does not match value in vk. Expected: {}; Got: {}",
                vk.num_public_inputs,
                pubs.len()
            ),
        })
    } else {
        Ok(())
    }
}

fn verify_sumcheck(
    proof: &ZKProof,
    tp: &ZKTranscript,
    log_circuit_size: u64,
    public_inputs_delta: Fr,
) -> Result<(), &'static str> {
    let log_circuit_size: usize = log_circuit_size
        .try_into()
        .map_err(|_| "Given log_circuit_size does not fit in a u64.")?;
    let mut round_target_sum = tp.libra_challenge * proof.libra_sum;
    let mut pow_partial_evaluation = Fr::ONE;

    // We perform sumcheck reductions over log n rounds (i.e., the multivariate degree)
    for round in 0..log_circuit_size {
        let round_univariate = proof.sumcheck_univariates[round];
        let total_sum = round_univariate[0] + round_univariate[1];
        if total_sum != round_target_sum {
            return Err("Total Sum differs from Round Target Sum.");
        }

        let round_challenge = tp.sumcheck_u_challenges[round];

        // Update round target for the next round
        round_target_sum = compute_next_target_sum(&round_univariate, round_challenge)
            .expect("compute_next_target_sum should always return an Ok variant");
        pow_partial_evaluation *= Fr::ONE + round_challenge * (tp.gate_challenges[round] - Fr::ONE);
    }

    // Final round
    let mut grand_honk_relation_sum = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations,
        &tp.relation_parameters_challenges,
        &tp.alphas,
        public_inputs_delta,
        pow_partial_evaluation,
    );

    let mut evaluation = Fr::ONE;
    for i in 2..log_circuit_size {
        evaluation *= tp.sumcheck_u_challenges[i];
    }

    grand_honk_relation_sum = grand_honk_relation_sum * (Fr::ONE - evaluation)
        + proof.libra_evaluation * tp.libra_challenge;

    if grand_honk_relation_sum == round_target_sum {
        Ok(())
    } else {
        Err("Grand Honk Relation Sum does not match Round Target Sum.")
    }
}

// Return the new target sum for the next sumcheck round.
fn compute_next_target_sum(
    round_univariates: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    round_challenge: Fr,
) -> Result<Fr, &str> {
    const BARYCENTRIC_LAGRANGE_DENOMINATORS: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] = [
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

    let mut target_sum = Fr::ZERO;

    // To compute the next target sum, we evaluate the given univariate at a point u (challenge).

    // Performing Barycentric evaluations
    // Compute B(x)
    let mut numerator_value = Fr::ONE;
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        numerator_value *= round_challenge - Fr::from(i as u64);
    }

    // Calculate domain size N of inverses using Montgomery's trick for batch inversion.
    // This reduces computation of `ZK_BATCHED_RELATION_PARTIAL_LENGTH`-many expensive inverses to
    // computing just 1 inverse + `O(ZK_BATCHED_RELATION_PARTIAL_LENGTH)` modular multiplications.
    // Notice that inversion will w.h.p. succeed because the `BARYCENTRIC_LAGRANGE_DENOMINATORS`
    // are all fixed (and non-zero), and w.h.p. `round_challenge - i` is also non-zero.
    let mut denominator_inverses: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] =
        from_fn(|i| BARYCENTRIC_LAGRANGE_DENOMINATORS[i] * (round_challenge - Fr::from(i as u64)));
    batch_inversion(&mut denominator_inverses);

    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        target_sum += round_univariates[i] * denominator_inverses[i];
    }

    // Scale the sum by the value of B(x)
    target_sum *= numerator_value;

    Ok(target_sum)
}

fn verify_shplemini<H: CurveHooks>(
    proof: &ZKProof,
    vk: &VerificationKey<H>,
    tp: &ZKTranscript,
) -> Result<(), ProofError> {
    // - Compute vector (r, r², ..., r²⁽ⁿ⁻¹⁾), where n := log_circuit_size
    let powers_of_evaluation_challenge = compute_squares(tp.gemini_r);
    // Arrays hold values that will be linearly combined for the gemini and shplonk batch openings
    let mut scalars = [Fr::ZERO; NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 3 + 3];
    let mut commitments = [G1::<H>::default(); NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 3 + 3];

    // NOTE: Can use batching here to go from 2 inversions to 1 inversion + 3 multiplications
    // but the benefit should be marginal.
    let mut pos_inverted_denominator = (tp.shplonk_z - powers_of_evaluation_challenge[0])
        .inverse()
        .expect("Inversion should work w.h.p.");
    let mut neg_inverted_denominator = (tp.shplonk_z + powers_of_evaluation_challenge[0])
        .inverse()
        .expect("Inversion should work w.h.p.");

    let unshifted_scalar = pos_inverted_denominator + tp.shplonk_nu * neg_inverted_denominator;
    let shifted_scalar = tp.gemini_r.inverse().expect("Inversion should work w.h.p.")
        * (pos_inverted_denominator - tp.shplonk_nu * neg_inverted_denominator);

    scalars[0] = Fr::ONE;
    commitments[0] =
        convert_proof_point::<H>(proof.shplonk_q).map_err(|_| ProofError::PointNotOnCurve {
            field: ZKProofCommitmentField::SHPLONK_Q.to_string(),
        })?;

    let mut batched_evaluation = proof.gemini_masking_eval;
    let mut batching_challenge = tp.rho;
    scalars[1] = -unshifted_scalar;
    for i in 0..NUMBER_UNSHIFTED {
        scalars[i + 2] = -unshifted_scalar * batching_challenge;
        batched_evaluation += proof.sumcheck_evaluations[i] * batching_challenge;
        batching_challenge *= tp.rho;
    }

    for i in NUMBER_UNSHIFTED..NUMBER_OF_ENTITIES {
        scalars[i + 2] = -shifted_scalar * batching_challenge;
        batched_evaluation += proof.sumcheck_evaluations[i] * batching_challenge;
        batching_challenge *= tp.rho;
    }

    commitments[1] = convert_proof_point::<H>(proof.gemini_masking_poly).map_err(|_| {
        ProofError::PointNotOnCurve {
            field: ZKProofCommitmentField::GEMINI_MASKING_POLY.to_string(),
        }
    })?;
    commitments[2] = vk.q_m;
    commitments[3] = vk.q_c;
    commitments[4] = vk.q_l;
    commitments[5] = vk.q_r;
    commitments[6] = vk.q_o;
    commitments[7] = vk.q_4;
    commitments[8] = vk.q_lookup;
    commitments[9] = vk.q_arith;
    commitments[10] = vk.q_deltarange;
    commitments[11] = vk.q_elliptic;
    commitments[12] = vk.q_aux;
    commitments[13] = vk.q_poseidon2external;
    commitments[14] = vk.q_poseidon2internal;
    commitments[15] = vk.s_1;
    commitments[16] = vk.s_2;
    commitments[17] = vk.s_3;
    commitments[18] = vk.s_4;
    commitments[19] = vk.id_1;
    commitments[20] = vk.id_2;
    commitments[21] = vk.id_3;
    commitments[22] = vk.id_4;
    commitments[23] = vk.t_1;
    commitments[24] = vk.t_2;
    commitments[25] = vk.t_3;
    commitments[26] = vk.t_4;
    commitments[27] = vk.lagrange_first;
    commitments[28] = vk.lagrange_last;

    // Accumulate proof points
    commitments[29] = convert_proof_point(proof.w1).map_err(|_| ProofError::PointNotOnCurve {
        field: ZKProofCommitmentField::W_1.to_string(),
    })?;
    commitments[30] = convert_proof_point(proof.w2).map_err(|_| ProofError::PointNotOnCurve {
        field: ZKProofCommitmentField::W_2.to_string(),
    })?;
    commitments[31] = convert_proof_point(proof.w3).map_err(|_| ProofError::PointNotOnCurve {
        field: ZKProofCommitmentField::W_3.to_string(),
    })?;
    commitments[32] = convert_proof_point(proof.w4).map_err(|_| ProofError::PointNotOnCurve {
        field: ZKProofCommitmentField::W_4.to_string(),
    })?;

    commitments[33] =
        convert_proof_point(proof.z_perm).map_err(|_| ProofError::PointNotOnCurve {
            field: ZKProofCommitmentField::Z_PERM.to_string(),
        })?;
    commitments[34] =
        convert_proof_point(proof.lookup_inverses).map_err(|_| ProofError::PointNotOnCurve {
            field: ZKProofCommitmentField::LOOKUP_INVERSES.to_string(),
        })?;
    commitments[35] =
        convert_proof_point(proof.lookup_read_counts).map_err(|_| ProofError::PointNotOnCurve {
            field: ZKProofCommitmentField::LOOKUP_READ_COUNTS.to_string(),
        })?;
    commitments[36] =
        convert_proof_point(proof.lookup_read_tags).map_err(|_| ProofError::PointNotOnCurve {
            field: ZKProofCommitmentField::LOOKUP_READ_TAGS.to_string(),
        })?;

    // to be Shifted
    // The following 5 points are copied to avoid re-validation.
    commitments[37] = commitments[29];
    commitments[38] = commitments[30];
    commitments[39] = commitments[31];
    commitments[40] = commitments[32];
    commitments[41] = commitments[33];

    // Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
    // Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., logN - 1.
    let fold_pos_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N] = compute_fold_pos_evaluations(
        &tp.sumcheck_u_challenges,
        &mut batched_evaluation,
        &proof.gemini_a_evaluations,
        &powers_of_evaluation_challenge,
        vk.log_circuit_size,
    );

    let mut constant_term_accumulator = fold_pos_evaluations[0] * pos_inverted_denominator;
    constant_term_accumulator +=
        proof.gemini_a_evaluations[0] * tp.shplonk_nu * neg_inverted_denominator;

    batching_challenge = tp.shplonk_nu.square();
    let mut boundary = NUMBER_OF_ENTITIES + 2;

    let mut scaling_factor_pos: Fr;
    let mut scaling_factor_neg: Fr;

    // Compute Shplonk constant term contributions from Aₗ(± r^{2ˡ}) for l = 1, ..., m-1;
    // Compute scalar multipliers for each fold commitment.
    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        let dummy_round = i as u64 >= (vk.log_circuit_size - 1);

        if !dummy_round {
            // Update inverted denominators
            pos_inverted_denominator = (tp.shplonk_z - powers_of_evaluation_challenge[i + 1])
                .inverse()
                .expect("Inversion should work w.h.p.");
            neg_inverted_denominator = (tp.shplonk_z + powers_of_evaluation_challenge[i + 1])
                .inverse()
                .expect("Inversion should work w.h.p.");

            // Compute the scalar multipliers for Aₗ(± r^{2ˡ}) and [Aₗ]
            scaling_factor_pos = batching_challenge * pos_inverted_denominator;
            scaling_factor_neg = batching_challenge * tp.shplonk_nu * neg_inverted_denominator;
            scalars[boundary + i] = -(scaling_factor_neg + scaling_factor_pos);

            // Accumulate the const term contribution given by
            // v^{2l} * Aₗ(r^{2ˡ}) /(z-r^{2^l}) + v^{2l+1} * Aₗ(-r^{2ˡ}) /(z+ r^{2^l})
            let mut accum_contribution = scaling_factor_neg * proof.gemini_a_evaluations[i + 1];
            accum_contribution += scaling_factor_pos * fold_pos_evaluations[i + 1];
            constant_term_accumulator += accum_contribution;
        }
        // Update the running power of v
        batching_challenge *= tp.shplonk_nu.square();

        commitments[boundary + i] =
            convert_proof_point(proof.gemini_fold_comms[i]).map_err(|_| {
                ProofError::PointNotOnCurve {
                    field: ZKProofCommitmentField::GEMINI_FOLD_COMMS(i).to_string(),
                }
            })?;
    }

    boundary += CONST_PROOF_SIZE_LOG_N - 1;

    // Finalize the batch opening claim
    let mut denominators = [Fr::ZERO; LIBRA_EVALUATIONS];

    denominators[0] = (tp.shplonk_z - tp.gemini_r)
        .inverse()
        .expect("shplonk_z - gemini_r should be invertible w.h.p.");
    denominators[1] = (tp.shplonk_z - SUBGROUP_GENERATOR * tp.gemini_r)
        .inverse()
        .expect("tp.shplonk_z - SUBGROUP_GENERATOR * tp.gemini_r should be invertible w.h.p.");
    denominators[2] = denominators[0];
    denominators[3] = denominators[0];

    let mut batching_scalars = [Fr::ZERO; LIBRA_EVALUATIONS];

    // Artifact of interleaving, see TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
    batching_challenge *= tp.shplonk_nu.square();
    for i in 0..LIBRA_EVALUATIONS {
        let scaling_factor = denominators[i] * batching_challenge;
        batching_scalars[i] = -scaling_factor;
        batching_challenge *= tp.shplonk_nu;
        constant_term_accumulator += scaling_factor * proof.libra_poly_evals[i];
    }
    scalars[boundary] = batching_scalars[0];
    scalars[boundary + 1] = batching_scalars[1] + batching_scalars[2];
    scalars[boundary + 2] = batching_scalars[3];

    for i in 0..LIBRA_COMMITMENTS {
        commitments[boundary] = convert_proof_point(proof.libra_commitments[i]).map_err(|_| {
            ProofError::PointNotOnCurve {
                field: ZKProofCommitmentField::LIBRA_COMMITMENTS(i).to_string(),
            }
        })?;
        boundary += 1;
    }

    commitments[boundary] = G1::<H>::generator(); // (1, 2)
    scalars[boundary] = constant_term_accumulator;
    boundary += 1;

    if let Err(msg) = check_evals_consistency(
        &proof.libra_poly_evals,
        tp.gemini_r,
        &tp.sumcheck_u_challenges,
        proof.libra_evaluation,
    ) {
        return Err(ProofError::ConsistencyCheckFailed { message: msg });
    }

    let quotient_commitment =
        convert_proof_point(proof.kzg_quotient).map_err(|_| ProofError::PointNotOnCurve {
            field: ProofCommitmentField::KZG_QUOTIENT.to_string(),
        })?;

    commitments[boundary] = quotient_commitment;
    scalars[boundary] = tp.shplonk_z; // evaluation challenge

    // Pairing Check
    let p_0 = H::bn254_msm_g1(&commitments, &scalars).map_err(|_| ProofError::OtherError {
        message: "Shplemini MSM computation failed.".to_string(),
    })?;
    let p_1 = -quotient_commitment;

    let g1_points = [G1Prepared::from(p_0.into_affine()), G1Prepared::from(p_1)];

    let g2_points = [
        G2Prepared::from(read_g2::<H>(&SRS_G2).expect("Parsing the SRS point should always work")),
        G2Prepared::from(
            read_g2::<H>(&SRS_G2_VK).expect("Parsing the SRS point should always work"),
        ),
    ];

    let product = Bn254::<H>::multi_pairing(g1_points, g2_points);

    if product.0.is_one() {
        Ok(())
    } else {
        Err(ProofError::ShpleminiPairingCheckFailed)
    }
}

fn check_evals_consistency(
    libra_poly_evals: &[Fr; LIBRA_EVALUATIONS],
    gemini_r: Fr,
    u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    libra_eval: Fr,
) -> Result<(), &'static str> {
    let vanishing_poly_eval = gemini_r.pow([SUBGROUP_SIZE as u64]) - Fr::ONE;
    if vanishing_poly_eval == Fr::ZERO {
        return Err("Gemini Challenge In Subgroup");
    }

    let mut challenge_poly_lagrange = [Fr::ZERO; SUBGROUP_SIZE as usize];

    challenge_poly_lagrange[0] = Fr::ONE;
    for (round, u_ch) in u_challenges.iter().enumerate().take(CONST_PROOF_SIZE_LOG_N) {
        let curr_idx = 1 + 9 * round;
        challenge_poly_lagrange[curr_idx] = Fr::ONE;
        for idx in (curr_idx + 1)..(curr_idx + 9) {
            challenge_poly_lagrange[idx] = challenge_poly_lagrange[idx - 1] * u_ch;
        }
    }

    let mut denominators = [Fr::ZERO; SUBGROUP_SIZE as usize];

    let mut root_power = Fr::ONE;
    let mut challenge_poly_eval = Fr::ZERO;
    for idx in 0..denominators.len() {
        // Pr[root_power * gemini_r - 1 is invertible]
        //   = Pr[root_power * gemini_r - 1 != 0]
        //   = 1 - Pr[root_power * gemini_r - 1 = 0]
        //   = 1 - Pr[gemini_r = root_power^{-1}]
        //   >= 1 - 1/2^128 because gemini_r is the 128 lower-significance bits output by Keccak256
        denominators[idx] = (root_power * gemini_r - Fr::ONE)
            .inverse()
            .expect("With overwhelming probability, inversion succeeds");
        challenge_poly_eval += challenge_poly_lagrange[idx] * denominators[idx];
        root_power *= SUBGROUP_GENERATOR_INVERSE;
    }

    let numerator = vanishing_poly_eval
        * Fr::from(SUBGROUP_SIZE)
            .inverse()
            .expect("SUBGROUP_SIZE will always be invertible modulo r");
    challenge_poly_eval *= numerator;
    let lagrange_first = denominators[0] * numerator;
    let lagrange_last = *denominators
        .last()
        .expect("Last element should always exist")
        * numerator;

    let mut diff = lagrange_first * libra_poly_evals[2];

    diff += (gemini_r - SUBGROUP_GENERATOR_INVERSE)
        * (libra_poly_evals[1] - libra_poly_evals[2] - libra_poly_evals[0] * challenge_poly_eval);
    diff += lagrange_last * (libra_poly_evals[2] - libra_eval)
        - vanishing_poly_eval * libra_poly_evals[3];

    if diff != Fr::ZERO {
        return Err("Consistency Condition Not Satisfied");
    }

    Ok(())
}

#[cfg(test)]
mod should;
