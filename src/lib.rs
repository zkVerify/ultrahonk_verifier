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
mod types;
mod transcript;
mod utils;

use core::array::from_fn;

use crate::{commitment::{compute_fold_pos_evaluations, compute_squares}, constants::{CONST_PROOF_SIZE_LOG_N, LIBRA_POLY_EVALS_LENGTH, NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES, NUMBER_UNSHIFTED, SUBGROUP_SIZE, ZK_BATCHED_RELATION_PARTIAL_LENGTH}, key::VerificationKey, proof::{convert_proof_point, ProofCommitmentField, ProofError, ZKProof}, relations::accumulate_relation_evaluations, srs::{SRS_G2, SRS_G2_VK}, transcript::{generate_transcript, ZKTranscript}, utils::{read_g2, IntoFr, IntoU256}};
use alloc::{format, string::ToString};
use ark_bn254_ext::{Config, CurveHooks};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, MontFp, PrimeField, One, batch_inversion};
use ark_models_ext::bn::{BnConfig, G1Prepared, G2Prepared};
use errors::VerifyError;
use ark_ec::pairing::Pairing;
// use sha3::{Digest, Keccak256};

use proof::ProofType;
pub use types::*;

extern crate alloc;
extern crate core;

use constants::{PROOF_SIZE, ZK_PROOF_SIZE, SUBGROUP_GENERATOR, SUBGROUP_GENERATOR_INVERSE};

pub const VK_SIZE: usize = 1760;
pub const PUB_SIZE: usize = 32;

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
    let mut proof: ZKProof;
    if let ProofType::ZK(proof_bytes) = proof_type {
        proof = ZKProof::try_from(&proof_bytes[..]).map_err(|_| VerifyError::InvalidProofError)?;
    } else {
        unimplemented!();
    }

    check_public_input_number(&vk, pubs)?;

    // let public_inputs = &pubs
    //     .iter()
    //     .map(|pi_bytes| pi_bytes.into_u256())
    //     .collect::<Vec<U256>>();

    verify_inner(&vk, &proof, &pubs)
}

fn verify_inner<H: CurveHooks>(
    vk: &VerificationKey<H>,
    proof: &ZKProof,
    public_inputs: &Pubs,
) -> Result<(), VerifyError> {
    // Generate the Fiat-Shamir challenges for the whole protocol and derive public inputs delta
    let t: ZKTranscript = generate_transcript(&proof, &public_inputs, vk.circuit_size, public_inputs.len() as u64, /*pubInputsOffset=*/1);

    // t.relationParameters.publicInputsDelta = compute_public_input_delta(
    //     public_inputs, t.relationParameters.beta, t.relationParameters.gamma, /*pubInputsOffset=*/1
    // );
    let public_inputs_delta =
        t.relation_parameters_challenges.public_inputs_delta(public_inputs, vk.circuit_size, vk.pub_inputs_offset);

    // Sumcheck
    verify_sumcheck(proof, &t, vk.log_circuit_size, public_inputs_delta).map_err(|msg| VerifyError::VerificationError { message: msg })?;

    // Shplemini
    if !verify_shplemini(p, vk, t); // revert ShpleminiFailed()
}

fn check_public_input_number<H: CurveHooks>(
    vk: &VerificationKey<H>,
    pubs: &Pubs,
) -> Result<(), VerifyError> {
    if vk.num_public_inputs != pubs.len() as u64 {
        Err(VerifyError::PublicInputError {
            message: format!(
                "Provided public inputs length does not match. Expected: {}; Got: {}",
                vk.num_public_inputs,
                pubs.len()
            ),
        })
    } else {
        Ok(())
    }
}

// TODO: Replace &'static str with a proper error enum.
fn verify_sumcheck(proof: &ZKProof, tp: &ZKTranscript, log_circuit_size: u64, public_inputs_delta: Fr) -> Result<(), &'static str> {
    let log_circuit_size: usize = log_circuit_size.try_into().map_err(|_| "Given log_circuit_size does not fit in a u64.")?;
    let mut round_target_sum = tp.libra_challenge * proof.libra_sum; // default 0
    let mut pow_partial_evaluation = Fr::ONE;

    // We perform sumcheck reductions over log n rounds (i.e., the multivariate degree)
    // for (uint256 round; round < LOG_N; ++round) {
    for round in 0..log_circuit_size {
        let round_univariate = proof.sumcheck_univariates[round];
        let total_sum = round_univariate[0] + round_univariate[1];
        if total_sum != round_target_sum {
            return Err("Sumcheck failed"); // revert SumcheckFailed();
        }

        let round_challenge = tp.sumcheck_u_challenges[round];

        // Update the round target for the next rounf
        round_target_sum = compute_next_target_sum(&round_univariate, round_challenge).expect("compute_next_target_sum should always return an Ok variant");
        pow_partial_evaluation =
            pow_partial_evaluation * (Fr::ONE + round_challenge * (tp.gate_challenges[round] - Fr::ONE));
    }

    // Last round
    let mut grand_honk_relation_sum = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations, &tp.relation_parameters_challenges, &tp.alphas, public_inputs_delta, pow_partial_evaluation
    );

    let mut evaluation = Fr::ONE;
    for i in 2..log_circuit_size { // (uint256 i = 2; i < LOG_N; i++) {
        evaluation *= tp.sumcheck_u_challenges[i];
    }

    grand_honk_relation_sum = grand_honk_relation_sum * (Fr::ONE - evaluation) + proof.libra_evaluation * tp.libra_challenge;
    if grand_honk_relation_sum == round_target_sum {
        Ok(())
    } else {
        Err("Grand Honk Relation Sum does not match Round Target Sum")
    }
}

// Return the new target sum for the next sumcheck round.
fn compute_next_target_sum(round_univariates: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH], round_challenge: Fr) -> Result<Fr, &str> {
    // NOTE: This function can't actually fail with the current BARYCENTRIC_LAGRANGE_DENOMINATORS.
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

    // TODO: opt: use same array mem for each iteration
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

fn verify_shplemini<H: CurveHooks>(proof: &ZKProof, vk: &VerificationKey<H>, tp: &ZKTranscript)
    -> Result<(), ProofError> {
    // ShpleminiIntermediates mem; // stack

    // - Compute vector (r, r², ..., r²⁽ⁿ⁻¹⁾), where n := log_circuit_size
    let powers_of_evaluation_challenge = compute_squares(tp.gemini_r); // [Fr; CONST_PROOF_SIZE_LOG_N]
    // Arrays hold values that will be linearly combined for the gemini and shplonk batch openings
    let mut scalars: [Fr; NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 3 + 3];
    let mut commitments: [G1<H>; NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 3 + 3];

    // NOTE: Can use batching here to go from 2 inversions to 1 inversion + 3 multiplications
    // but the benefit should be marginal.
    let pos_inverted_denominator = (tp.shplonk_z - powers_of_evaluation_challenge[0]).inverse().expect("Inversion should work w.h.p.");
    let neg_inverted_denominator = (tp.shplonk_z + powers_of_evaluation_challenge[0]).inverse().expect("Inversion should work w.h.p.");

    let unshifted_scalar = pos_inverted_denominator + tp.shplonk_nu * neg_inverted_denominator;
    let shifted_scalar =
        tp.gemini_r.inverse().expect("Inversion should work w.h.p.") * (pos_inverted_denominator - tp.shplonk_nu * neg_inverted_denominator);

    scalars[0] = Fr::ONE;
    commitments[0] = convert_proof_point::<H>(proof.shplonk_q).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::SHPLONK_Q.to_str(),
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

    commitments[1] = convert_proof_point::<H>(proof.gemini_masking_poly).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::GEMINI_MASKING_POLY.to_str(),
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
                field: ProofCommitmentField::W_1.to_str(),
            })?;
    commitments[30] = convert_proof_point(proof.w2).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_2.to_str(),
            })?;
    commitments[31] = convert_proof_point(proof.w3).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_3.to_str(),
            })?;
    commitments[32] = convert_proof_point(proof.w4).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_4.to_str(),
            })?;

    commitments[33] = convert_proof_point(proof.z_perm).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::Z_PERM.to_str(),
            })?;
    commitments[34] = convert_proof_point(proof.lookup_inverses).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::LOOKUP_INVERSES.to_str(),
            })?;
    commitments[35] = convert_proof_point(proof.lookup_read_counts).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::LOOKUP_READ_COUNTS.to_str(),
            })?;
    commitments[36] = convert_proof_point(proof.lookup_read_tags).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::LOOKUP_READ_TAGS.to_str(),
            })?;

    // to be Shifted
    // NOTE: The following 5 points are validated anew. Can skip that by cloning.
    commitments[37] = convert_proof_point(proof.w1).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_1.to_str(),
            })?;
    commitments[38] = convert_proof_point(proof.w2).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_2.to_str(),
            })?;
    commitments[39] = convert_proof_point(proof.w3).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_3.to_str(),
            })?;
    commitments[40] = convert_proof_point(proof.w4).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::W_4.to_str(),
            })?;
    commitments[41] = convert_proof_point(proof.z_perm).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::Z_PERM.to_str(),
            })?;

    // Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
    // Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., logN - 1.
    let fold_pos_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N] = compute_fold_pos_evaluations(
        &tp.sumcheck_u_challenges,
        batched_evaluation,
        &proof.gemini_a_evaluations,
        &powers_of_evaluation_challenge,
        vk.log_circuit_size
    );

    let mut constant_term_accumulator = fold_pos_evaluations[0] * pos_inverted_denominator;
    constant_term_accumulator += proof.gemini_a_evaluations[0] * tp.shplonk_nu * neg_inverted_denominator;

    batching_challenge = tp.shplonk_nu.square();
    let mut boundary = NUMBER_OF_ENTITIES + 2;

    let mut scaling_factor_pos = Fr::ZERO;
    let mut scaling_factor_neg = Fr::ZERO;

    // Compute Shplonk constant term contributions from Aₗ(± r^{2ˡ}) for l = 1, ..., m-1;
    // Compute scalar multipliers for each fold commitment
    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) { // for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N - 1; ++i) {
        let dummy_round = i >= (LOG_N - 1);

        if !dummy_round {
            // Update inverted denominators
            pos_inverted_denominator = (tp.shplonk_z - powers_of_evaluation_challenge[i + 1]).inverse().expect("Inversion should work w.h.p.");
            neg_inverted_denominator = (tp.shplonk_z + powers_of_evaluation_challenge[i + 1]).inverse().expect("Inversion should work w.h.p.");

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

        commitments[boundary + i] = convert_proof_point(proof.gemini_fold_comms[i]).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::GEMINI_FOLD_COMMS(i).to_str(),
            })?;
    }

    boundary += CONST_PROOF_SIZE_LOG_N - 1;

    let mut denominators = [Fr::ZERO; LIBRA_POLY_EVALS_LENGTH];

    // Finalise the batch opening claim
    denominators[0] = (tp.shplonk_z - tp.gemini_r).inverse().expect("shplonk_z - gemini_r should be invertible w.h.p.");
    denominators[1] = (tp.shplonk_z - SUBGROUP_GENERATOR * tp.gemini_r).inverse();
    denominators[2] = denominators[0];
    denominators[3] = denominators[0];

    let mut batching_scalars = [Fr::ZERO; LIBRA_POLY_EVALS_LENGTH];

    // Artifact of interleaving, see TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
    batching_challenge *= tp.shplonk_nu.square();
    for i in 0..LIBRA_POLY_EVALS_LENGTH { // for (uint256 i = 0; i < 4; i++) {
        let scaling_factor = denominators[i] * batching_challenge;
        batching_scalars[i] = -scaling_factor;
        batching_challenge *= tp.shplonk_nu;
        constant_term_accumulator += scaling_factor * proof.libra_poly_evals[i];
    }
    scalars[boundary] = batching_scalars[0];
    scalars[boundary + 1] = batching_scalars[1] + batching_scalars[2];
    scalars[boundary + 2] = batching_scalars[3];

    for i in 0..3 {
        commitments[boundary] = convert_proof_point(proof.libra_commitments[i]).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::LIBRA_COMMITMENTS(i).to_str(),
            })?;
        boundary += 1;
    }

    commitments[boundary] = G1::<H>::generator(); // (1, 2)
    scalars[boundary] = constant_term_accumulator;
    boundary += 1;

    if !check_evals_consistency(proof.libra_poly_evals, tp.gemini_r, tp.sumcheck_u_challenges, proof.libra_evaluation) {
        revert ConsistencyCheckFailed();
    }
    let quotient_commitment = 
        convert_proof_point(proof.kzg_quotient).map_err(|_| ProofError::PointNotOnCurve {
                field: ProofCommitmentField::KZG_QUOTIENT.to_str(),
            })?;

    commitments[boundary] = quotient_commitment;
    scalars[boundary] = tp.shplonk_z; // evaluation challenge

    // Pairing Check
    let p_0 = H::bn254_msm_g1(&commitments, &scalars).map_err(|_| ProofError::OtherError { message: "Shplemini MSM computation failed.".to_string() })?; // batchMul(commitments, scalars);
    let p_1 = -quotient_commitment;

    let g1_points = [
        G1Prepared::from(p_0.into_affine()),
        G1Prepared::from(p_1),
    ];
    let g2_points = [
        G2Prepared::from(read_g2::<H>(&SRS_G2).expect("Parsing the SRS should always work")),
        G2Prepared::from(read_g2::<H>(&SRS_G2_VK).expect("Parsing the SRS should always work")),
    ];

    let product = Bn254::<H>::multi_pairing(g1_points, g2_points);

    if product.0.is_one() {
        Ok(())
    } else {
        Err(ProofError::ShpleminiPairingCheckFailed)
    }
}

fn check_evals_consistency(
    libra_poly_evals: &[Fr; LIBRA_POLY_EVALS_LENGTH],
    gemini_r: Fr,
    u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    libra_eval: Fr,
) -> Result<bool, &str> {
    let vanishing_poly_eval = gemini_r.pow([SUBGROUP_SIZE]) - Fr::ONE;
    if vanishing_poly_eval == Fr::ZERO {
        revert GeminiChallengeInSubgroup();
    }

    // SmallSubgroupIpaIntermediates memory mem;
    challenge_poly_lagrange[0] = Fr::ONE;
    for (uint256 round = 0; round < CONST_PROOF_SIZE_LOG_N; round++) {
        uint256 currIdx = 1 + 9 * round;
        mem.challengePolyLagrange[currIdx] = Fr::ONE;
        for (uint256 idx = currIdx + 1; idx < currIdx + 9; idx++) {
            challenge_poly_lagrange[idx] = challenge_poly_lagrange[idx - 1] * u_challenges[round];
        }
    }

    mem.rootPower = Fr::ONE;
    mem.challengePolyEval = Fr::ZERO;
    for (uint256 idx = 0; idx < SUBGROUP_SIZE; idx++) {
        mem.denominators[idx] = mem.rootPower * geminiR - ONE;
        mem.denominators[idx] = mem.denominators[idx].inverse();
        mem.challengePolyEval = mem.challengePolyEval + mem.challengePolyLagrange[idx] * mem.denominators[idx];
        mem.rootPower = mem.rootPower * SUBGROUP_GENERATOR_INVERSE;
    }

    Fr numerator = vanishingPolyEval * Fr.wrap(SUBGROUP_SIZE).inverse();
    mem.challengePolyEval = mem.challengePolyEval * numerator;
    mem.lagrangeFirst = mem.denominators[0] * numerator;
    mem.lagrangeLast = mem.denominators[SUBGROUP_SIZE - 1] * numerator;

    mem.diff = mem.lagrangeFirst * libraPolyEvals[2];

    mem.diff = mem.diff
        + (geminiR - SUBGROUP_GENERATOR_INVERSE)
            * (libraPolyEvals[1] - libraPolyEvals[2] - libraPolyEvals[0] * mem.challengePolyEval);
    mem.diff = mem.diff + mem.lagrangeLast * (libraPolyEvals[2] - libraEval) - vanishingPolyEval * libraPolyEvals[3];

    check = mem.diff == ZERO;
}

#[cfg(test)]
mod should;
