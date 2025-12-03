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

// #![cfg_attr(not(feature = "std"), no_std)]
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

extern crate alloc;
extern crate core;

use crate::{
    commitment::{compute_fold_pos_evaluations, compute_squares},
    constants::{
        CONST_PROOF_SIZE_LOG_N, LIBRA_UNIVARIATES_LENGTH, NUMBER_TO_BE_SHIFTED, NUMBER_UNSHIFTED,
        NUM_LIBRA_COMMITMENTS, NUM_LIBRA_EVALUATIONS, PAIRING_POINTS_SIZE, SUBGROUP_SIZE,
    },
    key::VerificationKey,
    proof::{
        convert_pairing_points_to_g1, generate_recursion_separator, CommonProofData, ParsedProof,
        PlainProof, ProofError, ZKProof,
    },
    relations::accumulate_relation_evaluations,
    srs::{SRS_G2, SRS_G2_VK},
    transcript::{generate_transcript, CommonTranscriptData, Transcript},
    utils::{read_g2, to_hex_string},
};
use alloc::{boxed::Box, format, string::ToString, vec::Vec};
use ark_bn254_ext::CurveHooks;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{batch_inversion, AdditiveGroup, Field, One};
use ark_models_ext::bn::{G1Prepared, G2Prepared};
use constants::{SUBGROUP_GENERATOR, SUBGROUP_GENERATOR_INVERSE};
use errors::VerifyError;

pub use constants::{PUB_SIZE, VK_SIZE};
pub use proof::ProofType;
pub use types::*;

/// A single public input.
pub type PublicInput = [u8; PUB_SIZE];
pub type Pubs = [PublicInput];

pub fn verify<H: CurveHooks + Default>(
    vk_bytes: &[u8],
    proof: &ProofType,
    pubs: &Pubs,
) -> Result<(), VerifyError> {
    let vk = VerificationKey::<H>::try_from(vk_bytes).map_err(|_| VerifyError::KeyError)?;

    // TODO: Check upper bound for vk.circuit_size?

    // TODO: Move check inside the from_bytes functions if possible.
    check_proof_size::<H>(proof, vk.log_circuit_size)?;

    check_public_input_number(&vk, pubs)?;

    let proof = match proof {
        ProofType::ZK(proof_bytes) => ParsedProof::ZK(Box::new(
            ZKProof::from_bytes(&proof_bytes[..], vk.log_circuit_size).map_err(|_| {
                VerifyError::InvalidProofError {
                    message: "Failed parsing ZK proof".to_string(),
                }
            })?,
        )),
        ProofType::Plain(proof_bytes) => ParsedProof::Plain(Box::new(
            PlainProof::from_bytes(&proof_bytes[..], vk.log_circuit_size).map_err(|_| {
                VerifyError::InvalidProofError {
                    message: "Failed parsing Plain proof".to_string(),
                }
            })?,
        )),
    };

    verify_inner(&vk, &proof, pubs)
}

fn verify_inner<H: CurveHooks>(
    vk: &VerificationKey<H>,
    parsed_proof: &ParsedProof<H>,
    public_inputs: &Pubs,
) -> Result<(), VerifyError> {
    // TODO: Fix this so that we do not rely on a hard-coded hash
    // let vk_hash = vk.compute_vk_hash();

    let vk_hash =
        hex_literal::hex!("0a1c3472f1f33e6a26c5735f3cfcfeb8247edd1c38791be7a0590fb55b01c4bd");

    println!("vk_hash = {}", to_hex_string(&vk_hash));
    // What I actually get: 0x6ae4d158b4567ebd9765fecc3fffaf7274e6adad2bebfd0a281cfadd3b01c4bf
    // The correct hash is: 0x0a1c3472f1f33e6a26c5735f3cfcfeb8247edd1c38791be7a0590fb55b01c4bd

    // Generate the Fiat-Shamir challenges for the whole protocol and derive public inputs delta
    let t: Transcript =
        generate_transcript(parsed_proof, public_inputs, &vk_hash, vk.log_circuit_size);

    let public_inputs_delta = t
        .relation_parameters_challenges()
        .compute_public_input_delta(
            public_inputs,
            parsed_proof.pairing_point_object(),
            vk.pub_inputs_offset,
        );

    // Sumcheck
    verify_sumcheck(parsed_proof, &t, vk.log_circuit_size, public_inputs_delta).map_err(
        |cause| VerifyError::VerificationError {
            message: format!("Sumcheck Failed. Cause: {cause}"),
        },
    )?;

    // Shplemini
    verify_shplemini(parsed_proof, vk, &t).map_err(|cause| VerifyError::VerificationError {
        message: format!("Shplemini Failed. Cause: {cause}"),
    })?;

    Ok(())
}

// Checks that number of public inputs in the vk, matches the actual length of the PI list.
fn check_public_input_number<H: CurveHooks>(
    vk: &VerificationKey<H>,
    pubs: &Pubs,
) -> Result<(), VerifyError> {
    // In bb 0.86.0, public inputs and the pairing point object are combined under the hood.
    // see: https://github.com/AztecProtocol/barretenberg/issues/1331
    if vk.combined_input_size - PAIRING_POINTS_SIZE as u64 != pubs.len() as u64 {
        Err(VerifyError::PublicInputError {
            message: format!(
                "Provided public inputs length does not match value in vk. Expected: {}; Got: {}",
                vk.combined_input_size - PAIRING_POINTS_SIZE as u64,
                pubs.len()
            ),
        })
    } else {
        Ok(())
    }
}

fn verify_sumcheck<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    tp: &Transcript,
    log_circuit_size: u64,
    public_inputs_delta: Fr,
) -> Result<(), &'static str> {
    let log_circuit_size: usize = log_circuit_size
        .try_into()
        .map_err(|_| "Given log_circuit_size does not fit in a u64.")?;
    let mut round_target_sum = match (tp, parsed_proof) {
        (Transcript::ZK(zktp), ParsedProof::ZK(zk_proof)) => {
            zktp.libra_challenge * zk_proof.libra_sum
        }
        (Transcript::Plain(_), ParsedProof::Plain(_)) => Fr::ZERO,
        _ => unreachable!("parsed_proof and transcript will always have the same type"),
    };

    let mut pow_partial_evaluation = Fr::ONE;

    // We perform sumcheck reductions over log n rounds (i.e., the multivariate degree)
    for (round, round_univariate) in parsed_proof
        .sumcheck_univariates()
        .enumerate()
        .take(log_circuit_size)
    {
        let total_sum = round_univariate[0] + round_univariate[1];
        if total_sum != round_target_sum {
            return Err("Total Sum differs from Round Target Sum.");
        }

        let round_challenge = tp.sumcheck_u_challenges()[round];

        // Update round target for the next round
        round_target_sum = compute_next_target_sum(round_univariate, round_challenge, parsed_proof)
            .expect("compute_next_target_sum should always return an Ok variant");
        pow_partial_evaluation *=
            Fr::ONE + round_challenge * (tp.gate_challenges()[round] - Fr::ONE);
    }

    // Final round
    let mut grand_honk_relation_sum = accumulate_relation_evaluations(
        parsed_proof.sumcheck_evaluations(),
        tp.relation_parameters_challenges(),
        tp.alphas(),
        public_inputs_delta,
        pow_partial_evaluation,
    );

    if let ParsedProof::ZK(zk_proof) = parsed_proof {
        let mut evaluation = Fr::ONE;
        for i in 2..log_circuit_size {
            evaluation *= tp.sumcheck_u_challenges()[i];
        }

        // This will always be the case
        if let Transcript::ZK(zktp) = tp {
            grand_honk_relation_sum = grand_honk_relation_sum * (Fr::ONE - evaluation)
                + zk_proof.libra_evaluation * zktp.libra_challenge;
        }
    }

    if grand_honk_relation_sum == round_target_sum {
        Ok(())
    } else {
        Err("Grand Honk Relation Sum does not match Round Target Sum.")
    }
}

// Return the new target sum for the next sumcheck round.
fn compute_next_target_sum<H: CurveHooks>(
    round_univariates: &[Fr],
    round_challenge: Fr,
    parsed_proof: &ParsedProof<H>,
) -> Result<Fr, &'static str> {
    let baricentric_lagrange_denominators = parsed_proof.get_baricentric_lagrange_denominators();

    let mut target_sum = Fr::ZERO;

    // To compute the next target sum, we evaluate the given univariate at a point u (challenge).

    // Performing Barycentric evaluations
    // Compute B(x)
    let mut numerator_value = Fr::ONE;
    let batched_relation_partial_length = parsed_proof.get_batched_relation_partial_length();
    for i in 0..batched_relation_partial_length {
        numerator_value *= round_challenge - Fr::from(i as u64);
    }

    // Calculate domain size N of inverses using Montgomery's trick for simultaneous inversion.
    // This reduces computation of `ZK_BATCHED_RELATION_PARTIAL_LENGTH`-many expensive inverses to
    // computing just 1 inverse + `O(ZK_BATCHED_RELATION_PARTIAL_LENGTH)` modular multiplications.
    // Notice that inversion will w.h.p. succeed because the `BARYCENTRIC_LAGRANGE_DENOMINATORS`
    // are all fixed (and non-zero), and w.h.p. `round_challenge - i` is also non-zero.
    let mut denominator_inverses = Vec::with_capacity(batched_relation_partial_length);
    denominator_inverses
        .extend((0..batched_relation_partial_length).map(|i| {
            baricentric_lagrange_denominators[i] * (round_challenge - Fr::from(i as u64))
        }));
    batch_inversion(&mut denominator_inverses);

    for i in 0..batched_relation_partial_length {
        target_sum += round_univariates[i] * denominator_inverses[i];
    }

    // Scale the sum by the value of B(x)
    target_sum *= numerator_value;

    Ok(target_sum)
}

fn verify_shplemini<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    vk: &VerificationKey<H>,
    tp: &Transcript,
) -> Result<(), ProofError> {
    // - Compute vector (r, r², ..., r²⁽ⁿ⁻¹⁾), where n := log_circuit_size
    let powers_of_evaluation_challenge = compute_squares(tp.gemini_r(), vk.log_circuit_size);
    // Vectors hold values that will be linearly combined for the gemini and shplonk batch openings
    let capacity = if matches!(parsed_proof, ParsedProof::ZK(_)) {
        NUMBER_UNSHIFTED + vk.log_circuit_size as usize + NUM_LIBRA_COMMITMENTS + 3
    } else {
        NUMBER_UNSHIFTED + vk.log_circuit_size as usize + 2
    };
    let mut scalars = Vec::with_capacity(capacity);
    scalars.resize(capacity, Fr::ZERO);
    let mut commitments = Vec::with_capacity(capacity);
    commitments.resize(capacity, G1::<H>::default());

    // NOTE: Can use batching here to go from 2 inversions to 1 inversion + 3 multiplications
    // but the benefit is probably not worth it.
    let pos_inverted_denominator = (tp.shplonk_z() - powers_of_evaluation_challenge[0])
        .inverse()
        .expect("Inversion should work w.h.p.");
    let neg_inverted_denominator = (tp.shplonk_z() + powers_of_evaluation_challenge[0])
        .inverse()
        .expect("Inversion should work w.h.p.");

    let unshifted_scalar = pos_inverted_denominator + tp.shplonk_nu() * neg_inverted_denominator;
    let shifted_scalar = tp
        .gemini_r()
        .inverse()
        .expect("Inversion should work w.h.p.")
        * (pos_inverted_denominator - tp.shplonk_nu() * neg_inverted_denominator);

    scalars[0] = Fr::ONE;
    commitments[0] = *parsed_proof.shplonk_q();

    let unshifted_scalar_neg = -unshifted_scalar;
    let shifted_scalar_neg = -shifted_scalar;

    let (mut batched_evaluation, mut batching_challenge, offset) = match parsed_proof {
        ParsedProof::ZK(zkp) => {
            scalars[1] = unshifted_scalar_neg;
            (zkp.gemini_masking_eval, tp.rho(), 1)
        }
        ParsedProof::Plain(_) => (Fr::ZERO, Fr::ONE, 0),
    };

    for i in (1 - offset)..=(NUMBER_UNSHIFTED - offset) {
        scalars[i + 2 * offset] = unshifted_scalar_neg * batching_challenge;
        batched_evaluation +=
            parsed_proof.sumcheck_evaluations()[i + offset - 1] * batching_challenge;
        batching_challenge *= tp.rho();
    }

    // g commitments are accumulated at r
    // For each of the to be shifted commitments perform the shift in place by
    // adding to the unshifted value.
    // We do so, as the values are to be used in batchMul later, and as
    // `a * c + b * c = (a + b) * c` this will allow us to reduce memory and compute.
    // Applied to w1, w2, w3, w4 and zPerm
    let shifted_commitments_start = parsed_proof.get_shifted_commitments_start();

    for i in 0..NUMBER_TO_BE_SHIFTED {
        let scalar_off = i + shifted_commitments_start;
        let evaluation_off = i + NUMBER_UNSHIFTED;

        scalars[scalar_off] += shifted_scalar_neg * batching_challenge;
        batched_evaluation +=
            parsed_proof.sumcheck_evaluations()[evaluation_off] * batching_challenge;
        batching_challenge *= tp.rho();
    }

    if let ParsedProof::ZK(zkp) = parsed_proof {
        commitments[1] = zkp.gemini_masking_poly;
    }

    commitments[1 + offset] = vk.q_m;
    commitments[2 + offset] = vk.q_c;
    commitments[3 + offset] = vk.q_l;
    commitments[4 + offset] = vk.q_r;
    commitments[5 + offset] = vk.q_o;
    commitments[6 + offset] = vk.q_4;
    commitments[7 + offset] = vk.q_lookup;
    commitments[8 + offset] = vk.q_arith;
    commitments[9 + offset] = vk.q_deltarange;
    commitments[10 + offset] = vk.q_elliptic;
    commitments[11 + offset] = vk.q_memory;
    commitments[12 + offset] = vk.q_nnf;
    commitments[13 + offset] = vk.q_poseidon2external;
    commitments[14 + offset] = vk.q_poseidon2internal;
    commitments[15 + offset] = vk.s_1;
    commitments[16 + offset] = vk.s_2;
    commitments[17 + offset] = vk.s_3;
    commitments[18 + offset] = vk.s_4;
    commitments[19 + offset] = vk.id_1;
    commitments[20 + offset] = vk.id_2;
    commitments[21 + offset] = vk.id_3;
    commitments[22 + offset] = vk.id_4;
    commitments[23 + offset] = vk.t_1;
    commitments[24 + offset] = vk.t_2;
    commitments[25 + offset] = vk.t_3;
    commitments[26 + offset] = vk.t_4;
    commitments[27 + offset] = vk.lagrange_first;
    commitments[28 + offset] = vk.lagrange_last;

    // TODO: Elliptic curve points will likely need to be validated during parsing now!

    // Accumulate proof points
    commitments[29 + offset] = *parsed_proof.w1();
    commitments[30 + offset] = *parsed_proof.w2();
    commitments[31 + offset] = *parsed_proof.w3();
    commitments[32 + offset] = *parsed_proof.w4();

    commitments[33 + offset] = *parsed_proof.z_perm();
    commitments[34 + offset] = *parsed_proof.lookup_inverses();
    commitments[35 + offset] = *parsed_proof.lookup_read_counts();
    commitments[36 + offset] = *parsed_proof.lookup_read_tags();

    // Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
    // Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., logN - 1.
    let fold_pos_evaluations: Vec<Fr> = compute_fold_pos_evaluations(
        tp.sumcheck_u_challenges(),
        &mut batched_evaluation,
        parsed_proof.gemini_a_evaluations(),
        &powers_of_evaluation_challenge,
        vk.log_circuit_size,
    );

    let mut constant_term_accumulator = fold_pos_evaluations[0] * pos_inverted_denominator;
    constant_term_accumulator +=
        parsed_proof.gemini_a_evaluations()[0] * tp.shplonk_nu() * neg_inverted_denominator;

    batching_challenge = tp.shplonk_nu().square();

    // Compute Shplonk constant term contributions from Aₗ(± r^{2ˡ}) for l = 1, ..., m-1;
    // Compute scalar multipliers for each fold commitment.
    let mut scaling_factor_pos: Fr;
    let mut scaling_factor_neg: Fr;
    let mut boundary = NUMBER_UNSHIFTED + 1 + offset;

    let num_non_dummy_rounds = vk.log_circuit_size as usize - 1;
    let mut inverted_denominators: Vec<_> = (0..num_non_dummy_rounds)
        .flat_map(|i| {
            // Both invertible w.h.p.
            [
                tp.shplonk_z() - powers_of_evaluation_challenge[i + 1],
                tp.shplonk_z() + powers_of_evaluation_challenge[i + 1],
            ]
        })
        .collect();

    batch_inversion(&mut inverted_denominators);

    for i in 0..(vk.log_circuit_size as usize - 1) {
        let dummy_round = i as u64 >= (vk.log_circuit_size - 1);

        if !dummy_round {
            let pos_inverted_denominator = inverted_denominators[2 * i];
            let neg_inverted_denominator = inverted_denominators[2 * i + 1];

            // Compute the scalar multipliers for Aₗ(± r^{2ˡ}) and [Aₗ]
            scaling_factor_pos = batching_challenge * pos_inverted_denominator;
            scaling_factor_neg = batching_challenge * tp.shplonk_nu() * neg_inverted_denominator;
            scalars[boundary + i] = -(scaling_factor_neg + scaling_factor_pos);

            // Accumulate the const term contribution given by
            // v^{2l} * Aₗ(r^{2ˡ}) /(z-r^{2^l}) + v^{2l+1} * Aₗ(-r^{2ˡ}) /(z+ r^{2^l})
            let mut accum_contribution =
                scaling_factor_neg * parsed_proof.gemini_a_evaluations()[i + 1];
            accum_contribution += scaling_factor_pos * fold_pos_evaluations[i + 1];
            constant_term_accumulator += accum_contribution;
        }
        // Update the running power of v
        batching_challenge *= tp.shplonk_nu().square();

        commitments[boundary + i] = parsed_proof.gemini_fold_comms()[i];
    }

    boundary += vk.log_circuit_size as usize - 1;

    // Finalize the batch opening claim
    match (tp, parsed_proof) {
        (Transcript::ZK(zktp), ParsedProof::ZK(zk_proof)) => {
            let mut denominators = [Fr::ZERO; NUM_LIBRA_EVALUATIONS];

            denominators[0] = (zktp.shplonk_z - zktp.gemini_r)
                .inverse()
                .expect("shplonk_z - gemini_r should be invertible w.h.p.");
            denominators[1] = (zktp.shplonk_z - SUBGROUP_GENERATOR * zktp.gemini_r)
                .inverse()
                .expect(
                    "tp.shplonk_z - SUBGROUP_GENERATOR * tp.gemini_r should be invertible w.h.p.",
                );
            denominators[2] = denominators[0];
            denominators[3] = denominators[0];

            let mut batching_scalars = [Fr::ZERO; NUM_LIBRA_EVALUATIONS];

            // Artifact of interleaving, see TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
            batching_challenge *= zktp.shplonk_nu.square();

            for i in 0..NUM_LIBRA_EVALUATIONS {
                let scaling_factor = denominators[i] * batching_challenge;
                batching_scalars[i] = -scaling_factor;
                batching_challenge *= zktp.shplonk_nu;
                constant_term_accumulator += scaling_factor * zk_proof.libra_poly_evals[i];
            }

            scalars[boundary] = batching_scalars[0];
            scalars[boundary + 1] = batching_scalars[1] + batching_scalars[2];
            scalars[boundary + 2] = batching_scalars[3];

            for i in 0..NUM_LIBRA_COMMITMENTS {
                commitments[boundary] = zk_proof.libra_commitments[i];
                boundary += 1;
            }
        }
        (Transcript::Plain(_), ParsedProof::Plain(_)) => {}
        _ => {
            unreachable!("parsed_proof and transcript must always be of the same type");
        }
    }

    commitments[boundary] = G1::<H>::generator(); // (1, 2)
    scalars[boundary] = constant_term_accumulator;
    boundary += 1;

    // ZKProofs only
    if let ParsedProof::ZK(zk_proof) = parsed_proof {
        if let Err(msg) = check_evals_consistency(
            &zk_proof.libra_poly_evals,
            tp.gemini_r(),
            tp.sumcheck_u_challenges(),
            zk_proof.libra_evaluation,
            vk.log_circuit_size,
        ) {
            return Err(ProofError::ConsistencyCheckFailed { message: msg });
        }
    }

    let quotient_commitment = *parsed_proof.kzg_quotient();

    commitments[boundary] = quotient_commitment;
    scalars[boundary] = tp.shplonk_z(); // evaluation challenge

    // Pairing Check
    let p_0 = H::bn254_msm_g1(&commitments, &scalars)
        .map_err(|_| ProofError::OtherError {
            message: "Shplemini MSM computation failed.".to_string(),
        })?
        .into_affine();
    let p_1 = -quotient_commitment;

    // Aggregate pairing points
    let (p_0_other, p_1_other) = convert_pairing_points_to_g1(parsed_proof.pairing_point_object())?;
    let recursion_separator = generate_recursion_separator(&p_0, &p_1, &p_0_other, &p_1_other);

    // accumulate with aggregate points in proof
    let g1_points = [
        G1Prepared::from(p_0 * recursion_separator + p_0_other),
        G1Prepared::from(p_1 * recursion_separator + p_1_other),
    ];

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
    libra_poly_evals: &[Fr; NUM_LIBRA_EVALUATIONS],
    gemini_r: Fr,
    u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    libra_eval: Fr,
    log_n: u64,
) -> Result<(), &'static str> {
    let vanishing_poly_eval = gemini_r.pow([SUBGROUP_SIZE as u64]) - Fr::ONE;
    if vanishing_poly_eval == Fr::ZERO {
        return Err("Gemini Challenge In Subgroup");
    }

    let mut challenge_poly_lagrange = [Fr::ZERO; SUBGROUP_SIZE as usize];

    challenge_poly_lagrange[0] = Fr::ONE;
    for (round, u_ch) in u_challenges.iter().enumerate().take(log_n as usize) {
        let curr_idx = 1 + LIBRA_UNIVARIATES_LENGTH * round;
        challenge_poly_lagrange[curr_idx] = Fr::ONE;
        for idx in (curr_idx + 1)..(curr_idx + LIBRA_UNIVARIATES_LENGTH) {
            challenge_poly_lagrange[idx] = challenge_poly_lagrange[idx - 1] * u_ch;
        }
    }

    let mut root_power = Fr::ONE;

    // Notice that no array copies are needed.
    let mut extended_denominators: [Fr; SUBGROUP_SIZE as usize + 1] = core::array::from_fn(|i| {
        if i == 0 {
            Fr::from(SUBGROUP_SIZE as u64) // invertible mod r
        } else {
            // For each i < SUBGROUP_SIZE, we have:
            // Pr[SUBGROUP_GENERATOR_INVERSE^i * gemini_r - 1 is invertible]
            //   = Pr[SUBGROUP_GENERATOR_INVERSE^i * gemini_r - 1 != 0]
            //   = 1 - Pr[SUBGROUP_GENERATOR_INVERSE^i * gemini_r - 1 = 0]
            //   = 1 - Pr[gemini_r = (SUBGROUP_GENERATOR_INVERSE^i)^{-1}]
            //   >= 1 - 1/2^128 because gemini_r is the 128 lower-significance bits output by Keccak256
            let result = root_power * gemini_r - Fr::ONE;
            root_power *= SUBGROUP_GENERATOR_INVERSE;
            result
        }
    });

    batch_inversion(&mut extended_denominators);

    // O(1) since we are simply manipulating pointers
    let (subgroup_size_inverse, inverted_denominators_slice) = extended_denominators
        .as_mut_slice()
        .split_first_mut()
        .expect("Array is always non-empty");
    let inverted_denominators: &mut [Fr; SUBGROUP_SIZE as usize] = inverted_denominators_slice
        .try_into()
        .expect("Slice length should always match");

    let mut challenge_poly_eval: Fr = inverted_denominators
        .iter()
        .zip(challenge_poly_lagrange)
        .map(|(ai, bi)| *ai * bi)
        .sum();

    let numerator = vanishing_poly_eval * subgroup_size_inverse;
    challenge_poly_eval *= numerator;
    let lagrange_first = inverted_denominators[0] * numerator;
    let lagrange_last = *inverted_denominators
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

fn check_proof_size<H: CurveHooks>(proof: &ProofType, log_n: u64) -> Result<(), VerifyError> {
    // Calculate expected proof size based on log_n.
    let (expected_proof_size, proof_length) = match proof {
        ProofType::ZK(zkp) => (ZKProof::<H>::calculate_proof_size(log_n), zkp.len()),
        ProofType::Plain(p) => (PlainProof::<H>::calculate_proof_size(log_n), p.len()),
    };
    let expected_proof_length = 32 * expected_proof_size;

    // Check the received proof is the expected size where each field element is 32 bytes
    if proof_length != expected_proof_length {
        Err(VerifyError::InvalidProofError {
            message: format!(
                "Provided proof length does not match expected length. Expected: {expected_proof_length}; Got: {proof_length}"
            ),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod should;
