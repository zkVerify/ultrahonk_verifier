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

mod commitment; // probably redundant...
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

use crate::{constants::{CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS, ZK_BATCHED_RELATION_PARTIAL_LENGTH}, key::VerificationKey, proof::ZKProof, relations::accumulate_relation_evaluations, transcript::{generate_transcript, ZKTranscript}, utils::{IntoFr, IntoU256}};
use alloc::format;
use ark_bn254_ext::{Config, CurveHooks};
use ark_ff::{AdditiveGroup, BigInteger, Field, MontFp, PrimeField, batch_inversion};
use ark_models_ext::bn::{BnConfig, G1Prepared, G2Prepared};
use errors::VerifyError;
// use sha3::{Digest, Keccak256};

use proof::ProofType;
pub use types::*;

extern crate alloc;
extern crate core;

use constants::{PROOF_SIZE, ZK_PROOF_SIZE};

pub const VK_SIZE: usize = 1760;
pub const PUBS_SIZE: usize = 32;

/// A single public input.
pub type PublicInput = [u8; PUBS_SIZE];
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

    // Sumcheck
    if (!verify_sumcheck(p, t)) revert SumcheckFailed();

    // Shplemini
    if (!verifyShplemini(p, vk, t)) revert ShpleminiFailed();
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

fn verify_sumcheck(proof: &ZKProof, tp: &ZKTranscript) -> Result<(), &str> {
    let mut round_target_sum = tp.libra_challenge * proof.libra_sum; // default 0
    let mut pow_partial_evaluation = Fr::ONE;

    // We perform sumcheck reductions over log n rounds (i.e., the multivariate degree)
    // for (uint256 round; round < LOG_N; ++round) {
    for round in 0..LOG_N {
        let round_univariate = proof.sumcheck_univariates[round];
        let total_sum = round_univariate[0] + round_univariate[1];
        if total_sum != round_target_sum {
            return Err("Sumcheck failed"); // revert SumcheckFailed();
        }

        let round_challenge = tp.sumcheck_u_challenges[round];

        // Update the round target for the next rounf
        round_target_sum = compute_next_target_sum(round_univariate, round_challenge);
        pow_partial_evaluation =
            pow_partial_evaluation * (Fr::ONE + round_challenge * (tp.gate_challenges[round] - Fr::ONE));
    }

    // Last round
    let mut grand_honk_relation_sum = accumulate_relation_evaluations(
        &proof.sumcheck_evaluations, tp.relation_parameters, tp.alphas, pow_partial_evaluation
    );

    let mut evaluation = Fr::ONE;
    for i in 2..LOG_N { // (uint256 i = 2; i < LOG_N; i++) {
        evaluation *= tp.sumcheck_u_challenges[i];
    }

    grand_honk_relation_sum = grand_honk_relation_sum * (Fr::ONE - evaluation) + proof.libra_evaluation * tp.libra_challenge;
    if grand_honk_relation_sum == round_target_sum {
        Ok(())
    } else {
        Err("Grand Honk Relation Sum does not match Round Target Sum")
    }
}

// Return the new target sum for the next sumcheck round
fn compute_next_target_sum(round_univariates: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH], round_challenge: Fr) -> Result<Fr, &str> {
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

    // TODO: opt: use same array mem for each iteratioon
    // Performing Barycentric evaluations
    // Compute B(x)
    let mut numerator_value = Fr::ONE;
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH { // (uint256 i; i < ZK_BATCHED_RELATION_PARTIAL_LENGTH; ++i) {
        numerator_value *= round_challenge - Fr::from(i as u64);
    }

    // Calculate domain size N of inverses using Montgomery's trick for batch inversion.
    // This reduces computation of `ZK_BATCHED_RELATION_PARTIAL_LENGTH`-many expensive inverses
    // to computing just 1 inverse + `O(ZK_BATCHED_RELATION_PARTIAL_LENGTH)` modular multiplications.
    // Notice that we do not need to check for successfull inversion since `BARYCENTRIC_LAGRANGE_DENOMINATORS`
    // are fixed (and non-zero) and w.h.p. `round_challenge - Fr::from(i as u64)` is non-zero.
    let mut denominator_inverses: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] = from_fn(|i| BARYCENTRIC_LAGRANGE_DENOMINATORS[i] * (round_challenge - Fr::from(i as u64)));
    batch_inversion(&mut denominator_inverses);

    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        target_sum += round_univariates[i]*denominator_inverses[i];
    }

    // Scale the sum by the value of B(x)
    target_sum *= numerator_value;

    Ok(target_sum)
}

fn verifyShplemini(Honk.ZKProof memory proof, Honk.VerificationKey memory vk, ZKTranscript memory tp)
    -> (bool verified)
{
    ShpleminiIntermediates memory mem; // stack

    // - Compute vector (r, r², ... , r²⁽ⁿ⁻¹⁾), where n = log_circuit_size
    Fr[CONST_PROOF_SIZE_LOG_N] memory powers_of_evaluation_challenge = CommitmentSchemeLib.computeSquares(tp.geminiR);
    // Arrays hold values that will be linearly combined for the gemini and shplonk batch openings
    Fr[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 3 + 3] memory scalars;
    Honk.G1Point[NUMBER_OF_ENTITIES + CONST_PROOF_SIZE_LOG_N + 3 + 3] memory commitments;

    mem.posInvertedDenominator = (tp.shplonkZ - powers_of_evaluation_challenge[0]).invert();
    mem.negInvertedDenominator = (tp.shplonkZ + powers_of_evaluation_challenge[0]).invert();


    mem.unshiftedScalar = mem.posInvertedDenominator + (tp.shplonkNu * mem.negInvertedDenominator);
    mem.shiftedScalar =
        tp.geminiR.invert() * (mem.posInvertedDenominator - (tp.shplonkNu * mem.negInvertedDenominator));

    scalars[0] = ONE;
    commitments[0] = convertProofPoint(proof.shplonkQ);

    mem.batchedEvaluation = proof.geminiMaskingEval;
    mem.batchingChallenge = tp.rho;
    scalars[1] = mem.unshiftedScalar.neg();
    for (uint256 i = 0; i < NUMBER_UNSHIFTED; ++i) {
        scalars[i + 2] = mem.unshiftedScalar.neg() * mem.batchingChallenge;
        mem.batchedEvaluation = mem.batchedEvaluation + (proof.sumcheckEvaluations[i] * mem.batchingChallenge);
        mem.batchingChallenge = mem.batchingChallenge * tp.rho;
    }

    for (uint256 i = NUMBER_UNSHIFTED; i < NUMBER_OF_ENTITIES; ++i) {
        scalars[i + 2] = mem.shiftedScalar.neg() * mem.batchingChallenge;
        mem.batchedEvaluation = mem.batchedEvaluation + (proof.sumcheckEvaluations[i] * mem.batchingChallenge);
        mem.batchingChallenge = mem.batchingChallenge * tp.rho;
    }

    commitments[1] = convertProofPoint(proof.geminiMaskingPoly);

    commitments[2] = vk.qm;
    commitments[3] = vk.qc;
    commitments[4] = vk.ql;
    commitments[5] = vk.qr;
    commitments[6] = vk.qo;
    commitments[7] = vk.q4;
    commitments[8] = vk.qLookup;
    commitments[9] = vk.qArith;
    commitments[10] = vk.qDeltaRange;
    commitments[11] = vk.qElliptic;
    commitments[12] = vk.qAux;
    commitments[13] = vk.qPoseidon2External;
    commitments[14] = vk.qPoseidon2Internal;
    commitments[15] = vk.s1;
    commitments[16] = vk.s2;
    commitments[17] = vk.s3;
    commitments[18] = vk.s4;
    commitments[19] = vk.id1;
    commitments[20] = vk.id2;
    commitments[21] = vk.id3;
    commitments[22] = vk.id4;
    commitments[23] = vk.t1;
    commitments[24] = vk.t2;
    commitments[25] = vk.t3;
    commitments[26] = vk.t4;
    commitments[27] = vk.lagrangeFirst;
    commitments[28] = vk.lagrangeLast;

    // Accumulate proof points
    commitments[29] = convertProofPoint(proof.w1);
    commitments[30] = convertProofPoint(proof.w2);
    commitments[31] = convertProofPoint(proof.w3);
    commitments[32] = convertProofPoint(proof.w4);
    commitments[33] = convertProofPoint(proof.zPerm);
    commitments[34] = convertProofPoint(proof.lookupInverses);
    commitments[35] = convertProofPoint(proof.lookupReadCounts);
    commitments[36] = convertProofPoint(proof.lookupReadTags);

    // to be Shifted
    commitments[37] = convertProofPoint(proof.w1);
    commitments[38] = convertProofPoint(proof.w2);
    commitments[39] = convertProofPoint(proof.w3);
    commitments[40] = convertProofPoint(proof.w4);
    commitments[41] = convertProofPoint(proof.zPerm);


    // Add contributions from A₀(r) and A₀(-r) to constant_term_accumulator:
    // Compute the evaluations Aₗ(r^{2ˡ}) for l = 0, ..., logN - 1
    Fr[CONST_PROOF_SIZE_LOG_N] memory foldPosEvaluations = CommitmentSchemeLib.computeFoldPosEvaluations(
        tp.sumCheckUChallenges,
        mem.batchedEvaluation,
        proof.geminiAEvaluations,
        powers_of_evaluation_challenge,
        LOG_N
    );

    mem.constantTermAccumulator = foldPosEvaluations[0] * mem.posInvertedDenominator;
    mem.constantTermAccumulator =
        mem.constantTermAccumulator + (proof.geminiAEvaluations[0] * tp.shplonkNu * mem.negInvertedDenominator);

    mem.batchingChallenge = tp.shplonkNu.sqr();
    uint256 boundary = NUMBER_OF_ENTITIES + 2;

    // Compute Shplonk constant term contributions from Aₗ(± r^{2ˡ}) for l = 1, ..., m-1;
    // Compute scalar multipliers for each fold commitment
    for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N - 1; ++i) {
        bool dummy_round = i >= (LOG_N - 1);

        if (!dummy_round) {
            // Update inverted denominators
            mem.posInvertedDenominator = (tp.shplonkZ - powers_of_evaluation_challenge[i + 1]).invert();
            mem.negInvertedDenominator = (tp.shplonkZ + powers_of_evaluation_challenge[i + 1]).invert();

            // Compute the scalar multipliers for Aₗ(± r^{2ˡ}) and [Aₗ]
            mem.scalingFactorPos = mem.batchingChallenge * mem.posInvertedDenominator;
            mem.scalingFactorNeg = mem.batchingChallenge * tp.shplonkNu * mem.negInvertedDenominator;
            scalars[boundary + i] = mem.scalingFactorNeg.neg() + mem.scalingFactorPos.neg();

            // Accumulate the const term contribution given by
            // v^{2l} * Aₗ(r^{2ˡ}) /(z-r^{2^l}) + v^{2l+1} * Aₗ(-r^{2ˡ}) /(z+ r^{2^l})
            Fr accumContribution = mem.scalingFactorNeg * proof.geminiAEvaluations[i + 1];
            accumContribution = accumContribution + mem.scalingFactorPos * foldPosEvaluations[i + 1];
            mem.constantTermAccumulator = mem.constantTermAccumulator + accumContribution;
        }
        // Update the running power of v
        mem.batchingChallenge = mem.batchingChallenge * tp.shplonkNu * tp.shplonkNu;

        commitments[boundary + i] = convertProofPoint(proof.geminiFoldComms[i]);
    }

    boundary += CONST_PROOF_SIZE_LOG_N - 1;


    // Finalise the batch opening claim
    mem.denominators[0] = ONE.div(tp.shplonkZ - tp.geminiR);
    mem.denominators[1] = ONE.div(tp.shplonkZ - SUBGROUP_GENERATOR * tp.geminiR);
    mem.denominators[2] = mem.denominators[0];
    mem.denominators[3] = mem.denominators[0];

    // Artifact of interleaving, see TODO(https://github.com/AztecProtocol/barretenberg/issues/1293): Decouple Gemini from Interleaving
    mem.batchingChallenge = mem.batchingChallenge * tp.shplonkNu * tp.shplonkNu;
    for (uint256 i = 0; i < 4; i++) {
        Fr scalingFactor = mem.denominators[i] * mem.batchingChallenge;
        mem.batchingScalars[i] = scalingFactor.neg();
        mem.batchingChallenge = mem.batchingChallenge * tp.shplonkNu;
        mem.constantTermAccumulator = mem.constantTermAccumulator + scalingFactor * proof.libraPolyEvals[i];
    }
    scalars[boundary] = mem.batchingScalars[0];
    scalars[boundary + 1] = mem.batchingScalars[1] + mem.batchingScalars[2];
    scalars[boundary + 2] = mem.batchingScalars[3];

    for (uint256 i = 0; i < 3; i++) {
        commitments[boundary++] = convertProofPoint(proof.libraCommitments[i]);
    }

    commitments[boundary] = Honk.G1Point({x: 1, y: 2});
    scalars[boundary++] = mem.constantTermAccumulator;

    if (! checkEvalsConsistency(proof.libraPolyEvals, tp.geminiR, tp.sumCheckUChallenges, proof.libraEvaluation)) {
        revert ConsistencyCheckFailed();
    }
    Honk.G1Point memory quotient_commitment = convertProofPoint(proof.kzgQuotient);

    commitments[boundary] = quotient_commitment;
    scalars[boundary] = tp.shplonkZ; // evaluation challenge

    Honk.G1Point memory P_0 = batchMul(commitments, scalars);
    Honk.G1Point memory P_1 = negateInplace(quotient_commitment);

    return pairing(P_0, P_1);
}

#[cfg(test)]
mod should;
