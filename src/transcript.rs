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

use crate::{
    constants::{
        CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES,
        ZK_BATCHED_RELATION_PARTIAL_LENGTH,
    },
    proof::ZKProof,
    utils::IntoBEBytes32,
    Pubs,
};
// use alloc::vec::Vec;
use ark_bn254_ext::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use sha3::{Digest, Keccak256};

pub(crate) struct ZKTranscript {
    // Oink
    pub(crate) relation_parameters_challenges: RelationParametersChallenges,
    pub(crate) alphas: [Fr; NUMBER_OF_ALPHAS],
    pub(crate) gate_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Sumcheck
    pub(crate) libra_challenge: Fr,
    pub(crate) sumcheck_u_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Shplemini
    pub(crate) rho: Fr,
    pub(crate) gemini_r: Fr,
    pub(crate) shplonk_nu: Fr,
    pub(crate) shplonk_z: Fr,
    // Derived
    pub(crate) public_inputs_delta: Fr,
}

// NOTE: This type simply isolates the challenges in the `RelationParameters` type.
// We thus need to handle the public_inputs_delta field separately.
// This should be doable given the usage of public_inputs_delta during verification.
#[derive(Debug)]
pub(crate) struct RelationParametersChallenges {
    pub(crate) eta: Fr,
    pub(crate) eta_two: Fr,
    pub(crate) eta_three: Fr,
    pub(crate) beta: Fr,
    pub(crate) gamma: Fr,
}

impl RelationParametersChallenges {
    pub(crate) fn new(eta: Fr, eta_two: Fr, eta_three: Fr, beta: Fr, gamma: Fr) -> Self {
        RelationParametersChallenges {
            eta,
            eta_two,
            eta_three,
            beta,
            gamma,
        }
    }

    pub(crate) fn public_inputs_delta(
        &self,
        public_inputs: &Pubs,
        circuit_size: u64,
        offset: u64,
    ) -> Fr {
        let mut numerator = Fr::ONE;
        let mut denominator = Fr::ONE;

        let mut numerator_acc = self.gamma + self.beta * Fr::from(circuit_size + offset);
        // Fr numerator_acc = gamma + (beta * FrLib.from(N + offset));
        let mut denominator_acc = self.gamma - self.beta * Fr::from(offset + 1);
        // Fr denominatorAcc = gamma - (beta * FrLib.from(offset + 1));

        {
            for pi_bytes in public_inputs {
                let pi = Fr::from_be_bytes_mod_order(pi_bytes);

                numerator = numerator * (numerator_acc + pi);
                denominator = denominator * (denominator_acc + pi);

                numerator_acc += self.beta;
                denominator_acc -= self.beta;
            }

            // for (uint256 i = 0; i < NUMBER_OF_PUBLIC_INPUTS; i++) {
            //     Fr pubInput = FrLib.fromBytes32(publicInputs[i]);

            //     numerator = numerator * (numeratorAcc + pubInput);
            //     denominator = denominator * (denominatorAcc + pubInput);

            //     numeratorAcc = numeratorAcc + beta;
            //     denominatorAcc = denominatorAcc - beta;
            // }
        }

        let public_inputs_delta = numerator / denominator;
        // publicInputDelta = FrLib.div(numerator, denominator);

        public_inputs_delta
    }
}

// Do we really need this type?
// #[derive(Debug)]
// pub struct RelationParameters {
//     // challenges
//     challenges: RelationParametersChallenges,
//     // derived
//     public_inputs_delta: Fr,
// }

pub(crate) fn generate_transcript(
    proof: &ZKProof,
    public_inputs: &Pubs,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> ZKTranscript {
    // (t.relationParameters, previousChallenge) =
    //     generateRelationParametersChallenges(proof, publicInputs, circuitSize, publicInputsSize, pubInputsOffset, previousChallenge);
    let (rp_challenges, previous_challenge) = generate_relation_parameters_challenges(
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );

    // (t.alphas, previousChallenge) = generateAlphaChallenges(previousChallenge, proof);
    let (alphas, previous_challenge) = generate_alpha_challenges(previous_challenge, proof);

    // (t.gateChallenges, previousChallenge) = generateGateChallenges(previousChallenge);
    let (gate_challenges, previous_challenge) = generate_gate_challenges(previous_challenge);
    // (t.libraChallenge, previousChallenge) = generateLibraChallenge(previousChallenge, proof);
    let (libra_challenge, previous_challenge) = generate_libra_challenge(previous_challenge, proof);
    // (t.sumCheckUChallenges, previousChallenge) = generateSumcheckChallenges(proof, previousChallenge);
    let (sumcheck_u_challenges, previous_challenge) =
        generate_sumcheck_challenges(proof, previous_challenge);

    // (t.rho, previousChallenge) = generateRhoChallenge(proof, previousChallenge);
    let (rho, previous_challenge) = generate_rho_challenge(proof, previous_challenge);

    // (t.geminiR, previousChallenge) = generateGeminiRChallenge(proof, previousChallenge);
    let (gemini_r, previous_challenge) = generate_gemini_r_challenge(proof, previous_challenge);

    // (t.shplonkNu, previousChallenge) = generateShplonkNuChallenge(proof, previousChallenge);
    let (shplonk_nu, previous_challenge) = generate_shplonk_nu_challenge(proof, previous_challenge);

    // (t.shplonkZ, previousChallenge) = generateShplonkZChallenge(proof, previousChallenge);
    let (shplonk_z, _) = generate_shplonk_z_challenge(proof, previous_challenge);

    let public_inputs_delta =
        rp_challenges.public_inputs_delta(public_inputs, circuit_size, pub_inputs_offset);

    ZKTranscript {
        relation_parameters_challenges: rp_challenges, // relation_parameters,
        alphas,
        gate_challenges,
        libra_challenge,
        sumcheck_u_challenges,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
        public_inputs_delta,
    }
}

/// Utility for splitting a given challenge into two "halves": one containing its
/// 128 lower significance bits and one containing its higher significance bits.
/// The two "halves" are interpreted and returned as `Fr`.
fn split_challenge(challenge: Fr) -> (Fr, Fr) {
    let limbs = challenge.into_bigint().0;
    // compose lower 128 bits as an `Fr`
    let lower = Fr::from((limbs[1] as u128) << 64 | (limbs[0] as u128));
    // compose upper 128 bits as an `Fr`
    let upper = Fr::from((limbs[3] as u128) << 64 | (limbs[2] as u128));
    (lower, upper)
}

fn generate_relation_parameters_challenges(
    proof: &ZKProof,
    public_inputs: &Pubs,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> (RelationParametersChallenges, Fr) {
    // internal pure returns (Honk.RelationParameters memory rp, Fr nextPreviousChallenge)
    // Round 0
    let [eta, eta_two, eta_three, previous_challenge] = generate_eta_challenge(
        proof,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );

    // Round 1
    let [beta, gamma, next_previous_challenge] =
        generate_beta_and_gamma_challenges(previous_challenge, proof);

    (
        RelationParametersChallenges::new(eta, eta_two, eta_three, beta, gamma),
        next_previous_challenge,
    )
}

fn generate_eta_challenge(
    proof: &ZKProof,
    public_inputs: &Pubs,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> [Fr; 4] {
    let mut round0 = Keccak256::new()
        .chain_update(circuit_size.into_be_bytes32())
        .chain_update(public_inputs_size.into_be_bytes32())
        .chain_update(pub_inputs_offset.into_be_bytes32());

    for pi in public_inputs {
        round0 = round0.chain_update(*pi);
    }

    // Create the first challenge
    // Note: w4 is added to the challenge later on
    let hash: [u8; 32] = round0
        .chain_update(proof.w1.x_0.into_be_bytes32())
        .chain_update(proof.w1.x_1.into_be_bytes32())
        .chain_update(proof.w1.y_0.into_be_bytes32())
        .chain_update(proof.w1.y_1.into_be_bytes32())
        .chain_update(proof.w2.x_0.into_be_bytes32())
        .chain_update(proof.w2.x_1.into_be_bytes32())
        .chain_update(proof.w2.y_0.into_be_bytes32())
        .chain_update(proof.w2.y_1.into_be_bytes32())
        .chain_update(proof.w3.x_0.into_be_bytes32())
        .chain_update(proof.w3.x_1.into_be_bytes32())
        .chain_update(proof.w3.y_0.into_be_bytes32())
        .chain_update(proof.w3.y_1.into_be_bytes32())
        .finalize()
        .into();

    let mut previous_challenge = Fr::from_be_bytes_mod_order(&hash); // keccak256(abi.encodePacked(round0))
    let (eta, eta_two) = split_challenge(previous_challenge);

    let hash: [u8; 32] = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .finalize()
        .into();
    previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (eta_three, _) = split_challenge(previous_challenge);

    [eta, eta_two, eta_three, previous_challenge]
}

fn generate_beta_and_gamma_challenges(previous_challenge: Fr, proof: &ZKProof) -> [Fr; 3] {
    let round1: [u8; 32] = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(proof.lookup_read_counts.x_0.into_be_bytes32())
        .chain_update(proof.lookup_read_counts.x_1.into_be_bytes32())
        .chain_update(proof.lookup_read_counts.y_0.into_be_bytes32())
        .chain_update(proof.lookup_read_counts.y_1.into_be_bytes32())
        .chain_update(proof.lookup_read_tags.x_0.into_be_bytes32())
        .chain_update(proof.lookup_read_tags.x_1.into_be_bytes32())
        .chain_update(proof.lookup_read_tags.y_0.into_be_bytes32())
        .chain_update(proof.lookup_read_tags.y_1.into_be_bytes32())
        .chain_update(proof.w4.x_0.into_be_bytes32())
        .chain_update(proof.w4.x_1.into_be_bytes32())
        .chain_update(proof.w4.y_0.into_be_bytes32())
        .chain_update(proof.w4.y_1.into_be_bytes32())
        .finalize()
        .into();

    // bytes32[13] memory round1;
    // round1[0] = FrLib.toBytes32(previousChallenge);
    // round1[1] = bytes32(proof.lookupReadCounts.x_0);
    // round1[2] = bytes32(proof.lookupReadCounts.x_1);
    // round1[3] = bytes32(proof.lookupReadCounts.y_0);
    // round1[4] = bytes32(proof.lookupReadCounts.y_1);
    // round1[5] = bytes32(proof.lookupReadTags.x_0);
    // round1[6] = bytes32(proof.lookupReadTags.x_1);
    // round1[7] = bytes32(proof.lookupReadTags.y_0);
    // round1[8] = bytes32(proof.lookupReadTags.y_1);
    // round1[9] = bytes32(proof.w4.x_0);
    // round1[10] = bytes32(proof.w4.x_1);
    // round1[11] = bytes32(proof.w4.y_0);
    // round1[12] = bytes32(proof.w4.y_1);

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&round1);
    let (beta, gamma) = split_challenge(next_previous_challenge);

    [beta, gamma, next_previous_challenge]
}

// Alpha challenges non-linearise the gate contributions
fn generate_alpha_challenges(
    previous_challenge: Fr,
    proof: &ZKProof,
) -> ([Fr; NUMBER_OF_ALPHAS], Fr) {
    //     returns (Fr[NUMBER_OF_ALPHAS] memory alphas, Fr nextPreviousChallenge)
    let mut alphas = [Fr::ZERO; NUMBER_OF_ALPHAS];
    // let mut next_previous_challenge: Fr;

    // Generate the original sumcheck alpha 0 by hashing zPerm and zLookup
    let alpha0: [u8; 32] = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(proof.lookup_inverses.x_0.into_be_bytes32())
        .chain_update(proof.lookup_inverses.x_1.into_be_bytes32())
        .chain_update(proof.lookup_inverses.y_0.into_be_bytes32())
        .chain_update(proof.lookup_inverses.y_1.into_be_bytes32())
        .chain_update(proof.z_perm.x_0.into_be_bytes32())
        .chain_update(proof.z_perm.x_1.into_be_bytes32())
        .chain_update(proof.z_perm.y_0.into_be_bytes32())
        .chain_update(proof.z_perm.y_1.into_be_bytes32())
        .finalize()
        .into();

    // alpha0[0] = Fr.unwrap(previousChallenge);
    // alpha0[1] = proof.lookupInverses.x_0;
    // alpha0[2] = proof.lookupInverses.x_1;
    // alpha0[3] = proof.lookupInverses.y_0;
    // alpha0[4] = proof.lookupInverses.y_1;
    // alpha0[5] = proof.zPerm.x_0;
    // alpha0[6] = proof.zPerm.x_1;
    // alpha0[7] = proof.zPerm.y_0;
    // alpha0[8] = proof.zPerm.y_1;

    let mut next_previous_challenge = Fr::from_be_bytes_mod_order(&alpha0);
    (alphas[0], alphas[1]) = split_challenge(next_previous_challenge);

    for i in 1..(NUMBER_OF_ALPHAS / 2) {
        let hash: [u8; 32] = Keccak256::new()
            .chain_update(next_previous_challenge.into_be_bytes32())
            .finalize()
            .into();
        next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
        // FrLib.fromBytes32(keccak256(
        //     abi.encodePacked(Fr.unwrap(next_previous_challenge)),
        // ));
        (alphas[2 * i], alphas[2 * i + 1]) = split_challenge(next_previous_challenge);
    }

    if ((NUMBER_OF_ALPHAS & 1) == 1) && NUMBER_OF_ALPHAS > 2 {
        let hash: [u8; 32] = Keccak256::new()
            .chain_update(next_previous_challenge.into_be_bytes32())
            .finalize()
            .into();
        next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);

        (alphas[NUMBER_OF_ALPHAS - 1], _) = split_challenge(next_previous_challenge);

        // nextPreviousChallenge = FrLib.fromBytes32(keccak256(
        //     abi.encodePacked(Fr.unwrap(next_previous_challenge)),
        // ));
        // (alphas[NUMBER_OF_ALPHAS - 1], _) = split_challenge(next_previous_challenge);
    }

    (alphas, next_previous_challenge)
}

fn generate_gate_challenges(previous_challenge: Fr) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut gate_challenges = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N];
    let mut previous_challenge = previous_challenge;

    for i in 0..CONST_PROOF_SIZE_LOG_N {
        let hash: [u8; 32] = Keccak256::new()
            .chain_update(previous_challenge.into_be_bytes32())
            .finalize()
            .into();
        previous_challenge = Fr::from_be_bytes_mod_order(&hash);

        (gate_challenges[i], _) = split_challenge(previous_challenge);
    }
    let next_previous_challenge = previous_challenge;

    (gate_challenges, next_previous_challenge)
}

fn generate_libra_challenge(previous_challenge: Fr, proof: &ZKProof) -> (Fr, Fr) {
    // 4 commitments, 1 sum, 1 challenge

    // uint256[6] memory challengeData;
    // challengeData[0] = Fr.unwrap(previousChallenge);
    // challengeData[1] = proof.libraCommitments[0].x_0;
    // challengeData[2] = proof.libraCommitments[0].x_1;
    // challengeData[3] = proof.libraCommitments[0].y_0;
    // challengeData[4] = proof.libraCommitments[0].y_1;
    // challengeData[5] = Fr.unwrap(proof.libraSum);

    let hash: [u8; 32] = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(proof.libra_commitments[0].x_0.into_be_bytes32())
        .chain_update(proof.libra_commitments[0].x_1.into_be_bytes32())
        .chain_update(proof.libra_commitments[0].y_0.into_be_bytes32())
        .chain_update(proof.libra_commitments[0].y_1.into_be_bytes32())
        .chain_update(proof.libra_sum.into_be_bytes32())
        .finalize()
        .into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (libra_challenge, _) = split_challenge(next_previous_challenge);

    (libra_challenge, next_previous_challenge)
}

fn generate_sumcheck_challenges(
    proof: &ZKProof,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut sumcheck_challenges = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N];
    let mut previous_challenge = previous_challenge;

    // for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N; i++) {
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        // Fr[ZK_BATCHED_RELATION_PARTIAL_LENGTH + 1] memory univariateChal;
        // let mut univariate_chal = [Fr::ZERO; ZK_BATCHED_RELATION_PARTIAL_LENGTH + 1];
        let mut hasher = Keccak256::new();

        // univariate_chal[0] = previous_challenge;
        hasher = hasher.chain_update(previous_challenge.into_be_bytes32());

        // TODO(https://github.com/AztecProtocol/barretenberg/issues/1098): memcpy
        for j in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
            // (uint256 j = 0; j < ZK_BATCHED_RELATION_PARTIAL_LENGTH; j++) {
            // univariate_chal[j + 1] = proof.sumcheck_univariates[i][j];
            hasher = hasher.chain_update(proof.sumcheck_univariates[i][j].into_be_bytes32());
        }
        let hash: [u8; 32] = hasher.finalize().into();
        previous_challenge = Fr::from_be_bytes_mod_order(&hash);

        (sumcheck_challenges[i], _) = split_challenge(previous_challenge);
    }
    let next_previous_challenge = previous_challenge;

    (sumcheck_challenges, next_previous_challenge)
}

// We add Libra claimed eval + 3 commitments + 1 more eval
fn generate_rho_challenge(proof: &ZKProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut hasher = Keccak256::new();

    // uint256[NUMBER_OF_ENTITIES + 15] memory rhoChallengeElements;
    // rhoChallengeElements[0] = Fr.unwrap(prevChallenge);
    hasher.update(previous_challenge.into_be_bytes32());

    // TODO(https://github.com/AztecProtocol/barretenberg/issues/1098): memcpy
    // uint256 i;
    // for (i = 1; i <= NUMBER_OF_ENTITIES; i++) {
    //     rhoChallengeElements[i] = Fr.unwrap(proof.sumcheckEvaluations[i - 1]);
    // }
    for i in 0..NUMBER_OF_ENTITIES {
        hasher.update(proof.sumcheck_evaluations[i].into_be_bytes32());
    }

    hasher.update(proof.libra_evaluation.into_be_bytes32());
    // rhoChallengeElements[i] = Fr.unwrap(proof.libraEvaluation);

    hasher.update(proof.libra_commitments[1].x_0.into_be_bytes32());
    hasher.update(proof.libra_commitments[1].x_1.into_be_bytes32());
    hasher.update(proof.libra_commitments[1].y_0.into_be_bytes32());
    hasher.update(proof.libra_commitments[1].y_1.into_be_bytes32());
    // i += 1;
    // rhoChallengeElements[i] = proof.libraCommitments[1].x_0;
    // rhoChallengeElements[i + 1] = proof.libraCommitments[1].x_1;
    // rhoChallengeElements[i + 2] = proof.libraCommitments[1].y_0;
    // rhoChallengeElements[i + 3] = proof.libraCommitments[1].y_1;

    hasher.update(proof.libra_commitments[2].x_0.into_be_bytes32());
    hasher.update(proof.libra_commitments[2].x_1.into_be_bytes32());
    hasher.update(proof.libra_commitments[2].y_0.into_be_bytes32());
    hasher.update(proof.libra_commitments[2].y_1.into_be_bytes32());
    // i += 4;
    // rhoChallengeElements[i] = proof.libraCommitments[2].x_0;
    // rhoChallengeElements[i + 1] = proof.libraCommitments[2].x_1;
    // rhoChallengeElements[i + 2] = proof.libraCommitments[2].y_0;
    // rhoChallengeElements[i + 3] = proof.libraCommitments[2].y_1;

    hasher.update(proof.gemini_masking_poly.x_0.into_be_bytes32());
    hasher.update(proof.gemini_masking_poly.x_1.into_be_bytes32());
    hasher.update(proof.gemini_masking_poly.y_0.into_be_bytes32());
    hasher.update(proof.gemini_masking_poly.y_1.into_be_bytes32());
    // i += 4;
    // rhoChallengeElements[i] = proof.geminiMaskingPoly.x_0;
    // rhoChallengeElements[i + 1] = proof.geminiMaskingPoly.x_1;
    // rhoChallengeElements[i + 2] = proof.geminiMaskingPoly.y_0;
    // rhoChallengeElements[i + 3] = proof.geminiMaskingPoly.y_1;

    hasher.update(proof.gemini_masking_eval.into_be_bytes32());
    // i += 4;
    // rhoChallengeElements[i] = Fr.unwrap(proof.geminiMaskingEval);

    let hash: [u8; 32] = hasher.finalize().into();
    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (rho, _) = split_challenge(next_previous_challenge);

    (rho, next_previous_challenge)
}

fn generate_gemini_r_challenge(proof: &ZKProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut hasher = Keccak256::new();
    // uint256[(CONST_PROOF_SIZE_LOG_N - 1) * 4 + 1] memory gR;

    hasher.update(previous_challenge.into_be_bytes32());
    // gR[0] = Fr.unwrap(prevChallenge);

    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        hasher.update(proof.gemini_fold_comms[i].x_0.into_be_bytes32());
        hasher.update(proof.gemini_fold_comms[i].x_1.into_be_bytes32());
        hasher.update(proof.gemini_fold_comms[i].y_0.into_be_bytes32());
        hasher.update(proof.gemini_fold_comms[i].y_1.into_be_bytes32());
    }
    // for (uint256 i = 0; i < CONST_PROOF_SIZE_LOG_N - 1; i++) {
    //     gR[1 + i * 4] = proof.geminiFoldComms[i].x_0;
    //     gR[2 + i * 4] = proof.geminiFoldComms[i].x_1;
    //     gR[3 + i * 4] = proof.geminiFoldComms[i].y_0;
    //     gR[4 + i * 4] = proof.geminiFoldComms[i].y_1;
    // }

    let hash: [u8; 32] = hasher.finalize().into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);

    let (gemini_r, _) = split_challenge(next_previous_challenge);

    (gemini_r, next_previous_challenge)
}

fn generate_shplonk_nu_challenge(proof: &ZKProof, prev_challenge: Fr) -> (Fr, Fr) {
    // uint256[(CONST_PROOF_SIZE_LOG_N) + 1 + 4] memory shplonkNuChallengeElements;
    let mut hasher = Keccak256::new();

    hasher.update(prev_challenge.into_be_bytes32());
    // shplonkNuChallengeElements[0] = Fr.unwrap(prevChallenge);

    // for (uint256 i = 1; i <= CONST_PROOF_SIZE_LOG_N; i++) {
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        hasher.update(proof.gemini_a_evaluations[i].into_be_bytes32());
        // shplonkNuChallengeElements[i] = Fr.unwrap(proof.geminiAEvaluations[i - 1]);
    }

    for lpe in proof.libra_poly_evals {
        hasher.update(lpe.into_be_bytes32());
    }

    // uint256 libraIdx = 0;
    // for (uint256 i = CONST_PROOF_SIZE_LOG_N + 1; i <= CONST_PROOF_SIZE_LOG_N + 4; i++) {
    //     shplonkNuChallengeElements[i] = Fr.unwrap(proof.libraPolyEvals[libraIdx]);
    //     libraIdx++;
    // }

    let hash: [u8; 32] = hasher.finalize().into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (shplonk_nu, _) = split_challenge(next_previous_challenge);

    (shplonk_nu, next_previous_challenge)
}

fn generate_shplonk_z_challenge(proof: &ZKProof, previous_challenge: Fr) -> (Fr, Fr) {
    // uint256[5] memory shplonkZChallengeElements;

    let hash: [u8; 32] = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(proof.shplonk_q.x_0.into_be_bytes32())
        .chain_update(proof.shplonk_q.x_1.into_be_bytes32())
        .chain_update(proof.shplonk_q.y_0.into_be_bytes32())
        .chain_update(proof.shplonk_q.y_1.into_be_bytes32())
        .finalize()
        .into();
    // shplonkZChallengeElements[0] = Fr.unwrap(prevChallenge);
    // shplonkZChallengeElements[1] = proof.shplonkQ.x_0;
    // shplonkZChallengeElements[2] = proof.shplonkQ.x_1;
    // shplonkZChallengeElements[3] = proof.shplonkQ.y_0;
    // shplonkZChallengeElements[4] = proof.shplonkQ.y_1;

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (shplonk_z, _) = split_challenge(next_previous_challenge);

    (shplonk_z, next_previous_challenge)
}
