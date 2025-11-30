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
        CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES, PAIRING_POINTS_SIZE,
        PERMUTATION_ARGUMENT_VALUE_SEPARATOR,
    },
    proof::{CommonProofData, ZKProof},
    utils::{to_hex_string, IntoBEBytes32},
    EVMWord, ParsedProof, Pubs,
};
use ark_bn254_ext::{CurveHooks, Fr};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub(crate) enum Transcript {
    ZK(ZKTranscript),
    Plain(PlainTranscript),
}

#[derive(Debug)]
pub(crate) struct PlainTranscript {
    // Oink
    pub(crate) relation_parameters_challenges: RelationParametersChallenges,
    pub(crate) alphas: [Fr; NUMBER_OF_ALPHAS],
    pub(crate) gate_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Sumcheck
    pub(crate) sumcheck_u_challenges: [Fr; CONST_PROOF_SIZE_LOG_N],
    // Shplemini
    pub(crate) rho: Fr,
    pub(crate) gemini_r: Fr,
    pub(crate) shplonk_nu: Fr,
    pub(crate) shplonk_z: Fr,
}

#[derive(Debug)]
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
}

pub(crate) trait CommonTranscriptData {
    // getters
    fn relation_parameters_challenges(&self) -> &RelationParametersChallenges;
    fn alphas(&self) -> &[Fr; NUMBER_OF_ALPHAS];
    fn gate_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N];
    fn sumcheck_u_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N];
    fn rho(&self) -> Fr;
    fn gemini_r(&self) -> Fr;
    fn shplonk_nu(&self) -> Fr;
    fn shplonk_z(&self) -> Fr;
}

impl CommonTranscriptData for PlainTranscript {
    fn relation_parameters_challenges(&self) -> &RelationParametersChallenges {
        &self.relation_parameters_challenges
    }

    fn alphas(&self) -> &[Fr; NUMBER_OF_ALPHAS] {
        &self.alphas
    }

    fn gate_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.gate_challenges
    }

    fn sumcheck_u_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.sumcheck_u_challenges
    }

    fn rho(&self) -> Fr {
        self.rho
    }

    fn gemini_r(&self) -> Fr {
        self.gemini_r
    }

    fn shplonk_nu(&self) -> Fr {
        self.shplonk_nu
    }

    fn shplonk_z(&self) -> Fr {
        self.shplonk_z
    }
}

impl CommonTranscriptData for ZKTranscript {
    fn relation_parameters_challenges(&self) -> &RelationParametersChallenges {
        &self.relation_parameters_challenges
    }

    fn alphas(&self) -> &[Fr; NUMBER_OF_ALPHAS] {
        &self.alphas
    }

    fn gate_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.gate_challenges
    }

    fn sumcheck_u_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        &self.sumcheck_u_challenges
    }

    fn rho(&self) -> Fr {
        self.rho
    }

    fn gemini_r(&self) -> Fr {
        self.gemini_r
    }

    fn shplonk_nu(&self) -> Fr {
        self.shplonk_nu
    }

    fn shplonk_z(&self) -> Fr {
        self.shplonk_z
    }
}

impl CommonTranscriptData for Transcript {
    fn relation_parameters_challenges(&self) -> &RelationParametersChallenges {
        match self {
            Transcript::ZK(zkt) => zkt.relation_parameters_challenges(),
            Transcript::Plain(pt) => pt.relation_parameters_challenges(),
        }
    }

    fn alphas(&self) -> &[Fr; NUMBER_OF_ALPHAS] {
        match self {
            Transcript::ZK(zkt) => zkt.alphas(),
            Transcript::Plain(pt) => pt.alphas(),
        }
    }

    fn gate_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        match self {
            Transcript::ZK(zkt) => zkt.gate_challenges(),
            Transcript::Plain(pt) => pt.gate_challenges(),
        }
    }

    fn sumcheck_u_challenges(&self) -> &[Fr; CONST_PROOF_SIZE_LOG_N] {
        match self {
            Transcript::ZK(zkt) => zkt.sumcheck_u_challenges(),
            Transcript::Plain(pt) => pt.sumcheck_u_challenges(),
        }
    }

    fn rho(&self) -> Fr {
        match self {
            Transcript::ZK(zkt) => zkt.rho(),
            Transcript::Plain(pt) => pt.rho(),
        }
    }

    fn gemini_r(&self) -> Fr {
        match self {
            Transcript::ZK(zkt) => zkt.gemini_r(),
            Transcript::Plain(pt) => pt.gemini_r(),
        }
    }

    fn shplonk_nu(&self) -> Fr {
        match self {
            Transcript::ZK(zkt) => zkt.shplonk_nu(),
            Transcript::Plain(pt) => pt.shplonk_nu(),
        }
    }

    fn shplonk_z(&self) -> Fr {
        match self {
            Transcript::ZK(zkt) => zkt.shplonk_z(),
            Transcript::Plain(pt) => pt.shplonk_z(),
        }
    }
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

    pub(crate) fn compute_public_input_delta(
        &self,
        public_inputs: &Pubs,
        pairing_point_object: &[EVMWord; PAIRING_POINTS_SIZE],
        offset: u64,
    ) -> Fr {
        let mut numerator = Fr::ONE;
        let mut denominator = Fr::ONE;

        let mut numerator_acc =
            self.gamma + (self.beta * Fr::from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR + offset));
        let mut denominator_acc = self.gamma - self.beta * Fr::from(offset + 1);

        for word in public_inputs.iter().chain(pairing_point_object) {
            let elem = Fr::from_be_bytes_mod_order(word);

            numerator *= numerator_acc + elem;
            denominator *= denominator_acc + elem;

            numerator_acc += self.beta;
            denominator_acc -= self.beta;
        }

        numerator / denominator
    }
}

pub(crate) fn generate_transcript<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    public_inputs: &Pubs,
    vk_hash: &EVMWord,
    log_n: u64,
) -> Transcript {
    let (rp_challenges, previous_challenge) =
        generate_relation_parameters_challenges::<H>(parsed_proof, public_inputs, vk_hash);
    let (alphas, previous_challenge) = generate_alpha_challenges(previous_challenge, parsed_proof);
    let (gate_challenges, mut previous_challenge) =
        generate_gate_challenges(previous_challenge, log_n);

    let mut libra_challenge = Fr::ZERO;
    if let ParsedProof::ZK(zk_proof) = parsed_proof {
        (libra_challenge, previous_challenge) =
            generate_libra_challenge(previous_challenge, zk_proof);
    }

    let (sumcheck_u_challenges, previous_challenge) =
        generate_sumcheck_challenges(parsed_proof, previous_challenge, log_n);
    let (rho, previous_challenge) = generate_rho_challenge(parsed_proof, previous_challenge);
    let (gemini_r, previous_challenge) =
        generate_gemini_r_challenge(parsed_proof, previous_challenge, log_n);
    let (shplonk_nu, previous_challenge) =
        generate_shplonk_nu_challenge(parsed_proof, previous_challenge, log_n);
    let (shplonk_z, _) = generate_shplonk_z_challenge(parsed_proof, previous_challenge);

    match parsed_proof {
        ParsedProof::ZK(_) => Transcript::ZK(ZKTranscript {
            relation_parameters_challenges: rp_challenges,
            alphas,
            gate_challenges,
            libra_challenge,
            sumcheck_u_challenges,
            rho,
            gemini_r,
            shplonk_nu,
            shplonk_z,
        }),
        ParsedProof::Plain(_) => Transcript::Plain(PlainTranscript {
            relation_parameters_challenges: rp_challenges,
            alphas,
            gate_challenges,
            sumcheck_u_challenges,
            rho,
            gemini_r,
            shplonk_nu,
            shplonk_z,
        }),
    }
}

/// Utility for splitting a given challenge into two "halves": one containing its
/// 128 lower significance bits and one containing its higher significance bits.
/// The two "halves" are interpreted and returned as `Fr`.
fn split_challenge(challenge: Fr) -> (Fr, Fr) {
    let limbs = challenge.into_bigint().0;
    // compose lower 128 bits as an `Fr`
    let lower = Fr::from(((limbs[1] as u128) << 64) | (limbs[0] as u128));
    // compose upper 128 bits as an `Fr`
    let upper = Fr::from(((limbs[3] as u128) << 64) | (limbs[2] as u128));
    (lower, upper)
}

fn generate_relation_parameters_challenges<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    public_inputs: &Pubs,
    vk_hash: &EVMWord,
) -> (RelationParametersChallenges, Fr) {
    // Round 0
    let [eta, eta_two, eta_three, previous_challenge] =
        generate_eta_challenge::<H>(parsed_proof, public_inputs, vk_hash);

    // Round 1
    let [beta, gamma, next_previous_challenge] =
        generate_beta_and_gamma_challenges(previous_challenge, parsed_proof);

    (
        RelationParametersChallenges::new(eta, eta_two, eta_three, beta, gamma),
        next_previous_challenge,
    )
}

fn generate_eta_challenge<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    public_inputs: &Pubs,
    vk_hash: &EVMWord,
) -> [Fr; 4] {
    let mut round0 = Keccak256::new().chain_update(vk_hash);

    for word in public_inputs
        .iter()
        .chain(parsed_proof.pairing_point_object())
    {
        round0 = round0.chain_update(word);
    }

    // Create the first challenge
    // Note: w4 is added to the challenge later on
    let hash: EVMWord = round0
        .chain_update(
            parsed_proof
                .w1()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w1()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w2()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w2()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w3()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w3()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .finalize()
        .into();

    let mut previous_challenge = Fr::from_be_bytes_mod_order(&hash);

    let (eta, eta_two) = split_challenge(previous_challenge);

    let hash: EVMWord = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .finalize()
        .into();
    previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (eta_three, _) = split_challenge(previous_challenge);

    [eta, eta_two, eta_three, previous_challenge]
}

fn generate_beta_and_gamma_challenges<H: CurveHooks>(
    previous_challenge: Fr,
    parsed_proof: &ParsedProof<H>,
) -> [Fr; 3] {
    let round1: EVMWord = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(
            parsed_proof
                .lookup_read_counts()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .lookup_read_counts()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .lookup_read_tags()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .lookup_read_tags()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w4()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .w4()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .finalize()
        .into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&round1);
    let (beta, gamma) = split_challenge(next_previous_challenge);

    [beta, gamma, next_previous_challenge]
}

// Alpha challenges non-linearise the gate contributions
fn generate_alpha_challenges<H: CurveHooks>(
    previous_challenge: Fr,
    parsed_proof: &ParsedProof<H>,
) -> ([Fr; NUMBER_OF_ALPHAS], Fr) {
    let mut alphas = [Fr::ZERO; NUMBER_OF_ALPHAS];

    // Generate the original sumcheck alpha 0 by hashing zPerm and zLookup
    let alpha0: EVMWord = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(
            parsed_proof
                .lookup_inverses()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .lookup_inverses()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .z_perm()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .z_perm()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .finalize()
        .into();

    let mut next_previous_challenge = Fr::from_be_bytes_mod_order(&alpha0);
    (alphas[0], alphas[1]) = split_challenge(next_previous_challenge);

    for i in 1..(NUMBER_OF_ALPHAS / 2) {
        let hash: EVMWord = Keccak256::new()
            .chain_update(next_previous_challenge.into_be_bytes32())
            .finalize()
            .into();
        next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
        (alphas[2 * i], alphas[2 * i + 1]) = split_challenge(next_previous_challenge);
    }

    // If NUMBER_OF_ALPHAS is an odd number > 2, squeeze one more alpha challenge
    if ((NUMBER_OF_ALPHAS & 1) == 1) && NUMBER_OF_ALPHAS > 2 {
        let hash: EVMWord = Keccak256::new()
            .chain_update(next_previous_challenge.into_be_bytes32())
            .finalize()
            .into();
        next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);

        (alphas[NUMBER_OF_ALPHAS - 1], _) = split_challenge(next_previous_challenge);
    }

    (alphas, next_previous_challenge)
}

fn generate_gate_challenges(
    previous_challenge: Fr,
    log_n: u64,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut gate_challenges = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N];
    let hash: EVMWord = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .finalize()
        .into();
    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);

    (gate_challenges[0], _) = split_challenge(next_previous_challenge);

    for i in 1..log_n as usize {
        gate_challenges[i] = gate_challenges[i - 1].square();
    }

    (gate_challenges, next_previous_challenge)
}

// Function exclusive to `ZKProof`.
fn generate_libra_challenge<H: CurveHooks>(
    previous_challenge: Fr,
    zk_proof: &ZKProof<H>,
) -> (Fr, Fr) {
    let hash: EVMWord = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(
            zk_proof.libra_commitments[0]
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            zk_proof.libra_commitments[0]
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(zk_proof.libra_sum.into_be_bytes32())
        .finalize()
        .into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (libra_challenge, _) = split_challenge(next_previous_challenge);

    (libra_challenge, next_previous_challenge)
}

fn generate_sumcheck_challenges<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    previous_challenge: Fr,
    log_n: u64,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut sumcheck_challenges = [Fr::ZERO; CONST_PROOF_SIZE_LOG_N];
    let mut previous_challenge = previous_challenge;

    for (i, sumcheck_univariate) in parsed_proof
        .sumcheck_univariates()
        .enumerate()
        .take(log_n as usize)
    {
        let mut hasher = Keccak256::new();

        hasher = hasher.chain_update(previous_challenge.into_be_bytes32());

        for su in sumcheck_univariate.iter() {
            hasher = hasher.chain_update(su.into_be_bytes32());
        }
        let hash: EVMWord = hasher.finalize().into();
        previous_challenge = Fr::from_be_bytes_mod_order(&hash);

        (sumcheck_challenges[i], _) = split_challenge(previous_challenge);
    }
    let next_previous_challenge = previous_challenge;

    (sumcheck_challenges, next_previous_challenge)
}

// For ZKProofs, we add Libra claimed eval + 3 commitments + 1 more eval
fn generate_rho_challenge<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    previous_challenge: Fr,
) -> (Fr, Fr) {
    let mut hasher = Keccak256::new();

    hasher.update(previous_challenge.into_be_bytes32());

    for i in 0..NUMBER_OF_ENTITIES {
        hasher.update(parsed_proof.sumcheck_evaluations()[i].into_be_bytes32());
    }

    // ZKProof only
    if let ParsedProof::ZK(zk_proof) = parsed_proof {
        hasher.update(zk_proof.libra_evaluation.into_be_bytes32());

        hasher.update(
            zk_proof.libra_commitments[1]
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );
        hasher.update(
            zk_proof.libra_commitments[1]
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );

        hasher.update(
            zk_proof.libra_commitments[2]
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );
        hasher.update(
            zk_proof.libra_commitments[2]
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );

        hasher.update(
            zk_proof
                .gemini_masking_poly
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );
        hasher.update(
            zk_proof
                .gemini_masking_poly
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );

        hasher.update(zk_proof.gemini_masking_eval.into_be_bytes32());
    }

    let hash: EVMWord = hasher.finalize().into();
    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (rho, _) = split_challenge(next_previous_challenge);

    (rho, next_previous_challenge)
}

fn generate_gemini_r_challenge<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    previous_challenge: Fr,
    log_n: u64,
) -> (Fr, Fr) {
    let mut hasher = Keccak256::new();

    hasher.update(previous_challenge.into_be_bytes32());

    for i in 0..(log_n as usize - 1) {
        hasher.update(
            parsed_proof.gemini_fold_comms()[i]
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );
        hasher.update(
            parsed_proof.gemini_fold_comms()[i]
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        );
    }

    let hash: EVMWord = hasher.finalize().into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);

    let (gemini_r, _) = split_challenge(next_previous_challenge);

    (gemini_r, next_previous_challenge)
}

fn generate_shplonk_nu_challenge<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    prev_challenge: Fr,
    log_n: u64,
) -> (Fr, Fr) {
    let mut hasher = Keccak256::new();

    hasher.update(prev_challenge.into_be_bytes32());

    for i in 0..log_n as usize {
        hasher.update(parsed_proof.gemini_a_evaluations()[i].into_be_bytes32());
    }

    // ZProof only
    if let ParsedProof::ZK(zk_proof) = parsed_proof {
        for lpe in zk_proof.libra_poly_evals {
            hasher.update(lpe.into_be_bytes32());
        }
    }

    let hash: EVMWord = hasher.finalize().into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (shplonk_nu, _) = split_challenge(next_previous_challenge);

    (shplonk_nu, next_previous_challenge)
}

fn generate_shplonk_z_challenge<H: CurveHooks>(
    parsed_proof: &ParsedProof<H>,
    previous_challenge: Fr,
) -> (Fr, Fr) {
    let hash: EVMWord = Keccak256::new()
        .chain_update(previous_challenge.into_be_bytes32())
        .chain_update(
            parsed_proof
                .shplonk_q()
                .x()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .chain_update(
            parsed_proof
                .shplonk_q()
                .y()
                .expect("Coordinate should be set")
                .into_be_bytes32(),
        )
        .finalize()
        .into();

    let next_previous_challenge = Fr::from_be_bytes_mod_order(&hash);
    let (shplonk_z, _) = split_challenge(next_previous_challenge);

    (shplonk_z, next_previous_challenge)
}
