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

#![allow(non_camel_case_types)]

use crate::{
    constants::CONST_PROOF_SIZE_LOG_N,
    errors::ConversionError,
    utils::{
        read_g1_by_splitting, read_u64_from_evm_word, read_u64_from_evm_word_by_splitting,
        IntoBEBytes32,
    },
    EVMWord, G1, U256, VK_SIZE,
};
use ark_bn254_ext::CurveHooks;
use core::fmt;
use sha3::{digest::Update, Digest, Keccak256};
use snafu::Snafu;

#[derive(Debug, PartialEq, Snafu)]
pub enum VerificationKeyError {
    #[snafu(display("Buffer too short"))]
    BufferTooShort,
    #[snafu(display("Invalid log circuit size. Must be a positive integer."))]
    InvalidLogCircuitSize,
    #[snafu(display("Invalid log circuit size. Must not exceed {CONST_PROOF_SIZE_LOG_N}."))]
    LogCircuitSizeTooBig,
    #[snafu(display("Group element conversion error: {conv_error}"))]
    GroupConversionError { conv_error: ConversionError },
    #[snafu(display("Parsing error"))]
    ParsingError,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum VkCommitmentField {
    Q_M,
    Q_C,
    Q_L,
    Q_R,
    Q_O,
    Q_4,
    Q_LOOKUP,
    Q_ARITH,
    Q_DELTARANGE,
    Q_ELLIPTIC,
    Q_MEMORY,
    Q_NNF,
    Q_POSEIDON2EXTERNAL,
    Q_POSEIDON2INTERNAL,
    S_1,
    S_2,
    S_3,
    S_4,
    ID_1,
    ID_2,
    ID_3,
    ID_4,
    T_1,
    T_2,
    T_3,
    T_4,
    Lagrange_First,
    Lagrange_Last,
}

impl fmt::Display for VkCommitmentField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VkCommitmentField::Q_M => write!(f, "Q_M"),
            VkCommitmentField::Q_C => write!(f, "Q_C"),
            VkCommitmentField::Q_L => write!(f, "Q_L"),
            VkCommitmentField::Q_R => write!(f, "Q_R"),
            VkCommitmentField::Q_O => write!(f, "Q_O"),
            VkCommitmentField::Q_4 => write!(f, "Q_4"),
            VkCommitmentField::Q_LOOKUP => write!(f, "Q_LOOKUP"),
            VkCommitmentField::Q_ARITH => write!(f, "Q_ARITH"),
            VkCommitmentField::Q_DELTARANGE => write!(f, "Q_DELTARANGE"),
            VkCommitmentField::Q_ELLIPTIC => write!(f, "Q_ELLIPTIC"),
            VkCommitmentField::Q_MEMORY => write!(f, "Q_MEMORY"),
            VkCommitmentField::Q_NNF => write!(f, "Q_NNF"),
            VkCommitmentField::Q_POSEIDON2EXTERNAL => write!(f, "Q_POSEIDON2EXTERNAL"),
            VkCommitmentField::Q_POSEIDON2INTERNAL => write!(f, "Q_POSEIDON2INTERNAL"),
            VkCommitmentField::S_1 => write!(f, "S_1"),
            VkCommitmentField::S_2 => write!(f, "S_2"),
            VkCommitmentField::S_3 => write!(f, "S_3"),
            VkCommitmentField::S_4 => write!(f, "S_4"),
            VkCommitmentField::ID_1 => write!(f, "ID_1"),
            VkCommitmentField::ID_2 => write!(f, "ID_2"),
            VkCommitmentField::ID_3 => write!(f, "ID_3"),
            VkCommitmentField::ID_4 => write!(f, "ID_4"),
            VkCommitmentField::T_1 => write!(f, "T_1"),
            VkCommitmentField::T_2 => write!(f, "T_2"),
            VkCommitmentField::T_3 => write!(f, "T_3"),
            VkCommitmentField::T_4 => write!(f, "T_4"),
            VkCommitmentField::Lagrange_First => write!(f, "Lagrange_First"),
            VkCommitmentField::Lagrange_Last => write!(f, "Lagrange_Last"),
        }
    }
}

impl VkCommitmentField {
    pub fn str(&self) -> &'static str {
        match self {
            VkCommitmentField::Q_M => "Q_M",
            VkCommitmentField::Q_C => "Q_C",
            VkCommitmentField::Q_L => "Q_L",
            VkCommitmentField::Q_R => "Q_R",
            VkCommitmentField::Q_O => "Q_O",
            VkCommitmentField::Q_4 => "Q_4",
            VkCommitmentField::Q_LOOKUP => "Q_LOOKUP",
            VkCommitmentField::Q_ARITH => "Q_ARITH",
            VkCommitmentField::Q_DELTARANGE => "Q_DELTARANGE",
            VkCommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC",
            VkCommitmentField::Q_MEMORY => "Q_MEMORY",
            VkCommitmentField::Q_NNF => "Q_NNF",
            VkCommitmentField::Q_POSEIDON2EXTERNAL => "Q_POSEIDON2EXTERNAL",
            VkCommitmentField::Q_POSEIDON2INTERNAL => "Q_POSEIDON2INTERNAL",
            VkCommitmentField::S_1 => "S_1",
            VkCommitmentField::S_2 => "S_2",
            VkCommitmentField::S_3 => "S_3",
            VkCommitmentField::S_4 => "S_4",
            VkCommitmentField::ID_1 => "ID_1",
            VkCommitmentField::ID_2 => "ID_2",
            VkCommitmentField::ID_3 => "ID_3",
            VkCommitmentField::ID_4 => "ID_4",
            VkCommitmentField::T_1 => "T_1",
            VkCommitmentField::T_2 => "T_2",
            VkCommitmentField::T_3 => "T_3",
            VkCommitmentField::T_4 => "T_4",
            VkCommitmentField::Lagrange_First => "Lagrange_First",
            VkCommitmentField::Lagrange_Last => "Lagrange_Last",
        }
    }
}

/// Number of commitments in a verification key.
pub(crate) const NUM_VK_COMMITMENTS: usize = 28;

/// The order in which bb v5.0.0 serializes (and hashes) the verification key commitments: its
/// `PrecomputedEntities` layout (`flavor/generated/ultra_flavor_generated.hpp`).
const VK_COMMITMENT_ORDER: [VkCommitmentField; NUM_VK_COMMITMENTS] = [
    VkCommitmentField::S_1,
    VkCommitmentField::S_2,
    VkCommitmentField::S_3,
    VkCommitmentField::S_4,
    VkCommitmentField::ID_1,
    VkCommitmentField::ID_2,
    VkCommitmentField::ID_3,
    VkCommitmentField::ID_4,
    VkCommitmentField::Lagrange_First,
    VkCommitmentField::Lagrange_Last,
    VkCommitmentField::Q_LOOKUP,
    VkCommitmentField::T_1,
    VkCommitmentField::T_2,
    VkCommitmentField::T_3,
    VkCommitmentField::T_4,
    VkCommitmentField::Q_M,
    VkCommitmentField::Q_R,
    VkCommitmentField::Q_O,
    VkCommitmentField::Q_C,
    VkCommitmentField::Q_L,
    VkCommitmentField::Q_4,
    VkCommitmentField::Q_ARITH,
    VkCommitmentField::Q_DELTARANGE,
    VkCommitmentField::Q_ELLIPTIC,
    VkCommitmentField::Q_MEMORY,
    VkCommitmentField::Q_NNF,
    VkCommitmentField::Q_POSEIDON2EXTERNAL,
    VkCommitmentField::Q_POSEIDON2INTERNAL,
];

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    // Misc Params
    pub log_circuit_size: u64,
    pub combined_input_size: u64, // Since bb 0.86.0, this is num_public_inputs + PAIRING_POINTS_SIZE
    pub pub_inputs_offset: u64,
    // Selectors
    pub q_m: G1<H>,
    pub q_c: G1<H>,
    pub q_l: G1<H>,
    pub q_r: G1<H>,
    pub q_o: G1<H>,
    pub q_4: G1<H>,
    pub q_lookup: G1<H>,     // Lookup
    pub q_arith: G1<H>,      // Arithmetic widget
    pub q_deltarange: G1<H>, // Delta Range sort
    pub q_elliptic: G1<H>,
    pub q_memory: G1<H>, // Memory
    pub q_nnf: G1<H>,    // Non-Native Field
    pub q_poseidon2external: G1<H>,
    pub q_poseidon2internal: G1<H>,
    // Copy Constraints
    pub s_1: G1<H>,
    pub s_2: G1<H>,
    pub s_3: G1<H>,
    pub s_4: G1<H>,
    // Copy Identity
    pub id_1: G1<H>,
    pub id_2: G1<H>,
    pub id_3: G1<H>,
    pub id_4: G1<H>,
    // Precomputed Lookup Table
    pub t_1: G1<H>,
    pub t_2: G1<H>,
    pub t_3: G1<H>,
    pub t_4: G1<H>,
    // Fixed first and last
    pub lagrange_first: G1<H>,
    pub lagrange_last: G1<H>,
}

impl<H: CurveHooks> VerificationKey<H> {
    // Only parses the log_circuit_size from the provided raw verification key without
    // doing any validation whatsoever on the rest of the verification key's fields.
    #[allow(unused)]
    pub fn extract_log_circuit_size(raw_vk: &[u8]) -> Result<u64, VerificationKeyError> {
        match read_u64_from_evm_word(raw_vk) {
            Ok(0) => Err(VerificationKeyError::InvalidLogCircuitSize)?,
            Ok(log_n) => Ok(log_n),
            _ => Err(VerificationKeyError::ParsingError)?,
        }
    }
}

impl<H: CurveHooks> TryFrom<&[u8]> for VerificationKey<H> {
    type Error = VerificationKeyError;

    fn try_from(mut raw_vk: &[u8]) -> Result<Self, Self::Error> {
        if raw_vk.len() < VK_SIZE {
            return Err(VerificationKeyError::BufferTooShort);
        }

        let log_circuit_size = match read_u64_from_evm_word_by_splitting(&mut raw_vk) {
            Ok(0) => Err(VerificationKeyError::InvalidLogCircuitSize)?,
            Ok(log_n) => log_n,
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        if log_circuit_size > CONST_PROOF_SIZE_LOG_N as u64 {
            return Err(VerificationKeyError::LogCircuitSizeTooBig);
        }

        let combined_input_size = match read_u64_from_evm_word_by_splitting(&mut raw_vk) {
            Ok(num_pubs) => num_pubs,
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        let pub_inputs_offset = match read_u64_from_evm_word_by_splitting(&mut raw_vk) {
            Ok(pi_offset) => pi_offset,
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        let mut commitments = [G1::<H>::default(); NUM_VK_COMMITMENTS];
        for (commitment, field) in commitments.iter_mut().zip(VK_COMMITMENT_ORDER) {
            *commitment = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
                VerificationKeyError::GroupConversionError {
                    conv_error: ConversionError {
                        group: e,
                        field: Some(field.into()),
                    },
                }
            })?;
        }
        // Destructured in `VK_COMMITMENT_ORDER`.
        let [s_1, s_2, s_3, s_4, id_1, id_2, id_3, id_4, lagrange_first, lagrange_last, q_lookup, t_1, t_2, t_3, t_4, q_m, q_r, q_o, q_c, q_l, q_4, q_arith, q_deltarange, q_elliptic, q_memory, q_nnf, q_poseidon2external, q_poseidon2internal] =
            commitments;

        Ok(Self {
            log_circuit_size,
            combined_input_size,
            pub_inputs_offset,
            q_m,
            q_c,
            q_l,
            q_r,
            q_o,
            q_4,
            q_lookup,
            q_arith,
            q_deltarange,
            q_elliptic,
            q_memory,
            q_nnf,
            q_poseidon2external,
            q_poseidon2internal,
            s_1,
            s_2,
            s_3,
            s_4,
            id_1,
            id_2,
            id_3,
            id_4,
            t_1,
            t_2,
            t_3,
            t_4,
            lagrange_first,
            lagrange_last,
        })
    }
}

impl<H: CurveHooks> VerificationKey<H> {
    /// The commitments in serialization order (`VK_COMMITMENT_ORDER`).
    pub(crate) fn commitments(&self) -> [&G1<H>; NUM_VK_COMMITMENTS] {
        [
            &self.s_1,
            &self.s_2,
            &self.s_3,
            &self.s_4,
            &self.id_1,
            &self.id_2,
            &self.id_3,
            &self.id_4,
            &self.lagrange_first,
            &self.lagrange_last,
            &self.q_lookup,
            &self.t_1,
            &self.t_2,
            &self.t_3,
            &self.t_4,
            &self.q_m,
            &self.q_r,
            &self.q_o,
            &self.q_c,
            &self.q_l,
            &self.q_4,
            &self.q_arith,
            &self.q_deltarange,
            &self.q_elliptic,
            &self.q_memory,
            &self.q_nnf,
            &self.q_poseidon2external,
            &self.q_poseidon2internal,
        ]
    }

    /// Computes the hash of the verification key using Keccak256, over the fields in
    /// serialization order (bb's `NativeVerificationKey_::to_field_elements`).
    pub fn compute_vk_hash(&self) -> EVMWord {
        let mut hasher = Keccak256::new()
            .chain(U256::from(self.log_circuit_size).into_be_bytes32())
            .chain(U256::from(self.combined_input_size).into_be_bytes32())
            .chain(U256::from(self.pub_inputs_offset).into_be_bytes32());
        for commitment in self.commitments() {
            hasher = hasher
                .chain(commitment.x.into_be_bytes32())
                .chain(commitment.y.into_be_bytes32());
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod should {
    use super::*;
    use crate::errors::GroupError;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_vk() -> [u8; VK_SIZE] {
        hex_literal::hex!(
            "
            000000000000000000000000000000000000000000000000000000000000000c
            0000000000000000000000000000000000000000000000000000000000000009
            0000000000000000000000000000000000000000000000000000000000000005
            0414711f1cb55d881e23e078ce820ce640bcfbfc4644eb7718a56535f9511fc4
            1d0bc1f88c9cb4ad37775ef5eea8aa0b9a32d1998fd2f86737597bbafb06161c
            15686104e91efc39e0f37272d54c3772fb171a24a687e96d263752570968033a
            0bbce21ca5b94c0925594e08f6b01e8c8412ebfe30e2c6b4047c0408761031cc
            0be06a73bbea0b41d22304f020bac4861d2ad3301d310510c761f434b525060a
            0d376870fa808ad56ea98166ad8baaab62e0ce668aff659a9341041864d6c307
            03ad000571c1b673d280328478635be79f12ac8b9954e5cabb7d350febe13143
            17f4042e114f2b6cc9057700fa2709145c78869fd45793d55a5ce11e5b402bbe
            297ead4ae40c447b2dfd806ea011bfcd3cb09ae9556a8ca71b44b31674f5ac8b
            00b5221fecb8f67f09106a8155b71b35d3968b15ac0b55f8bc6cec22c623d409
            160f5210d06caa11422cc6d9370f1dfe15b28456c7a863170ae0c89676565fc8
            1a93b2aead73beded273bdd7ce1918e0c0d7e87093247ce56e9857eacbe4d86a
            22d0904dbb053ab7d20ef438f8f05181247b28b5aa8ced9fe9e146543254a30f
            0a9b5901c901ad03416445384dc3b06bedbfd7baf379731ba48155394b8f8cc9
            12f1996d8e833b56aabff586aab06e4dbeac4eae9bba858a737f9d72ab9790f5
            26db9ef0b3e5a7b24569a264b52077cd7ad54481e664749d0f693fa55017e906
            2a56ce41f6b0be13b9c26747621b821eee81b23a887f299049b14c11e98460d6
            1aa98f2de3ddda547d8f6de4e725ded5827d6338c78656c0d12ca1aea6ef2c7c
            0e3269dce2a0d7d04509815f2936918597897bde9676b07c5964fab16041f771
            258f13a1982eac087393039c9b4194bc1731bfb5c642300bfcf6a10c90055b28
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            08ea0feb6baf144cb2844977cf618ac2d39ece0a0deb455a597c40db2e69ea3a
            2579e763559dc4218b0b169e0c60b80d5f035d1a8cccfff124f42d6714e6d2fd
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            08ea0feb6baf144cb2844977cf618ac2d39ece0a0deb455a597c40db2e69ea3a
            2579e763559dc4218b0b169e0c60b80d5f035d1a8cccfff124f42d6714e6d2fd
            2b69b9140825b800760ed06999df4fd873995457c9bb4e69f7ebb5ad5860eac9
            2cb789eee777ca9f4ab166b04535b6132196132403e5f82d81ca35ddc26a2029
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            254fcb7e9dd43e5265f3b34b0d696bb4df208618fdd7cc2e61cbbcb59bb999ad
            1a7a99d140c7416fddcdeea7b6b485a83c011060f607a6267a75d0004546732b
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            "
        )
    }

    #[rstest]
    fn parse_valid_vk(valid_vk: [u8; VK_SIZE]) {
        assert!(VerificationKey::<()>::try_from(&valid_vk[..]).is_ok());
    }

    #[rstest]
    fn extract_log_circuit_size_from_valid_vk(valid_vk: [u8; VK_SIZE]) {
        assert_eq!(
            VerificationKey::<()>::extract_log_circuit_size(&valid_vk[..]),
            Ok(0x0c)
        );
    }

    mod reject {
        use ark_bn254::Fr;
        use ark_ff::{Field, PrimeField};

        use crate::constants::{EVM_WORD_SIZE, GROUP_ELEMENT_SIZE};

        use super::*;

        #[rstest]
        fn a_vk_from_a_short_buffer(valid_vk: [u8; VK_SIZE]) {
            let invalid_vk = &valid_vk[..VK_SIZE - 1];
            assert_eq!(
                VerificationKey::<()>::try_from(&invalid_vk[..]),
                Err(VerificationKeyError::BufferTooShort)
            );
        }

        #[rstest]
        fn a_vk_with_log_circuit_size_zero(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[..EVM_WORD_SIZE].fill(0);
            assert_eq!(
                VerificationKey::<()>::try_from(&invalid_vk[..]),
                Err(VerificationKeyError::InvalidLogCircuitSize)
            );
        }

        #[rstest]
        fn a_vk_with_log_circuit_size_too_big(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            let invalid_bytes = U256::from(CONST_PROOF_SIZE_LOG_N as u64 + 1).into_be_bytes32();
            invalid_vk[0..EVM_WORD_SIZE].copy_from_slice(&invalid_bytes);
            assert_eq!(
                VerificationKey::<()>::try_from(&invalid_vk[..]),
                Err(VerificationKeyError::LogCircuitSizeTooBig)
            );
        }

        #[rstest]
        fn a_vk_with_insufficient_bytes_for_log_circuit_size(valid_vk: [u8; VK_SIZE]) {
            let invalid_vk = &valid_vk[..EVM_WORD_SIZE - 1];
            assert!(VerificationKey::<()>::extract_log_circuit_size(invalid_vk).is_err());
        }

        #[rstest]
        fn a_vk_where_extracted_log_circuit_size_is_zero(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[..EVM_WORD_SIZE].fill(0);
            assert!(VerificationKey::<()>::extract_log_circuit_size(&invalid_vk[..]).is_err());
        }

        #[rstest]
        fn a_vk_where_extracted_log_circuit_size_does_not_fit_in_an_u64(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            let invalid_bytes = (Fr::from_be_bytes_mod_order(&u64::MAX.into_be_bytes32())
                + Fr::ONE)
                .into_be_bytes32();
            invalid_vk[..EVM_WORD_SIZE].copy_from_slice(&invalid_bytes);
            assert!(VerificationKey::<()>::extract_log_circuit_size(&invalid_vk[..]).is_err());
        }

        #[rstest]
        fn a_vk_with_a_point_not_on_curve_for_any_commitment_field(valid_vk: [u8; VK_SIZE]) {
            const OFFSET: usize = 3 * EVM_WORD_SIZE;
            for (i, cm) in VK_COMMITMENT_ORDER.into_iter().enumerate() {
                let mut invalid_vk = [0u8; VK_SIZE];
                invalid_vk.copy_from_slice(&valid_vk);
                // Please note that (0, 0) is treated as the point at infinity
                invalid_vk[OFFSET + i * GROUP_ELEMENT_SIZE..OFFSET + (i + 1) * GROUP_ELEMENT_SIZE]
                    .fill(1);

                assert_eq!(
                    VerificationKey::<()>::try_from(&invalid_vk[..]).unwrap_err(),
                    VerificationKeyError::GroupConversionError {
                        conv_error: ConversionError {
                            group: GroupError::NotOnCurve,
                            field: Some(cm.into()),
                        }
                    }
                );
            }
        }
    }
}
