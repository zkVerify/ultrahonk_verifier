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
    utils::{read_g1_by_splitting, read_u64_from_evm_word, IntoBEBytes32},
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

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    // Misc Params
    pub log_circuit_size: u64,
    pub combined_input_size: u64, // Since bb 0.86.0, this is num_public_inputs + PAIRING_OBJECT_SIZE
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

impl<H: CurveHooks> TryFrom<&[u8]> for VerificationKey<H> {
    type Error = VerificationKeyError;

    fn try_from(mut raw_vk: &[u8]) -> Result<Self, Self::Error> {
        if raw_vk.len() < VK_SIZE {
            return Err(VerificationKeyError::BufferTooShort);
        }

        let log_circuit_size = match read_u64_from_evm_word(&mut raw_vk) {
            Ok(0) => Err(VerificationKeyError::InvalidLogCircuitSize)?,
            Ok(log_n) => log_n,
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        if log_circuit_size > CONST_PROOF_SIZE_LOG_N as u64 {
            return Err(VerificationKeyError::LogCircuitSizeTooBig);
        }

        let combined_input_size = match read_u64_from_evm_word(&mut raw_vk) {
            Ok(num_pubs) => num_pubs,
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        let pub_inputs_offset = match read_u64_from_evm_word(&mut raw_vk) {
            Ok(pi_offset) => pi_offset,
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        let q_m = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_M.into()),
                },
            }
        })?;
        let q_c = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_C.into()),
                },
            }
        })?;
        let q_l = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_L.into()),
                },
            }
        })?;
        let q_r = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_R.into()),
                },
            }
        })?;
        let q_o = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_O.into()),
                },
            }
        })?;
        let q_4 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_4.into()),
                },
            }
        })?;
        let q_lookup = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_LOOKUP.into()),
                },
            }
        })?;
        let q_arith = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_ARITH.into()),
                },
            }
        })?;
        let q_deltarange = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_DELTARANGE.into()),
                },
            }
        })?;
        let q_elliptic = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_ELLIPTIC.into()),
                },
            }
        })?;
        let q_memory = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_MEMORY.into()),
                },
            }
        })?;
        let q_nnf = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_NNF.into()),
                },
            }
        })?;
        let q_poseidon2external = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_POSEIDON2EXTERNAL.into()),
                },
            }
        })?;
        let q_poseidon2internal = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Q_POSEIDON2INTERNAL.into()),
                },
            }
        })?;
        let s_1 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::S_1.into()),
                },
            }
        })?;
        let s_2 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::S_2.into()),
                },
            }
        })?;
        let s_3 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::S_3.into()),
                },
            }
        })?;
        let s_4 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::S_4.into()),
                },
            }
        })?;
        let id_1 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::ID_1.into()),
                },
            }
        })?;
        let id_2 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::ID_2.into()),
                },
            }
        })?;
        let id_3 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::ID_3.into()),
                },
            }
        })?;
        let id_4 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::ID_4.into()),
                },
            }
        })?;
        let t_1 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::T_1.into()),
                },
            }
        })?;
        let t_2 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::T_2.into()),
                },
            }
        })?;
        let t_3 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::T_3.into()),
                },
            }
        })?;
        let t_4 = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::T_4.into()),
                },
            }
        })?;
        let lagrange_first = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Lagrange_First.into()),
                },
            }
        })?;
        let lagrange_last = read_g1_by_splitting::<H>(&mut raw_vk).map_err(|e| {
            VerificationKeyError::GroupConversionError {
                conv_error: ConversionError {
                    group: e,
                    field: Some(VkCommitmentField::Lagrange_Last.into()),
                },
            }
        })?;

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
    /// Computes the hash of the verification key using Keccak256.
    pub fn compute_vk_hash(&self) -> EVMWord {
        Keccak256::new()
            .chain(U256::from(self.log_circuit_size).into_be_bytes32())
            .chain(U256::from(self.combined_input_size).into_be_bytes32())
            .chain(U256::from(self.pub_inputs_offset).into_be_bytes32())
            .chain(self.q_m.x.into_be_bytes32())
            .chain(self.q_m.y.into_be_bytes32())
            .chain(self.q_c.x.into_be_bytes32())
            .chain(self.q_c.y.into_be_bytes32())
            .chain(self.q_l.x.into_be_bytes32())
            .chain(self.q_l.y.into_be_bytes32())
            .chain(self.q_r.x.into_be_bytes32())
            .chain(self.q_r.y.into_be_bytes32())
            .chain(self.q_o.x.into_be_bytes32())
            .chain(self.q_o.y.into_be_bytes32())
            .chain(self.q_4.x.into_be_bytes32())
            .chain(self.q_4.y.into_be_bytes32())
            .chain(self.q_lookup.x.into_be_bytes32())
            .chain(self.q_lookup.y.into_be_bytes32())
            .chain(self.q_arith.x.into_be_bytes32())
            .chain(self.q_arith.y.into_be_bytes32())
            .chain(self.q_deltarange.x.into_be_bytes32())
            .chain(self.q_deltarange.y.into_be_bytes32())
            .chain(self.q_elliptic.x.into_be_bytes32())
            .chain(self.q_elliptic.y.into_be_bytes32())
            .chain(self.q_memory.x.into_be_bytes32())
            .chain(self.q_memory.y.into_be_bytes32())
            .chain(self.q_nnf.x.into_be_bytes32())
            .chain(self.q_nnf.y.into_be_bytes32())
            .chain(self.q_poseidon2external.x.into_be_bytes32())
            .chain(self.q_poseidon2external.y.into_be_bytes32())
            .chain(self.q_poseidon2internal.x.into_be_bytes32())
            .chain(self.q_poseidon2internal.y.into_be_bytes32())
            .chain(self.s_1.x.into_be_bytes32())
            .chain(self.s_1.y.into_be_bytes32())
            .chain(self.s_2.x.into_be_bytes32())
            .chain(self.s_2.y.into_be_bytes32())
            .chain(self.s_3.x.into_be_bytes32())
            .chain(self.s_3.y.into_be_bytes32())
            .chain(self.s_4.x.into_be_bytes32())
            .chain(self.s_4.y.into_be_bytes32())
            .chain(self.id_1.x.into_be_bytes32())
            .chain(self.id_1.y.into_be_bytes32())
            .chain(self.id_2.x.into_be_bytes32())
            .chain(self.id_2.y.into_be_bytes32())
            .chain(self.id_3.x.into_be_bytes32())
            .chain(self.id_3.y.into_be_bytes32())
            .chain(self.id_4.x.into_be_bytes32())
            .chain(self.id_4.y.into_be_bytes32())
            .chain(self.t_1.x.into_be_bytes32())
            .chain(self.t_1.y.into_be_bytes32())
            .chain(self.t_2.x.into_be_bytes32())
            .chain(self.t_2.y.into_be_bytes32())
            .chain(self.t_3.x.into_be_bytes32())
            .chain(self.t_3.y.into_be_bytes32())
            .chain(self.t_4.x.into_be_bytes32())
            .chain(self.t_4.y.into_be_bytes32())
            .chain(self.lagrange_first.x.into_be_bytes32())
            .chain(self.lagrange_first.y.into_be_bytes32())
            .chain(self.lagrange_last.x.into_be_bytes32())
            .chain(self.lagrange_last.y.into_be_bytes32())
            .finalize()
            .into()
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
            0000000000000000000000000000000000000000000000000000000000000011
            0000000000000000000000000000000000000000000000000000000000000001
            142bd66bdb7a2bc125c78e040da5a5cbe6f296ee1a11b55dce82f38413640a64
            0d1415082e63c88eaa34836fe60428f70dee92853dc8a5d19d0bf85b0fa95ad4
            2deae537974aa5697c77ce4f20f0fd5a3a264861cd51216bd8c56683467cd704
            068627460599c3db714496966bf5f4374fb6087ba1179c7a8ed5c59a1015e784
            06681df238df2a0f864a67847d46222c9aee090f36d34df5c2aab80f85a218f2
            18e37167fd19d013b9c1b8da3c671ec025fe40eebc5d11d2d55e4ac8adccae27
            177c7a07701c29d13dc4669f3d97f847e96e4bcefe3f9cf39c6f73896b06e821
            2d31ea12ba12ee2338f1a638b192ffc9b995fd687c23cf6fe4a49a8e4f4c5aba
            2d623ef9f6f62903ac68b01fa7f3faaa5a881854d8b0a3fb6597416a145754e3
            20b75671e0dd20da52b442fa3ce1643a24c7ac8e6059e6db24a7e1bfc51be2ac
            07ea8dd8b4d3fd18e2edafe7a56dfd287d677b48528aeba6bdb01913c3236ff8
            2826602478d64dc4e23f777f35827a35ea2716bc853ad38b76968342e932d84b
            0c4032c3079594eb75a8449d3d5ce8bc3661650d53f9b24d923d8f404cb0bbc9
            1084d709650356d40f0158fd6da81f54eb5fe796a0ca89441369b7c24301f851
            3057f9cfd5edb0e7c2c72a3c00da41d4c7c7b6d01c518c7ea0b38257198a9523
            027eb0839ef4980d6a98575cedc65ee5700a7148f647b842154c13fa145167b7
            1775fbd3ba5e43163b9a8bc08ae2fdbd8e9dc005befcd8cd631818993e143702
            1d8011ee756abfa19e409fcb2e19a72238c07631bdde06678d3bce4455d2086f
            09c706e73a00d84450fb0eae1d72783faba96bc3990b1eaa86226b3574e5c43f
            276d401f1c0f9a2668fcae74683a84de1084739f9b1f547ec36638d7b5a1ecd9
            12b12523f7d04a83276f3537c64334419e05b13fc20dedd7ff81c5677d3286ce
            2e741be4fe42cc1155a526829445f3fda95e243c4e602d1c13a77a2472f082da
            16a1350662e14b4ce4e8e364439d0abba02dc62a5526834f93c6db848d56dcb0
            0563b1f480cad9069296d71489889503dda143f0b2e746ed0b6e85782c26040e
            20e1bb3056279dc342f6c756379f231d5f472088e4d88b5517e40b2a0133f401
            23ee36ecb11b62789eb4da763de77062d23ce01e2c8d1a5a6b3bd0ec93b42e77
            0d1611c856951969fdda50b3205d5aa4486b632519d18424d0e92f60a31671d9
            0ce97ee59d45d76230c0b534ea958de4c47e2f4c94aa3cadd7cd42e719521e0f
            154bdee4123a9946d2ae3eafb3800ee0eaf997cb1b074244b7337b923c097eaf
            0d5f22b8ade2c19f3c0953803a3a34d916eefb5bf34e2352250dd3fb63d6d8c6
            22d2dd0a34c3a1da7c62cc30718076db1836d9e1111168b4d7ab689558c334db
            262c701396f0e3ae243059518c261a4137e7f6a698a26842094b80c6e88321bf
            172f8c6455a2bfe284b08b441d010fc2976235c0e1213cb7ef934c944e4e8374
            178afa12bf161e7e640beab3f563e0a2402c116a960773bd1e8b46a6a182239d
            21f45516c16fcb3033204ad4109fa0fbb54c4fead14c60e677f8e1897f658057
            0a7a5c9f897fd8dab82792c925627d7348f0bf1152efc7a0ee6a29e06296bb4d
            1d1934c19b595461621962d025f0fbb42467ce5caa69e812f125d20848fd1c50
            10e15c437db6ae7edf91438bfa5b19a7bad0f91d8971dba72882ee742a0b57f4
            146dc127b54505020320938baa053cd1f3dccb713a6957e0c9aa54ec21894a61
            2d5cbdbf9edeff0d828ba063530a81a329131fb4fd19216bf0829882cdabebe6
            1e214a8b0ce35f8e600ed91fa96cd915db4ed7fdbe73592b0b543997ac9ec27b
            214375d66b2db2ba7203e26ecee99e2307846f5a5eb2130b9c574c4e04e6e477
            2825f908ee9357e409b46a4cf0acba266c2a9b02c0ed29b2c26f8c8cbcbd82cf
            264ef648e67140128100429b213b9140ed25274a0f0bd3cf808a6d1bcd0d63ba
            0450f8716810dff987300c3bc10a892b1c1c2637db3f8fecd9d8bb38442cc468
            10005567f9eb3d3a97098baa0d71c65db2bf83f8a194086a4cca39916b578faf
            103bcf2cf468d53c71d57b5c0ab31231e12e1ce3a444583203ea04c16ec69eb2
            0c5d6e7a8b0b14d4ed8f51217ae8af4207277f4116e0af5a9268b38a5d34910b
            0924c2d3fa7bd443b6244e3f29179883c120acb66ce414b5147c31531392c530
            07e5e59aa353dc977d4e082214179998a8086106f1eaaf33ee0b012cbd77066f
            132b76a71278e567595f3aaf837a72eb0ab515191143e5a3c8bd587526486628
            2c6b2a0de0a3fefdfc4fb4f3b8381d2c37ccc495848c2887f98bfbaca776ca39
            0000000000000000000000000000000000000000000000000000000000000001
            0000000000000000000000000000000000000000000000000000000000000002
            06a032e44c27b0ce9ed4d186a2debd4bfe72be9bc894b742744cf102a554d06f
            053396ef4f905183ad76960162ff0d8c34d25b6126660c8385d13a63d2078399
            "
        )
    }

    #[rstest]
    fn parse_valid_vk(valid_vk: [u8; VK_SIZE]) {
        assert!(VerificationKey::<()>::try_from(&valid_vk[..]).is_ok());
    }

    mod reject {
        use crate::{
            constants::{EVM_WORD_SIZE, GROUP_ELEMENT_SIZE},
            errors::CommitmentField,
        };

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
        fn a_vk_with_a_point_not_on_curve_for_any_commitment_field(valid_vk: [u8; VK_SIZE]) {
            let commitment_fields = [
                VkCommitmentField::Q_M,
                VkCommitmentField::Q_C,
                VkCommitmentField::Q_L,
                VkCommitmentField::Q_R,
                VkCommitmentField::Q_O,
                VkCommitmentField::Q_4,
                VkCommitmentField::Q_LOOKUP,
                VkCommitmentField::Q_ARITH,
                VkCommitmentField::Q_DELTARANGE,
                VkCommitmentField::Q_ELLIPTIC,
                VkCommitmentField::Q_MEMORY,
                VkCommitmentField::Q_NNF,
                VkCommitmentField::Q_POSEIDON2EXTERNAL,
                VkCommitmentField::Q_POSEIDON2INTERNAL,
                VkCommitmentField::S_1,
                VkCommitmentField::S_2,
                VkCommitmentField::S_3,
                VkCommitmentField::S_4,
                VkCommitmentField::ID_1,
                VkCommitmentField::ID_2,
                VkCommitmentField::ID_3,
                VkCommitmentField::ID_4,
                VkCommitmentField::T_1,
                VkCommitmentField::T_2,
                VkCommitmentField::T_3,
                VkCommitmentField::T_4,
                VkCommitmentField::Lagrange_First,
                VkCommitmentField::Lagrange_Last,
            ];
            const OFFSET: usize = 3 * EVM_WORD_SIZE;
            for (i, cm) in commitment_fields.iter().enumerate() {
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
                            field: Some(<CommitmentField as From<VkCommitmentField>>::from(
                                cm.clone()
                            )),
                        }
                    }
                );
            }
        }
    }
}
