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

use crate::utils::{read_g1, read_u64};
use crate::{G1, VK_SIZE};
use ark_bn254_ext::CurveHooks;
use snafu::Snafu;

#[derive(Debug, PartialEq, Snafu)]
pub enum VerificationKeyError {
    #[snafu(display("Buffer too short"))]
    BufferTooShort,
    #[snafu(display("Point for field '{field:?}' is not on curve"))]
    PointNotOnCurve { field: &'static str },

    // // #[snafu(display("Point for field '{}' is not in the correct subgroup", field))]
    // // PointNotInCorrectSubgroup { field: &'static str },
    #[snafu(display("Invalid circuit size. Must be a power of 2."))]
    InvalidCircuitSize,

    #[snafu(display("Invalid log circuit size. Must be consistent with circuit size."))]
    InvalidLogCircuitSize,

    #[snafu(display("Could not parse vk"))]
    ParsingError,
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum CommitmentField {
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
    Q_AUX,
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

impl CommitmentField {
    pub fn str(&self) -> &'static str {
        match self {
            CommitmentField::Q_M => "Q_M",
            CommitmentField::Q_C => "Q_C",
            CommitmentField::Q_L => "Q_L",
            CommitmentField::Q_R => "Q_R",
            CommitmentField::Q_O => "Q_O",
            CommitmentField::Q_4 => "Q_4",
            CommitmentField::Q_LOOKUP => "Q_LOOKUP",
            CommitmentField::Q_ARITH => "Q_ARITH",
            CommitmentField::Q_DELTARANGE => "Q_DELTARANGE",
            CommitmentField::Q_ELLIPTIC => "Q_ELLIPTIC",
            CommitmentField::Q_AUX => "Q_AUX",
            CommitmentField::Q_POSEIDON2EXTERNAL => "Q_POSEIDON2EXTERNAL",
            CommitmentField::Q_POSEIDON2INTERNAL => "Q_POSEIDON2INTERNAL",
            CommitmentField::S_1 => "S_1",
            CommitmentField::S_2 => "S_2",
            CommitmentField::S_3 => "S_3",
            CommitmentField::S_4 => "S_4",
            CommitmentField::ID_1 => "ID_1",
            CommitmentField::ID_2 => "ID_2",
            CommitmentField::ID_3 => "ID_3",
            CommitmentField::ID_4 => "ID_4",
            CommitmentField::T_1 => "T_1",
            CommitmentField::T_2 => "T_2",
            CommitmentField::T_3 => "T_3",
            CommitmentField::T_4 => "T_4",
            CommitmentField::Lagrange_First => "Lagrange_First",
            CommitmentField::Lagrange_Last => "Lagrange_Last",
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    // Misc Params
    pub circuit_size: u64,
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
    pub q_lookup: G1<H>,
    pub q_arith: G1<H>,
    pub q_deltarange: G1<H>,
    pub q_elliptic: G1<H>,
    pub q_aux: G1<H>,
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

    fn try_from(raw_vk: &[u8]) -> Result<Self, Self::Error> {
        if raw_vk.len() < VK_SIZE {
            return Err(VerificationKeyError::BufferTooShort);
        }

        let (circuit_size, raw_vk) = match read_u64(raw_vk) {
            Ok((n, raw_vk)) => (n, raw_vk),
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        // Assert: circuit_size > 0 and also(?) a power of 2
        if circuit_size == 0 || (circuit_size & (circuit_size - 1) != 0) {
            return Err(VerificationKeyError::InvalidCircuitSize);
        }

        let (log_circuit_size, raw_vk) = match read_u64(raw_vk) {
            Ok((log_n, raw_vk)) => (log_n, raw_vk),
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        // Assert: log_circuit_size == log_2(circuit_size)
        if 1 << log_circuit_size != circuit_size {
            return Err(VerificationKeyError::InvalidLogCircuitSize);
        }

        let (combined_input_size, raw_vk) = match read_u64(raw_vk) {
            Ok((num_pubs, raw_vk)) => (num_pubs, raw_vk),
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        let (pub_inputs_offset, raw_vk) = match read_u64(raw_vk) {
            Ok((pi_offset, raw_vk)) => (pi_offset, raw_vk),
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        let (q_m, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_M.str(),
            })?;
        let (q_c, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_C.str(),
            })?;
        let (q_l, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_L.str(),
            })?;
        let (q_r, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_R.str(),
            })?;
        let (q_o, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_O.str(),
            })?;
        let (q_4, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_4.str(),
            })?;
        let (q_lookup, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_LOOKUP.str(),
            })?;
        let (q_arith, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_ARITH.str(),
            })?;
        let (q_deltarange, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_DELTARANGE.str(),
            })?;
        let (q_elliptic, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_ELLIPTIC.str(),
            })?;
        let (q_aux, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_AUX.str(),
            })?;
        let (q_poseidon2external, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_POSEIDON2EXTERNAL.str(),
            })?;
        let (q_poseidon2internal, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Q_POSEIDON2INTERNAL.str(),
            })?;
        let (s_1, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::S_1.str(),
            })?;
        let (s_2, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::S_2.str(),
            })?;
        let (s_3, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::S_3.str(),
            })?;
        let (s_4, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::S_4.str(),
            })?;
        let (id_1, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_1.str(),
            })?;
        let (id_2, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_2.str(),
            })?;
        let (id_3, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_3.str(),
            })?;
        let (id_4, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::ID_4.str(),
            })?;
        let (t_1, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::T_1.str(),
            })?;
        let (t_2, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::T_2.str(),
            })?;
        let (t_3, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::T_3.str(),
            })?;
        let (t_4, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::T_4.str(),
            })?;
        let (lagrange_first, raw_vk) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Lagrange_First.str(),
            })?;
        let (lagrange_last, _) =
            read_g1::<H>(raw_vk).map_err(|_| VerificationKeyError::PointNotOnCurve {
                field: CommitmentField::Lagrange_Last.str(),
            })?;

        Ok(Self {
            circuit_size,
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
            q_aux,
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

#[cfg(test)]
mod should {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn valid_vk() -> [u8; VK_SIZE] {
        hex_literal::hex!(
            "0000000000001000000000000000000c000000000000001100000000000000010bacc07b163a7486c2bd235250a5e8e07ac5bd0dfd2f81f38d63a570adec1e3f0060381dd486efe8272bad6e733f9f3d354019a2a1ff37b121ea98ddcff363b018876158f8df4ea51e3b32b7124bf4fa91c0616cd5f34d87c5de3d3b1da5549f1a23d5a6678a8c3bff6a6e99bd49d2a47bfbfd2f0e305e3b5e0551ae3e26b48316a0c9f638810dce46378f69c5ae35df6a4666da4310461bd3c1df2cdcbca68212a706ae1326528b2fa2a974a5b181b58ce5aa8d59e460179523aad682df420f0f7b3a190344f58edf66e802f7443b9ca866c2d56edacd5cf085afa5fa9266592916d57af4de17360ef895b8dc90a32cafbc21e13ae3c7932fc9b36c86d8c12105c2162a69112d16562cc5dca971db837df62934fa1a34b08439aa22231887f22e4e4e1b78f20985efe1b79a7c6faf283c26c1c48b20ac40b93cf7b81c59c2ba0574e4eaabca0be0b484d4cb102c8828a367c0bc7410a4087be779836d3ac6be01105217d26a475433ecf26dc166697381a456cc5ced6aadac6017865063cd010c4032c3079594eb75a8449d3d5ce8bc3661650d53f9b24d923d8f404cb0bbc91084d709650356d40f0158fd6da81f54eb5fe796a0ca89441369b7c24301f8512e63970d20de99e21154d4f8e85a53ca705f41f3934305343a7d37b36bdc95ca25a1e6a6d9139bf90ac92ae051c814876679994fdfa424edfd5743fe79ee6d5302b1ad53e9115a47ee95dc67cfa237b11c8d367885166d748e7333ff8c836fff073e330045941828960664bc03a87eaafac7c6e689905cc1fe57d14584f9587018b6e4781a7b02e2a95f7a095b98cedede5bc515dbe02504d79e6546552e5b10285856d11a298f18c03033404c363b83183da23922b6ec9df33b029cddc3420511656f8faa4a333dca53ccfdad3648ca3236d3b8faedddd32745b942a44eabbf127c5856a0217ce7f9957207acaf60abd07dde29e7426d10d8b1c1af4f4a40311dfe66ebd27fba4fccfa539763b5d25c4b379711213680f7a7f1ebfe6c1de399291a5fd7f84bb2f9b745fee80d0c4d0767b8a652ea20a7f5e67a779d7ca3999729e0ff75bf43c9359885c91324f6342ad9eb22625ba5f282624f1d39612d5d08043106d655b1dcfcd219da56100a7ec773ddc56bcdfd364e2834d0b1dfceee682044f09e45c385f5be927ed5a868a3208f2467c939e1c462a2d5c3fc7571b74a0603a5e4d6a0d192f5b37cbc00edec40377291404a102c3c11e3cb967c0751662344678750d7d6163211b27fa3ea586c25eb2f0e85b75db16e3772f5feb7c8700d5dacec9639bc29f31219bda3ffaeca035bc6e3ea4d8ab82d8e5510fe2596eb0f00d5775c78368d2303f7098221cfa097ccc73a7723a8c1a92cb052fa759ade193e86bd52f5eab0f0d947e34767f9267f023c0dbfa8ed3647f45492b24d276900a6f7666eccc077e7ecc54cad449fcf23846853154e86539e758149a54f68da28c96c78044a5e698a7857e96c82c41df83e366be777c08ec8ed4f17a151967b2a828e52fe0036d7c370ad034a3b38e16f52551516ea604ab4d66c0bc334bac90a5f867a3d5711a55c732d5fa9487b8c3e1c1ae01a60c2a014fe560acf7fb9fe15ee2691ddecfe39d7612b1ccb5c6f82c6cc901dfc3e48fda7fb16211829fa550d094339480804ffd3043a7eb249f2f9a8891fda1aa157f1a39b4abb2614e2ea0bd820fd99bba859aea90badf373e95c6e1017304ed2b9dae8ec8fa6542f21ad0d104d06c3ae5ce3f279068623b01d4dd8787a674eafb3bb3cbda13c3f97167f275fa813d3868531c5a337ecea47c1b9c0815199d05b6107e1ffdab72166dcb72e04de1f795fceede2d254f26e210f0b2723f6c562c1f9e9ae33a4597a8856990450f8716810dff987300c3bc10a892b1c1c2637db3f8fecd9d8bb38442cc46810005567f9eb3d3a97098baa0d71c65db2bf83f8a194086a4cca39916b578faf103bcf2cf468d53c71d57b5c0ab31231e12e1ce3a444583203ea04c16ec69eb20c5d6e7a8b0b14d4ed8f51217ae8af4207277f4116e0af5a9268b38a5d34910b187b9371870f579be414054241d418f5689db2f6cbfabe968378fd68e9b280c00964ab30f99cb72cc59d0f621604926cfebfcff535f724f619bb0e7a4853dbdb132b76a71278e567595f3aaf837a72eb0ab515191143e5a3c8bd5875264866282c6b2a0de0a3fefdfc4fb4f3b8381d2c37ccc495848c2887f98bfbaca776ca390000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000220b549c7f8cdd7943b558904e08f54a1f80d17e617532b80db4e890d5ccf29822a72466b55e86351db40afd62853d975699f4f8ee8b44860a804a703e11bd451"
        )
    }

    #[rstest]
    fn parse_valid_vk(valid_vk: [u8; VK_SIZE]) {
        assert!(VerificationKey::<()>::try_from(&valid_vk[..]).is_ok());
    }

    mod reject {
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
        fn a_vk_with_circuit_size_zero(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[..8].fill(0);
            assert_eq!(
                VerificationKey::<()>::try_from(&invalid_vk[..]),
                Err(VerificationKeyError::InvalidCircuitSize)
            );
        }

        #[rstest]
        fn a_vk_with_an_invalid_circuit_size(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[..8].fill(1); // not a power of 2
            assert_eq!(
                VerificationKey::<()>::try_from(&invalid_vk[..]),
                Err(VerificationKeyError::InvalidCircuitSize)
            );
        }

        #[rstest]
        fn a_vk_with_an_invalid_log_circuit_size(valid_vk: [u8; VK_SIZE]) {
            let mut invalid_vk = [0u8; VK_SIZE];
            invalid_vk.copy_from_slice(&valid_vk);
            invalid_vk[8..16].fill(0);
            assert_eq!(
                VerificationKey::<()>::try_from(&invalid_vk[..]),
                Err(VerificationKeyError::InvalidLogCircuitSize)
            );
        }

        #[rstest]
        fn a_vk_with_a_point_not_on_curve_for_any_commitment_field(valid_vk: [u8; VK_SIZE]) {
            let commitment_fields = [
                CommitmentField::Q_M,
                CommitmentField::Q_C,
                CommitmentField::Q_L,
                CommitmentField::Q_R,
                CommitmentField::Q_O,
                CommitmentField::Q_4,
                CommitmentField::Q_LOOKUP,
                CommitmentField::Q_ARITH,
                CommitmentField::Q_DELTARANGE,
                CommitmentField::Q_ELLIPTIC,
                CommitmentField::Q_AUX,
                CommitmentField::Q_POSEIDON2EXTERNAL,
                CommitmentField::Q_POSEIDON2INTERNAL,
                CommitmentField::S_1,
                CommitmentField::S_2,
                CommitmentField::S_3,
                CommitmentField::S_4,
                CommitmentField::ID_1,
                CommitmentField::ID_2,
                CommitmentField::ID_3,
                CommitmentField::ID_4,
                CommitmentField::T_1,
                CommitmentField::T_2,
                CommitmentField::T_3,
                CommitmentField::T_4,
                CommitmentField::Lagrange_First,
                CommitmentField::Lagrange_Last,
            ];
            for (i, cm) in commitment_fields.iter().enumerate() {
                let mut invalid_vk = [0u8; VK_SIZE];
                invalid_vk.copy_from_slice(&valid_vk);
                // Please note that (0, 0) is treated as the point at infinity
                invalid_vk[32 + i * 64..32 + (i + 1) * 64].fill(1);

                assert_eq!(
                    VerificationKey::<()>::try_from(&invalid_vk[..]).unwrap_err(),
                    VerificationKeyError::PointNotOnCurve { field: cm.str() }
                );
            }
        }
    }
}
