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

    // #[snafu(display("Invalid circuit size"))]
    // InvalidCircuitSize,

    // #[snafu(display("Invalid number of public inputs"))]
    // InvalidNumberOfPublicInputs,
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
    pub num_public_inputs: u64,
    pub pub_inputs_offset: u64, // NOTE: May end up being removed in the future
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

        let (log_circuit_size, raw_vk) = match read_u64(raw_vk) {
            Ok((log_n, raw_vk)) => (log_n, raw_vk),
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        // Assert: log_circuit_size == log_2(circuit_size)

        let (num_public_inputs, raw_vk) = match read_u64(raw_vk) {
            Ok((num_pubs, raw_vk)) => (num_pubs, raw_vk),
            _ => Err(VerificationKeyError::ParsingError)?,
        };

        // Assert: num_pubs == pubs.len()

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
            num_public_inputs,
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
            "
            0000000000000020000000000000000500000000000000020000000000000001
            1d4e2b662cf75598ae75c80cb6190d6d86bc92fd69f1420fc9e6d5be8ba09e2c
            30210ded34398f54e3048f65c3f1dac749cc5022828668a6b345712af7369cbb
            1c3736f27bc34afe8eb1021704555717e76024100c144933330df5d9a6fb7e7f
            215612b168ecf42291b6df40da24069d5a0d5f2599d8be1ec34c5095e0922151
            059aecd0bba76edd4de929d587575b50c50f4be99a4615bfbd4ece89cb1442f1
            121b12b8bfa67425811621a1be826bcc5add41edb51fdce6c134c8e3ff5b1578
            2ad6f88dd8a25590c065ad43adb6f3d4ccba5a7312f27dd564b12325a2594ae5
            038c0c60a3dfed43a24eefcc0331f08074bea7bb5c7f65191ec2c3fe59a239cc
            17bebc96661564acc3f5c59647e9270570e0c238916df6390c8590445f256d1d
            0bf23741444a9bf150d33f19d70a31863256e71d2bb1adf96b04d61f2c95a2c4
            1b8058db3a5b9890b24d2545b7dd4aca37844bb0964691811a3dfe7b9fd24f8f
            28362861904e4b69161d7f43201c9213ede6e74eb63800123b82c73ad0156c40
            3058b7f62cbcbdc8763b05935e9965bea86cd205281d331fb426ef4232ffe5c5
            2b312f13fea65176bc0fe06aef8724f256898d215c78835f40bfe56fbf3f0de3
            0ac6c48b063b744bbeecb29c8962cf27853ae788601a92a0420ba047a7f7a643
            265a8af9070f8bd5e18bc97a13c985d35a59c188d3d5ee626bbc4589bba9ff9f
            024236bda126650fb5228cf424a0878775499e69e8bd2c39af33bd5fa0b4079a
            233cda9292be02cfa2da9d0fc7b0eab0eb1a867b06854066589b967455259b32
            0ca0bc4b1cd9eadbbf49eae56a99a4502ef13d965226a634d0981555e4a4da56
            1a8a818e6c61f68cefa329f2fabc95c80ad56a538d852f75eda858ed1a616c74
            09dfd2992ac1708f0dd1d28c2ad910d9cf21a1510948580f406bc9416113d620
            205f76eebda12f565c98c775c4e4f3534b5dcc29e57eed899b1a1a880534dcb9
            1b8afad764d2cbe67c94249535bba7fcbd3f412f868487222aa54f3268ab64a2
            01b70a90a334c9bd5096aad8a0cc5d4c1d1cdb0fe415445bd0c84309caaf213e
            13240f97a584b45184c8ec31319b5f6c04ee19ec1dfec87ed47d6d04aa158de2
            2dad22022121d689f57fb38ca21349cefb5d240b07ceb4be26ea429b6dc9d9e0
            2dbea5caeded6749d2ef2e2074dbea56c8d54fa043a54c6e6a40238fb0a52c8e
            1f299b74e3867e8c8bc149ef3a308007a3bd6f9935088ec247cce992c33a5336
            06652c2a72cb81284b190e235ee029a9463f36b2e29a1775c984b9d9b2714bab
            268e8d1e619fde85a71e430b77974326d790cb64c87558085332df639b8ce410
            2849ce9f77669190ed63388b3cc4a6d4e0d895c683ae0057f36a00e62416de5e
            2f8d58d08d4b4bb3a63e23e091e7a1f13c581c8a98c75014d5ec8a20890c62a5
            0fff3b4e49a2e6e05bc63d8438368182639ef435c89f30e3a3a9053d97bea5f2
            1820cafe7ffbef14880565ed976d53ed31c844187447d21f09100e8e569d3aec
            2e89eeb660cac820de50be4c53b608dd67c6977f5f1746fcf0fb6475d81ccd93
            18ca593957d2677420236138b3659a6b95b580bcc09a3dfbdadfa58a38222c15
            0c756ba6a0c66b05655349f04c61dff94dddf3a4d0117fafda741f9518c42f00
            0f87a1201ebad9bd23fed33824ae4ba2a1a307a45fb15594f8d553d2ebf9c285
            248460656ec9bc0ad940051e3b0751d25bb97885d8bc362eb06b96ea78d82f84
            0a5eebc538dc40185864706e22d850e3c02ce38e325761a59132bdb9e9d795be
            161edd8773a3b74c0553b690b4b80b2a5cbd4a1a25fda097bef23e349531b43e
            287139da895215c216aebe8cce7d3b944f4a3b051bd407126007921cb1fbc5fc
            20d671263cad88c119d0a5d172679309087e385f8e76d4cfa834fab61ebd6603
            0f9e6dfd3e6f4584b28e2cb00483dc2ffd9bf5f7ae2cc3f1ea0869c5ae71d9a1
            101e267b586089a8bb447e83ab3b7029ed788cc214e0be44485e2f39afbb7ae6
            13410d68bce429dc36e23023cfe21c5f2ced7e136529a4bcd4317232f2fc16b6
            1054a26ae3aeeeedc653cf5c5e3c09e2258141e67f4a5a48b50cbf48958b40bd
            2d14190edcf9b2aa697b677c779083aaf0151cc4f673dcf4bdba392d6280e376
            2e9e762a66fed77eb0e72645e5ba54f32c1d1bfbc4bd862361dafd7ebd6c68dd
            0b4a012fbc876f57da669215383f3595383f787bca153e972e6cfb9dfebeaa1b
            0000000000000000000000000000000000000000000000000000000000000001
            0000000000000000000000000000000000000000000000000000000000000002
            0af3884ecad3331429af995779c2602e93ca1ea976e9e1bc64bbcdbb9fe79212
            1f18803add8ad686e13dc2a989dcfb010cb69b0b38200df51787b7104bc74fb6
            "
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
                // Q: We should decide how we should handle (0, 0)? Do we interpret it
                // as G1's point at infinity, or do we want want to return an error?
                invalid_vk[32 + i * 64..32 + (i + 1) * 64].fill(0);

                assert_eq!(
                    VerificationKey::<()>::try_from(&invalid_vk[..]).unwrap_err(),
                    VerificationKeyError::PointNotOnCurve { field: cm.str() }
                );
            }
        }
    }
}
