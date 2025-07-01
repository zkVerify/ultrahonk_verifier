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

// Copyright 2022 Aztec
// Copyright 2024 Horizen Labs, Inc.
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
    // errors::{FieldError, GroupError},
    errors::FieldError,
    types::G1,
    Fq,
    Fq2,
    Fr,
    G2,
    U256,
};
use ark_bn254_ext::CurveHooks;
use ark_ff::PrimeField;

pub(crate) trait IntoFq {
    fn into_fq(self) -> Fq;
}

impl IntoFq for U256 {
    fn into_fq(self) -> Fq {
        Fq::from(self)
    }
}

// impl IntoFq for u64 {
//     fn into_fq(self) -> Fq {
//         Fq::new(U256::from(self))
//     }
// }

// impl IntoFq for Fr {
//     fn into_fq(self) -> Fq {
//         let big_int = self.into_bigint();
//         Fq::from_bigint(big_int).expect("Fr value is always a valid Fq element")
//     }
// }

pub(crate) trait IntoFr {
    fn into_fr(self) -> Fr;
}

impl IntoFr for &[u8; 32] {
    fn into_fr(self) -> Fr {
        self.into_u256().into_fr()
    }
}

impl IntoFr for [u8; 32] {
    fn into_fr(self) -> Fr {
        (&self).into_fr()
    }
}

impl IntoFr for U256 {
    fn into_fr(self) -> Fr {
        Fr::new(self)
    }
}

// impl IntoFr for u64 {
//     fn into_fr(self) -> Fr {
//         Fr::new(U256::from(self))
//     }
// }

// impl IntoFr for Fq {
//     fn into_fr(self) -> Fr {
//         Fr::from(self.into_bigint())
//     }
// }

pub(crate) trait IntoU256 {
    fn into_u256(self) -> U256;
}

// impl IntoU256 for u32 {
//     fn into_u256(self) -> U256 {
//         U256::from(self)
//     }
// }

impl IntoU256 for &[u8; 32] {
    fn into_u256(self) -> U256 {
        // Convert the byte array to a little-endian byte vector
        let mut bytes = self.to_vec(); // Convert the &[u8; 32] slice to a Vec<u8>
        bytes.reverse(); // Reverse the bytes to ensure little-endian order

        // Create a BigInteger256 from the little-endian byte array
        let mut limbs = [0u64; 4];

        // Populate the limbs from the byte vector (which is little-endian)
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(
                bytes[(i << 3)..((i + 1) << 3)]
                    .try_into()
                    .expect("Invalid byte slice"),
            );
        }

        U256::new(limbs)
    }
}

impl IntoU256 for [u8; 32] {
    fn into_u256(self) -> U256 {
        (&self).into_u256()
    }
}

/// Trait for returning a big-endian representation of some object as a `[u8; 32]`.
pub(crate) trait IntoBEBytes32 {
    fn into_be_bytes32(self) -> [u8; 32];
}

impl IntoBEBytes32 for U256 {
    fn into_be_bytes32(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, limb) in self.0.iter().rev().enumerate() {
            // Convert each limb to big-endian bytes
            let limb_bytes = limb.to_be_bytes();
            // Copy the bytes into the correct position in the output array
            bytes[(i << 3)..((i + 1) << 3)].copy_from_slice(&limb_bytes);
        }
        bytes
    }
}

impl IntoBEBytes32 for Fr {
    fn into_be_bytes32(self) -> [u8; 32] {
        self.into_bigint().into_be_bytes32()
    }
}

impl IntoBEBytes32 for Fq {
    fn into_be_bytes32(self) -> [u8; 32] {
        self.into_bigint().into_be_bytes32()
    }
}

impl IntoBEBytes32 for u64 {
    fn into_be_bytes32(self) -> [u8; 32] {
        let be = self.to_be_bytes();
        let mut arr = [0u8; 32];
        arr[24..].copy_from_slice(&be);
        arr
    }
}

pub(crate) fn read_u64(data: &[u8]) -> Result<(u64, &[u8]), ()> {
    let value = u64::from_be_bytes(data[..8].try_into().map_err(|_| ())?);
    Ok((value, &data[8..]))
}

pub(crate) fn read_u256(bytes: &[u8]) -> Result<U256, ()> {
    <&[u8; 32]>::try_from(bytes)
        .map_err(|_| ())
        .map(IntoU256::into_u256)
}

// Parse point in G1.
pub(crate) fn read_g1<H: CurveHooks>(data: &[u8]) -> Result<(G1<H>, &[u8]), ()> {
    if data.len() < 64 {
        return Err(());
    }

    let x = Fq::from_bigint(read_u256(&data[0..32])?).ok_or(())?;
    let y = Fq::from_bigint(read_u256(&data[32..64])?).ok_or(())?;

    let point = G1::new_unchecked(x, y);

    // Validate point
    if !point.is_on_curve() {
        return Err(());
    }
    // This cannot happen for G1 with the BN254 curve.
    // if !point.is_in_correct_subgroup_assuming_on_curve() {
    //     return Err(());
    // }

    Ok((point, &data[64..]))
}

// Parse point in G2.
pub(crate) fn read_g2<H: CurveHooks>(data: &[u8]) -> Result<G2<H>, ()> {
    if data.len() != 128 {
        return Err(());
    }

    // Reverse order to obtain the same encoding as Solidity:
    // https://eips.ethereum.org/EIPS/eip-197#encoding
    let x_c1 = read_fq_util(&data[0..32]).expect("Parsing the SRS should always succeed!");
    let x_c0 = read_fq_util(&data[32..64]).expect("Parsing the SRS should always succeed!");
    let y_c1 = read_fq_util(&data[64..96]).expect("Parsing the SRS should always succeed!");
    let y_c0 = read_fq_util(&data[96..128]).expect("Parsing the SRS should always succeed!");

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2::<H>::new(x, y))
}

// Utility function for parsing points in G2.
pub(crate) fn read_fq_util(data: &[u8]) -> Result<Fq, FieldError> {
    if data.len() != 32 {
        return Err(FieldError::InvalidSliceLength {
            expected_length: 32,
            actual_length: data.len(),
        });
    }

    // Convert bytes to limbs manually
    let mut limbs = [0u64; 4];
    for (i, chunk) in data.chunks(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    let bigint = U256::new(limbs);

    Ok(bigint.into_fq())
}
