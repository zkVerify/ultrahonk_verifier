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
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, PrimeField};

pub(crate) trait IntoFq {
    fn into_fq(self) -> Fq;
}

impl IntoFq for U256 {
    fn into_fq(self) -> Fq {
        Fq::from(self)
    }
}

pub(crate) trait IntoU256 {
    fn into_u256(self) -> U256;
}

impl IntoU256 for &[u8; 32] {
    fn into_u256(self) -> U256 {
        let mut rchunks_iter = self.rchunks_exact(8);
        let limbs: [_; 4] = core::array::from_fn(|_| {
            u64::from_be_bytes(rchunks_iter.next().unwrap().try_into().unwrap())
        });
        debug_assert!(rchunks_iter.remainder().is_empty());

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
        let mut rev_iter_be = self.0.iter().rev().flat_map(|limb| limb.to_be_bytes());
        core::array::from_fn(|_| rev_iter_be.next().unwrap())
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

    // If (0, 0) is given, we interpret this as the point at infinity:
    // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
    if x == Fq::ZERO && y == Fq::ZERO {
        return Ok((G1::zero(), &data[64..]));
    }

    let point = G1::new_unchecked(x, y);

    // Validate point
    if !point.is_on_curve() {
        return Err(());
    }
    // This is always true for G1 with the BN254 curve.
    debug_assert!(point.is_in_correct_subgroup_assuming_on_curve());

    Ok((point, &data[64..]))
}

// Parse point in G2.
pub(crate) fn read_g2<H: CurveHooks>(data: &[u8]) -> Result<G2<H>, ()> {
    if data.len() != 128 {
        return Err(());
    }

    // Read in reverse order (i.e., imaginary part before real part) to match
    // Solidity's encoding:
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

    let mut rchunks_iter = data.rchunks(8);
    let limbs = core::array::from_fn(|_| {
        u64::from_be_bytes(rchunks_iter.next().unwrap().try_into().unwrap())
    });

    Ok(U256::new(limbs).into_fq())
}
