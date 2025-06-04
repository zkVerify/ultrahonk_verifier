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

pub use ark_bn254_ext::{Fq, Fq2, Fr, FrConfig};
use ark_bn254_ext::{G1Affine, G2Affine};

pub type U256 = ark_ff::BigInteger256;
pub type G1<H> = G1Affine<H>;
pub type G2<H> = G2Affine<H>;
pub type Bn254<H> = ark_bn254_ext::Bn254<H>;
