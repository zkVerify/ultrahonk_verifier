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

// Fixed G2 point
pub static SRS_G2: [u8; 128] = hex_literal::hex!(
    "
    198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
    1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
    090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
    12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
    "
);

// G2 point from VK
pub static SRS_G2_VK: [u8; 128] = hex_literal::hex!(
    "
    260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1
    0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0
    04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4
    22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55
    "
);
