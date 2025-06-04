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

use alloc::string::String;
use snafu::Snafu;

/// The verification error type
#[derive(Debug, PartialEq, Snafu)]
pub enum VerifyError {
    /// Failure due to another reason.
    #[snafu(display("Other Error"))]
    OtherError,
    /// Provided data has not valid public inputs.
    #[snafu(display("Invalid public input: {}", message))]
    PublicInputError { message: String },
    /// Provided data has not valid proof.
    #[snafu(display("Invalid Proof"))]
    InvalidProofError,
    /// Verify proof failed.
    #[snafu(display("Verification Failed"))]
    VerificationError,
    /// Provided an invalid verification key.
    #[snafu(display("Key Error"))]
    KeyError,
}

#[derive(Debug, PartialEq)]
pub enum GroupError {
    InvalidSliceLength {
        actual_length: usize,
        expected_length: usize,
    },
    NotOnCurve,
}

#[derive(Debug, PartialEq)]
pub enum FieldError {
    InvalidSliceLength {
        actual_length: usize,
        expected_length: usize,
    },
    NotMember,
}
