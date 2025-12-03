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
use core::fmt;
use snafu::Snafu;

use crate::{
    key::VkCommitmentField,
    proof::ProofCommitmentField,
    utils::{to_hex_string, IntoBEBytes32},
    U256,
};

/// The verification error type
#[derive(Debug, PartialEq, Snafu)]
pub enum VerifyError {
    /// Failure due to another reason.
    #[snafu(display("Other Error"))]
    OtherError,
    /// Provided data has not valid public inputs.
    #[snafu(display("Invalid public input: {message}"))]
    PublicInputError { message: String },
    /// Provided data has not valid proof.
    #[snafu(display("Invalid Proof"))]
    InvalidProofError { message: String },
    /// Verify proof failed.
    #[snafu(display("Verification Failed. Message: {message}"))]
    VerificationError { message: String },
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
    CoordinateExceedsModulus {
        coordinate_value: U256,
        modulus: U256,
    },
}

impl fmt::Display for GroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupError::InvalidSliceLength {
                actual_length,
                expected_length,
            } => {
                write!(
                    f,
                    "Invalid Slice Length. Actual length: {actual_length}, Expected length: {expected_length}",
                )
            }
            GroupError::NotOnCurve => {
                write!(f, "Point not on curve")
            }
            GroupError::CoordinateExceedsModulus {
                coordinate_value,
                modulus,
            } => {
                write!(
                    f,
                    "Coordinate value {} exceeds base field modulus {}",
                    to_hex_string(&coordinate_value.into_be_bytes32()),
                    modulus
                )
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CommitmentField {
    Proof(ProofCommitmentField),
    Vk(VkCommitmentField),
}

impl From<ProofCommitmentField> for CommitmentField {
    fn from(pcf: ProofCommitmentField) -> Self {
        CommitmentField::Proof(pcf)
    }
}

impl From<VkCommitmentField> for CommitmentField {
    fn from(vkcf: VkCommitmentField) -> Self {
        CommitmentField::Vk(vkcf)
    }
}

impl fmt::Display for CommitmentField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitmentField::Proof(field_name) => {
                write!(f, "{field_name}")
            }
            CommitmentField::Vk(field_name) => {
                write!(f, "{field_name}")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ConversionError {
    pub group: GroupError,
    pub field: Option<CommitmentField>,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            Some(field_name) => {
                write!(
                    f,
                    "Failed to convert data into an EC point for field \"{}\". Cause: {}",
                    field_name, self.group
                )
            }
            None => {
                write!(
                    f,
                    "Failed to convert data into an EC point. Cause: {}",
                    self.group
                )
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum FieldError {
    InvalidSliceLength {
        actual_length: usize,
        expected_length: usize,
    },
    NotMember,
}
