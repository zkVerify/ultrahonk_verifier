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

use crate::{
    constants::{NUMBER_OF_ALPHAS, NUMBER_OF_ENTITIES, NUMBER_OF_SUBRELATIONS},
    transcript::RelationParametersChallenges,
};
use ark_bn254_ext::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp};

/// Enum for wires.
pub enum Wire {
    Q_M,
    Q_C,
    Q_L,
    Q_R,
    Q_O,
    Q_4,
    Q_LOOKUP,
    Q_ARITH,
    Q_RANGE,
    Q_ELLIPTIC,
    Q_AUX,
    Q_POSEIDON2_EXTERNAL,
    Q_POSEIDON2_INTERNAL,
    SIGMA_1,
    SIGMA_2,
    SIGMA_3,
    SIGMA_4,
    ID_1,
    ID_2,
    ID_3,
    ID_4,
    TABLE_1,
    TABLE_2,
    TABLE_3,
    TABLE_4,
    LAGRANGE_FIRST,
    LAGRANGE_LAST,
    W_L,
    W_R,
    W_O,
    W_4,
    Z_PERM,
    LOOKUP_INVERSES,
    LOOKUP_READ_COUNTS,
    LOOKUP_READ_TAGS,
    W_L_SHIFT,
    W_R_SHIFT,
    W_O_SHIFT,
    W_4_SHIFT,
    Z_PERM_SHIFT,
}

/// Typed accessor for wire-related indexed data; used to index by enum into
/// proof.sumcheck_evaluations.
fn wire(p: &[Fr; NUMBER_OF_ENTITIES], wire: Wire) -> Fr {
    p[wire as usize]
}

// Constants for the auxiliary relation.
const LIMB_SIZE: Fr = MontFp!("295147905179352825856"); // 1 << 68
const SUBLIMB_SHIFT: Fr = MontFp!("16384"); // 1 << 14

// Constants for avoiding recomputations.
const MINUS_ONE: Fr =
    MontFp!("21888242871839275222246405745257275088548364400416034343698204186575808495616");
const MINUS_TWO: Fr =
    MontFp!("21888242871839275222246405745257275088548364400416034343698204186575808495615");
const MINUS_THREE: Fr =
    MontFp!("21888242871839275222246405745257275088548364400416034343698204186575808495614");

pub(crate) fn accumulate_relation_evaluations(
    purported_evaluations: &[Fr; NUMBER_OF_ENTITIES],
    rp_challenges: &RelationParametersChallenges,
    alphas: &[Fr; NUMBER_OF_ALPHAS],
    public_inputs_delta: Fr,
    pow_partial_eval: Fr,
) -> Fr {
    let mut evaluations = [Fr::ZERO; NUMBER_OF_SUBRELATIONS];

    // Accumulate all relations in Ultra Honk - each with varying number of subrelations
    accumulate_arithmetic_relation(purported_evaluations, &mut evaluations, pow_partial_eval);
    accumulate_permutation_relation(
        purported_evaluations,
        rp_challenges,
        &mut evaluations,
        public_inputs_delta,
        pow_partial_eval,
    );
    accumulate_log_derivative_lookup_relation(
        purported_evaluations,
        rp_challenges,
        &mut evaluations,
        pow_partial_eval,
    );
    accumulate_delta_range_relation(purported_evaluations, &mut evaluations, pow_partial_eval);
    accumulate_elliptic_relation(purported_evaluations, &mut evaluations, pow_partial_eval);
    accumulate_auxillary_relation(
        purported_evaluations,
        rp_challenges,
        &mut evaluations,
        pow_partial_eval,
    );
    accumulate_poseidon_external_relation(
        purported_evaluations,
        &mut evaluations,
        pow_partial_eval,
    );
    accumulate_poseidon_internal_relation(
        purported_evaluations,
        &mut evaluations,
        pow_partial_eval,
    );

    // batch the subrelations with the alpha challenges to obtain the full honk relation
    scale_and_batch_subrelations(&evaluations, alphas) // accumulator
}

/// Ultra Arithmetic Relation.
fn accumulate_arithmetic_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    // Relation 0
    let q_arith = wire(p, Wire::Q_ARITH);
    {
        const NEG_HALF: Fr = MontFp!(
            "10944121435919637611123202872628637544274182200208017171849102093287904247808"
        ); // neg half modulo P

        let mut accum = (q_arith + MINUS_THREE)
            * (wire(p, Wire::Q_M) * wire(p, Wire::W_R) * wire(p, Wire::W_L))
            * NEG_HALF;
        accum += (wire(p, Wire::Q_L) * wire(p, Wire::W_L))
            + (wire(p, Wire::Q_R) * wire(p, Wire::W_R))
            + (wire(p, Wire::Q_O) * wire(p, Wire::W_O))
            + (wire(p, Wire::Q_4) * wire(p, Wire::W_4))
            + wire(p, Wire::Q_C);
        accum += (q_arith - Fr::ONE) * wire(p, Wire::W_4_SHIFT);
        accum *= q_arith;
        accum *= domain_sep;
        evals[0] = accum;
    }

    // Relation 1
    {
        let mut accum =
            wire(p, Wire::W_L) + wire(p, Wire::W_4) - wire(p, Wire::W_L_SHIFT) + wire(p, Wire::Q_M);
        accum *= q_arith + MINUS_TWO;
        accum *= q_arith + MINUS_ONE;
        accum *= q_arith;
        accum *= domain_sep;
        evals[1] = accum;
    }
}

fn accumulate_permutation_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    rp_challenges: &RelationParametersChallenges,
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    public_inputs_delta: Fr,
    domain_sep: Fr,
) {
    let mut num =
        wire(p, Wire::W_L) + wire(p, Wire::ID_1) * rp_challenges.beta + rp_challenges.gamma;
    num =
        num * (wire(p, Wire::W_R) + wire(p, Wire::ID_2) * rp_challenges.beta + rp_challenges.gamma);
    num =
        num * (wire(p, Wire::W_O) + wire(p, Wire::ID_3) * rp_challenges.beta + rp_challenges.gamma);
    num =
        num * (wire(p, Wire::W_4) + wire(p, Wire::ID_4) * rp_challenges.beta + rp_challenges.gamma);

    let grand_product_numerator = num;

    let mut den =
        wire(p, Wire::W_L) + wire(p, Wire::SIGMA_1) * rp_challenges.beta + rp_challenges.gamma;
    den = den
        * (wire(p, Wire::W_R) + wire(p, Wire::SIGMA_2) * rp_challenges.beta + rp_challenges.gamma);
    den = den
        * (wire(p, Wire::W_O) + wire(p, Wire::SIGMA_3) * rp_challenges.beta + rp_challenges.gamma);
    den = den
        * (wire(p, Wire::W_4) + wire(p, Wire::SIGMA_4) * rp_challenges.beta + rp_challenges.gamma);

    let grand_product_denominator = den;

    // Contribution 2
    let mut acc = (wire(p, Wire::Z_PERM) + wire(p, Wire::LAGRANGE_FIRST)) * grand_product_numerator;

    acc = acc
        - ((wire(p, Wire::Z_PERM_SHIFT) + (wire(p, Wire::LAGRANGE_LAST) * public_inputs_delta))
            * grand_product_denominator);
    acc *= domain_sep;
    evals[2] = acc;

    // Contribution 3
    evals[3] = (wire(p, Wire::LAGRANGE_LAST) * wire(p, Wire::Z_PERM_SHIFT)) * domain_sep;
}

fn accumulate_log_derivative_lookup_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    rp_challenges: &RelationParametersChallenges,
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    // Calculate the write term (the table accumulation)
    let write_term = wire(p, Wire::TABLE_1)
        + rp_challenges.gamma
        + (wire(p, Wire::TABLE_2) * rp_challenges.eta)
        + (wire(p, Wire::TABLE_3) * rp_challenges.eta_two)
        + (wire(p, Wire::TABLE_4) * rp_challenges.eta_three);

    // Calculate the write term
    let derived_entry_1 =
        wire(p, Wire::W_L) + rp_challenges.gamma + (wire(p, Wire::Q_R) * wire(p, Wire::W_L_SHIFT));
    let derived_entry_2 = wire(p, Wire::W_R) + wire(p, Wire::Q_M) * wire(p, Wire::W_R_SHIFT);
    let derived_entry_3 = wire(p, Wire::W_O) + wire(p, Wire::Q_C) * wire(p, Wire::W_O_SHIFT);

    let read_term = derived_entry_1
        + derived_entry_2 * rp_challenges.eta
        + derived_entry_3 * rp_challenges.eta_two
        + wire(p, Wire::Q_O) * rp_challenges.eta_three;

    let read_inverse = wire(p, Wire::LOOKUP_INVERSES) * write_term;
    let write_inverse = wire(p, Wire::LOOKUP_INVERSES) * read_term;

    let inverse_exists_xor = wire(p, Wire::LOOKUP_READ_TAGS) + wire(p, Wire::Q_LOOKUP)
        - (wire(p, Wire::LOOKUP_READ_TAGS) * wire(p, Wire::Q_LOOKUP));

    // Inverse calculated correctly relation
    let mut accumulator_none =
        read_term * write_term * wire(p, Wire::LOOKUP_INVERSES) - inverse_exists_xor;
    accumulator_none *= domain_sep;

    // Inverse
    let accumulator_one =
        wire(p, Wire::Q_LOOKUP) * read_inverse - wire(p, Wire::LOOKUP_READ_COUNTS) * write_inverse;

    evals[4] = accumulator_none;
    evals[5] = accumulator_one;
}

fn accumulate_delta_range_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    // Compute wire differences
    let delta_1 = wire(p, Wire::W_R) - wire(p, Wire::W_L);
    let delta_2 = wire(p, Wire::W_O) - wire(p, Wire::W_R);
    let delta_3 = wire(p, Wire::W_4) - wire(p, Wire::W_O);
    let delta_4 = wire(p, Wire::W_L_SHIFT) - wire(p, Wire::W_4);

    // Contribution 6
    {
        let mut acc = delta_1;
        acc *= delta_1 + MINUS_ONE;
        acc *= delta_1 + MINUS_TWO;
        acc *= delta_1 + MINUS_THREE;
        acc *= wire(p, Wire::Q_RANGE);
        acc *= domain_sep;
        evals[6] = acc;
    }

    // Contribution 7
    {
        let mut acc = delta_2;
        acc *= delta_2 + MINUS_ONE;
        acc *= delta_2 + MINUS_TWO;
        acc *= delta_2 + MINUS_THREE;
        acc *= wire(p, Wire::Q_RANGE);
        acc *= domain_sep;
        evals[7] = acc;
    }

    // Contribution 8
    {
        let mut acc = delta_3;
        acc *= delta_3 + MINUS_ONE;
        acc *= delta_3 + MINUS_TWO;
        acc *= delta_3 + MINUS_THREE;
        acc *= wire(p, Wire::Q_RANGE);
        acc *= domain_sep;
        evals[8] = acc;
    }

    // Contribution 9
    {
        let mut acc = delta_4;
        acc *= delta_4 + MINUS_ONE;
        acc *= delta_4 + MINUS_TWO;
        acc *= delta_4 + MINUS_THREE;
        acc *= wire(p, Wire::Q_RANGE);
        acc *= domain_sep;
        evals[9] = acc;
    }
}

fn accumulate_elliptic_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let x_1 = wire(p, Wire::W_R);
    let y_1 = wire(p, Wire::W_O);

    let x_2 = wire(p, Wire::W_L_SHIFT);
    let y_2 = wire(p, Wire::W_4_SHIFT);
    let x_3 = wire(p, Wire::W_R_SHIFT);
    let y_3 = wire(p, Wire::W_O_SHIFT);

    let q_sign = wire(p, Wire::Q_L);
    let q_is_double = wire(p, Wire::Q_M);

    // Contribution 10 point addition, x-coordinate check
    // q_elliptic * (x3 + x2 + x1)(x2 - x1)(x2 - x1) - y2^2 - y1^2 + 2(y2y1)*q_sign = 0
    let x_diff = x_2 - x_1;
    let y1_sqr = y_1 * y_1;
    {
        // Move to top
        let partial_eval = domain_sep;

        let y2_sqr = y_2 * y_2;
        let y1y2 = y_1 * y_2 * q_sign;
        let mut x_add_identity = x_3 + x_2 + x_1;
        x_add_identity *= x_diff * x_diff;
        x_add_identity += y1y2 + y1y2 - y2_sqr - y1_sqr; // x_add_identity = x_add_identity - y2_sqr - y1_sqr + y1y2 + y1y2;

        evals[10] =
            x_add_identity * partial_eval * wire(p, Wire::Q_ELLIPTIC) * (Fr::ONE - q_is_double);
    }

    // Contribution 11 point addition, x-coordinate check
    // q_elliptic * (q_sign * y1 + y3)(x2 - x1) + (x3 - x1)(y2 - q_sign * y1) = 0
    {
        let y1_plus_y3 = y_1 + y_3;
        let y_diff = y_2 * q_sign - y_1;
        let y_add_identity = y1_plus_y3 * x_diff + (x_3 - x_1) * y_diff;
        evals[11] =
            y_add_identity * domain_sep * wire(p, Wire::Q_ELLIPTIC) * (Fr::ONE - q_is_double);
    }

    // Contribution 10 point doubling, x-coordinate check
    // (x3 + x1 + x1) (4y1*y1) - 9 * x1 * x1 * x1 * x1 = 0
    // N.B. we're using the equivalence x1*x1*x1 === y1*y1 - curve_b to reduce degree by 1
    {
        let x_pow_4 = (y1_sqr + MontFp!("17")) * x_1;
        let y1_sqr_mul_4 = y1_sqr.double().double();
        let x1_pow_4_mul_9 = x_pow_4 * MontFp!("9");
        let x_double_identity = (x_3 + x_1.double()) * y1_sqr_mul_4 - x1_pow_4_mul_9;

        evals[10] += x_double_identity * domain_sep * wire(p, Wire::Q_ELLIPTIC) * q_is_double;
    }

    // Contribution 11 point doubling, y-coordinate check:
    // (y1 + y1) (2y1) - (3 * x1 * x1)(x1 - x3) = 0
    {
        let x1_sqr_mul_3 = (x_1.double() + x_1) * x_1;
        let y_double_identity = x1_sqr_mul_3 * (x_1 - x_3) - y_1.double() * (y_1 + y_3);
        evals[11] += y_double_identity * domain_sep * wire(p, Wire::Q_ELLIPTIC) * q_is_double;
    }
}

fn accumulate_auxillary_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    rp: &RelationParametersChallenges,
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    // Contribution 12
    // Non native field arithmetic gate 2
    // deg 4
    //             _                                                                               _
    //            /   _                   _                               _       14                \
    // q_2 . q_4 |   (w_1 . w_2) + (w_1 . w_2) + (w_1 . w_4 + w_2 . w_3 - w_3) . 2    - w_3 - w_4   |
    //            \_                                                                               _/
    //
    let mut limb_subproduct = wire(p, Wire::W_L) * wire(p, Wire::W_R_SHIFT)
        + wire(p, Wire::W_L_SHIFT) * wire(p, Wire::W_R);
    let mut non_native_field_gate_2 = wire(p, Wire::W_L) * wire(p, Wire::W_4)
        + wire(p, Wire::W_R) * wire(p, Wire::W_O)
        - wire(p, Wire::W_O_SHIFT);
    non_native_field_gate_2 *= LIMB_SIZE;
    non_native_field_gate_2 -= wire(p, Wire::W_4_SHIFT);
    non_native_field_gate_2 += limb_subproduct;
    non_native_field_gate_2 *= wire(p, Wire::Q_4);

    limb_subproduct *= LIMB_SIZE;
    limb_subproduct += wire(p, Wire::W_L_SHIFT) * wire(p, Wire::W_R_SHIFT);
    let mut non_native_field_gate_1 = limb_subproduct;
    non_native_field_gate_1 -= wire(p, Wire::W_O) + wire(p, Wire::W_4);
    non_native_field_gate_1 *= wire(p, Wire::Q_O);

    let mut non_native_field_gate_3 = limb_subproduct;
    non_native_field_gate_3 += wire(p, Wire::W_4);
    non_native_field_gate_3 -= wire(p, Wire::W_O_SHIFT) + wire(p, Wire::W_4_SHIFT);
    non_native_field_gate_3 *= wire(p, Wire::Q_M);

    let mut non_native_field_identity =
        non_native_field_gate_1 + non_native_field_gate_2 + non_native_field_gate_3;
    non_native_field_identity *= wire(p, Wire::Q_R);

    // ((((w2' * 2^14 + w1') * 2^14 + w3) * 2^14 + w2) * 2^14 + w1 - w4) * qm
    // deg 2
    let mut limb_accumulator_1 = wire(p, Wire::W_R_SHIFT) * SUBLIMB_SHIFT;
    limb_accumulator_1 += wire(p, Wire::W_L_SHIFT);
    limb_accumulator_1 *= SUBLIMB_SHIFT;
    limb_accumulator_1 += wire(p, Wire::W_O);
    limb_accumulator_1 *= SUBLIMB_SHIFT;
    limb_accumulator_1 += wire(p, Wire::W_R);
    limb_accumulator_1 *= SUBLIMB_SHIFT;
    limb_accumulator_1 += wire(p, Wire::W_L);
    limb_accumulator_1 -= wire(p, Wire::W_4);
    limb_accumulator_1 *= wire(p, Wire::Q_4);

    // ((((w3' * 2^14 + w2') * 2^14 + w1') * 2^14 + w4) * 2^14 + w3 - w4') * qm
    // deg 2
    let mut limb_accumulator_2 = wire(p, Wire::W_O_SHIFT) * SUBLIMB_SHIFT;
    limb_accumulator_2 += wire(p, Wire::W_R_SHIFT);
    limb_accumulator_2 *= SUBLIMB_SHIFT;
    limb_accumulator_2 += wire(p, Wire::W_L_SHIFT);
    limb_accumulator_2 *= SUBLIMB_SHIFT;
    limb_accumulator_2 += wire(p, Wire::W_4);
    limb_accumulator_2 *= SUBLIMB_SHIFT;
    limb_accumulator_2 += wire(p, Wire::W_O);
    limb_accumulator_2 -= wire(p, Wire::W_4_SHIFT);
    limb_accumulator_2 *= wire(p, Wire::Q_M);

    let mut limb_accumulator_identity = limb_accumulator_1 + limb_accumulator_2;
    limb_accumulator_identity *= wire(p, Wire::Q_O); //  deg 3

    // MEMORY
    //
    // A RAM memory record contains a tuple of the following fields:
    //  * i: `index` of memory cell being accessed
    //  * t: `timestamp` of memory cell being accessed (used for RAM, set to 0 for ROM)
    //  * v: `value` of memory cell being accessed
    //  * a: `access` type of record. read: 0 = read, 1 = write
    //  * r: `record` of memory cell. record = access + index * eta + timestamp * eta_two + value * eta_three
    //
    // A ROM memory record contains a tuple of the following fields:
    //  * i: `index` of memory cell being accessed
    //  * v: `value1` of memory cell being accessed (ROM tables can store up to 2 values per index)
    //  * v2:`value2` of memory cell being accessed (ROM tables can store up to 2 values per index)
    //  * r: `record` of memory cell. record = index * eta + value2 * eta_two + value1 * eta_three
    //
    //  When performing a read/write access, the values of i, t, v, v2, a, r are stored in the following wires +
    // selectors, depending on whether the gate is a RAM read/write or a ROM read
    //
    //  | gate type | i  | v2/t  |  v | a  | r  |
    //  | --------- | -- | ----- | -- | -- | -- |
    //  | ROM       | w1 | w2    | w3 | -- | w4 |
    //  | RAM       | w1 | w2    | w3 | qc | w4 |
    //
    // (for accesses where `index` is a circuit constant, it is assumed the circuit will apply a copy constraint on
    // `w2` to fix its value)
    //

    //
    // Memory Record Check
    // Partial degree: 1
    // Total degree: 4
    //
    // A ROM/ROM access gate can be evaluated with the identity:
    //
    // qc + w1 \eta + w2 \eta_two + w3 \eta_three - w4 = 0
    //
    // For ROM gates, qc = 0
    //
    let mut memory_record_check = wire(p, Wire::W_O) * rp.eta_three;
    memory_record_check += wire(p, Wire::W_R) * rp.eta_two;
    memory_record_check += wire(p, Wire::W_L) * rp.eta;
    memory_record_check += wire(p, Wire::Q_C);
    let partial_record_check = memory_record_check; // used in RAM consistency check; deg 1 or 4
    memory_record_check -= wire(p, Wire::W_4);

    //
    // Contribution 13 & 14
    // ROM Consistency Check
    // Partial degree: 1
    // Total degree: 4
    //
    // For every ROM read, a set equivalence check is applied between the record witnesses, and a second set of
    // records that are sorted.
    //
    // We apply the following checks for the sorted records:
    //
    // 1. w1, w2, w3 correctly map to 'index', 'v1, 'v2' for a given record value at w4
    // 2. index values for adjacent records are monotonically increasing
    // 3. if, at gate i, index_i == index_{i + 1}, then value1_i == value1_{i + 1} and value2_i == value2_{i + 1}
    //
    let index_delta = wire(p, Wire::W_L_SHIFT) - wire(p, Wire::W_L);
    let record_delta = wire(p, Wire::W_4_SHIFT) - wire(p, Wire::W_4);

    let index_is_monotonically_increasing = index_delta.square() - index_delta; // deg 2

    let adjacent_values_match_if_adjacent_indices_match =
        (index_delta * MINUS_ONE + Fr::ONE) * record_delta; // deg 2

    evals[13] = adjacent_values_match_if_adjacent_indices_match
        * wire(p, Wire::Q_L)
        * wire(p, Wire::Q_R)
        * wire(p, Wire::Q_AUX)
        * domain_sep; // deg 5
    evals[14] = index_is_monotonically_increasing
        * wire(p, Wire::Q_L)
        * wire(p, Wire::Q_R)
        * wire(p, Wire::Q_AUX)
        * domain_sep; // deg 5

    let rom_consistency_check_identity =
        memory_record_check * wire(p, Wire::Q_L) * wire(p, Wire::Q_R); // deg 3 or 7

    //
    // Contributions 15, 16, 17
    // RAM Consistency Check
    //
    // The 'access' type of the record is extracted with the expression `w_4 - ap.partial_record_check`
    // (i.e. for an honest Prover `w1 * eta + w2 * eta^2 + w3 * eta^3 - w4 = access`.
    // This is validated by requiring `access` to be boolean
    //
    // For two adjacent entries in the sorted list if _both_
    //  A) index values match
    //  B) adjacent access value is 0 (i.e. next gate is a READ)
    // then
    //  C) both values must match.
    // The gate boolean check is
    // (A && B) => C  === !(A && B) || C ===  !A || !B || C
    //
    // N.B. it is the responsibility of the circuit writer to ensure that every RAM cell is initialized
    // with a WRITE operation.
    //
    let access_type = wire(p, Wire::W_4) - partial_record_check; // will be 0 or 1 for honest Prover; deg 1 or 4
    let access_check = access_type.square() - access_type; // check value is 0 or 1; deg 2 or 8

    let mut next_gate_access_type = wire(p, Wire::W_O_SHIFT) * rp.eta_three;
    next_gate_access_type += wire(p, Wire::W_R_SHIFT) * rp.eta_two;
    next_gate_access_type += wire(p, Wire::W_L_SHIFT) * rp.eta;
    next_gate_access_type = wire(p, Wire::W_4_SHIFT) - next_gate_access_type;

    let value_delta = wire(p, Wire::W_O_SHIFT) - wire(p, Wire::W_O);
    let adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation =
        (index_delta * MINUS_ONE + Fr::ONE)
            * value_delta
            * (next_gate_access_type * MINUS_ONE + Fr::ONE); // deg 3 or 6

    // We can't apply the RAM consistency check identity on the final entry in the sorted list (the wires in the
    // next gate would make the identity fail).  We need to validate that its 'access type' bool is correct. Can't
    // do  with an arithmetic gate because of the  `eta` factors. We need to check that the *next* gate's access
    // type is  correct, to cover this edge case
    // deg 2 or 4
    let next_gate_access_type_is_boolean = next_gate_access_type.square() - next_gate_access_type;

    // Putting it all together...
    evals[15] = adjacent_values_match_if_adjacent_indices_match_and_next_access_is_a_read_operation
        * wire(p, Wire::Q_ARITH)
        * wire(p, Wire::Q_AUX)
        * domain_sep; // deg 5 or 8
    evals[16] = index_is_monotonically_increasing
        * wire(p, Wire::Q_ARITH)
        * wire(p, Wire::Q_AUX)
        * domain_sep; // deg 4
    evals[17] = next_gate_access_type_is_boolean
        * wire(p, Wire::Q_ARITH)
        * wire(p, Wire::Q_AUX)
        * domain_sep; // deg 4 or 6

    let ram_consistency_check_identity = access_check * wire(p, Wire::Q_ARITH); // deg 3 or 9

    //
    // RAM Timestamp Consistency Check
    //
    // | w1 | w2 | w3 | w4 |
    // | index | timestamp | timestamp_check | -- |
    //
    // Let delta_index = index_{i + 1} - index_{i}
    //
    // Iff delta_index == 0, timestamp_check = timestamp_{i + 1} - timestamp_i
    // Else timestamp_check = 0
    //
    let timestamp_delta = wire(p, Wire::W_R_SHIFT) - wire(p, Wire::W_R);
    let ram_timestamp_check_identity =
        (index_delta * MINUS_ONE + Fr::ONE) * timestamp_delta - wire(p, Wire::W_O); // deg 3

    //
    // Complete Contribution 12
    // The complete RAM/ROM memory identity
    // Partial degree:
    //
    let mut memory_identity = rom_consistency_check_identity; // deg 3 or 6
    memory_identity += ram_timestamp_check_identity * wire(p, Wire::Q_4) * wire(p, Wire::Q_L); // deg 4
    memory_identity += memory_record_check * wire(p, Wire::Q_M) * wire(p, Wire::Q_L); // deg 3 or 6
    memory_identity += ram_consistency_check_identity; // deg 3 or 9

    // (deg 3 or 9) + (deg 4) + (deg 3)
    let mut auxiliary_identity =
        memory_identity + non_native_field_identity + limb_accumulator_identity;
    auxiliary_identity *= wire(p, Wire::Q_AUX) * domain_sep; // deg 4 or 10
    evals[12] = auxiliary_identity;
}

fn accumulate_poseidon_external_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    let s1 = wire(p, Wire::W_L) + wire(p, Wire::Q_L);
    let s2 = wire(p, Wire::W_R) + wire(p, Wire::Q_R);
    let s3 = wire(p, Wire::W_O) + wire(p, Wire::Q_O);
    let s4 = wire(p, Wire::W_4) + wire(p, Wire::Q_4);

    let u1 = s1.square().square() * s1; // s1 * s1 * s1 * s1 * s1;
    let u2 = s2.square().square() * s2; // s2 * s2 * s2 * s2 * s2;
    let u3 = s3.square().square() * s3; // s3 * s3 * s3 * s3 * s3;
    let u4 = s4.square().square() * s4; // s4 * s4 * s4 * s4 * s4;
                                        // matrix mul v = M_E * u with 14 additions
    let t0 = u1 + u2; // u_1 + u_2
    let t1 = u3 + u4; // u_3 + u_4
    let t2 = u2.double() + t1; // 2u_2
                               // ep.t2 += ep.t1; // 2u_2 + u_3 + u_4
    let t3 = u4.double() + t0; // 2u_4
                               // ep.t3 += ep.t0; // u_1 + u_2 + 2u_4
    let mut v4 = t1.double();
    v4 = v4.double() + t3;
    // ep.v4 += ep.t3; // u_1 + u_2 + 4u_3 + 6u_4
    let mut v2 = t0.double();
    v2 = v2.double() + t2;
    // ep.v2 += ep.t2; // 4u_1 + 6u_2 + u_3 + u_4
    let v1 = t3 + v2; // 5u_1 + 7u_2 + u_3 + 3u_4
    let v3 = t2 + v4; // u_1 + 3u_2 + 5u_3 + 7u_4

    let q_pos_by_scaling = wire(p, Wire::Q_POSEIDON2_EXTERNAL) * domain_sep;
    evals[18] += q_pos_by_scaling * (v1 - wire(p, Wire::W_L_SHIFT));

    evals[19] += q_pos_by_scaling * (v2 - wire(p, Wire::W_R_SHIFT));

    evals[20] += q_pos_by_scaling * (v3 - wire(p, Wire::W_O_SHIFT));

    evals[21] += q_pos_by_scaling * (v4 - wire(p, Wire::W_4_SHIFT));
}

fn accumulate_poseidon_internal_relation(
    p: &[Fr; NUMBER_OF_ENTITIES],
    evals: &mut [Fr; NUMBER_OF_SUBRELATIONS],
    domain_sep: Fr,
) {
    // add round constants
    let s1 = wire(p, Wire::W_L) + wire(p, Wire::Q_L);

    // apply s-box round
    let u1 = s1.square().square() * s1; // s1 * s1 * s1 * s1 * s1;
    let u2 = wire(p, Wire::W_R);
    let u3 = wire(p, Wire::W_O);
    let u4 = wire(p, Wire::W_4);

    // matrix mul with v = M_I * u 4 muls and 7 additions
    let u_sum = u1 + u2 + u3 + u4;

    let q_pos_by_scaling = wire(p, Wire::Q_POSEIDON2_INTERNAL) * domain_sep;

    let v1 = u1
        * MontFp!("7626475329478847982857743246276194948757851985510858890691733676098590062311")
        + u_sum;
    evals[22] += q_pos_by_scaling * (v1 - wire(p, Wire::W_L_SHIFT));

    let v2 = u2
        * MontFp!("5498568565063849786384470689962419967523752476452646391422913716315471115275")
        + u_sum;
    evals[23] += q_pos_by_scaling * (v2 - wire(p, Wire::W_R_SHIFT));

    let v3 = u3
        * MontFp!("148936322117705719734052984176402258788283488576388928671173547788498414613")
        + u_sum;
    evals[24] += q_pos_by_scaling * (v3 - wire(p, Wire::W_O_SHIFT));

    let v4 = u4
        * MontFp!("15456385653678559339152734484033356164266089951521103188900320352052358038155")
        + u_sum;
    evals[25] += q_pos_by_scaling * (v4 - wire(p, Wire::W_4_SHIFT));
}

fn scale_and_batch_subrelations(
    evaluations: &[Fr; NUMBER_OF_SUBRELATIONS],
    subrelation_challenges: &[Fr; NUMBER_OF_ALPHAS],
) -> Fr {
    let mut accumulator = evaluations[0];

    for i in 1..NUMBER_OF_SUBRELATIONS {
        accumulator += evaluations[i] * subrelation_challenges[i - 1];
    }

    accumulator
}
