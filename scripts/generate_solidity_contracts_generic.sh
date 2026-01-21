#!/usr/bin/env bash

PROJECT_NAME=hello_world
PROVER_FILE=Prover.toml
ARTIFACTS_DIR=artifacts
ORACLE_HASH=keccak
SCHEME=ultra_honk
VERSIONS=(
  "0.86.0"
  "0.87.0"
  "1.0.0"
  "1.1.0"
  "1.2.0"
  "2.0.2"
  "2.0.3"
  "2.0.4"
  # "2.1.1" (404)
  "2.1.2"
  "2.1.3"
  "2.1.4"
  "2.1.5"
  "2.1.6"
  "2.1.7"
  "2.1.8"
  "2.1.9"
  "3.0.1"
  "3.0.2"
  "3.0.3"
)

function generate_artifacts() {
    BB_VERSION=$1
    VERSION_DIR="bb${BB_VERSION//./_}"
    OUTPUT_DIR="${ARTIFACTS_DIR}/${VERSION_DIR}"
    ZK_OUTPUT_DIR="${OUTPUT_DIR}/zk"
    PLAIN_OUTPUT_DIR="${OUTPUT_DIR}/plain"
    ZK_CONTRACTS_DIR="${ZK_OUTPUT_DIR}/contracts"
    PLAIN_CONTRACTS_DIR="${PLAIN_OUTPUT_DIR}/contracts"
    ZK_ZKV_ARTIFACTS_DIR="${ZK_OUTPUT_DIR}/zkv_artifacts"
    PLAIN_ZKV_ARTIFACTS_DIR="${PLAIN_OUTPUT_DIR}/zkv_artifacts"

    bbup -v "${BB_VERSION}"
    rm -rf ./target

    function generate_zkv_artifacts() {
        local PROOF_TYPE=$1
        local PROOF_FILE_PATH=$2
        local VK_FILE_PATH=$3
        local PUBS_FILE_PATH=$4
        local ZKV_OUT_DIR

        if [[ "${PROOF_TYPE}" == "ZK" ]]; then
            ZKV_OUT_DIR="${ZK_ZKV_ARTIFACTS_DIR}"
        elif [[ "${PROOF_TYPE}" == "Plain" ]]; then
            ZKV_OUT_DIR="${PLAIN_ZKV_ARTIFACTS_DIR}"
        else
            echo "Invalid proof type: ${PROOF_TYPE}"
            exit 1
        fi

        local ZKV_PROOF_HEX_FILE_PATH="${ZKV_OUT_DIR}/zkv_proof.hex"
        local ZKV_VK_HEX_FILE_PATH="${ZKV_OUT_DIR}/zkv_vk.hex"
        local ZKV_PUBS_HEX_FILE_PATH="${ZKV_OUT_DIR}/zkv_pubs.hex"

        # Convert proof to hexadecimal format
        if [ -f "$PROOF_FILE_PATH" ]; then
            PROOF_BYTES=$(xxd -p -c 256 "$PROOF_FILE_PATH" | tr -d '\n')
            printf '`{\n    "%s:" "0x%s"\n}`\n' "$PROOF_TYPE" "$PROOF_BYTES" > "$ZKV_PROOF_HEX_FILE_PATH"
            echo "✅ 'proof' hex file generated at ${ZKV_PROOF_HEX_FILE_PATH}."
        else
            echo "❌ Error: Proof file '$PROOF_FILE_PATH' not found. Skipping." >&2
        fi

        # Convert vk to hexadecimal format
        if [ -f "$VK_FILE_PATH" ]; then
            printf "\"0x%s\"\n" "$(xxd -p -c 0 "$VK_FILE_PATH")" > "$ZKV_VK_HEX_FILE_PATH"
            echo "✅ 'vk' hex file generated at ${ZKV_VK_HEX_FILE_PATH}."
        else
            echo "❌ Error: Verification key file '$VK_FILE_PATH' not found. Skipping." >&2
        fi

        # Convert public inputs to hexadecimal format
        if [ -f "$PUBS_FILE_PATH" ]; then
            xxd -p -c 32 "$PUBS_FILE_PATH" | sed 's/.*/"0x&"/' | paste -sd, - | sed 's/.*/[&]/' > "$ZKV_PUBS_HEX_FILE_PATH"
            echo "✅ 'pubs' hex file generated at ${ZKV_PUBS_HEX_FILE_PATH}."
        else
            echo "❌ Error: Public inputs file '$PUBS_FILE_PATH' not found. Skipping." >&2
        fi
    }

    function generate_prover_witness_and_compile() {
        nargo check
        printf "x = \"1\"\ny = \"2\"" > "${PROVER_FILE}"
        nargo execute
    }

    mkdir -p "${ZK_CONTRACTS_DIR}"
    mkdir -p "${PLAIN_CONTRACTS_DIR}"
    mkdir -p "${ZK_ZKV_ARTIFACTS_DIR}"
    mkdir -p "${PLAIN_ZKV_ARTIFACTS_DIR}"

    # These are essentially what would go into the tutorial:
    if [[ "${BB_VERSION}" == "0.86.0" ]]; then
        # Use noirup to 1.0.0-beta.4 for proof generation to work (newer versions will not work).
        noirup -v 1.0.0-beta.4

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" --zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol" --zk
        mv ./target/vk ./target/proof ./target/public_inputs "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "0.87.0" ]]; then
        # Use noirup to 1.0.0-beta.6 for proof generation to work (newer versions might also work).
        noirup -v 1.0.0-beta.6

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" --zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol" --zk
        mv ./target/vk ./target/proof ./target/public_inputs "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "1.0.0" ]]; then
        # Use noirup to 1.0.0-beta.6 for proof generation to work (newer versions might also work).
        noirup -v 1.0.0-beta.6

        generate_prover_witness_and_compile

        # Starting from this version, --zk is removed and --disable_zk is introduced.
        # By default, proofs are now ZK.
        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "1.1.0" ]]; then
        # Use noirup to 1.0.0-beta.6 for proof generation to work (newer versions might also work).
        noirup -v 1.0.0-beta.6

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "1.2.0" ]]; then
        # Use noirup to 1.0.0-beta.6 for proof generation to work (newer versions might also work).
        noirup -v 1.0.0-beta.6

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "2.0.2" ]]; then
        # Use noirup to 1.0.0-beta.14 for proof generation to work (newer versions will not work).
        noirup -v 1.0.0-beta.14

        generate_prover_witness_and_compile

        # The option to generate an optimized version of the verifier contract is offered.
        # From now on, a vk_hash artifact is also generated.

        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --optimized -k ./target/vk -o "${ZK_CONTRACTS_DIR}/OptimizedZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk --optimized -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/OptimizedPlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "2.0.3" ]]; then
        # Use noirup to 1.0.0-beta.15 for proof generation to work (earlier versions might work).
        noirup -v 1.0.0-beta.15

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --optimized -k ./target/vk -o "${ZK_CONTRACTS_DIR}/OptimizedZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk --optimized -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/OptimizedPlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" == "2.0.4" ]]; then
        # Use noirup to 1.0.0-beta.15 for proof generation to work (earlier versions might work).
        noirup -v 1.0.0-beta.15

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --optimized -k ./target/vk -o "${ZK_CONTRACTS_DIR}/OptimizedZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk --optimized -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/OptimizedPlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" =~ ^2\.1\.[2-9]$ ]]; then
        # Use noirup to 1.0.0-beta.15 for proof generation to work (earlier versions might work).
        noirup -v 1.0.0-beta.15

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -s "${SCHEME}" -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --optimized -k ./target/vk -o "${ZK_CONTRACTS_DIR}/OptimizedZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -s "${SCHEME}" --disable_zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz --oracle_hash "${ORACLE_HASH}" -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        bb write_solidity_verifier -s "${SCHEME}" --disable_zk --optimized -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/OptimizedPlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${PLAIN_OUTPUT_DIR}"
    elif [[ "${BB_VERSION}" =~ ^3\.0\.[1-3]$ ]]; then
        # Use noirup to 1.0.0-beta.17 for proof generation to work (earlier versions might also work).
        noirup -v 1.0.0-beta.17

        generate_prover_witness_and_compile

        # ZK variant
        bb prove -t evm -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz -o ./target --write_vk
        generate_zkv_artifacts "ZK" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -t evm -k ./target/vk -o "${ZK_CONTRACTS_DIR}/ZKVerifier.sol"
        bb write_solidity_verifier -t evm --optimized -k ./target/vk -o "${ZK_CONTRACTS_DIR}/OptimizedZKVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${ZK_OUTPUT_DIR}"

        # Plain (non-zk) variant
        bb prove -t evm-no-zk -b ./target/${PROJECT_NAME}.json -w ./target/${PROJECT_NAME}.gz -o ./target --write_vk
        generate_zkv_artifacts "Plain" "./target/proof" "./target/vk" "./target/public_inputs"
        bb write_solidity_verifier -t evm-no-zk -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/PlainVerifier.sol"
        bb write_solidity_verifier -t evm-no-zk --optimized -k ./target/vk -o "${PLAIN_CONTRACTS_DIR}/OptimizedPlainVerifier.sol"
        mv ./target/vk ./target/proof ./target/public_inputs ./target/vk_hash "${PLAIN_OUTPUT_DIR}"
    else
        echo "Unrecognized version: ${BB_VERSION}"
    fi
}

nargo new "${PROJECT_NAME}"

for v in "${VERSIONS[@]}"; do
    (cd "${PROJECT_NAME}" && generate_artifacts "${v}")
done