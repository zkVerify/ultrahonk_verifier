#!/usr/bin/env bash

NOIR_VERSION="1.0.0-beta.17"
BB_VERSION="3.0.3"

set -e

if [ $# -ne 2 ]; then
  echo "Usage: $0 <number_of_public_inputs> <padding>"
  exit 1
fi

N=$1
PADDING=$2

if ! [[ "${N}" =~ ^[0-9]+$ ]] || [ "${N}" -le 0 ]; then
  echo "Error: number_of_public_inputs must be a positive integer"
  exit 1
fi

if ! [[ "${PADDING}" =~ ^[0-9]+$ ]]; then
  echo "Error: padding must be a non-negative integer"
  exit 1
fi

PROJECT_NAME="hello_test_${N}_pad_${PADDING}"

########################################
# Clean existing project (if any)
########################################

if [ -d "${PROJECT_NAME}" ]; then
  echo "Removing existing project directory: ${PROJECT_NAME}"
  rm -rf "${PROJECT_NAME}"
fi

########################################
# Work inside a subshell so cwd is restored
########################################

(
  noirup -v "${NOIR_VERSION}"
  bbup -v "${BB_VERSION}"

  echo "Creating Noir project: ${PROJECT_NAME}"
  nargo new "${PROJECT_NAME}"

  cd "${PROJECT_NAME}"

  echo "Running nargo check"
  nargo check

  ########################################
  # Generate src/main.nr
  ########################################

  echo "Generating src/main.nr with ${N} public input(s) and padding=${PADDING}"

  # Function arguments
  ARGS=""
  for ((i=1; i<=PADDING; i++)); do
    ARGS+="x${i}: Field, "
  done
  for i in $(seq 1 "${N}"); do
    ARGS+="y${i}: pub Field, "
  done

  # Normal asserts
  ASSERTS=""
  for ((i=1; i<=PADDING; i++)); do
    ASSERTS+="    assert(0 != x${i});\n"
  done
  for i in $(seq 1 "${N}"); do
    ASSERTS+="    assert(0 != y${i});\n"
  done

  # Test arguments
  TEST_ARGS=""
  for ((i=1; i<=PADDING; i++)); do
    TEST_ARGS+="${i}, "
  done
  for i in $(seq 1 "${N}"); do
    TEST_ARGS+="${i}, "
  done

  # Generate main.nr with loop for padding
  cat <<EOF > src/main.nr
fn main(${ARGS}) {
$(printf "${ASSERTS}")
}

#[test]
fn test_main() {
    main(${TEST_ARGS});
}
EOF

  ########################################
  # Populate Prover.toml
  ########################################

  echo "Populating Prover.toml"

  {
    for ((i=1; i<=PADDING; i++)); do
      echo "x${i} =\"${i}\""
    done
    for i in $(seq 1 "$N"); do
      echo "y${i} = \"${i}\""
    done
  } > Prover.toml

  echo "Project '${PROJECT_NAME}' setup complete."

  ########################################
  # Execute and generate contracts
  ########################################

  nargo execute

  CONTRACTS_DIR=contracts
  ARTIFACTS_DIR="artifacts"

  mkdir -p "${CONTRACTS_DIR}"

  for flavor in zk plain; do
    case "${flavor}" in
      zk)
        bb_target=evm
        verifier_prefix=ZKVerifier
        ;;
      plain)
        bb_target=evm-no-zk
        verifier_prefix=PlainVerifier
        ;;
    esac

    mkdir -p "${ARTIFACTS_DIR}/${flavor}"

    bb write_vk \
      -t "$bb_target" \
      -b "./target/${PROJECT_NAME}.json" \
      -o ./target

    bb prove \
      -t "${bb_target}" \
      -b "./target/${PROJECT_NAME}.json" \
      -w "./target/${PROJECT_NAME}.gz" \
      -o ./target
    
    bb verify \
      -p ./target/proof \
      -k ./target/vk \
      -i ./target/public_inputs \
      -t "${bb_target}"

    bb write_solidity_verifier \
      -t "${bb_target}" \
      -k ./target/vk \
      -o "${CONTRACTS_DIR}/${verifier_prefix}_${N}_pad_${PADDING}.sol"

    mv target/proof         "${ARTIFACTS_DIR}/${flavor}/proof"
    mv target/vk            "${ARTIFACTS_DIR}/${flavor}/vk"
    mv target/public_inputs "${ARTIFACTS_DIR}/${flavor}/pubs"
  done
)

echo
echo "All done."
echo "Project '${PROJECT_NAME}' is ready."