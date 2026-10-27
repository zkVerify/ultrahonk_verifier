#!/usr/bin/env bash

# Generates the per-log_n fixtures used by zkVerify's ultrahonk pallet tests and benchmarks:
#   <out_dir>/{zk,plain}/log_<n>/{vk,proof,pubs}
# for every n in [min_log_n, max_log_n], with NUM_PUBS public inputs (the runtime maximum).
#
# The circuit is padded with `acc = acc * x + 1` steps (one gate each). The padding is calibrated
# with `bb gates`, then the circuit's log_n is read back from the written vk of each flavor, so
# every fixture is known to have exactly the requested size. Every proof is checked with
# `bb verify`.
#
# bb must be the v5.0.0 *release* (or later): every 5.0.0 nightly still ships the pre-fix
# SmallSubgroupIPA. Set NARGO / BB to use specific binaries instead of the ones on PATH.

set -euo pipefail

if [ $# -ne 3 ]; then
  echo "Usage: $0 <out_dir> <min_log_n> <max_log_n>"
  exit 1
fi

OUT_DIR=$(realpath -m "$1")
MIN_LOG_N=$2
MAX_LOG_N=$3
NUM_PUBS=${NUM_PUBS:-32}

NARGO=${NARGO:-nargo}
BB=${BB:-bb}

WORK_DIR=$(mktemp -d)
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "Using $("${NARGO}" --version | head -1), bb $("${BB}" --version)"

# Writes a circuit with NUM_PUBS public inputs padded by $1 gates.
write_circuit() {
  local padding=$1
  {
    echo "global PAD_FACTOR: u32 = ${padding};"
    printf "fn main(x: Field"
    for i in $(seq 1 "${NUM_PUBS}"); do printf ", y%d: pub Field" "${i}"; done
    echo ") {"
    for i in $(seq 1 "${NUM_PUBS}"); do echo "    assert(x != y${i});"; done
    echo "    let mut acc: Field = 1;"
    echo "    for _ in 0..PAD_FACTOR {"
    echo "        acc = acc * x + 1;"
    echo "    }"
    echo "    assert(acc == 1);"
    echo "}"
  } > "${WORK_DIR}/fixture/src/main.nr"
}

# Runs bb quietly; on failure prints the command and bb's output, then fails.
run_bb() {
  local log
  log=$(mktemp -p "${WORK_DIR}")
  if ! "${BB}" "$@" > "${log}" 2>&1; then
    echo "bb $* failed:" >&2
    cat "${log}" >&2
    return 1
  fi
}

# Prints the log_n recorded in the vk file $1.
vk_log_n() {
  echo $((16#$(xxd -p -l 32 "$1" | tr -d '\n')))
}

# Prints the log_n of the circuit padded by $1 gates, as recorded in its vk.
log_n_for_padding() {
  write_circuit "$1"
  (
    cd "${WORK_DIR}/fixture"
    "${NARGO}" compile > /dev/null
    run_bb write_vk -t evm -b target/fixture.json -o target/calib
    vk_log_n target/calib/vk
  )
}

mkdir -p "${WORK_DIR}/fixture/src"
cat > "${WORK_DIR}/fixture/Nargo.toml" <<EOF
[package]
name = "fixture"
type = "bin"
authors = [""]

[dependencies]
EOF

{
  echo 'x = "0"'
  for i in $(seq 1 "${NUM_PUBS}"); do echo "y${i} = \"${i}\""; done
} > "${WORK_DIR}/fixture/Prover.toml"

for log_n in $(seq "${MIN_LOG_N}" "${MAX_LOG_N}"); do
  # Aim for 3/4 of the domain, then step until the vk reports the requested size.
  padding=$(( (3 << log_n) / 4 - 256 ))
  if [ "${padding}" -lt 0 ]; then padding=0; fi
  actual=$(log_n_for_padding "${padding}")
  while [ "${actual}" -ne "${log_n}" ]; do
    if [ "${actual}" -gt "${log_n}" ]; then
      if [ "${padding}" -eq 0 ]; then
        echo "log_n ${log_n} is unreachable with ${NUM_PUBS} public inputs (minimum ${actual})"
        exit 1
      fi
      padding=$(( padding / 2 ))
    else
      # Step by 1/8 of the domain, at least 1 (a negative shift would wrap for log_n < 3).
      step=$(( log_n >= 3 ? 1 << (log_n - 3) : 1 ))
      padding=$(( padding + step ))
    fi
    actual=$(log_n_for_padding "${padding}")
  done
  echo "log_n ${log_n}: padding ${padding}"

  (
    cd "${WORK_DIR}/fixture"
    "${NARGO}" execute > /dev/null
    for flavor in zk plain; do
      case "${flavor}" in
        zk) target=evm ;;
        plain) target=evm-no-zk ;;
      esac
      dest="${OUT_DIR}/${flavor}/log_${log_n}"
      mkdir -p "${dest}" target/out
      run_bb write_vk -t "${target}" -b target/fixture.json -o target/out
      # The padding is calibrated on the zk vk; check this flavor landed on the same size.
      flavor_log_n=$(vk_log_n target/out/vk)
      if [ "${flavor_log_n}" -ne "${log_n}" ]; then
        echo "  ${flavor}: vk has log_n ${flavor_log_n}, expected ${log_n}"
        exit 1
      fi
      run_bb prove -t "${target}" -b target/fixture.json -w target/fixture.gz \
        -k target/out/vk -o target/out
      if ! run_bb verify -t "${target}" -p target/out/proof -k target/out/vk \
        -i target/out/public_inputs; then
        echo "  ${flavor}: bb verify rejected the log_n ${log_n} proof" >&2
        exit 1
      fi
      cp target/out/vk "${dest}/vk"
      cp target/out/proof "${dest}/proof"
      cp target/out/public_inputs "${dest}/pubs"
      echo "  ${flavor}: proof $(wc -c < "${dest}/proof") B, verified by bb"
    done
  )
done
