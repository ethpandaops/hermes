#!/usr/bin/env bash
set -euo pipefail

# Simple cleanup script

ENCLAVE_NAME="${1:-hermes-devnet}"

echo "Cleaning up enclave: $ENCLAVE_NAME"
kurtosis enclave rm -f $ENCLAVE_NAME

echo "Done!"