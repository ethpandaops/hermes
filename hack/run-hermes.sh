#!/usr/bin/env bash
set -euo pipefail

# Simple script to run Hermes against the devnet

ENCLAVE_NAME="${ENCLAVE_NAME:-hermes-devnet}"

echo "[INFO] Starting run-hermes.sh script..."
echo "[INFO] Enclave name: $ENCLAVE_NAME"

# Check if enclave exists
echo "[INFO] Checking if enclave exists..."
if ! kurtosis enclave inspect $ENCLAVE_NAME >/dev/null 2>&1; then
    echo "[ERROR] Enclave '$ENCLAVE_NAME' not found. Run ./spin-up-network.sh first"
    exit 1
fi
echo "[INFO] Enclave found!"

# Get Apache URL
echo "[INFO] Looking for Apache service..."
APACHE_INFO=$(kurtosis enclave inspect $ENCLAVE_NAME | grep -A3 "apache" | grep "http.*->")
if [ -z "$APACHE_INFO" ]; then
    echo "[ERROR] Apache service not found in enclave"
    echo "[ERROR] Make sure your Kurtosis config includes 'apache' in additional_services"
    exit 1
fi

APACHE_PORT=$(echo "$APACHE_INFO" | awk -F'-> ' '{print $2}')
APACHE_URL="http://${APACHE_PORT}"
echo "[INFO] Apache URL: $APACHE_URL"

# Test Apache connectivity
echo "[INFO] Testing Apache connectivity..."
if ! curl -s "${APACHE_URL}/cl/genesis.ssz" >/dev/null 2>&1; then
    echo "[WARN] Apache might not be ready yet, waiting 5 seconds..."
    sleep 5
    if ! curl -s "${APACHE_URL}/cl/genesis.ssz" >/dev/null 2>&1; then
        echo "[ERROR] Apache is not serving files at $APACHE_URL"
        exit 1
    fi
fi
echo "[INFO] Apache is serving files successfully!"

# Get Prysm ports
echo "[INFO] Getting Prysm service information..."
PRYSM_INFO=$(kurtosis enclave inspect $ENCLAVE_NAME | grep -A10 "prysm" | grep -E "(rpc:|http:)")
echo "[DEBUG] Prysm info raw:"
echo "$PRYSM_INFO"

PRYSM_GRPC=$(echo "$PRYSM_INFO" | grep "rpc:" | head -1 | awk -F'-> ' '{print $2}' | cut -d: -f2)
PRYSM_HTTP=$(echo "$PRYSM_INFO" | grep "http:" | head -1 | awk -F'-> ' '{print $2}' | sed 's/http:\/\///' | cut -d: -f2)

echo "[INFO] Prysm gRPC port: $PRYSM_GRPC"
echo "[INFO] Prysm HTTP port: $PRYSM_HTTP"

echo ""
echo "=== Connecting to devnet ==="
echo "  Apache: $APACHE_URL"
echo "  Prysm gRPC: 127.0.0.1:$PRYSM_GRPC"
echo "  Prysm HTTP: 127.0.0.1:$PRYSM_HTTP"
echo ""

# Run Hermes
echo "[INFO] Starting Hermes..."
echo "[DEBUG] Command: go run ./cmd/hermes --log.level=warn eth --prysm.host=127.0.0.1 --prysm.port.grpc=${PRYSM_GRPC} --prysm.port.http=${PRYSM_HTTP} --chain=devnet --genesis.ssz.url=${APACHE_URL}/cl/genesis.ssz --config.yaml.url=${APACHE_URL}/cl/config.yaml --bootnodes.yaml.url=${APACHE_URL}/cl/bootnodes.yaml --deposit-contract-block.txt.url=${APACHE_URL}/cl/deposit_contract_block.txt"

exec go run ./cmd/hermes --log.level=warn eth \
  --prysm.host=127.0.0.1 \
  --prysm.port.grpc=${PRYSM_GRPC} \
  --prysm.port.http=${PRYSM_HTTP} \
  --chain=devnet \
  --genesis.ssz.url=${APACHE_URL}/cl/genesis.ssz \
  --config.yaml.url=${APACHE_URL}/cl/config.yaml \
  --bootnodes.yaml.url=${APACHE_URL}/cl/bootnodes.yaml \
  --deposit-contract-block.txt.url=${APACHE_URL}/cl/deposit_contract_block.txt \
  "$@"