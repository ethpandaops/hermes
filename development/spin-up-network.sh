#!/usr/bin/env bash
set -euo pipefail

# Simple script to spin up a Kurtosis network and show how to connect Hermes

CONFIG="${1:-basic}"
ENCLAVE_NAME="hermes-devnet"

# Validate config
if [[ "$CONFIG" != "basic" && "$CONFIG" != "matrix" ]]; then
    echo "Usage: $0 [basic|matrix]"
    exit 1
fi

echo "[INFO] Starting Kurtosis network with config: $CONFIG"

# Clean up any existing enclave
echo "[INFO] Cleaning up any existing enclave..."
kurtosis enclave rm -f $ENCLAVE_NAME 2>/dev/null || true

# Start the network
echo "[INFO] Running Kurtosis with config file: hack/kurtosis/${CONFIG}.yaml"
kurtosis run --enclave $ENCLAVE_NAME github.com/ethpandaops/ethereum-package \
    --args-file "$(dirname "$0")/kurtosis/${CONFIG}.yaml"

echo ""
echo "[INFO] Waiting for services to start..."
sleep 15

# Get Apache URL if available
echo "[INFO] Looking for Apache service..."
APACHE_INFO=$(kurtosis enclave inspect $ENCLAVE_NAME | grep -A3 "apache" | grep "http.*->" || true)
if [ -n "$APACHE_INFO" ]; then
    echo "[INFO] Apache service found!"
    APACHE_PORT=$(echo "$APACHE_INFO" | awk -F'-> ' '{print $2}')
    APACHE_URL="http://${APACHE_PORT}"
    
    # Test Apache is serving files
    echo "[INFO] Testing Apache service at $APACHE_URL..."
    if curl -s "${APACHE_URL}/cl/genesis.ssz" > /dev/null; then
        echo "[INFO] Apache is ready and serving files!"
    else
        echo "[WARN] Apache might not be ready yet, waiting 5 more seconds..."
        sleep 5
    fi
else
    echo "[WARN] Apache service not available. You'll need to extract config files manually."
    APACHE_URL="<APACHE_NOT_AVAILABLE>"
fi

# Get Prysm ports
echo "[INFO] Getting Prysm service information..."
PRYSM_INFO=$(kurtosis enclave inspect $ENCLAVE_NAME | grep -A10 "prysm" | grep -E "(rpc:|http:)")
echo "[DEBUG] Raw Prysm info:"
echo "$PRYSM_INFO"

PRYSM_GRPC=$(echo "$PRYSM_INFO" | grep "rpc:" | head -1 | awk -F'-> ' '{print $2}' | cut -d: -f2)
PRYSM_HTTP=$(echo "$PRYSM_INFO" | grep "http:" | head -1 | awk -F'-> ' '{print $2}' | sed 's/http:\/\///' | cut -d: -f2)

echo "[INFO] Found Prysm ports - gRPC: $PRYSM_GRPC, HTTP: $PRYSM_HTTP"

echo ""
echo "==============================================="
echo "           Network is ready!"
echo "==============================================="
echo ""

if [ "$APACHE_URL" != "<APACHE_NOT_AVAILABLE>" ]; then
    echo "Connect Hermes with:"
    echo ""
    echo "go run ./cmd/hermes --log.level=warn eth \\"
    echo "  --prysm.host=127.0.0.1 \\"
    echo "  --prysm.port.grpc=${PRYSM_GRPC} \\"
    echo "  --prysm.port.http=${PRYSM_HTTP} \\"
    echo "  --chain=devnet \\"
    echo "  --genesis.ssz.url=${APACHE_URL}/cl/genesis.ssz \\"
    echo "  --config.yaml.url=${APACHE_URL}/cl/config.yaml \\"
    echo "  --bootnodes.yaml.url=${APACHE_URL}/cl/bootnodes.yaml \\"
    echo "  --deposit-contract-block.txt.url=${APACHE_URL}/cl/deposit_contract_block.txt"
    echo ""
    echo "Apache service: $APACHE_URL"
    echo ""
    echo "Or simply run: ./hack/run-hermes.sh"
else
    echo "Prysm endpoints:"
    echo "  gRPC: 127.0.0.1:${PRYSM_GRPC}"
    echo "  HTTP: 127.0.0.1:${PRYSM_HTTP}"
    echo ""
    echo "To extract config files:"
    echo "  kurtosis files download $ENCLAVE_NAME el_cl_genesis_data ./devnet-config"
    echo ""
    echo "Then run:"
    echo "  ./hack/run-hermes.sh --use-local-config"
fi

echo ""
echo "To stop the network: kurtosis enclave rm -f $ENCLAVE_NAME"
echo "To view logs: kurtosis service logs $ENCLAVE_NAME <service-name>"