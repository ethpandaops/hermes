# Hermes Devnet Testing Scripts

Simple scripts to test Hermes against local Kurtosis devnets.

## Scripts

- `spin-up-network.sh [basic|matrix]` - Start a Kurtosis network and show connection info
- `run-hermes.sh` - Run Hermes against the running devnet
- `cleanup.sh [enclave-name]` - Stop and remove the devnet

## Quick Start

```bash
# Start a basic network
./hack/spin-up-network.sh basic

# In another terminal, run Hermes
./hack/run-hermes.sh

# When done, cleanup
./hack/cleanup.sh
```

## Matrix Testing

To test against multiple consensus clients:

```bash
./hack/spin-up-network.sh matrix
```

## Custom Enclave Names

```bash
# Use a custom enclave name
ENCLAVE_NAME=my-test ./hack/run-hermes.sh

# Cleanup custom enclave
./hack/cleanup.sh my-test
```