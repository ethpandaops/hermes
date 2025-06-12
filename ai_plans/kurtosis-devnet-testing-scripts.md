# Kurtosis Devnet Testing Scripts Implementation Plan

## Executive Summary

The Hermes project requires a streamlined testing workflow to validate its Ethereum network monitoring capabilities against local development networks. Currently, developers must manually orchestrate multiple steps: spinning up a Kurtosis-based Ethereum devnet, configuring network parameters, and launching Hermes with the correct connection details. This manual process is error-prone and time-consuming, particularly when testing against different client configurations.

This implementation plan outlines the creation of composable shell scripts that automate the entire testing workflow. The solution will provide developers with simple, reliable commands to spin up either a basic single-client network or a comprehensive multi-client matrix, automatically detect the host's local IPv4 address for NAT configuration, and seamlessly connect Hermes to the appropriate Prysm beacon node endpoints. By implementing proper error handling, service health checks, and cleanup procedures, these scripts will significantly reduce testing friction and enable rapid iteration during development.

The approach leverages existing Kurtosis configurations while adding intelligent automation layers that handle the complexities of network setup, service discovery, and connection management. This will enable developers to focus on Hermes functionality rather than infrastructure management, ultimately improving development velocity and test coverage.

## Goals & Objectives

### Primary Goals
- **Automated Testing Workflow**: Create a one-command solution to spin up a complete Ethereum devnet and run Hermes against it, reducing setup time from 15-20 minutes to under 2 minutes
- **Reliable Network Configuration**: Automatically detect and inject the host's local IPv4 address for NAT configuration, eliminating manual IP configuration errors
- **Network Connection Discovery**: Provide clear connection instructions with all required URLs for genesis, config, and bootnodes from the Apache service

### Secondary Objectives
- **Composable Script Architecture**: Design modular scripts that can be combined for different testing scenarios
- **Comprehensive Error Handling**: Implement fail-fast behavior with clear error messages to quickly identify issues
- **Support Multiple Network Configurations**: Enable testing against both simple (basic.yaml) and complex (matrix.yaml) network setups via command-line arguments

## Solution Overview

### Approach
The solution consists of a set of bash scripts organized in a composable architecture. A network management script handles Kurtosis lifecycle operations, including starting networks with dynamic NAT configuration and health checking. A separate Hermes runner script discovers Prysm endpoints from the running network and launches Hermes with appropriate configuration. An orchestrator script combines these components for single-command testing workflows.

The scripts utilize Kurtosis CLI commands for network management, jq for parsing JSON outputs, and standard Unix utilities for network detection and process management. All scripts implement strict error handling with `set -euo pipefail` to ensure failures are caught immediately. The architecture allows developers to use scripts individually for specific tasks or combined for end-to-end testing.

### Key Components
1. **spin-up-network.sh**: Starts Kurtosis network with chosen config, outputs connection instructions including Apache URLs
2. **kurtosis-network.sh**: Manages Kurtosis enclave lifecycle, handles NAT IP detection, and provides network information
3. **run-hermes.sh**: Discovers Prysm endpoints from running network, configures and launches Hermes with appropriate flags
4. **test-devnet.sh**: Orchestrates the complete workflow, combining network setup and Hermes execution
5. **Common Functions Library**: Shared utilities for logging, error handling, and service discovery

### Expected Outcomes
- **Reduced Testing Friction**: Developers can test Hermes against a full Ethereum devnet with a single command
- **Improved Reliability**: Automatic IP detection and health checks eliminate common configuration errors
- **Enhanced Developer Experience**: Clear logging and error messages make debugging straightforward
- **Flexible Testing Options**: Support for different network configurations enables comprehensive testing scenarios

## Implementation Tasks

### Phase 1: Foundation

- [ ] **Task 1.1**: Create common functions library
  - Files: `hack/lib/common.sh`
  - Key functions: logging utilities, error handling, IP detection
  - Dependencies: None
  - Implementation approach:
    ```bash
    # Core functions for reuse across scripts
    log_info() { echo "[INFO] $*" >&2; }
    log_error() { echo "[ERROR] $*" >&2; }
    detect_local_ip() { # Platform-specific IP detection }
    check_command() { # Verify required commands exist }
    ```

- [ ] **Task 1.2**: Implement NAT IP detection logic
  - Files: Update `hack/lib/common.sh`
  - Platform support: macOS (primary), Linux (secondary)
  - Key decisions: Use `ipconfig getifaddr en0` for macOS, `ip route` for Linux
  - Code example:
    ```bash
    detect_nat_exit_ip() {
        if [[ "$OSTYPE" == "darwin"* ]]; then
            ipconfig getifaddr en0 || ipconfig getifaddr en1
        else
            ip route get 1 | awk '{print $7;exit}'
        fi
    }
    ```

### Phase 2: Core Implementation

- [ ] **Task 2.1**: Create network spin-up script with connection info output
  - Files: `hack/spin-up-network.sh`
  - Dependencies: kurtosis CLI, jq
  - Key features: Start network, discover Apache URL, output Hermes connection command
  - Implementation approach:
    ```bash
    #!/usr/bin/env bash
    # Usage: ./spin-up-network.sh [--config basic|matrix] [--name <enclave-name>]
    # Outputs complete Hermes connection command with all URLs
    ```
  - Apache service discovery:
    ```bash
    get_apache_url() {
        local apache_port=$(kurtosis enclave inspect "$ENCLAVE_NAME" | \
            grep -A3 "apache" | grep "http.*36" | \
            awk -F'-> ' '{print $2}')
        echo "http://${apache_port}"
    }
    ```
  - Output format:
    ```bash
    # After network is up, output connection instructions:
    echo "Network is ready! Connect Hermes with:"
    echo ""
    echo "go run ./cmd/hermes --log.level=warn eth \\"
    echo "  --prysm.host=127.0.0.1 \\"
    echo "  --prysm.port.grpc=${PRYSM_GRPC_PORT} \\"
    echo "  --prysm.port.http=${PRYSM_HTTP_PORT} \\"
    echo "  --chain=devnet \\"
    echo "  --genesis.ssz.url=${APACHE_URL}/cl/genesis.ssz \\"
    echo "  --config.yaml.url=${APACHE_URL}/cl/config.yaml \\"
    echo "  --bootnodes.yaml.url=${APACHE_URL}/cl/bootnodes.yaml \\"
    echo "  --deposit-contract-block.txt.url=${APACHE_URL}/cl/deposit_contract_block.txt"
    ```

- [ ] **Task 2.2**: Create Kurtosis network management script
  - Files: `hack/kurtosis-network.sh`
  - Dependencies: kurtosis CLI, jq
  - Key features: start/stop/status commands, config selection, health checks
  - Implementation structure:
    ```bash
    #!/usr/bin/env bash
    # Commands: start, stop, status, info
    # Options: --config (basic|matrix), --name, --wait-healthy
    ```

- [ ] **Task 2.3**: Implement Prysm endpoint discovery
  - Files: Update `hack/kurtosis-network.sh`
  - Approach: Parse `kurtosis enclave inspect` output to find Prysm services
  - Output format: JSON with host, http_port, grpc_port
  - Code pattern:
    ```bash
    discover_prysm_endpoints() {
        kurtosis enclave inspect "$ENCLAVE_NAME" --output json | \
        jq '.services | to_entries | map(select(.key | contains("prysm")))'
    }
    ```

- [ ] **Task 2.4**: Create Hermes runner script
  - Files: `hack/run-hermes.sh`
  - Dependencies: Built hermes binary or go command
  - Key features: Auto-discovery of Prysm endpoints, configurable data streams
  - Options: --build (rebuild before run), --data-stream, --log-level

- [ ] **Task 2.5**: Implement test orchestrator script
  - Files: `hack/test-devnet.sh`
  - Combines: Network setup + Hermes execution
  - Features: Cleanup on exit, signal handling, parallel log tailing
  - Usage example:
    ```bash
    ./hack/test-devnet.sh --config basic --duration 300
    ```

### Phase 3: Integration & Testing

- [ ] **Task 3.1**: Add comprehensive error handling
  - All scripts: Add trap handlers for cleanup
  - Implement: Timeout mechanisms for network startup
  - Health checks: Verify Prysm is responding before starting Hermes

- [ ] **Task 3.2**: Create usage documentation
  - Files: `hack/README.md`
  - Content: Script descriptions, usage examples, troubleshooting guide
  - Examples for common scenarios

- [ ] **Task 3.3**: Add development helper scripts
  - Files: `hack/logs.sh`, `hack/cleanup.sh`
  - Features: Tail logs from all services, force cleanup of stuck resources
  - Integration with main scripts

- [ ] **Task 3.4**: Implement configuration validation
  - Validate: Kurtosis configs exist, required tools installed
  - Pre-flight checks: Network availability, port conflicts
  - User-friendly error messages with remediation steps

### Phase 4: Enhancement & Polish

- [ ] **Task 4.1**: Add multi-client testing support
  - Extend run-hermes.sh: Connect to multiple consensus clients
  - Feature: --client flag to select specific client from matrix
  - Default behavior: Connect to first available Prysm instance

- [ ] **Task 4.2**: Implement script composition examples
  - Files: `hack/examples/`
  - Scenarios: Long-running tests, client rotation, performance testing
  - Shell functions for common patterns

- [ ] **Task 4.3**: Add CI/CD integration hooks
  - Environment variable support: Override defaults for CI
  - Machine-readable output: --json flag for structured output
  - Exit codes: Meaningful codes for different failure scenarios

## Testing Strategy

### Unit Testing
- Test IP detection on different platforms
- Validate JSON parsing for various Kurtosis outputs
- Error handling verification

### Integration Testing
- Full workflow execution with basic.yaml
- Multi-client testing with matrix.yaml
- Cleanup verification after failures

### Performance Validation
- Measure startup time for different configurations
- Resource usage monitoring
- Hermes message throughput verification

## Risk Mitigation

### Technical Risks
- **Kurtosis API Changes**: Pin Kurtosis version, add version checks
- **Platform Differences**: Extensive testing on macOS and Linux
- **Network Conflicts**: Port availability checks, configurable port ranges

### Operational Risks
- **Resource Exhaustion**: Implement resource limits, cleanup procedures
- **Hung Processes**: Timeout mechanisms, force-kill options
- **Configuration Drift**: Version lock files for dependencies

## Usage Examples

### Spin Up Network Only
```bash
# Start basic network and get connection info
./hack/spin-up-network.sh --config basic

# Start matrix network with custom name
./hack/spin-up-network.sh --config matrix --name my-test-network

# Output includes complete Hermes command:
# Network is ready! Connect Hermes with:
# 
# go run ./cmd/hermes --log.level=warn eth \
#   --prysm.host=127.0.0.1 \
#   --prysm.port.grpc=4000 \
#   --prysm.port.http=3500 \
#   --chain=devnet \
#   --genesis.ssz.url=http://127.0.0.1:36000/cl/genesis.ssz \
#   --config.yaml.url=http://127.0.0.1:36000/cl/config.yaml \
#   --bootnodes.yaml.url=http://127.0.0.1:36000/cl/bootnodes.yaml \
#   --deposit-contract-block.txt.url=http://127.0.0.1:36000/cl/deposit_contract_block.txt
```

### Full Test Workflow
```bash
# Run complete test with basic config
./hack/test-devnet.sh --config basic --duration 300

# Run with matrix config and custom log level
./hack/test-devnet.sh --config matrix --log-level debug
```

### Individual Component Usage
```bash
# Just manage network lifecycle
./hack/kurtosis-network.sh start --config basic
./hack/kurtosis-network.sh status
./hack/kurtosis-network.sh stop

# Run Hermes against existing network
./hack/run-hermes.sh --enclave my-network --data-stream logger
```