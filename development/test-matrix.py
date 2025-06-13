#!/usr/bin/env python3
"""
Test script for validating Hermes can connect to all consensus clients in a Kurtosis devnet.
"""

import argparse
import json
import subprocess
import time
import signal
import sys
import os
import threading
import queue
import re
import yaml
import requests
from datetime import datetime
from collections import defaultdict
from typing import Dict, Set, List, Optional

class HermesMatrixTest:
    def __init__(self, duration: int, log_file: str, use_existing_network: bool = False):
        self.duration = duration
        self.log_file = log_file
        self.json_file = log_file.replace('.log', '.json')
        self.enclave_name = "hermes-devnet"
        self.use_existing_network = use_existing_network
        self.hermes_process = None
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(self.script_dir)
        
        # Metrics tracking
        self.peer_connections: Dict[str, Set[str]] = defaultdict(set)  # peer_id -> set of event types
        self.peer_last_seen: Dict[str, float] = {}  # peer_id -> timestamp
        self.event_counts: Dict[str, int] = defaultdict(int)  # event_type -> count
        self.client_types: Dict[str, str] = {}  # peer_id -> client_type
        self.expected_clients = []  # Will be discovered from network
        self.discovered_participants = {}  # service_name -> client_type
        self.hermes_peer_id = None  # Will be extracted from logs
        
        # Threading for output processing
        self.output_queue = queue.Queue()
        self.stop_processing = threading.Event()
        
    def log(self, message: str, level: str = "INFO"):
        """Print timestamped log message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def cleanup(self):
        """Clean up resources on exit."""
        self.log("Cleaning up...")
        
        # Stop output processing
        self.stop_processing.set()
        
        # Stop Hermes
        if self.hermes_process and self.hermes_process.poll() is None:
            self.log(f"Stopping Hermes (PID: {self.hermes_process.pid})...")
            self.hermes_process.terminate()
            time.sleep(2)
            if self.hermes_process.poll() is None:
                self.hermes_process.kill()
                
        # Stop Kurtosis network only if we created it
        if not self.use_existing_network:
            self.log("Stopping Kurtosis network...")
            subprocess.run(["kurtosis", "enclave", "rm", "-f", self.enclave_name], 
                          capture_output=True)
        
        self.log("Cleanup complete")
        
    def start_network(self):
        """Start Kurtosis network with matrix configuration."""
        self.log("Starting Kurtosis network with matrix configuration...")
        self.log("This may take a few minutes...")
        
        spin_up_script = os.path.join(self.script_dir, "spin-up-network.sh")
        result = subprocess.run([spin_up_script, "matrix"], capture_output=True, text=True)
        
        if result.returncode != 0:
            self.log(f"Failed to start network: {result.stderr}", "ERROR")
            sys.exit(1)
            
        # Wait for network to stabilize
        self.log("Waiting 30s for network to stabilize...")
        time.sleep(30)
        
    def get_service_info(self):
        """Discover all services in the network."""
        result = subprocess.run(
            ["kurtosis", "enclave", "inspect", self.enclave_name],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            self.log("Failed to inspect enclave", "ERROR")
            sys.exit(1)
            
        lines = result.stdout.split('\n')
        
        # Find Apache
        apache_url = None
        for line in lines:
            if "apache" in line and "http:" in line:
                # Extract the URL from format: http: 80/tcp -> http://127.0.0.1:32844
                parts = line.split('->')
                if len(parts) > 1:
                    apache_url = parts[1].strip().split()[0]
                    break
                    
        if not apache_url:
            self.log("Apache service not found", "ERROR")
            sys.exit(1)
            
        self.apache_url = apache_url
        self.log(f"Apache URL: {self.apache_url}")
        
        # Discover all consensus layer participants
        prysm_grpc = None
        prysm_http = None
        current_service = None
        
        for i, line in enumerate(lines):
            # Check if this is a consensus layer service
            if line.strip() and not line.startswith(' '):
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith('cl-'):
                    service_name = parts[1]
                    # Extract client type from service name (e.g., cl-1-prysm-geth -> prysm)
                    name_parts = service_name.split('-')
                    if len(name_parts) >= 3:
                        client_type = name_parts[2]
                        self.discovered_participants[service_name] = client_type
                        if client_type not in self.expected_clients:
                            self.expected_clients.append(client_type)
                        current_service = service_name
                else:
                    current_service = None
            
            # If we're in a cl- service section, look for ports
            if current_service and "prysm" in current_service:
                if "rpc:" in line and not prysm_grpc:
                    parts = line.split('->')
                    if len(parts) > 1:
                        prysm_grpc = parts[1].strip().split(':')[-1].split()[0]
                elif "http:" in line and "metrics" not in line and not prysm_http:
                    parts = line.split('->')
                    if len(parts) > 1:
                        port_info = parts[1].strip()
                        prysm_http = port_info.split(':')[-1].split()[0]
                            
        # We need at least one Prysm for delegation
        if not prysm_grpc or not prysm_http:
            # Find any Prysm service
            for service_name, client_type in self.discovered_participants.items():
                if client_type == "prysm":
                    self.log(f"Looking for Prysm ports in service {service_name}")
                    # Re-scan for this specific service
                    in_service = False
                    for line in lines:
                        if service_name in line:
                            in_service = True
                        elif in_service and line.strip() and not line.startswith(' '):
                            break
                        elif in_service:
                            if "rpc:" in line and not prysm_grpc:
                                parts = line.split('->')
                                if len(parts) > 1:
                                    prysm_grpc = parts[1].strip().split(':')[-1].split()[0]
                            elif "http:" in line and "metrics" not in line and not prysm_http:
                                parts = line.split('->')
                                if len(parts) > 1:
                                    port_info = parts[1].strip()
                                    prysm_http = port_info.split(':')[-1].split()[0]
                    if prysm_grpc and prysm_http:
                        break
                        
        if not prysm_grpc or not prysm_http:
            self.log("No Prysm service found for delegation!", "ERROR")
            sys.exit(1)
            
        self.prysm_grpc = prysm_grpc
        self.prysm_http = prysm_http
        self.log(f"Prysm gRPC: 127.0.0.1:{self.prysm_grpc}")
        self.log(f"Prysm HTTP: 127.0.0.1:{self.prysm_http}")
        
        # Log discovered participants
        self.log(f"Discovered {len(self.discovered_participants)} consensus layer participants:")
        for service, client in self.discovered_participants.items():
            self.log(f"  - {service}: {client}")
        self.log(f"Expected client types: {sorted(self.expected_clients)}")
        
    def fetch_bootnode_enrs(self) -> List[str]:
        """Fetch bootnode ENRs from the network config."""
        try:
            self.log("Fetching bootnode ENRs...")
            response = requests.get(f"{self.apache_url}/network-configs/boot_enr.yaml", timeout=10)
            response.raise_for_status()
            
            # Parse YAML
            data = yaml.safe_load(response.text)
            
            # Extract ENRs - could be in different formats
            enrs = []
            if isinstance(data, list):
                enrs = data
            elif isinstance(data, dict):
                # Check common keys
                for key in ['enrs', 'ENRs', 'bootnodes', 'boot_enr']:
                    if key in data:
                        if isinstance(data[key], list):
                            enrs = data[key]
                        else:
                            enrs = [data[key]]
                        break
            
            # Filter valid ENRs
            valid_enrs = [enr for enr in enrs if isinstance(enr, str) and enr.startswith('enr:')]
            self.log(f"Found {len(valid_enrs)} bootnode ENRs")
            return valid_enrs
            
        except Exception as e:
            self.log(f"Failed to fetch bootnode ENRs: {e}", "ERROR")
            return []
            
    def get_beacon_node_peer_ids(self) -> Dict[str, Optional[str]]:
        """Get peer IDs from beacon nodes via their API endpoints."""
        peer_ids = {}
        
        self.log("Fetching peer IDs from beacon nodes...")
        
        # Get all beacon node services
        result = subprocess.run(
            ["kurtosis", "enclave", "inspect", self.enclave_name],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            self.log("Failed to inspect enclave for beacon nodes", "ERROR")
            return peer_ids
            
        lines = result.stdout.split('\n')
        current_service = None
        
        for line in lines:
            # Check if this is a consensus layer service
            if line.strip() and not line.startswith(' '):
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith('cl-'):
                    current_service = parts[1]
                else:
                    current_service = None
            
            # If we're in a cl- service section, look for HTTP port
            if current_service and current_service in self.discovered_participants:
                if "http:" in line and "metrics" not in line:
                    parts = line.split('->')
                    if len(parts) > 1:
                        port_info = parts[1].strip()
                        port = port_info.split(':')[-1].split()[0]
                        
                        # Try to get peer ID from beacon node API
                        try:
                            url = f"http://127.0.0.1:{port}/eth/v1/node/identity"
                            response = requests.get(url, timeout=5)
                            
                            if response.status_code == 200:
                                data = response.json()
                                if 'data' in data and 'peer_id' in data['data']:
                                    peer_id = data['data']['peer_id']
                                    peer_ids[current_service] = peer_id
                                    self.log(f"  {current_service}: {peer_id}")
                            else:
                                self.log(f"  {current_service}: API returned {response.status_code}", "WARN")
                                
                        except Exception as e:
                            self.log(f"  {current_service}: Failed to get peer ID - {str(e)}", "WARN")
                            
        return peer_ids
        
    def process_json_line(self, line: str):
        """Process a line from stdout."""
        line = line.strip()
        if not line:
            return
            
        # Also check stdout for peer ID
        self.check_for_peer_id(line)
            
        # Check if this line is JSON
        if line.startswith('{') and '"Type"' in line:
            try:
                event = json.loads(line)
                self.process_event(event)
                # Save JSON events to file
                with open(self.json_file, 'a') as f:
                    f.write(line + '\n')
            except json.JSONDecodeError:
                # Not JSON, save to regular log
                with open(self.log_file, 'a') as f:
                    f.write(line + '\n')
        else:
            # Regular log line from stdout
            with open(self.log_file, 'a') as f:
                f.write(line + '\n')
                
    def check_for_peer_id(self, line: str):
        """Check a line for Hermes peer ID."""
        if self.hermes_peer_id:
            return
            
        # Just look for HERMES_PEER_ID= and grab everything after it
        if "HERMES_PEER_ID=" in line:
            # Split on HERMES_PEER_ID= and take what's after
            parts = line.split("HERMES_PEER_ID=", 1)
            if len(parts) > 1:
                # Take the peer ID part and strip any whitespace or quotes
                peer_id = parts[1].strip().strip('"').strip("'")
                # Validate it looks like a peer ID (starts with 1 or 2, has enough length)
                if peer_id and peer_id[0] in ['1', '2'] and len(peer_id) >= 40:
                    self.hermes_peer_id = peer_id
                    self.log("=====================================")
                    self.log(f"HERMES PEER ID: {self.hermes_peer_id}")
                    self.log("=====================================")
                else:
                    self.log(f"[DEBUG] Found HERMES_PEER_ID but invalid format: {line}")
    
    def process_log_line(self, line: str):
        """Process a line from stderr."""
        line = line.strip()
        if not line:
            return
            
        # Check for peer ID
        self.check_for_peer_id(line)
            
        # Check if stderr has JSON events
        if line.startswith('{') and '"Type"' in line:
            try:
                event = json.loads(line)
                self.process_event(event)
                # Save JSON events to file
                with open(self.json_file, 'a') as f:
                    f.write(line + '\n')
            except json.JSONDecodeError:
                # Not JSON, save to regular log
                with open(self.log_file, 'a') as f:
                    f.write(line + '\n')
        else:
            # Regular log line
            with open(self.log_file, 'a') as f:
                f.write(line + '\n')
                
    def stdout_reader(self):
        """Thread function to read Hermes stdout (JSON events)."""
        while not self.stop_processing.is_set():
            if self.hermes_process and self.hermes_process.poll() is None:
                line = self.hermes_process.stdout.readline()
                if line:
                    self.output_queue.put(('stdout', line.decode('utf-8', errors='replace')))
            else:
                time.sleep(0.1)
                
    def stderr_reader(self):
        """Thread function to read Hermes stderr (logs)."""
        while not self.stop_processing.is_set():
            if self.hermes_process and self.hermes_process.poll() is None:
                line = self.hermes_process.stderr.readline()
                if line:
                    self.output_queue.put(('stderr', line.decode('utf-8', errors='replace')))
            else:
                time.sleep(0.1)
                
    def output_processor(self):
        """Thread function to process output queue."""
        while not self.stop_processing.is_set():
            try:
                stream_type, line = self.output_queue.get(timeout=0.1)
                if stream_type == 'stdout':
                    self.process_json_line(line)
                else:
                    self.process_log_line(line)
            except queue.Empty:
                continue
                
    def start_hermes(self):
        """Start Hermes process with output streaming."""
        self.log("Starting Hermes...")
        
        cmd = [
            "go", "run", "./cmd/hermes",
            "--log.level=info",
            "eth",
            "--prysm.host=127.0.0.1",
            f"--prysm.port.grpc={self.prysm_grpc}",
            f"--prysm.port.http={self.prysm_http}",
            "--libp2p.port=0",
            "--local.trusted.addr",
            "--chain=devnet",
            f"--genesis.ssz.url={self.apache_url}/network-configs/genesis.ssz",
            f"--config.yaml.url={self.apache_url}/network-configs/config.yaml",
            f"--bootnodes.yaml.url={self.apache_url}/network-configs/boot_enr.yaml",
            f"--deposit-contract-block.txt.url={self.apache_url}/network-configs/deposit_contract_block.txt"
        ]

        self.log(f"Hermes command: {' '.join(cmd)}")
        
        # Clear/create log files
        open(self.log_file, 'w').close()
        open(self.json_file, 'w').close()
        
        self.hermes_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.project_root
        )
        
        self.log(f"Hermes started with PID: {self.hermes_process.pid}")
        
        # Start output processing threads
        stdout_thread = threading.Thread(target=self.stdout_reader, daemon=True)
        stderr_thread = threading.Thread(target=self.stderr_reader, daemon=True)
        processor_thread = threading.Thread(target=self.output_processor, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        processor_thread.start()
        
        # Wait for Hermes peer ID with timeout
        self.log("Waiting for Hermes to start and announce its peer ID...")
        timeout = 60
        start_wait = time.time()
        last_progress_update = 0
        
        while True:
            elapsed = time.time() - start_wait
            elapsed_int = int(elapsed)
            
            # Check if we got the peer ID
            if self.hermes_peer_id:
                self.log(f"Got Hermes peer ID after {elapsed_int}s")
                break
                
            # Check timeout
            if elapsed >= timeout:
                self.log(f"Timeout waiting for Hermes peer ID after {timeout}s!", "ERROR")
                self.log(f"Check log file: {self.log_file}", "ERROR")
                sys.exit(1)
                
            # Check if process died
            if self.hermes_process.poll() is not None:
                self.log(f"Hermes died after {elapsed_int}s!", "ERROR")
                self.log(f"Check log file: {self.log_file}", "ERROR")
                sys.exit(1)
                
            # Progress update every 5 seconds
            if elapsed_int > last_progress_update and elapsed_int % 5 == 0:
                self.log(f"  ... still waiting ({elapsed_int}s elapsed)")
                last_progress_update = elapsed_int
                
            time.sleep(0.1)  # Check frequently
            
        # Give it a bit more time to fully initialize after peer ID
        self.log("Waiting 5s more for full initialization...")
        time.sleep(5)
            
    def process_event(self, event: dict):
        """Process a JSON event and update metrics."""
        event_type = event.get("Type")  # Changed from "Event" to "Type"
        if not event_type:
            return
            
        self.event_counts[event_type] += 1
        
        # Log first few events for debugging
        if sum(self.event_counts.values()) <= 5:
            self.log(f"[DEBUG] Event #{sum(self.event_counts.values())}: Type={event_type}, PeerID={event.get('PeerID', 'N/A')[:16]}...")
        
        # Extract peer information
        peer_id = None
        if "PeerID" in event:
            peer_id = event["PeerID"]
        elif "peer_id" in event:
            peer_id = event["peer_id"]
        elif "Peer" in event:
            peer_id = event["Peer"]
            
        if peer_id:
            self.peer_connections[peer_id].add(event_type)
            self.peer_last_seen[peer_id] = time.time()
            
            # Try to identify client type from event data
            # Check in the Data/Payload field for client info
            data = event.get("Data", {})
            if isinstance(data, dict):
                # Look for client info in various fields
                for field in ["Client", "client", "AgentVersion", "agent_version", "UserAgent", "user_agent"]:
                    if field in data:
                        client_info = str(data[field]).lower()
                        for client in self.expected_clients:
                            if client in client_info:
                                self.client_types[peer_id] = client
                                break
                                
            # Also check top-level fields
            for field in ["Client", "client", "AgentVersion", "agent_version", "UserAgent", "user_agent"]:
                if field in event:
                    client_info = str(event[field]).lower()
                    for client in self.expected_clients:
                        if client in client_info:
                            self.client_types[peer_id] = client
                            break
                            
    def get_active_peers(self, timeout: int = 60) -> Set[str]:
        """Get peers that have been seen recently."""
        current_time = time.time()
        active_peers = set()
        
        for peer_id, last_seen in self.peer_last_seen.items():
            if current_time - last_seen < timeout:
                active_peers.add(peer_id)
                
        return active_peers
        
    def get_connected_clients(self) -> Set[str]:
        """Get the set of client types we're connected to."""
        connected_clients = set()
        active_peers = self.get_active_peers()
        
        for peer_id in active_peers:
            if peer_id in self.client_types:
                connected_clients.add(self.client_types[peer_id])
                
        return connected_clients
        
    def run_test(self):
        """Run the main test loop."""
        self.log("=" * 50)
        self.log(f"Starting {self.duration}s test run...")
        self.log("=" * 50)
        
        start_time = time.time()
        last_peer_report = 0
        last_status_report = 0
        last_event_report = 0
        peer_report_interval = 15  # Report peers every 15 seconds
        status_report_interval = 30  # Full status every 30 seconds
        event_report_interval = 10  # Quick event count every 10 seconds
        
        while True:
            current_time = time.time()
            elapsed = int(current_time - start_time)
            
            if elapsed >= self.duration:
                break
                
            # Check if Hermes is still running
            if self.hermes_process.poll() is not None:
                self.log(f"Hermes process died after {elapsed}s!", "ERROR")
                return False
                
            # Quick event count every 10 seconds
            if elapsed - last_event_report >= event_report_interval:
                total_events = sum(self.event_counts.values())
                self.log(f"[{elapsed}s] Events: {total_events}, Peers seen: {len(self.peer_connections)}")
                last_event_report = elapsed
                
            # Report active peers every 15 seconds
            if elapsed - last_peer_report >= peer_report_interval:
                active_peers = self.get_active_peers()
                connected_clients = self.get_connected_clients()
                self.log(f"[{elapsed}s] Active peers: {len(active_peers)} (clients: {sorted(connected_clients)})")
                
                # Show which clients we're missing
                missing_clients = set(self.expected_clients) - connected_clients
                if missing_clients:
                    self.log(f"         Missing: {sorted(missing_clients)}")
                    
                last_peer_report = elapsed
                
            # Full status report every 30 seconds
            if elapsed - last_status_report >= status_report_interval:
                remaining = self.duration - elapsed
                self.log("--- Status Report ---")
                self.log(f"Progress: {elapsed}s / {self.duration}s ({remaining}s remaining)")
                self.log(f"Total events: {sum(self.event_counts.values())}")
                self.log(f"Unique peers: {len(self.peer_connections)}")
                self.log(f"Active peers (60s): {len(self.get_active_peers())}")
                
                # Show top event types
                top_events = sorted(self.event_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                if top_events:
                    self.log("Top events: " + ", ".join(f"{e[0]}:{e[1]}" for e in top_events))
                    
                last_status_report = elapsed
                
            time.sleep(1)
            
        return True
        
    def grep_participant_logs(self):
        """Grep through participant logs for Hermes peer ID."""
        if not self.hermes_peer_id:
            self.log("Cannot grep logs: Hermes peer ID not found", "WARN")
            return
            
        self.log("")
        self.log("=== Searching participant logs for Hermes peer ID ===")
        self.log(f"Looking for: {self.hermes_peer_id}")
        self.log("")
        
        # Get list of participant containers
        result = subprocess.run(
            ["kurtosis", "enclave", "inspect", self.enclave_name],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            self.log("Failed to inspect enclave for participant logs", "ERROR")
            return
            
        # Use discovered participants
        self.log(f"Found {len(self.discovered_participants)} consensus client containers")
        
        # Grep each participant's logs
        for container_name, client_type in self.discovered_participants.items():
            self.log(f"\n--- Checking {client_type} ({container_name}) ---")
            
            # Get logs from the container
            log_result = subprocess.run(
                ["kurtosis", "service", "logs", self.enclave_name, container_name, "-n", "5000"],
                capture_output=True, text=True
            )
            
            if log_result.returncode != 0:
                self.log(f"Failed to get logs from {container_name}", "ERROR")
                self.log(f"Error: {log_result.stderr}", "ERROR")
                continue
                
            # Search for Hermes peer ID in logs
            lines = log_result.stdout.split('\n')
            matches = []
            for i, line in enumerate(lines):
                if self.hermes_peer_id in line:
                    # Get context (5 lines before and after)
                    start = max(0, i - 5)
                    end = min(len(lines), i + 6)
                    context = lines[start:end]
                    matches.append((i, context))
                    
            if matches:
                self.log(f"Found {len(matches)} occurrences in {client_type} logs:")
                for line_num, context in matches[:3]:  # Show first 3 matches
                    self.log(f"\n  Line {line_num}:")
                    for ctx_line in context:
                        if self.hermes_peer_id in ctx_line:
                            self.log(f"  >>> {ctx_line[:200]}")
                        else:
                            self.log(f"      {ctx_line[:200]}")
            else:
                self.log(f"No occurrences found in {client_type} logs")
                
        self.log("\n=== End of participant log search ===\n")
        
    def search_hermes_logs_for_targets(self, bootnode_enrs: List[str], beacon_peer_ids: Dict[str, str]):
        """Search Hermes logs for bootnode ENRs and beacon node peer IDs."""
        self.log("")
        self.log("=== Searching Hermes logs for bootnode ENRs and beacon peer IDs ===")
        self.log("")
        
        # Read Hermes log files
        all_logs = []
        
        # Read regular log file
        try:
            with open(self.log_file, 'r') as f:
                all_logs.extend(f.readlines())
        except Exception as e:
            self.log(f"Failed to read log file: {e}", "ERROR")
            
        # Read JSON log file
        try:
            with open(self.json_file, 'r') as f:
                all_logs.extend(f.readlines())
        except Exception as e:
            self.log(f"Failed to read JSON log file: {e}", "ERROR")
            
        if not all_logs:
            self.log("No Hermes logs found to search", "WARN")
            return
            
        # Search for bootnode ENRs
        if bootnode_enrs:
            self.log("--- Searching for bootnode ENRs ---")
            for enr in bootnode_enrs:
                enr_short = enr[:20] + "..." + enr[-20:] if len(enr) > 45 else enr
                matches = []
                
                for i, line in enumerate(all_logs):
                    if enr in line:
                        matches.append((i, line.strip()))
                        
                if matches:
                    self.log(f"\nFound {len(matches)} occurrences of bootnode ENR: {enr_short}")
                    for line_num, line in matches[:3]:  # Show first 3 matches
                        self.log(f"  Line {line_num}: {line[:200]}")
                else:
                    self.log(f"\nNo occurrences found for bootnode ENR: {enr_short}")
                    
        # Search for beacon node peer IDs
        if beacon_peer_ids:
            self.log("\n--- Searching for beacon node peer IDs ---")
            for service, peer_id in beacon_peer_ids.items():
                if not peer_id:
                    continue
                    
                matches = []
                for i, line in enumerate(all_logs):
                    if peer_id in line:
                        matches.append((i, line.strip()))
                        
                if matches:
                    self.log(f"\nFound {len(matches)} occurrences of {service} peer ID: {peer_id}")
                    for line_num, line in matches[:3]:  # Show first 3 matches
                        self.log(f"  Line {line_num}: {line[:200]}")
                        
                        # Try to extract more context from JSON events
                        if line.startswith('{'):
                            try:
                                event = json.loads(line)
                                event_type = event.get('Type', event.get('Event', 'Unknown'))
                                self.log(f"    Event Type: {event_type}")
                                
                                # Show relevant fields
                                for field in ['Direction', 'Protocol', 'Error', 'State', 'Result']:
                                    if field in event:
                                        self.log(f"    {field}: {event[field]}")
                            except:
                                pass
                else:
                    self.log(f"\nNo occurrences found for {service} peer ID: {peer_id}")
                    
        self.log("\n=== End of Hermes log search ===\n")
    
    def analyze_results(self):
        """Analyze test results and determine pass/fail."""
        self.log("")
        self.log("Test run complete!")
        self.log("")
        
        # Stop output processing
        self.stop_processing.set()
        
        # Stop Hermes gracefully
        if self.hermes_process and self.hermes_process.poll() is None:
            self.log("Stopping Hermes...")
            self.hermes_process.terminate()
            time.sleep(5)
            
        # Wait for queue to empty
        time.sleep(2)
        
        # Analysis
        self.log("Analyzing results...")
        self.log("")
        
        total_peers = len(self.peer_connections)
        active_peers = len(self.get_active_peers())
        total_events = sum(self.event_counts.values())
        
        self.log("Event counts:")
        for event_type, count in sorted(self.event_counts.items()):
            self.log(f"  {event_type}: {count}")
            
        self.log("")
        self.log(f"Total unique peers: {total_peers}")
        self.log(f"Active peers (last 60s): {active_peers}")
        self.log(f"Total events: {total_events}")
        
        # Check client coverage
        connected_clients = self.get_connected_clients()
        
        self.log("")
        self.log("Client coverage:")
        all_clients_connected = True
        for client in self.expected_clients:
            if client in connected_clients:
                self.log(f"  ✓ {client}")
            else:
                self.log(f"  ✗ {client}")
                all_clients_connected = False
                
        # Summary
        self.log("")
        self.log("=" * 50)
        self.log("SUMMARY")
        self.log("=" * 50)
        self.log(f"Test duration: {self.duration}s")
        self.log(f"Regular logs: {self.log_file}")
        self.log(f"JSON events: {self.json_file}")
        self.log("")
        
        # Pass/fail criteria
        passed = True
        reasons = []
        
        if active_peers < 5:  # Should have at least 5 peers for 6 clients
            passed = False
            reasons.append(f"Too few active peers ({active_peers})")
            
        if not all_clients_connected:
            passed = False
            missing = set(self.expected_clients) - connected_clients
            reasons.append(f"Missing clients: {missing}")
            
        if total_events < 100:  # Arbitrary minimum
            passed = False
            reasons.append(f"Too few events ({total_events})")
            
        if passed:
            self.log("Result: PASS ✓")
            self.log("Hermes successfully connected to all consensus clients")
            return True
        else:
            self.log("Result: FAIL ✗")
            for reason in reasons:
                self.log(f"  - {reason}")
                
            # On failure, gather debug info
            self.log("\n=== Gathering detailed failure information ===\n")
            
            # Grep participant logs for Hermes peer ID
            self.grep_participant_logs()
            
            # Fetch bootnode ENRs and beacon peer IDs
            bootnode_enrs = self.fetch_bootnode_enrs()
            beacon_peer_ids = self.get_beacon_node_peer_ids()
            
            # Search Hermes logs for these targets
            self.search_hermes_logs_for_targets(bootnode_enrs, beacon_peer_ids)
            
            return False
            
    def run(self):
        """Main entry point."""
        # Set up signal handler
        def signal_handler(sig, frame):
            _ = sig  # Unused but required by signal handler signature
            _ = frame  # Unused but required by signal handler signature
            self.log("Interrupted by user", "WARN")
            sys.exit(1)
            
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            if not self.use_existing_network:
                self.start_network()
            else:
                self.log("Using existing network, skipping network creation")
                
            self.get_service_info()
            self.start_hermes()
            
            test_passed = self.run_test()
            if test_passed:
                passed = self.analyze_results()
                return 0 if passed else 1
            else:
                return 1
                
        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Test Hermes against all consensus clients in a matrix configuration"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="How long to run the test in seconds (default: 300)"
    )
    parser.add_argument(
        "--log-file",
        default=f"hermes-test-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log",
        help="Where to save Hermes logs (without JSON events)"
    )
    parser.add_argument(
        "--use-existing-network",
        action="store_true",
        help="Use existing Kurtosis network instead of creating a new one"
    )
    
    args = parser.parse_args()
    
    test = HermesMatrixTest(args.duration, args.log_file, args.use_existing_network)
    sys.exit(test.run())


if __name__ == "__main__":
    main()