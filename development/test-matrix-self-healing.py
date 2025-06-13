#!/usr/bin/env python3
"""
Self-healing test script for Hermes that uses Claude to automatically debug and fix connection issues.
"""

import argparse
import asyncio
import json
import subprocess
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml

try:
    from claude_code_sdk import query, ClaudeCodeOptions
except ImportError:
    print("Error: claude_code_sdk not installed. Install with: pip install claude-code-sdk")
    sys.exit(1)

from test_matrix import HermesMatrixTest


class SelfHealingHermesTest:
    """Self-healing wrapper around HermesMatrixTest that uses Claude to fix issues."""
    
    def __init__(self, duration: int = 300, max_iterations: int = 5):
        self.duration = duration
        self.max_iterations = max_iterations
        self.iteration = 0
        self.attempts_log_file = f"hermes-healing-attempts-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        self.attempts = []
        self.project_root = Path(__file__).parent.parent
        
    def log(self, message: str, level: str = "INFO"):
        """Print timestamped log message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def save_attempt(self, attempt_data: dict):
        """Save attempt data to log file."""
        self.attempts.append(attempt_data)
        with open(self.attempts_log_file, 'w') as f:
            json.dump(self.attempts, f, indent=2)
            
    def get_git_status(self) -> Dict[str, List[str]]:
        """Get current git status."""
        try:
            # Get modified files
            modified = subprocess.run(
                ["git", "diff", "--name-only"],
                capture_output=True, text=True, cwd=self.project_root
            ).stdout.strip().split('\n') if subprocess.run(
                ["git", "diff", "--name-only"],
                capture_output=True, text=True, cwd=self.project_root
            ).stdout.strip() else []
            
            # Get staged files
            staged = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True, text=True, cwd=self.project_root
            ).stdout.strip().split('\n') if subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True, text=True, cwd=self.project_root
            ).stdout.strip() else []
            
            return {
                "modified": [f for f in modified if f],
                "staged": [f for f in staged if f]
            }
        except Exception as e:
            self.log(f"Failed to get git status: {e}", "ERROR")
            return {"modified": [], "staged": []}
            
    def reset_changes(self):
        """Reset any changes made during this iteration."""
        self.log("Resetting changes from failed attempt...")
        try:
            # Reset all changes
            subprocess.run(
                ["git", "reset", "--hard", "HEAD"],
                cwd=self.project_root,
                check=True
            )
            self.log("Changes reset successfully")
        except Exception as e:
            self.log(f"Failed to reset changes: {e}", "ERROR")
            
    async def run_claude_analysis(self, test_results: dict) -> Optional[str]:
        """Run Claude analysis on test results and get suggested fixes."""
        self.log(f"Running Claude analysis (iteration {self.iteration + 1}/{self.max_iterations})...")
        
        # Build context about previous attempts
        previous_attempts_summary = ""
        if self.attempts:
            previous_attempts_summary = "\n\nPrevious attempts that failed:\n"
            for i, attempt in enumerate(self.attempts):
                previous_attempts_summary += f"\nAttempt {i+1}:\n"
                previous_attempts_summary += f"- Approach: {attempt.get('approach', 'Unknown')}\n"
                previous_attempts_summary += f"- Changes made: {', '.join(attempt.get('files_modified', []))}\n"
                previous_attempts_summary += f"- Result: {attempt.get('result', 'Failed')}\n"
                if attempt.get('error'):
                    previous_attempts_summary += f"- Error: {attempt['error']}\n"
        
        # Build the prompt
        prompt = f"""
You are debugging a Hermes connectivity issue. Hermes needs to connect to all consensus layer clients in a Kurtosis devnet.

Current test results:
- Connected clients: {test_results.get('connected_clients', [])}
- Missing clients: {test_results.get('missing_clients', [])}
- Total peers: {test_results.get('total_peers', 0)}
- Active peers: {test_results.get('active_peers', 0)}
- Hermes peer ID: {test_results.get('hermes_peer_id', 'Unknown')}

Bootnode ENRs found: {len(test_results.get('bootnode_enrs', []))}
Beacon node peer IDs collected: {len(test_results.get('beacon_peer_ids', {}))}

Key log excerpts from Hermes:
{test_results.get('hermes_log_excerpt', 'No logs available')}

Key log excerpts from missing clients:
{test_results.get('missing_client_logs', 'No logs available')}

{previous_attempts_summary}

Your task is to:
1. Analyze why Hermes is not connecting to the missing clients
2. Suggest and implement a fix by modifying the Hermes source code
3. Focus on files in the eth/ directory, particularly around libp2p connection logic
4. Consider checking consensus-specs for any protocol specifics
5. DO NOT repeat approaches that have already failed

You can inspect consensus client implementations or the consensus-specs repository for guidance.

Please provide:
1. A brief analysis of the likely issue
2. The specific changes you want to make
3. A one-line summary of your approach (for logging)

Remember: Each client may have slightly different p2p behavior, handshake requirements, or discovery mechanisms.
"""
        
        options = ClaudeCodeOptions(
            max_turns=3,
            system_prompt="""You are an expert in Ethereum consensus layer protocols and p2p networking. 
You are helping debug why Hermes cannot connect to certain consensus clients.
You have deep knowledge of libp2p, discv5, and consensus layer specifications.
When you make changes, be precise and test-oriented. Focus on the root cause.""",
            cwd=self.project_root,
            allowed_tools=["Read", "Write", "Bash", "Grep", "Glob"],
            permission_mode="auto"
        )
        
        try:
            response = ""
            async for message in query(prompt=prompt, options=options):
                response = message  # Get the last message
                
            return response
        except Exception as e:
            self.log(f"Claude analysis failed: {e}", "ERROR")
            return None
            
    def extract_test_results(self, log_file: str, json_file: str) -> dict:
        """Extract relevant test results for Claude analysis."""
        results = {
            "connected_clients": [],
            "missing_clients": [],
            "total_peers": 0,
            "active_peers": 0,
            "hermes_peer_id": None,
            "bootnode_enrs": [],
            "beacon_peer_ids": {},
            "hermes_log_excerpt": "",
            "missing_client_logs": ""
        }
        
        # Run a quick test to gather data
        test = HermesMatrixTest(60, log_file, use_existing_network=True)  # Short 60s test
        
        try:
            # Get service info
            test.get_service_info()
            
            # Get bootnode ENRs
            results["bootnode_enrs"] = test.fetch_bootnode_enrs()
            
            # Get beacon peer IDs
            results["beacon_peer_ids"] = test.get_beacon_node_peer_ids()
            
            # Start Hermes and run brief test
            test.start_hermes()
            test.run_test()
            
            # Extract results
            results["connected_clients"] = list(test.get_connected_clients())
            results["missing_clients"] = list(set(test.expected_clients) - set(results["connected_clients"]))
            results["total_peers"] = len(test.peer_connections)
            results["active_peers"] = len(test.get_active_peers())
            results["hermes_peer_id"] = test.hermes_peer_id
            
            # Get log excerpts
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    # Get last 50 lines with errors or warnings
                    error_lines = [l for l in lines if 'error' in l.lower() or 'warn' in l.lower()]
                    results["hermes_log_excerpt"] = ''.join(error_lines[-20:])
            except:
                pass
                
            # Cleanup
            test.cleanup()
            
        except Exception as e:
            self.log(f"Failed to extract test results: {e}", "ERROR")
            
        return results
        
    async def run_iteration(self):
        """Run one iteration of the self-healing test."""
        self.iteration += 1
        self.log(f"\n{'='*60}")
        self.log(f"Starting self-healing iteration {self.iteration}/{self.max_iterations}")
        self.log(f"{'='*60}\n")
        
        # Track what we're doing
        attempt_data = {
            "iteration": self.iteration,
            "timestamp": datetime.now().isoformat(),
            "approach": None,
            "files_modified": [],
            "result": None,
            "error": None
        }
        
        # Get initial git status
        initial_git_status = self.get_git_status()
        
        # Run initial test
        log_file = f"hermes-test-iter{self.iteration}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
        json_file = log_file.replace('.log', '.json')
        
        self.log("Running diagnostic test...")
        test_results = self.extract_test_results(log_file, json_file)
        
        # Check if all clients are connected
        if not test_results["missing_clients"]:
            self.log("SUCCESS: All clients are connected!", "SUCCESS")
            attempt_data["result"] = "success"
            self.save_attempt(attempt_data)
            return True
            
        # Run Claude analysis
        claude_response = await self.run_claude_analysis(test_results)
        
        if not claude_response:
            self.log("Claude analysis failed, skipping iteration", "ERROR")
            attempt_data["result"] = "claude_failed"
            attempt_data["error"] = "Claude analysis returned no response"
            self.save_attempt(attempt_data)
            return False
            
        # Extract approach summary from Claude's response (look for common patterns)
        if "approach:" in claude_response.lower():
            approach_line = [l for l in claude_response.split('\n') if 'approach:' in l.lower()]
            if approach_line:
                attempt_data["approach"] = approach_line[0].split(':', 1)[1].strip()
        else:
            attempt_data["approach"] = "Claude's approach (see logs)"
            
        self.log(f"Claude's approach: {attempt_data['approach']}")
        
        # Wait for Claude to make changes
        self.log("Waiting for Claude to implement changes...")
        await asyncio.sleep(5)
        
        # Check what files were modified
        final_git_status = self.get_git_status()
        attempt_data["files_modified"] = list(set(final_git_status["modified"] + final_git_status["staged"]))
        
        if not attempt_data["files_modified"]:
            self.log("No files were modified by Claude", "WARN")
            attempt_data["result"] = "no_changes"
            self.save_attempt(attempt_data)
            return False
            
        self.log(f"Files modified: {', '.join(attempt_data['files_modified'])}")
        
        # Rebuild Hermes with changes
        self.log("Rebuilding Hermes with changes...")
        build_result = subprocess.run(
            ["go", "build", "./cmd/hermes"],
            cwd=self.project_root,
            capture_output=True,
            text=True
        )
        
        if build_result.returncode != 0:
            self.log("Build failed!", "ERROR")
            self.log(f"Error: {build_result.stderr}")
            attempt_data["result"] = "build_failed"
            attempt_data["error"] = build_result.stderr[:500]
            self.save_attempt(attempt_data)
            self.reset_changes()
            return False
            
        # Run full test with changes
        self.log("Running full test with changes...")
        full_test = HermesMatrixTest(
            self.duration, 
            f"hermes-test-iter{self.iteration}-full.log",
            use_existing_network=True
        )
        
        try:
            result = full_test.run()
            if result == 0:
                self.log("SUCCESS: Test passed with Claude's changes!", "SUCCESS")
                attempt_data["result"] = "success"
                self.save_attempt(attempt_data)
                
                # Save the successful changes
                self.log("Saving successful changes...")
                subprocess.run(
                    ["git", "add", "-A"],
                    cwd=self.project_root
                )
                subprocess.run(
                    ["git", "commit", "-m", f"Self-healing: {attempt_data['approach']}"],
                    cwd=self.project_root
                )
                return True
            else:
                self.log("Test still failing after changes", "WARN")
                attempt_data["result"] = "test_failed"
                connected = list(full_test.get_connected_clients())
                missing = list(set(full_test.expected_clients) - set(connected))
                attempt_data["error"] = f"Still missing: {missing}"
                self.save_attempt(attempt_data)
                self.reset_changes()
                return False
                
        except Exception as e:
            self.log(f"Test execution failed: {e}", "ERROR")
            attempt_data["result"] = "execution_failed"
            attempt_data["error"] = str(e)
            self.save_attempt(attempt_data)
            self.reset_changes()
            return False
            
    async def run(self):
        """Run the self-healing test loop."""
        self.log("Starting self-healing Hermes test")
        self.log(f"Max iterations: {self.max_iterations}")
        self.log(f"Test duration per iteration: {self.duration}s")
        self.log(f"Attempts log: {self.attempts_log_file}")
        
        # Ensure we have a network running
        enclave_check = subprocess.run(
            ["kurtosis", "enclave", "inspect", "hermes-devnet"],
            capture_output=True
        )
        
        if enclave_check.returncode != 0:
            self.log("No existing network found, creating one...")
            subprocess.run([
                os.path.join(Path(__file__).parent, "spin-up-network.sh"),
                "matrix"
            ])
            self.log("Waiting for network to stabilize...")
            time.sleep(30)
            
        # Run iterations
        for i in range(self.max_iterations):
            success = await self.run_iteration()
            if success:
                self.log("\n🎉 Self-healing successful! All clients connected.")
                self.log(f"Total iterations needed: {self.iteration}")
                self.log(f"See {self.attempts_log_file} for details")
                return 0
                
            if i < self.max_iterations - 1:
                self.log(f"\nIteration {self.iteration} failed, trying again...")
                await asyncio.sleep(10)  # Brief pause between iterations
                
        self.log("\n❌ Self-healing failed after all iterations")
        self.log(f"See {self.attempts_log_file} for attempted approaches")
        return 1


async def main():
    parser = argparse.ArgumentParser(
        description="Self-healing test for Hermes using Claude to fix connectivity issues"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=300,
        help="Test duration in seconds for validation (default: 300)"
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        help="Maximum number of self-healing iterations (default: 5)"
    )
    
    args = parser.parse_args()
    
    test = SelfHealingHermesTest(args.duration, args.max_iterations)
    result = await test.run()
    sys.exit(result)


if __name__ == "__main__":
    asyncio.run(main())