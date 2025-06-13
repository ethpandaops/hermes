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

# No longer using claude_code_sdk - using subprocess directly

# Import from file with hyphen in name
import importlib.util
spec = importlib.util.spec_from_file_location(
    "test_matrix", 
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-matrix.py")
)
test_matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test_matrix)
HermesMatrixTest = test_matrix.HermesMatrixTest


class SelfHealingHermesTest:
    """Self-healing wrapper around HermesMatrixTest that uses Claude to fix issues."""
    
    def __init__(self, duration: int = 300, max_iterations: int = 5):
        self.duration = duration
        self.max_iterations = max_iterations
        self.iteration = 0
        
        # Set up logging directories and files
        self.run_id = datetime.now().strftime('%Y%m%d-%H%M%S')
        self.logs_base_dir = Path("./logs") / self.run_id
        self.logs_base_dir.mkdir(parents=True, exist_ok=True)
        
        self.attempts_log_file = self.logs_base_dir / "attempts.json"
        self.summary_file = self.logs_base_dir / "SUMMARY.md"
        self.attempts = []
        self.project_root = Path(__file__).parent.parent
        
        # Initialize summary file
        self.init_summary_file()
        
    def init_summary_file(self):
        """Initialize the human-readable summary file."""
        with open(self.summary_file, 'w') as f:
            f.write(f"# Hermes Self-Healing Test Run\n\n")
            f.write(f"**Run ID**: {self.run_id}\n")
            f.write(f"**Started**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Max Iterations**: {self.max_iterations}\n")
            f.write(f"**Test Duration**: {self.duration}s\n\n")
            f.write("## Iterations\n\n")
    
    def log(self, message: str, level: str = "INFO"):
        """Print timestamped log message."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def save_attempt(self, attempt_data: dict):
        """Save attempt data to log file."""
        self.attempts.append(attempt_data)
        with open(self.attempts_log_file, 'w') as f:
            json.dump(self.attempts, f, indent=2)
        
        # Also update the human-readable summary
        self.update_summary(attempt_data)
    
    def update_summary(self, attempt_data: dict):
        """Update the human-readable summary file with iteration results."""
        with open(self.summary_file, 'a') as f:
            f.write(f"### Iteration {attempt_data['iteration']}\n")
            f.write(f"**Time**: {attempt_data['timestamp']}\n")
            f.write(f"**Result**: {attempt_data['result']}\n")
            f.write(f"**Approach**: {attempt_data['approach']}\n\n")
            
            if attempt_data.get('files_modified'):
                f.write("**Files Modified**:\n")
                for file in attempt_data['files_modified']:
                    f.write(f"- `{file}`\n")
                f.write("\n")
            
            if attempt_data.get('error'):
                f.write(f"**Error**: {attempt_data['error']}\n\n")
            
            if attempt_data.get('test_results'):
                results = attempt_data['test_results']
                f.write("**Test Results**:\n")
                f.write(f"- Connected: {results.get('connected_clients', [])}\n")
                f.write(f"- Missing: {results.get('missing_clients', [])}\n")
                f.write(f"- Total Peers: {results.get('total_peers', 0)}\n\n")
            
            f.write("---\n\n")
            
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

IMPORTANT CONSTRAINTS:
- DO NOT run this Python script (test-matrix-self-healing.py) - it will create an infinite loop!
- DO NOT run Hermes directly - the test script will handle that
- You MAY build Hermes (go build ./cmd/hermes) ONLY to verify your changes compile correctly
- DO NOT execute any long-running processes or services

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
        
        # Use subprocess to call claude directly, similar to the reference script
        cmd = [
            "claude", "-p", "--dangerously-skip-permissions",
            "--verbose", "--output-format", "stream-json",
            prompt
        ]
        
        try:
            self.log("Running Claude analysis...", "INFO")
            
            # Run the claude command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.project_root
            )
            
            response_content = []
            
            # Read output line by line
            async for line in process.stdout:
                line_str = line.decode('utf-8').strip()
                if not line_str:
                    continue
                    
                try:
                    # Parse JSON output
                    json_obj = json.loads(line_str)
                    
                    # Extract content from assistant messages
                    if isinstance(json_obj, dict) and json_obj.get('type') == 'assistant':
                        message = json_obj.get('message', {})
                        if 'content' in message and isinstance(message['content'], list):
                            for item in message['content']:
                                if isinstance(item, dict) and item.get('type') == 'text':
                                    text = item.get('text', '').strip()
                                    if text:
                                        response_content.append(text)
                                        
                except json.JSONDecodeError:
                    # Not JSON, skip it
                    pass
                except Exception as e:
                    self.log(f"Error parsing Claude output: {e}", "WARNING")
            
            # Wait for process to complete
            await process.wait()
            
            if process.returncode != 0:
                stderr = await process.stderr.read()
                self.log(f"Claude command failed with exit code {process.returncode}", "ERROR")
                self.log(f"Error output: {stderr.decode('utf-8')}", "ERROR")
                sys.exit(1)
            
            # Join all response content
            response = '\n'.join(response_content)
            
            if not response:
                self.log("No response received from Claude", "ERROR")
                sys.exit(1)
                
            return response
            
        except Exception as e:
            self.log(f"Claude analysis failed: {e}", "ERROR")
            self.log(f"Error details: {type(e).__name__}: {str(e)}", "ERROR")
            import traceback
            self.log(f"Traceback:\n{traceback.format_exc()}", "ERROR")
            self.log("Exiting due to Claude failure.", "ERROR")
            sys.exit(1)
            
    def extract_test_results(self, log_file: str, json_file: str = None) -> dict:
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
        
        # Create iteration directory
        iter_dir = self.logs_base_dir / f"iteration-{self.iteration}"
        iter_dir.mkdir(exist_ok=True)
        
        # Track what we're doing
        attempt_data = {
            "iteration": self.iteration,
            "timestamp": datetime.now().isoformat(),
            "approach": None,
            "files_modified": [],
            "result": None,
            "error": None,
            "test_results": None,
            "claude_response": None,
            "iteration_dir": str(iter_dir)
        }
        
        # Get initial git status (for tracking changes)
        self.get_git_status()
        
        # Run initial test
        log_file = str(iter_dir / "diagnostic_test.log")
        json_file = str(iter_dir / "diagnostic_test.json")
        
        self.log("Running diagnostic test...")
        test_results = self.extract_test_results(log_file, json_file)
        attempt_data["test_results"] = test_results
        
        # Save test results
        with open(iter_dir / "test_results.json", 'w') as f:
            json.dump(test_results, f, indent=2)
        
        # Check if all clients are connected
        if not test_results["missing_clients"]:
            self.log("SUCCESS: All clients are connected!", "SUCCESS")
            attempt_data["result"] = "success"
            self.save_attempt(attempt_data)
            return True
            
        # Run Claude analysis
        self.log("Starting Claude analysis...")
        claude_response = await self.run_claude_analysis(test_results)
        
        if not claude_response:
            self.log("Claude analysis failed, skipping iteration", "ERROR")
            attempt_data["result"] = "claude_failed"
            attempt_data["error"] = "Claude analysis returned no response"
            self.save_attempt(attempt_data)
            return False
        
        # Save Claude's full response
        with open(iter_dir / "claude_response.txt", 'w') as f:
            f.write(claude_response)
        attempt_data["claude_response"] = claude_response[:500] + "..." if len(claude_response) > 500 else claude_response
            
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
        
        # Save git diffs for each modified file
        for file in attempt_data["files_modified"]:
            diff_result = subprocess.run(
                ["git", "diff", file],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            diff_filename = file.replace('/', '_') + '.diff'
            with open(iter_dir / diff_filename, 'w') as f:
                f.write(f"Diff for {file}:\n\n")
                f.write(diff_result.stdout)
        
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
            # Don't reset - let changes accumulate
            return False
            
        # Run full test with changes
        self.log(f"Running full test with changes ({self.duration}s)...")
        full_test_log = str(iter_dir / "full_test.log")
        full_test = HermesMatrixTest(
            self.duration, 
            full_test_log,
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
                # Don't reset - let changes accumulate
                return False
                
        except Exception as e:
            self.log(f"Test execution failed: {e}", "ERROR")
            attempt_data["result"] = "execution_failed"
            attempt_data["error"] = str(e)
            self.save_attempt(attempt_data)
            # Don't reset - let changes accumulate
            return False
            
    async def run(self):
        """Run the self-healing test loop."""
        self.log("Starting self-healing Hermes test")
        self.log(f"Run ID: {self.run_id}")
        self.log(f"Logs directory: {self.logs_base_dir}")
        self.log(f"Summary file: {self.summary_file}")
        self.log(f"Max iterations: {self.max_iterations}")
        self.log(f"Test duration per iteration: {self.duration}s")
        
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
                self.log(f"Logs directory: {self.logs_base_dir}")
                self.log(f"Summary: {self.summary_file}")
                
                # Add success summary to the file
                with open(self.summary_file, 'a') as f:
                    f.write("\n## Final Result\n\n")
                    f.write("**Status**: ✅ Success\n")
                    f.write(f"**Total Iterations**: {self.iteration}\n")
                    f.write(f"**Ended**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                
                return 0
                
            if i < self.max_iterations - 1:
                self.log(f"\nIteration {self.iteration} failed, trying again...")
                await asyncio.sleep(10)  # Brief pause between iterations
                
        self.log("\n❌ Self-healing failed after all iterations")
        self.log(f"Logs directory: {self.logs_base_dir}")
        self.log(f"Summary: {self.summary_file}")
        
        # Add final summary to the file
        with open(self.summary_file, 'a') as f:
            f.write("\n## Final Result\n\n")
            f.write("**Status**: ❌ Failed\n")
            f.write(f"**Total Iterations**: {self.iteration}\n")
            f.write(f"**Ended**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
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