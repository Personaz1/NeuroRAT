#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NeuroZond - Web3 Smart Contract Analyzer Module
Version: 0.1.0
Last Updated: 2025-09-15

This module provides smart contract analysis capabilities for the NeuroZond framework.
It identifies common vulnerabilities and exploitable patterns in Ethereum smart contracts.
"""

import json
import os
import sys
from web3 import Web3
from eth_utils import to_checksum_address
import solcx
import re
import logging
import requests
import concurrent.futures
from typing import Dict, List, Any, Tuple, Optional
import subprocess
import tempfile
import time # Added for LLM rate limiting simulation

# Local imports
from src.core.config import Config
from src.utils.blockchain_utils import connect_to_node, get_contract_bytecode
from src.utils.reporting import generate_report

# Setup logging using standard logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set a default level
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
# Avoid adding handler multiple times if module reloads somehow
if not logger.hasHandlers():
    logger.addHandler(handler)

# Placeholder for LLM interaction
def call_llm_for_analysis(prompt: str, model_name: str = "default") -> Dict[str, Any]:
    """Simulates calling an LLM API for vulnerability analysis."""
    logger.info(f"Simulating LLM call for analysis (model: {model_name})...")
    # Simulate network delay and processing time
    time.sleep(0.5) 
    
    # Basic simulated response based on keywords in prompt
    # In a real scenario, this would parse the LLM's structured output
    assessment = {
        "is_likely_false_positive": False,
        "adjusted_severity": None, # Let LLM suggest adjusted severity
        "exploitability_notes": "LLM analysis suggests standard exploit vectors might apply.",
        "confidence_score": 0.75, # LLM's confidence in its assessment
        "raw_response": "Simulated LLM response: Finding seems valid. Standard severity applies."
    }
    
    if "low confidence" in prompt.lower() or "informational" in prompt.lower():
        assessment["is_likely_false_positive"] = True
        assessment["exploitability_notes"] = "LLM analysis suggests this is likely informational or a false positive in typical contexts."
        assessment["confidence_score"] = 0.85
        assessment["raw_response"] = "Simulated LLM response: Finding appears informational or low risk."
        
    elif "reentrancy" in prompt.lower() and "high impact" in prompt.lower():
         assessment["adjusted_severity"] = "high"
         assessment["exploitability_notes"] = "LLM analysis confirms potential for reentrancy. Exploit complexity depends on specific checks and balances."
         assessment["confidence_score"] = 0.9
         assessment["raw_response"] = "Simulated LLM response: Reentrancy confirmed as high risk."

    return assessment

class Web3ContractAnalyzer:
    """
    Analyzes Ethereum smart contracts for vulnerabilities and exploitable patterns.
    """
    
    def __init__(self, config_path: str = None):
        """
        Initialize the analyzer with configuration.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = Config(config_path) if config_path else Config()
        self.w3 = None
        # LLM Analysis Configuration
        self.llm_analysis_enabled = self.config.get('llm_analysis_enabled', False)
        self.llm_model_name = self.config.get('llm_model_name', 'default')
        self.llm_confidence_threshold = self.config.get('llm_confidence_threshold', 0.7) # Only analyze findings below this Slither confidence level
        self.llm_severity_threshold = self.config.get('llm_severity_threshold', ['high', 'medium']) # Only analyze findings with these severities

        self.vulnerability_patterns = {
            'reentrancy': r'(\.\s*call\s*{.*?value\s*:|\.\s*transfer\s*\()',
            'unchecked_return': r'\.call\s*{.*?}\s*\(',
            'tx_origin': r'tx\.origin',
            'timestamp_dependence': r'block\.timestamp',
            'integer_overflow': r'([\*\+\-]|[^\.]\.[\*\+\-])',
            'dos_attack': r'for\s*\(.+?\).+?\{',
            'selfdestruct': r'selfdestruct|suicide',
            'unused_variables': r'[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*;',
        }
        self.init_analyzer()
        
    def init_analyzer(self):
        """Initialize web3 connection and other components"""
        try:
            self.w3 = connect_to_node(self.config.get('ethereum_rpc_url'))
            logger.info(f"Connected to Ethereum node: {self.config.get('ethereum_rpc_url')}")
            
            # Install specific solc version if needed
            solc_version = self.config.get('solc_version', '0.8.17')
            if not solcx.get_installed_solc_versions() or solc_version not in solcx.get_installed_solc_versions():
                logger.info(f"Installing solc version {solc_version}")
                solcx.install_solc(solc_version)
            solcx.set_solc_version(solc_version)
            
        except Exception as e:
            logger.error(f"Failed to initialize Smart Contract Analyzer: {str(e)}")
            raise
    
    def analyze_contract(self, contract_address: str = None, source_code: str = None) -> Dict[str, Any]:
        """
        Analyze a smart contract for vulnerabilities.
        
        Args:
            contract_address: Ethereum contract address to analyze
            source_code: Source code of the contract if available
            
        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting analysis of contract: {contract_address}")
        
        results = {
            'address': contract_address,
            'vulnerabilities': [],
            'security_score': 0,
            'exploitable': False,
            'exploitation_vectors': [],
            'contract_info': {},
            'funds_at_risk': 0,
        }
        
        try:
            # Get contract information
            if contract_address:
                contract_address = to_checksum_address(contract_address)
                bytecode = get_contract_bytecode(self.w3, contract_address)
                balance = self.w3.eth.get_balance(contract_address)
                results['contract_info'] = {
                    'address': contract_address,
                    'bytecode': bytecode[:100] + '...' if bytecode and len(bytecode) > 100 else bytecode,
                    'balance': self.w3.from_wei(balance, 'ether'),
                    'code_size': len(bytecode) if bytecode else 0
                }
                results['funds_at_risk'] = float(results['contract_info']['balance'])
            
            # Analyze source code if available
            if source_code:
                source_vulnerabilities = self._analyze_source_code(source_code)
                results['vulnerabilities'].extend(source_vulnerabilities)
            
            # Calculate security score based on vulnerabilities
            security_score = 100 - (len(results['vulnerabilities']) * 10)
            results['security_score'] = max(0, security_score)
            
            # Determine if contract is exploitable
            results['exploitable'] = security_score < 70
            
            # Generate exploitation vectors for vulnerable contracts
            if results['exploitable']:
                results['exploitation_vectors'] = self._generate_exploitation_vectors(results['vulnerabilities'])
            
            logger.info(f"Completed analysis of contract: {contract_address}")
            
        except Exception as e:
            logger.error(f"Error analyzing contract {contract_address}: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_source_code(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Analyze contract source code for vulnerabilities using Slither.
        
        Args:
            source_code: Smart contract source code
            
        Returns:
            List of identified vulnerabilities
        """
        vulnerabilities = []
        # Create a temporary file to store the source code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as temp_file:
            temp_file.write(source_code)
            temp_file_path = temp_file.name

        try:
            # Run Slither analysis, outputting results as JSON
            # Ensure solc version is compatible or specify with --solc
            # We might need to adjust the solc path or version based on the environment
            slither_command = [
                'slither', 
                temp_file_path, 
                '--json', '-' # Output JSON to stdout
                # Add '--solc SOLC_VERSION' if specific version needed and not handled globally
            ]
            
            logger.info(f"Running Slither: {' '.join(slither_command)}")
            result = subprocess.run(slither_command, capture_output=True, text=True, check=False) # Use check=False to handle non-zero exit codes manually

            if result.returncode != 0:
                # Slither might return non-zero for informational findings or errors
                logger.warning(f"Slither finished with return code {result.returncode}")
                # Log stderr for more context, especially if stdout is empty or parsing fails later
                if result.stderr:
                     logger.warning(f"Slither stderr:\\n{result.stderr}")
                     
                if "Traceback" in result.stderr:
                     logger.error(f"Slither execution failed with Traceback.")
                     # Optionally raise an error or return empty vulnerabilities
                     # raise Exception(f"Slither execution failed: {result.stderr}")
                     return vulnerabilities # Return empty list on critical error
                # If no Traceback, it might be compilation errors or informational messages. Continue processing.

            if not result.stdout.strip():
                 logger.warning("Slither produced no JSON output.")
                 # Log stderr again if stdout is empty, might contain the reason
                 if result.stderr:
                      logger.error(f"Slither stderr (stdout was empty):\\n{result.stderr}")
                 return vulnerabilities

            # Parse the JSON output
            try:
                slither_results = json.loads(result.stdout)
            except json.JSONDecodeError as json_err:
                 logger.error(f"Failed to parse Slither JSON output: {json_err}")
                 logger.debug(f"Slither raw stdout: {result.stdout}")
                 return vulnerabilities


            if not slither_results.get('success', False):
                 logger.warning("Slither analysis reported issues or was not fully successful (JSON 'success' flag is false).")
                 # Log detector errors if available
                 if 'error' in slither_results and slither_results['error'] is not None:
                     logger.error(f"Slither analysis error message: {slither_results['error']}")
                     # Consider if this error prevents trusting the results.
                     # If the error is severe (e.g., 'solc instance not found'), we might want to return early.
                     if "not found" in slither_results['error'] or "compilation failed" in slither_results['error']:
                         return vulnerabilities # Return empty if critical error reported in JSON
                 # Continue processing results even if not fully successful, as some detectors might have run

            if 'results' in slither_results and 'detectors' in slither_results['results']:
                raw_findings = slither_results['results']['detectors']
                logger.info(f"Slither found {len(raw_findings)} potential issues. Proceeding with processing and LLM analysis (if enabled)." )
                
                for finding in raw_findings:
                    # Extract relevant information from Slither's finding
                    # The exact structure might need adjustment based on Slither's JSON format version
                    description = finding.get('description', 'N/A')
                    impact = finding.get('impact', 'Unknown').lower()
                    confidence = finding.get('confidence', 'Unknown').lower()
                    check = finding.get('check', 'unknown-check')
                    
                    # Try to find a specific line number if available
                    line_number = None
                    code_snippet = ""
                    if 'elements' in finding and finding['elements']:
                         element = finding['elements'][0]
                         if 'source_mapping' in element:
                             line_number = element['source_mapping'].get('lines', [None])[0] # Get first line
                             if line_number and source_code:
                                 lines = source_code.splitlines()
                                 start_line = max(0, line_number - 5) # More context for LLM
                                 end_line = min(len(lines), line_number + 5) # More context for LLM
                                 code_snippet = "\\n".join(lines[start_line:end_line])
                         if not code_snippet: code_snippet = element.get('name', 'N/A')

                    initial_severity = self._determine_severity(check, impact, confidence)

                    vuln_details = {
                        'type': check,
                        'line': line_number,
                        'code_snippet': code_snippet,
                        'severity': initial_severity,
                        'description': description,
                        'confidence': confidence,
                        'impact': impact,
                        'llm_assessment': None # Placeholder for LLM results
                    }
                    
                    # --- LLM Analysis Step ---
                    should_analyze_with_llm = (
                        self.llm_analysis_enabled and 
                        initial_severity in self.llm_severity_threshold and
                        (confidence != 'high') # Example condition: Analyze if not high confidence
                        # Alternative: use self.llm_confidence_threshold with numerical scores if available
                    )
                    
                    if should_analyze_with_llm:
                        logger.debug(f"Preparing finding for LLM analysis: {check} at line {line_number}")
                        prompt = f"""
                        Analyze the following potential Solidity vulnerability found by Slither:
                        Check Type: {check}
                        Impact: {impact}
                        Confidence: {confidence}
                        Description: {description}
                        Line: {line_number}
                        Code Context:
                        ```solidity
                        {code_snippet}
                        ```
                        
                        Questions:
                        1. Based on the code context, is this finding likely a false positive?
                        2. What is a more accurate severity assessment (High, Medium, Low, Informational)?
                        3. Provide brief notes on potential exploitability or reasons for it being a false positive.
                        
                        Provide your response as a structured JSON object with keys: 'is_likely_false_positive' (boolean), 'adjusted_severity' (string), 'exploitability_notes' (string).
                        """
                        
                        try:
                            llm_result = call_llm_for_analysis(prompt, self.llm_model_name)
                            vuln_details['llm_assessment'] = llm_result
                            # Optionally adjust severity based on LLM feedback
                            if llm_result.get('adjusted_severity') and llm_result.get('confidence_score', 0) > 0.6:
                                logger.info(f"LLM adjusted severity for {check} from {initial_severity} to {llm_result['adjusted_severity']}")
                                vuln_details['severity'] = llm_result['adjusted_severity'].lower()
                            elif llm_result.get('is_likely_false_positive') and llm_result.get('confidence_score', 0) > 0.7:
                                logger.info(f"LLM flagged {check} as likely false positive. Setting severity to informational.")
                                vuln_details['severity'] = 'informational'
                                
                        except Exception as llm_err:
                            logger.error(f"LLM analysis failed for finding {check}: {llm_err}")
                            vuln_details['llm_assessment'] = {"error": str(llm_err)}
                            
                    vulnerabilities.append(vuln_details)
            else:
                logger.info(f"No detectors found in Slither results for {temp_file_path}")


        except FileNotFoundError:
             logger.error("Slither command not found. Is Slither installed and in PATH?")
             # raise # Or handle gracefully
             return [] # Return empty list
        except Exception as e:
            logger.error(f"Error running Slither analysis: {str(e)}")
            # Optionally re-raise or handle
            return [] # Return empty list
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

        logger.info(f"Analysis completed. Found {len(vulnerabilities)} vulnerabilities (after potential LLM filtering)." )
        return vulnerabilities
    
    def _determine_severity(self, vuln_type: str, impact: str = 'Unknown', confidence: str = 'Unknown') -> str:
        """Determine the severity based on Slither's impact and confidence."""
        # Simple mapping based on impact first
        impact = impact.lower()
        confidence = confidence.lower()
        
        if impact == 'high':
            if confidence == 'high': return 'high'
            if confidence == 'medium': return 'medium' # High impact but medium confidence -> medium overall
            return 'low' # High impact but low confidence -> low overall
        elif impact == 'medium':
            if confidence == 'high': return 'medium'
            if confidence == 'medium': return 'low' # Medium impact, medium confidence -> low overall
            return 'low'
        elif impact == 'low':
            return 'low'
        elif impact == 'informational':
            return 'informational' # Add informational category
            
        # Fallback for unknown impact - use confidence or default to low
        if confidence == 'high': return 'medium' # Unknown impact, high confidence -> medium
        return 'low' # Default or low confidence
    
    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Get a description for a vulnerability type (can be enhanced later)."""
        # For now, we rely on Slither's description provided in the finding.
        # This function might become less relevant or used as a fallback.
        # We can keep the old descriptions map as a fallback or reference.
        old_descriptions = {
            'reentrancy': 'Contract state is modified after external calls, potentially allowing attackers to recursively call back into the contract.',
            'unchecked_return': 'The contract does not check the return value of a low-level call, which might fail silently.',
            'tx_origin': 'Use of tx.origin for authorization allows phishing attacks.',
            'timestamp_dependence': 'Reliance on block.timestamp can be manipulated by miners to a certain degree.',
            'integer_overflow': 'Potential integer overflow/underflow in arithmetic operations.',
            'dos_attack': 'Loops over unbounded data structures could lead to denial of service.',
            'selfdestruct': 'Contract can be destroyed using selfdestruct, potentially losing funds or breaking dependencies.',
            'unused_variables': 'Unused variables increase code size and gas costs.',
        }
        # Ideally, use the description from the Slither finding directly.
        # This function could map Slither check names to more detailed wiki links later.
        return f"Slither check: {vuln_type}. See Slither documentation for details."
    
    def _generate_exploitation_vectors(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate potential exploitation vectors based on identified vulnerabilities from Slither.
        
        Args:
            vulnerabilities: List of identified vulnerabilities (Slither format)
            
        Returns:
            List of potential exploitation vectors
        """
        exploitation_vectors = []
        
        for vuln in vulnerabilities:
            # Focus on high/medium severity vulnerabilities for exploitation vectors
            if vuln['severity'] not in ['high', 'medium']:
                continue
                
            exploit_template = None
            vuln_check = vuln['type'] # This is the Slither check ID
            
            # Map Slither checks to exploit templates
            if vuln_check.startswith('reentrancy'): # Covers reentrancy-eth, reentrancy-no-eth, etc.
                exploit_template = {
                    'name': 'Reentrancy Exploit',
                    'slither_check': vuln_check,
                    'description': f"Potential reentrancy detected ({vuln_check}). Deploy attacker contract to exploit.",
                    'template': self._get_reentrancy_exploit_template(vuln),
                    'estimated_success': '70-85%' if vuln['confidence'] == 'High' else '40-60%',
                    'complexity': 'Medium'
                }
            elif vuln_check == 'suicidal':
                exploit_template = {
                    'name': 'Selfdestruct Exploitation',
                    'slither_check': vuln_check,
                    'description': 'Contract can be killed via selfdestruct. Can potentially trap funds or disrupt logic.',
                    'template': '// Trigger the function containing selfdestruct. May require specific conditions or permissions.',
                    'estimated_success': '80-95%',
                    'complexity': 'Low'
                }
            elif vuln_check == 'unprotected-ether-withdrawal':
                 exploit_template = {
                    'name': 'Unprotected Ether Withdrawal',
                    'slither_check': vuln_check,
                    'description': 'Anyone can withdraw Ether from the contract.',
                    'template': '// Call the unprotected withdrawal function directly.',
                    'estimated_success': '95-100%',
                    'complexity': 'Very Low'
                 }
            elif vuln_check == 'arbitrary-send':
                 exploit_template = {
                    'name': 'Arbitrary Send / Call Injection',
                    'slither_check': vuln_check,
                    'description': 'Contract makes calls to user-supplied addresses. Potential for reentrancy or unexpected interactions.',
                    'template': '// Provide a malicious contract address as input to the vulnerable function.',
                    'estimated_success': '50-70%',
                    'complexity': 'Medium'
                 }
            # Add more mappings here for other critical Slither checks like:
            # - tx-origin
            # - timestamp
            # - delegatecall-related issues (e.g., controlled-delegatecall)
            # - access-control issues (e.g., unprotected-upgradeable-implementation)

            if exploit_template:
                # Add context from the vulnerability finding
                exploit_template['line'] = vuln.get('line')
                exploit_template['code_snippet'] = vuln.get('code_snippet')
                exploitation_vectors.append(exploit_template)
        
        return exploitation_vectors
    
    def _get_reentrancy_exploit_template(self, vuln: Dict[str, Any]) -> str:
        """Return a template for a reentrancy exploit contract, potentially using context."""
        # Basic template, could be enhanced to use function names/signatures from vuln elements if available
        vulnerable_function_sig = "vulnerableFunction()" # Placeholder, ideally extract from vuln
        
        # Attempt to get function name from the code snippet or elements if possible
        # This is a rough example, proper extraction needs more robust parsing of Slither elements
        if vuln.get('code_snippet') and '.call' in vuln['code_snippet']:
            match = re.search(r'abi\.encodeWithSignature\("([a-zA-Z0-9_\(\)]*)"\)', vuln['code_snippet'])
            if match:
                 vulnerable_function_sig = match.group(1)

        return f"""
        // Attacker contract template for {vuln['type']} at line {vuln.get('line', 'N/A')}
        contract Exploiter {{
            address payable target;
            uint attackBalance = 0;
            
            constructor(address payable _target) {{
                target = _target;
            }}
            
            // Initial attack call
            function attack() external payable {{
                require(msg.value > 0, "Need ETH to start attack");
                attackBalance = msg.value;
                // Call the potentially vulnerable function identified by Slither
                (bool success, ) = target.call{{value: msg.value}}(abi.encodeWithSignature("{vulnerable_function_sig}"));
                require(success, "Initial attack call failed");
            }}
            
            // Fallback function to receive ETH and re-enter
            receive() external payable {{
                // Re-enter if the target still has sufficient balance 
                // (adjust condition based on specific vulnerability)
                if (address(target).balance >= attackBalance) {{
                    (bool success, ) = target.call(abi.encodeWithSignature("{vulnerable_function_sig}"));
                    // Optional: check success, but often reentrancy relies on state changes before failure
                }}
            }}
            
            // Withdraw funds from this contract
            function withdraw() external {{
                payable(msg.sender).transfer(address(this).balance);
            }}
        }}
        """
    
    def batch_analyze(self, contract_addresses: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Analyze multiple contracts in parallel.
        
        Args:
            contract_addresses: List of contract addresses to analyze
            
        Returns:
            Dictionary mapping addresses to analysis results
        """
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get('max_workers', 5)) as executor:
            future_to_address = {
                executor.submit(self.analyze_contract, address): address 
                for address in contract_addresses
            }
            
            for future in concurrent.futures.as_completed(future_to_address):
                address = future_to_address[future]
                try:
                    results[address] = future.result()
                except Exception as e:
                    logger.error(f"Error analyzing contract {address}: {str(e)}")
                    results[address] = {'error': str(e)}
        
        return results
    
    def export_results(self, results: Dict[str, Any], output_path: str = None) -> str:
        """
        Export analysis results to a file.
        
        Args:
            results: Analysis results
            output_path: Path to save the results
            
        Returns:
            Path to the saved file
        """
        if not output_path:
            output_dir = self.config.get('output_dir', 'reports')
            os.makedirs(output_dir, exist_ok=True)
            timestamp = int(time.time())
            contract_id = results.get('address', 'batch')[:10]
            output_path = os.path.join(output_dir, f"contract_analysis_{contract_id}_{timestamp}.json")
        
        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Analysis results exported to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to export results: {str(e)}")
            return None

# Main function for standalone usage
def main():
    import argparse
    import time
    
    parser = argparse.ArgumentParser(description='Analyze Ethereum smart contracts for vulnerabilities')
    parser.add_argument('--address', '-a', help='Contract address to analyze')
    parser.add_argument('--file', '-f', help='Source code file to analyze')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--config', '-c', help='Configuration file path')
    args = parser.parse_args()
    
    if not args.address and not args.file:
        print("Error: Either contract address or source code file must be provided")
        parser.print_help()
        sys.exit(1)
    
    analyzer = Web3ContractAnalyzer(args.config)
    
    source_code = None
    if args.file:
        try:
            with open(args.file, 'r') as f:
                source_code = f.read()
        except Exception as e:
            print(f"Error reading source file: {str(e)}")
            sys.exit(1)
    
    results = analyzer.analyze_contract(args.address, source_code)
    
    if args.output:
        analyzer.export_results(results, args.output)
    else:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 