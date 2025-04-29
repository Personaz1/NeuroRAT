#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NeuroZond - Configuration Module
Version: 0.1.0
Last Updated: 2025-09-15

This module provides configuration management for the NeuroZond framework.
"""

import os
import json
import yaml
import logging
from typing import Any, Dict, List, Optional, Union

class Config:
    """
    Configuration manager for NeuroZond components.
    Handles loading, accessing, and saving configuration settings.
    """
    
    DEFAULT_CONFIG = {
        # General settings
        "app_name": "NeuroZond",
        "version": "0.1.0",
        "log_level": "INFO",
        "output_dir": "reports",
        
        # Web3 settings
        "ethereum_rpc_url": "https://eth-mainnet.g.alchemy.com/v2/demo",
        "alternative_rpc_urls": [
            "https://mainnet.infura.io/v3/your-infura-key",
            "https://rpc.ankr.com/eth"
        ],
        "solc_version": "0.8.17",
        "max_workers": 5,
        
        # API keys (should be overridden by local config)
        "etherscan_api_key": "",
        "infura_api_key": "",
        "alchemy_api_key": "",
        
        # Analysis settings
        "timeout": 60,
        "max_contract_size": 500000,
        "enable_decompilation": True,
        "vulnerability_scan_level": "standard",  # basic, standard, thorough
        
        # Exploitation settings
        "allow_exploitation": False,
        "max_gas_for_exploitation": 1000000,
        "safe_mode": True
    }
    
    def __init__(self, config_path: str = None):
        """
        Initialize configuration, loading from specified path or defaults.
        
        Args:
            config_path: Path to configuration file (JSON or YAML)
        """
        self.config_data = self.DEFAULT_CONFIG.copy()
        
        # Load config from default locations if not specified
        if not config_path:
            # Check for config in common locations
            possible_locations = [
                "config.json",
                "config.yaml",
                "config.yml",
                os.path.expanduser("~/.neurozond/config.json"),
                os.path.expanduser("~/.neurozond/config.yaml"),
                os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.json")
            ]
            
            for loc in possible_locations:
                if os.path.exists(loc):
                    config_path = loc
                    break
        
        # Load config from file if it exists
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
            
        # Override with environment variables
        self._load_from_env()
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to configuration file
        """
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith(('.yaml', '.yml')):
                    loaded_config = yaml.safe_load(f)
                else:
                    loaded_config = json.load(f)
                
                if loaded_config and isinstance(loaded_config, dict):
                    self.config_data.update(loaded_config)
                    print(f"Loaded configuration from {config_path}")
                else:
                    print(f"Warning: Invalid configuration format in {config_path}")
        except Exception as e:
            print(f"Error loading configuration from {config_path}: {str(e)}")
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables"""
        prefix = "NEUROZOND_"
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                
                # Handle nested keys with double underscores
                if "__" in config_key:
                    parts = config_key.split("__")
                    current = self.config_data
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = self._convert_value(value)
                else:
                    self.config_data[config_key] = self._convert_value(value)
    
    def _convert_value(self, value: str) -> Any:
        """Convert string values to appropriate types"""
        # Try to convert to boolean
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        
        # Try to convert to number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            # If conversion fails, keep as string
            return value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key.
        
        Args:
            key: Configuration key
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        # Handle nested keys with dots
        if "." in key:
            parts = key.split(".")
            current = self.config_data
            for part in parts:
                if not isinstance(current, dict) or part not in current:
                    return default
                current = current[part]
            return current
        
        return self.config_data.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key: Configuration key
            value: Value to set
        """
        # Handle nested keys with dots
        if "." in key:
            parts = key.split(".")
            current = self.config_data
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value
        else:
            self.config_data[key] = value
    
    def save(self, config_path: str = "config.json") -> bool:
        """
        Save current configuration to a file.
        
        Args:
            config_path: Path to save configuration
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            directory = os.path.dirname(config_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
                
            with open(config_path, 'w') as f:
                if config_path.endswith(('.yaml', '.yml')):
                    yaml.dump(self.config_data, f, default_flow_style=False)
                else:
                    json.dump(self.config_data, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving configuration to {config_path}: {str(e)}")
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get all configuration data.
        
        Returns:
            Dictionary with all configuration
        """
        return self.config_data.copy()
    
    def update(self, config_dict: Dict[str, Any]) -> None:
        """
        Update configuration with values from a dictionary.
        
        Args:
            config_dict: Dictionary with configuration values
        """
        self.config_data.update(config_dict)

# Simple test function
def test_config():
    """Test the Config class functionality"""
    config = Config()
    print("Default Ethereum RPC URL:", config.get("ethereum_rpc_url"))
    
    # Test setting and getting values
    config.set("test_key", "test_value")
    assert config.get("test_key") == "test_value"
    
    # Test nested keys
    config.set("nested.key.test", 123)
    assert config.get("nested.key.test") == 123
    
    # Test saving and loading
    tmp_config_path = "tmp_test_config.json"
    config.save(tmp_config_path)
    
    new_config = Config(tmp_config_path)
    assert new_config.get("test_key") == "test_value"
    assert new_config.get("nested.key.test") == 123
    
    # Clean up
    os.remove(tmp_config_path)
    print("Config tests passed!")

if __name__ == "__main__":
    test_config() 