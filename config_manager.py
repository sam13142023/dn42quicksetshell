#!/usr/bin/env python3
"""
DN42 Configuration Manager
Handles persistent storage of user configuration including ASN, WireGuard keys, etc.
"""
import yaml
import os
import json
from typing import Dict, Optional, Any

CONFIG_FILE = 'dn42_config.yaml'

class DN42Config:
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file, return empty dict if file doesn't exist."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as file:
                    return yaml.safe_load(file) or {}
            except (yaml.YAMLError, IOError) as e:
                print(f"Error loading config file: {e}")
                return {}
        return {}

    def _save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file, default_flow_style=False, allow_unicode=True)
        except IOError as e:
            print(f"Error saving config file: {e}")

    def get_user_info(self) -> Optional[Dict[str, str]]:
        """Get user's basic information (ASN, keys, etc.)."""
        return self.config.get('user_info')

    def set_user_info(self, asn: str, private_key: str, dn42_ip: str, 
                      listen_port: str, dn42_ipv6: str = "", 
                      public_key: str = "", net_segment: str = "", 
                      net_segment_v6: str = ""):
        """Set user's basic information."""
        if 'user_info' not in self.config:
            self.config['user_info'] = {}
        
        self.config['user_info'].update({
            'asn': asn,
            'private_key': private_key,
            'dn42_ip': dn42_ip,
            'listen_port': listen_port,
            'dn42_ipv6': dn42_ipv6,
            'public_key': public_key,
            'net_segment': net_segment,
            'net_segment_v6': net_segment_v6
        })
        self._save_config()

    def get_peers(self) -> Dict[str, Dict[str, str]]:
        """Get all peer configurations."""
        return self.config.get('peers', {})

    def add_peer(self, peer_name: str, asn: str, public_key: str, 
                 endpoint: str, dn42_ip: str = ""):
        """Add or update a peer configuration."""
        if 'peers' not in self.config:
            self.config['peers'] = {}
        
        self.config['peers'][peer_name] = {
            'asn': asn,
            'public_key': public_key,
            'endpoint': endpoint,
            'dn42_ip': dn42_ip
        }
        self._save_config()

    def get_peer(self, peer_name: str) -> Optional[Dict[str, str]]:
        """Get specific peer configuration."""
        return self.config.get('peers', {}).get(peer_name)

    def remove_peer(self, peer_name: str) -> bool:
        """Remove a peer configuration."""
        if 'peers' in self.config and peer_name in self.config['peers']:
            del self.config['peers'][peer_name]
            self._save_config()
            return True
        return False

    def is_initialized(self) -> bool:
        """Check if user configuration is initialized."""
        user_info = self.get_user_info()
        if not user_info:
            return False
        
        required_fields = ['asn', 'private_key', 'dn42_ip', 'listen_port']
        return all(user_info.get(field) for field in required_fields)

    def list_peers(self) -> list:
        """List all configured peer names."""
        return list(self.config.get('peers', {}).keys())

    def export_config(self) -> str:
        """Export configuration as YAML string."""
        return yaml.dump(self.config, default_flow_style=False, allow_unicode=True)

    def clear_config(self):
        """Clear all configuration."""
        self.config = {}
        self._save_config()