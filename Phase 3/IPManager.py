import json
import ipaddress
import threading
import os
import time
from datetime import datetime

class IPManager:
    def __init__(self, config_path):
        """
        Initialize the IP Manager with a config file path.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path
        self.config_lock = threading.Lock()
        self.active_leases = {}  # {ip: {'mac': mac, 'expires': timestamp}}
        self.currentIP = "0.0.0.0"  # Initialize currentIP to 0.0.0.0
        self.load_config()
        
        # Start configuration monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_config, daemon=True)
        self.monitor_thread.start()

    def get_broadcast_address(self):
        with self.config_lock:
            return self.config['network']['broadcast_address']
    
    def get_client_port(self):
        with self.config_lock:
            return self.config['server']['client_port']
        
    def get_listening_port(self):
        with self.config_lock:
            return self.config['server']['listening_port']
    
    def get_server_ip(self):
        with self.config_lock:
            return self.config['server']['server_ip']

    def get_subnet_mask(self):
        with self.config_lock:
            return self.config['network']['subnet_mask']

    def get_dns_servers(self):
        with self.config_lock:
            return self.config['network']['dns_servers']

    def get_router(self):
        with self.config_lock:
            return self.config['network']['router']

    def get_lease_time(self):
        with self.config_lock:
            return self.config['lease_settings']['default_lease_time']
        
    def get_renewal_time(self):
        with self.config_lock:
            return self.config['lease_settings']['renewal_time']
    
    def get_rebinding_time(self):
        with self.config_lock:
            return self.config['lease_settings']['rebinding_time']
    
    def get_current_ip(self):
            return self.currentIP

    def set_current_ip(self, ip):
            self.currentIP = ip

    def load_config(self):
        """Load or reload the configuration file."""
        with self.config_lock:
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                print("[INFO] Configuration loaded successfully")
            except Exception as e:
                print(f"[ERROR] Failed to load configuration: {e}")
                raise

    def save_config(self):
        """Save current configuration back to file."""
        with self.config_lock:
            try:
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)
                print("[INFO] Configuration saved successfully")
            except Exception as e:
                print(f"[ERROR] Failed to save configuration: {e}")
                raise

    def _monitor_config(self):
        """Monitor configuration file for changes and reload when necessary."""
        last_modified = None
        while True:
            try:
                current_modified = os.path.getmtime(self.config_path)
                if last_modified is None or current_modified > last_modified:
                    self.load_config()
                    last_modified = current_modified
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"[ERROR] Config monitoring error: {e}")
                time.sleep(5)

    def is_ip_available(self, ip):
        """Check if an IP address is available for assignment."""
        ip_str = str(ip)
        
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ipaddress.AddressValueError:
            print(f"[ERROR] Invalid IP address: {ip_str}")
            return False

        # Check if the IP lies within the configured range
        in_range = False
        for range_config in self.config['ip_pool']['ranges']:
            start_ip = ipaddress.IPv4Address(range_config['start'])
            end_ip = ipaddress.IPv4Address(range_config['end'])
            
            if start_ip <= ip_obj <= end_ip:
                in_range = True
                break

        if not in_range:
            print(f"[INFO] IP {ip_str} is outside the configured range.")
            return False

        # Check if IP is in reserved list
        for reserved in self.config['ip_pool']['reserved']:
            if reserved['ip'] == ip_str:
                return False
                
        # Check if IP is currently leased
        if ip_str in self.active_leases:
            lease = self.active_leases[ip_str]
            if lease['expires'] > time.time():
                return False
                
        return True

    def is_mac_blocked(self, mac):
        """Check if a MAC address is blocked."""
        mac = mac.lower()
        for blocked in self.config['ip_pool']['blocked']:
            if blocked['mac'].lower() == mac:
                return True
        return False

    def get_next_available_ip(self, mac_address):
        """
        Get the next available IP address from the pool.

        Args:
            mac_address: Client's MAC address

        Returns:
            str: Next available IP address or None if none available
        """
        try:
            # Check if MAC is blocked
            def is_mac_blocked(self, mac):
                """Check if a MAC address is blocked and optionally log the reason and block date."""
                mac = mac.lower()
                for blocked in self.config['ip_pool']['blocked']:
                    if blocked['mac'].lower() == mac:
                        reason = blocked.get('reason', 'No reason provided')
                        block_date = blocked.get('block_date', 'Unknown date')
                        print(f"[INFO] MAC {mac} is blocked. Reason: {reason}, Block Date: {block_date}")
                        return True
                return False

            # Existing reservation logic
            for reserved in self.config['ip_pool']['reserved']:
                if reserved['mac'].lower() == mac_address.lower():
                    return reserved['ip']

            # IP pool allocation logic
            for range_config in self.config['ip_pool']['ranges']:
                start_ip = ipaddress.IPv4Address(range_config['start'])
                end_ip = ipaddress.IPv4Address(range_config['end'])

                current_ip = start_ip
                while current_ip <= end_ip:
                    if self.is_ip_available(current_ip):
                        return str(current_ip)
                    current_ip += 1

            print("[WARNING] No available IP addresses in pool")
            return None

        except Exception as e:
            print(f"[ERROR] Error getting next available IP: {e}")
            return None

    def add_lease(self, ip, mac, lease_time):
        """Record a new lease."""
        with self.config_lock:
            self.active_leases[ip] = {
                'mac': mac,
                'expires': time.time() + lease_time
            }
        print(self.active_leases[ip])

    def remove_lease(self, ip):
        """Remove a lease."""
        with self.config_lock:
            if ip in self.active_leases:
                del self.active_leases[ip]

    def cleanup_expired_leases(self):
        """Remove expired leases."""
        current_time = time.time()
        with self.config_lock:
            expired = [ip for ip, lease in self.active_leases.items() 
                      if lease['expires'] <= current_time]
            for ip in expired:
                del self.active_leases[ip]
                print(f"[INFO] Lease expired for IP {ip}")