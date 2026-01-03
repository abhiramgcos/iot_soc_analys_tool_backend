# app/services/scanner.py
import asyncio
import aiohttp
from nmap import PortScanner
from typing import List, Dict

class AsyncNetworkScanner:
    def __init__(self):
        self.nm = PortScanner()
        self.active_scans = {}
    
    async def scan_network_async(
        self, 
        network: str = "192.168.1.0/24",
        callback=None
    ) -> List[Dict]:
        """
        Async network scan using python-libnmap.
        Returns device list with basic info.
        """
        devices = []
        try:
            # Non-blocking scan
            def callback_func(host, result):
                device = {
                    "ip": host,
                    "status": result.get("status", {}).get("state"),
                    "ports": self._extract_ports(result)
                }
                devices.append(device)
                if callback:
                    callback(device)
            
            # Use libnmap for async
            from libnmap.process import NmapProcess
            from libnmap.parser import NmapParser
            
            nmap_proc = NmapProcess(targets=network, options="-sn -T4")
            nmap_proc.run()
            
            nmap_results = NmapParser.parse(nmap_proc.stdout)
            for host in nmap_results.hosts:
                devices.append({
                    "ip": host.address,
                    "mac": host.mac,
                    "status": "up" if host.is_up() else "down",
                    "hostnames": [h["name"] for h in host.hostnames]
                })
            
            return devices
        except Exception as e:
            print(f"Scan error: {e}")
            return []
    
    async def identify_firmware(self, ip: str, ports: List[int]) -> Dict:
        """
        Identify device firmware via port scanning and HTTP headers.
        """
        firmware_info = {
            "ip": ip,
            "device_type": "Unknown",
            "firmware": "Unknown",
            "confidence": 0.0
        }
        
        # Check common ports
        async with aiohttp.ClientSession() as session:
            for port in [80, 443, 8080]:
                try:
                    async with session.get(
                        f"http://{ip}:{port}", 
                        timeout=2
                    ) as resp:
                        headers = dict(resp.headers)
                        firmware_info = self._parse_headers(headers, ip)
                        break
                except:
                    continue
        
        return firmware_info
    
    def _parse_headers(self, headers: Dict, ip: str) -> Dict:
        """Extract device type/firmware from HTTP headers."""
        server_header = headers.get("Server", "").lower()
        
        device_fingerprints = {
            "canon": ("Printer", "Canon"),
            "hp": ("Printer", "HP"),
            "cisco": ("Network", "Cisco"),
            "tplink": ("Router", "TP-Link"),
            "nest": ("IoT", "Google Nest"),
            "wyoming": ("Camera", "Wylie"),
        }
        
        for keyword, (dtype, vendor) in device_fingerprints.items():
            if keyword in server_header:
                return {
                    "ip": ip,
                    "device_type": dtype,
                    "firmware": vendor,
                    "confidence": 0.85
                }
        
        return {
            "ip": ip,
            "device_type": "Unknown",
            "firmware": server_header or "Unknown",
            "confidence": 0.3
        }