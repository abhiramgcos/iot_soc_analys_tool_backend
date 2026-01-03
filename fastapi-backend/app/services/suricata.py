# app/services/suricata.py
import asyncio
import json
from typing import List, Dict

class SuricataClient:
    def __init__(self, log_path="/var/log/suricata/eve.json"):
        self.log_path = log_path
    
    async def get_alerts(self, severity_level: int = 1) -> List[Dict]:
        """
        Parse Suricata EVE logs to get alerts.
        """
        alerts = []
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    log = json.loads(line)
                    if log.get("event_type") == "alert":
                        alert = log.get("alert", {})
                        if alert.get("severity", 0) >= severity_level:
                            alerts.append(alert)
            return alerts
        except FileNotFoundError:
            return []
    
    async def get_flow_data(self, device_ip: str = None) -> List[Dict]:
        """
        Parse Suricata EVE logs to get network flows.
        """
        flows = []
        try:
            with open(self.log_path, 'r') as f:
                for line in f:
                    log = json.loads(line)
                    if log.get("event_type") == "flow":
                        flow = log.get("flow", {})
                        if device_ip and flow.get("src_ip") != device_ip:
                            continue
                        flows.append(flow)
            return flows
        except FileNotFoundError:
            return []