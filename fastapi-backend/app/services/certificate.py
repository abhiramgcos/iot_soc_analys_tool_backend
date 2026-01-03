# app/services/certificate.py
from typing import List, Dict

class CertificateScorer:
    def score_network_security(self, devices: List[Dict]) -> Dict:
        """
        Calculate a security score and generate a certificate.
        """
        total_score = 100
        issues = []

        # Scoring criteria
        for device in devices:
            # 1. Unidentified devices
            if device.get("device_type") == "Unknown":
                total_score -= 5
                issues.append(f"Unidentified device at {device['ip']}")

            # 2. Open ports (simple check)
            if len(device.get("ports", [])) > 3:
                total_score -= 2
                issues.append(f"Excessive open ports on {device['ip']}")
        
        # 3. Presence of vulnerabilities (mock)
        # In a real scenario, this would check a vuln database
        # total_score -= num_vulns * 5

        return {
            "score": max(0, total_score),
            "grade": self._get_grade(total_score),
            "issues": issues,
            "certificate_id": "some-unique-id"
        }

    def _get_grade(self, score: int) -> str:
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        else:
            return "F"
