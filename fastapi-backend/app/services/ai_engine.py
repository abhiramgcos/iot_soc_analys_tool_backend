# app/services/ai_engine.py
import openai
from typing import List, Dict

class AIReportGenerator:
    def __init__(self, api_key: str):
        openai.api_key = api_key
    
    async def generate_network_report(
        self, 
        devices: List[Dict],
        traffic_data: List[Dict],
        vulnerabilities: List[Dict]
    ) -> Dict:
        """
        Generate a network credibility report using OpenAI.
        """
        prompt = self._build_prompt(devices, traffic_data, vulnerabilities)
        
        try:
            response = await openai.Completion.acreate(
                engine="text-davinci-003",
                prompt=prompt,
                max_tokens=1500,
                temperature=0.6
            )
            
            report_text = response.choices[0].text.strip()
            
            return {
                "report_text": report_text,
                "summary": self._summarize_report(report_text)
            }
        except Exception as e:
            return {"error": str(e)}

    def _build_prompt(
        self, 
        devices: List[Dict],
        traffic_data: List[Dict],
        vulnerabilities: List[Dict]
    ) -> str:
        """
        Constructs the detailed prompt for OpenAI.
        """
        # Device summary
        device_summary = "\n".join(
            [f"- IP: {d['ip']}, MAC: {d['mac']}, Type: {d.get('device_type', 'N/A')}" for d in devices]
        )
        
        # Traffic summary (simplified)
        total_flows = len(traffic_data)
        suspicious_flows = sum(1 for t in traffic_data if t.get('alert'))
        
        # Vulnerability summary
        total_vulns = len(vulnerabilities)
        
        prompt = f"""Generate a comprehensive network security and credibility report based on the following data:

**1. Discovered Devices ({len(devices)} total):**
{device_summary}

**2. Network Traffic Analysis:**
- Total network flows recorded: {total_flows}
- Flows with security alerts: {suspicious_flows}

**3. Vulnerability Scan:**
- Total potential vulnerabilities found: {total_vulns}

**Report Sections:**
1.  **Overall Security Posture**: Provide a score from 1-100 (100 being most secure) and a summary paragraph.
2.  **Key Risks & Recommendations**: Identify the top 3-5 risks and suggest actionable steps to mitigate them.
3.  **Suspicious Activity**: Detail any detected suspicious traffic or device behavior and what it could indicate.
4.  **Device-Specific Analysis**: Highlight any high-risk devices and why they are a concern.

Your analysis should be clear, concise, and targeted at a non-technical user.
"""
        return prompt
    
    def _summarize_report(self, report_text: str) -> str:
        """Extract key findings for a brief summary."""
        # A more sophisticated summary could be another AI call
        # For now, we'll extract the first paragraph.
        return report_text.split('\n\n')[0]