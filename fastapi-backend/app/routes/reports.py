from fastapi import APIRouter
from app.services.ai_engine import AIReportGenerator
from app.core.config import settings

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.post("/generate")
async def generate_report():
    """Generate AI network credibility report."""
    # Fetch all data
    devices = await fetch_all_devices()
    traffic = await suricata.get_flow_data()
    vulns = await fetch_vulnerabilities()
    
    ai_generator = AIReportGenerator(api_key=settings.OPENAI_API_KEY)
    report = await ai_generator.generate_network_report(devices, traffic, vulns)
    
    # Save to DB
    supabase.table("ai_reports").insert(report).execute()
    
    # Broadcast via WebSocket
    socketio.emit('report:generated', report, broadcast=True)
    
    return report