from fastapi import APIRouter
from app.services.suricata import SuricataClient

router = APIRouter(prefix="/api/traffic", tags=["traffic"])
suricata = SuricataClient()

@router.get("/alerts")
async def get_alerts(severity: str = None):
    """Fetch Suricata alerts with optional severity filter."""
    alerts = await suricata.get_alerts()
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    return {"alerts": alerts, "count": len(alerts)}

@router.get("/flows")
async def get_traffic_flows(device_ip: str = None):
    """Get network flows for traffic visualization."""
    flows = await suricata.get_flow_data(device_ip)
    return {"flows": flows}

@router.get("/heatmap")
async def get_traffic_heatmap():
    """Aggregate flows for heatmap visualization."""
    flows = await suricata.get_flow_data()
    # Transform into time-bucketed device data
    heatmap_data = aggregate_by_device_time(flows)
    return {"data": heatmap_data}