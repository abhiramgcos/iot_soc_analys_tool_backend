from fastapi import APIRouter, WebSocket, HTTPException
from fastapi.responses import JSONResponse
import asyncio

router = APIRouter(prefix="/api/devices", tags=["devices"])

@router.post("/scan")
async def start_network_scan(network: str = "192.168.1.0/24"):
    """
    Initiate network scan. Returns immediately with scan_id.
    """
    scanner = AsyncNetworkScanner()
    scan_id = generate_uuid()
    
    # Fire background task (non-blocking)
    asyncio.create_task(
        run_scan_background(scan_id, network)
    )
    
    return {
        "scan_id": scan_id,
        "status": "scanning",
        "message": f"Scanning {network}..."
    }

async def run_scan_background(scan_id: str, network: str):
    """Background scanning task."""
    scanner = AsyncNetworkScanner()
    
    def scan_callback(device):
        # Broadcast via WebSocket
        socketio.emit('device:new', device, broadcast=True)
        # Save to DB
        supabase.table("devices").insert(device).execute()
    
    devices = await scanner.scan_network_async(network, scan_callback)
    
    # Emit completion
    socketio.emit('scan:complete', {
        'scan_id': scan_id,
        'total_devices': len(devices)
    }, broadcast=True)

@router.get("/list")
async def get_devices(status: str = None):
    """Retrieve all discovered devices from DB."""
    query = supabase.table("devices").select("*")
    if status:
        query = query.eq("status", status)
    result = query.execute()
    return {"devices": result.data}

@router.get("/{device_id}")
async def get_device_details(device_id: str):
    """Get detailed info including vulnerabilities."""
    device = supabase.table("devices").select("*").eq("id", device_id).single().execute()
    
    # Get related traffic data
    traffic = supabase.table("traffic_data").select("*").eq("device_id", device_id).execute()
    
    # Get vulnerabilities (from CVE DB)
    vulns = await fetch_cve_data(device["firmware"])
    
    return {
        **device.data,
        "traffic_stats": aggregate_traffic(traffic.data),
        "vulnerabilities": vulns
    }

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time device updates."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            # Process command (e.g., subscribe to device)
            await websocket.send_json({
                "status": "connected",
                "message": "Receiving real-time updates"
            })
    except Exception as e:
        await websocket.close()