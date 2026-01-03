from fastapi import APIRouter
from app.services.certificate import CertificateScorer

router = APIRouter(prefix="/api/certificates", tags=["certificates"])

@router.post("/generate-certificate")
async def generate_certificate():
    """Generate network security certificate."""
    devices = await fetch_all_devices()
    
    scorer = CertificateScorer()
    cert_score = scorer.score_network_security(devices)
    
    # Save to DB
    supabase.table("certificates").insert(cert_score).execute()
    
    return cert_score