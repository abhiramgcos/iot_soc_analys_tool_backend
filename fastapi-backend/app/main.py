from fastapi import FastAPI
from app.routes import devices, traffic, reports, certificates, health

app = FastAPI()

app.include_router(devices.router)
app.include_router(traffic.router)
app.include_router(reports.router)
app.include_router(certificates.router)
app.include_router(health.router)
