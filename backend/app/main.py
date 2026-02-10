"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .routers import alerts, detections, ingest


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application on startup."""
    # Initialize database
    init_db()
    yield


app = FastAPI(
    title="SignalForge",
    description="Production-style security detection and abuse monitoring platform",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingest.router, prefix="/api/v1", tags=["Ingestion"])
app.include_router(detections.router, prefix="/api/v1", tags=["Detections"])
app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "service": "SignalForge",
        "version": "0.1.0",
        "status": "operational",
    }


@app.get("/health")
async def health():
    """Detailed health check."""
    return {
        "status": "healthy",
        "database": "connected",
    }
