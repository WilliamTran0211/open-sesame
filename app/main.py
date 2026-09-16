import logging
import logging.config
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.exception import register_exception_handlers
from app.db.session import session_manager
from app.logger.config import LOGGING_CONFIG
from app.middleware.auth import AuthMiddleware
from app.middleware.logging import LoggingMiddleware
from app.services.access_token import get_token_service

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    print("Starting application...")

    settings = get_settings()
    session_manager.init(database_url=settings.database_url)

    if await session_manager.health_check():
        print("Database connected")
    else:
        print("Database connection failed")
        raise RuntimeError("Cannot connect to database")
    yield

    await session_manager.close()


def create_app() -> FastAPI:
    app = FastAPI(title="OS - Open Sesame", version="0.0.1", lifespan=lifespan)

    register_exception_handlers(app)

    # middleware
    app.add_middleware(LoggingMiddleware)

    app.add_middleware(AuthMiddleware, token_service=get_token_service())

    # CORS
    origins = [
        "http://localhost",
        "http://localhost:8080",
        "https://example.com",
        "https://www.example.com",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # routers
    app.include_router(api_router, prefix="/api/v1")

    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
