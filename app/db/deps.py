# Global instance
from typing import Annotated, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .session import session_manager


# Dependency function
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with session_manager.session() as session:
        yield session


DBDep = Annotated[AsyncSession, Depends(get_db)]
