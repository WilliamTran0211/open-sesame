from fastapi import APIRouter

from app.api.deps import RequireSessionDep, RequireSuperuserDep, ScopeServicesDep
from app.schemas.scope import CreateScopeSchema, ScopeResponseSchema, UpdateScopeSchema

router = APIRouter()


@router.get("/")
def read_root():
    return {"message": "Open Sesame, Scope service!"}


@router.get("/list", response_model=list[ScopeResponseSchema])
async def list_scope(
    scope_services: ScopeServicesDep,
    _: RequireSessionDep,
):
    return await scope_services.list_active_scopes()


@router.post("/", response_model=ScopeResponseSchema)
async def create_scope(
    data: CreateScopeSchema,
    scope_services: ScopeServicesDep,
    _: RequireSuperuserDep,
):
    return await scope_services.create_scope(data.name, data.description)


@router.patch("/{name}", response_model=ScopeResponseSchema)
async def update_scope(
    name: str,
    data: UpdateScopeSchema,
    scope_services: ScopeServicesDep,
    _: RequireSuperuserDep,
):
    update_data = data.model_dump(exclude_none=True)
    return await scope_services.update_scope(name, update_data)


@router.delete("/{name}", response_model=ScopeResponseSchema)
async def delete_scope(
    name: str,
    scope_services: ScopeServicesDep,
    _: RequireSuperuserDep,
):
    return await scope_services.deactivate_scope(name)
