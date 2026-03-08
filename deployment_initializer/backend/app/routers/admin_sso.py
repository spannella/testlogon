from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
import os
from fastapi.responses import RedirectResponse

from app.db.session_store import get_session_store
from app.models import (
    AdminSSOCallbackResponse,
    AdminSSORoleMappingSimulationResponse,
    IdentityProvider,
    IdentityProviderConfigListResponse,
    IdentityProviderConfigResponse,
    IdentityProviderConfigUpdateRequest,
    IdentityProviderConfigUpsertRequest,
    IdentityProviderRoleMapping,
    DevDirectoryActivityEvent,
    DevDirectoryActivityResponse,
    DevDirectoryGroupsResponse,
    DevDirectoryUser as DevDirectoryUserModel,
    DevDirectoryUserCreateRequest,
    DevDirectoryUserGroupRequest,
    DevDirectoryUsersResponse,
    DevDirectoryUserUpdateRequest,
)
from app.services.auth import Principal, get_authenticated_principal, require_role
from app.services.admin_sso import create_admin_sso_start, handle_admin_sso_callback, simulate_admin_role_mapping
from app.services.admin_sso_config import validate_provider_protocol_config
from app.services.metrics import COLLECTOR
from app.services.sessions import SessionStore
from app.services.dev_directory import (
    add_user_to_group,
    create_keycloak_user,
    keycloak_admin_token,
    list_keycloak_groups,
    list_keycloak_users,
    list_recent_admin_sso_activity,
    remove_user_from_group,
    require_dev_directory_enabled,
    update_keycloak_user,
)


router = APIRouter(prefix='/auth/admin/sso', tags=['admin-sso'])


@router.get('/start')
def start_admin_sso(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
) -> RedirectResponse:
    result = create_admin_sso_start(store=store, provider_id=provider_id)
    return RedirectResponse(url=result.authorization_url, status_code=302)


@router.get('/callback', response_model=AdminSSOCallbackResponse)
def admin_sso_callback(
    state: str,
    id_token: str,
    store: SessionStore = Depends(get_session_store),
) -> AdminSSOCallbackResponse:
    return handle_admin_sso_callback(store=store, state=state, id_token=id_token)


@router.get('/simulate-role', response_model=AdminSSORoleMappingSimulationResponse)
def admin_sso_simulate_role_mapping(
    provider_id: str,
    groups: str = '',
    default_role: str | None = None,
    store: SessionStore = Depends(get_session_store),
) -> AdminSSORoleMappingSimulationResponse:
    parsed_groups = [item.strip() for item in groups.split(',') if item.strip()]
    return simulate_admin_role_mapping(
        store=store,
        provider_id=provider_id,
        groups=parsed_groups,
        default_role=default_role,
    )


def _require_root(principal: Principal) -> None:
    require_role(principal, {'root'})




def _validate_provider_protocol_config_or_record_failure(store: SessionStore, provider: IdentityProvider) -> None:
    try:
        validate_provider_protocol_config(provider, db_path=store._db_path)  # noqa: SLF001
    except HTTPException as exc:
        COLLECTOR.record_admin_sso_config_validation_failure(reason_code=str(exc.detail))
        raise

def _provider_config_response(store: SessionStore, provider: IdentityProvider) -> IdentityProviderConfigResponse:
    return IdentityProviderConfigResponse(
        provider=provider,
        config_status=store.get_identity_provider_config_status(provider.provider_id),
    )


@router.post('/providers', response_model=IdentityProviderConfigResponse)
def create_identity_provider_config(
    payload: IdentityProviderConfigUpsertRequest,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigResponse:
    _require_root(principal)
    provider = store.create_identity_provider(
        provider_id=payload.provider_id,
        provider_type=payload.provider_type,
        issuer=payload.issuer,
        metadata_url=payload.metadata_url,
        client_id=payload.client_id,
        secret_ref=payload.secret_ref,
        created_by=principal.email,
        enabled=False,
    )
    store.add_identity_provider_config_audit_event(
        payload.provider_id,
        'create',
        principal.email,
        f'provider_type={payload.provider_type}',
    )
    return _provider_config_response(store, provider)


@router.get('/providers', response_model=IdentityProviderConfigListResponse)
def list_identity_provider_configs(
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigListResponse:
    _require_root(principal)
    providers = store.list_identity_providers()
    return IdentityProviderConfigListResponse(providers=[_provider_config_response(store, item) for item in providers])


@router.get('/providers/{provider_id}', response_model=IdentityProviderConfigResponse)
def get_identity_provider_config(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigResponse:
    _require_root(principal)
    return _provider_config_response(store, store.get_identity_provider(provider_id))


@router.put('/providers/{provider_id}', response_model=IdentityProviderConfigResponse)
def update_identity_provider_config(
    provider_id: str,
    payload: IdentityProviderConfigUpdateRequest,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigResponse:
    _require_root(principal)
    current = store.get_identity_provider(provider_id)
    updated = store.update_identity_provider(
        provider_id=provider_id,
        provider_type=payload.provider_type or current.provider_type,
        issuer=payload.issuer or current.issuer,
        metadata_url=payload.metadata_url if payload.metadata_url is not None else current.metadata_url,
        client_id=payload.client_id or current.client_id,
        secret_ref=payload.secret_ref or current.secret_ref,
        updated_by=principal.email,
    )
    store.set_identity_provider_config_status(provider_id, 'draft', principal.email)
    store.add_identity_provider_config_audit_event(provider_id, 'update', principal.email, 'provider_config_updated_reset_to_draft')
    return _provider_config_response(store, updated)


@router.delete('/providers/{provider_id}')
def delete_identity_provider_config(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> dict[str, str]:
    _require_root(principal)
    store.add_identity_provider_config_audit_event(provider_id, 'delete', principal.email, 'provider_config_deleted')
    store.delete_identity_provider(provider_id)
    return {'status': 'deleted'}


@router.post('/providers/{provider_id}/role-mappings', response_model=IdentityProviderRoleMapping)
def add_identity_provider_role_mapping(
    provider_id: str,
    external_group_or_claim: str,
    internal_role: str,
    priority: int,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderRoleMapping:
    _require_root(principal)
    return store.add_identity_provider_role_mapping(
        provider_id=provider_id,
        external_group_or_claim=external_group_or_claim,
        internal_role=internal_role,
        priority=priority,
    )


@router.get('/providers/{provider_id}/role-mappings', response_model=list[IdentityProviderRoleMapping])
def list_identity_provider_role_mappings(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> list[IdentityProviderRoleMapping]:
    _require_root(principal)
    return store.list_identity_provider_role_mappings(provider_id)


@router.delete('/providers/{provider_id}/role-mappings/{mapping_id}')
def delete_identity_provider_role_mapping(
    provider_id: str,
    mapping_id: int,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> dict[str, str]:
    _require_root(principal)
    store.delete_identity_provider_role_mapping(provider_id, mapping_id)
    return {'status': 'deleted'}


@router.post('/providers/{provider_id}/validate', response_model=IdentityProviderConfigResponse)
def validate_identity_provider_config(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigResponse:
    _require_root(principal)
    provider = store.get_identity_provider(provider_id)
    _validate_provider_protocol_config_or_record_failure(store, provider)
    store.set_identity_provider_config_status(provider_id, 'validated', principal.email)
    store.add_identity_provider_config_audit_event(provider_id, 'validate', principal.email, 'validation_passed')
    return _provider_config_response(store, store.get_identity_provider(provider_id))


@router.post('/providers/{provider_id}/test-config')
def test_identity_provider_config(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> dict[str, str]:
    _require_root(principal)
    provider = store.get_identity_provider(provider_id)
    _validate_provider_protocol_config_or_record_failure(store, provider)
    store.add_identity_provider_config_audit_event(provider_id, 'test_config', principal.email, 'non_destructive_check_passed')
    return {'status': 'ok', 'detail': 'identity_provider_config_test_passed'}


@router.post('/providers/{provider_id}/activate', response_model=IdentityProviderConfigResponse)
def activate_identity_provider_config(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigResponse:
    _require_root(principal)
    provider = store.get_identity_provider(provider_id)
    _validate_provider_protocol_config_or_record_failure(store, provider)
    if store.get_identity_provider_config_status(provider_id) not in {'validated', 'active'}:
        raise HTTPException(status_code=400, detail='identity_provider_not_validated')
    store.set_identity_provider_config_status(provider_id, 'active', principal.email)
    store.add_identity_provider_config_audit_event(provider_id, 'activate', principal.email, 'config_activated')
    return _provider_config_response(store, store.get_identity_provider(provider_id))


@router.post('/providers/{provider_id}/deactivate', response_model=IdentityProviderConfigResponse)
def deactivate_identity_provider_config(
    provider_id: str,
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> IdentityProviderConfigResponse:
    _require_root(principal)
    store.set_identity_provider_config_status(provider_id, 'draft', principal.email)
    store.add_identity_provider_config_audit_event(provider_id, 'deactivate', principal.email, 'config_deactivated')
    return _provider_config_response(store, store.get_identity_provider(provider_id))


@router.post('/rollback')
def rollback_admin_sso(
    store: SessionStore = Depends(get_session_store),
    principal: Principal = Depends(get_authenticated_principal),
) -> dict[str, str | int]:
    _require_root(principal)
    affected = store.rollback_identity_provider_configs(actor_email=principal.email)
    os.environ['ADMIN_SSO_ENFORCE_FOR_ADMINS'] = 'false'
    return {
        'status': 'rolled_back',
        'providers_updated': affected,
        'detail': 'sso_disabled_restore_local_only_admin_login',
    }


@router.get('/dev-directory/users', response_model=DevDirectoryUsersResponse)
def list_dev_directory_users(
    principal: Principal = Depends(get_authenticated_principal),
) -> DevDirectoryUsersResponse:
    _require_root(principal)
    require_dev_directory_enabled()
    token = keycloak_admin_token()
    users = list_keycloak_users(token)
    return DevDirectoryUsersResponse(
        users=[
            DevDirectoryUserModel(
                user_id=user.user_id,
                username=user.username,
                email=user.email,
                enabled=user.enabled,
                groups=user.groups,
            )
            for user in users
        ]
    )


@router.get('/dev-directory/groups', response_model=DevDirectoryGroupsResponse)
def list_dev_directory_groups(
    principal: Principal = Depends(get_authenticated_principal),
) -> DevDirectoryGroupsResponse:
    _require_root(principal)
    require_dev_directory_enabled()
    token = keycloak_admin_token()
    return DevDirectoryGroupsResponse(groups=list_keycloak_groups(token))


@router.post('/dev-directory/users', response_model=DevDirectoryUserModel)
def create_dev_directory_user(
    payload: DevDirectoryUserCreateRequest,
    principal: Principal = Depends(get_authenticated_principal),
) -> DevDirectoryUserModel:
    _require_root(principal)
    require_dev_directory_enabled()
    token = keycloak_admin_token()
    created = create_keycloak_user(
        token,
        username=payload.username,
        email=payload.email,
        password=payload.password,
        groups=payload.groups,
    )
    return DevDirectoryUserModel(
        user_id=created.user_id,
        username=created.username,
        email=created.email,
        enabled=created.enabled,
        groups=created.groups,
    )


@router.put('/dev-directory/users/{username}', response_model=DevDirectoryUserModel)
def update_dev_directory_user(
    username: str,
    payload: DevDirectoryUserUpdateRequest,
    principal: Principal = Depends(get_authenticated_principal),
) -> DevDirectoryUserModel:
    _require_root(principal)
    require_dev_directory_enabled()
    token = keycloak_admin_token()
    updated = update_keycloak_user(
        token,
        username=username,
        email=payload.email,
        enabled=payload.enabled,
    )
    return DevDirectoryUserModel(
        user_id=updated.user_id,
        username=updated.username,
        email=updated.email,
        enabled=updated.enabled,
        groups=updated.groups,
    )


@router.post('/dev-directory/users/{username}/groups', response_model=DevDirectoryUserModel)
def add_dev_directory_user_group(
    username: str,
    payload: DevDirectoryUserGroupRequest,
    principal: Principal = Depends(get_authenticated_principal),
) -> DevDirectoryUserModel:
    _require_root(principal)
    require_dev_directory_enabled()
    token = keycloak_admin_token()
    updated = add_user_to_group(token, username=username, group_name=payload.group_name)
    return DevDirectoryUserModel(
        user_id=updated.user_id,
        username=updated.username,
        email=updated.email,
        enabled=updated.enabled,
        groups=updated.groups,
    )


@router.delete('/dev-directory/users/{username}/groups/{group_name}', response_model=DevDirectoryUserModel)
def remove_dev_directory_user_group(
    username: str,
    group_name: str,
    principal: Principal = Depends(get_authenticated_principal),
) -> DevDirectoryUserModel:
    _require_root(principal)
    require_dev_directory_enabled()
    token = keycloak_admin_token()
    updated = remove_user_from_group(token, username=username, group_name=group_name)
    return DevDirectoryUserModel(
        user_id=updated.user_id,
        username=updated.username,
        email=updated.email,
        enabled=updated.enabled,
        groups=updated.groups,
    )


@router.get('/dev-directory/activity', response_model=DevDirectoryActivityResponse)
def list_dev_directory_activity(
    limit: int = 50,
    actor_email: str | None = None,
    provider_id: str | None = None,
    outcome: str | None = None,
    since_minutes: int | None = None,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> DevDirectoryActivityResponse:
    _require_root(principal)
    require_dev_directory_enabled()
    events = list_recent_admin_sso_activity(
        db_path=store._db_path,  # noqa: SLF001
        limit=limit,
        actor_email=actor_email,
        provider_id=provider_id,
        outcome=outcome,
        since_minutes=since_minutes,
    )
    return DevDirectoryActivityResponse(events=[DevDirectoryActivityEvent(**event) for event in events])
