from __future__ import annotations

import os
import time
from time import perf_counter
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.db.session_store import get_session_store
from app.models import (
    ApprovalRequest,
    ApprovalResponse,
    DeployResponse,
    DeployStatus,
    AuditEntriesResponse,
    ArtifactDownloadResponse,
    ArtifactListItem,
    ArtifactListResponse,
    ArtifactRecord,
    CredentialProviderResult,
    CredentialTestRequest,
    CredentialTestResponse,
    DeploymentSession,
    DeploymentSessionCreate,
    DeploymentSessionUpdate,
    DryRunResponse,
    DryRunStep,
    GenerateArtifactsResponse,
    MockDeployResponse,
    SessionStatus,
    SessionEventsResponse,
)
from app.services.artifact_storage import build_storage_key, default_artifact_storage
from app.services.auth import Principal, get_authenticated_principal, require_role
from app.services.artifacts import build_artifacts, build_diff, next_run_id
from app.services.provider_credentials import (
    ProviderCredentialInput,
    default_registry,
    run_provider_test,
)
from app.services.deploy import build_deploy_response, execute_live_deploy, next_deploy_run_id
from app.services.mock_execution import default_mock_deploy_execution_client, resolve_scenario
from app.services.metrics import COLLECTOR
from app.services.redaction import redact_session
from app.services.sessions import SessionStore
from app.services.validation import SessionValidationResponse, validate_session

router = APIRouter(prefix='/sessions', tags=['sessions'])


def _requires_two_person_approval() -> bool:
    return os.getenv('DEPLOY_REQUIRE_TWO_PERSON_APPROVAL', 'false').lower() in {'1', 'true', 'yes'}


def _approved_actors(session_id: str, store: SessionStore) -> list[str]:
    records = store.list_approval_records(session_id)
    approved: list[str] = []
    for rec in records:
        if rec.decision.value == 'approve' and rec.actor_email not in approved:
            approved.append(rec.actor_email)
    return approved


def _authorize(session: DeploymentSession, principal: Principal) -> None:
    if principal.role == 'admin':
        return
    if principal.email.lower() == session.metadata.created_by.lower():
        return
    raise HTTPException(status_code=403, detail='artifact_access_denied')


@router.post('', response_model=DeploymentSession)
def create_session(
    payload: DeploymentSessionCreate,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> DeploymentSession:
    require_role(principal, {'operator', 'admin'})
    created = store.create(payload)
    store.add_audit_entry(
        session_id=created.session_id,
        actor_email=principal.email,
        actor_role=principal.role,
        action='session.create',
        details={'execution_mode': created.execution_mode.value},
    )
    return redact_session(created)


@router.get('/{session_id}', response_model=DeploymentSession)
def get_session(
    session_id: str,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> DeploymentSession:
    return redact_session(store.get(session_id))


@router.put('/{session_id}', response_model=DeploymentSession)
def update_session(
    session_id: str,
    payload: DeploymentSessionUpdate,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> DeploymentSession:
    require_role(principal, {'operator', 'admin'})
    updated = store.update(session_id, payload)
    store.add_audit_entry(
        session_id=session_id,
        actor_email=principal.email,
        actor_role=principal.role,
        action='session.update',
        details={'status': updated.status.value},
    )
    return redact_session(updated)


@router.post('/{session_id}/validate', response_model=SessionValidationResponse)
def validate_session_endpoint(
    session_id: str,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> SessionValidationResponse:
    session = store.get(session_id)
    result = validate_session(session)
    store.add_audit_entry(
        session_id=session_id,
        actor_email=principal.email,
        actor_role=principal.role,
        action='session.validate',
        details={
            'ready_to_deploy': str(result.ready_to_deploy).lower(),
            'blocking_issue_count': str(result.blocking_issue_count),
        },
    )
    COLLECTOR.record_validation(result.blocking_issue_count)
    return result


@router.get('/{session_id}/audit-events', response_model=AuditEntriesResponse)
def list_audit_events_endpoint(
    session_id: str,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> AuditEntriesResponse:
    session = store.get(session_id)
    _authorize(session, principal)
    return AuditEntriesResponse(session_id=session_id, entries=store.list_audit_entries(session_id))


@router.get('/{session_id}/events', response_model=SessionEventsResponse)
def list_session_events_endpoint(
    session_id: str,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> SessionEventsResponse:
    session = store.get(session_id)
    _authorize(session, principal)
    return SessionEventsResponse(session_id=session_id, events=store.list_session_events(session_id))


@router.post('/{session_id}/approvals', response_model=ApprovalResponse)
def add_approval_endpoint(
    session_id: str,
    payload: ApprovalRequest,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> ApprovalResponse:
    require_role(principal, {'operator', 'admin'})
    store.get(session_id)

    store.add_approval_record(
        session_id=session_id,
        actor_email=principal.email,
        decision=payload.decision,
        comment=payload.comment,
    )
    store.add_audit_entry(
        session_id=session_id,
        actor_email=principal.email,
        actor_role=principal.role,
        action='deploy.approval',
        details={'decision': payload.decision.value},
    )

    records = store.list_approval_records(session_id)
    approved_by = _approved_actors(session_id, store)
    required = 2 if _requires_two_person_approval() else 0
    return ApprovalResponse(
        session_id=session_id,
        approvals_required=required,
        approved_by=approved_by,
        approvals=records,
    )


@router.post('/{session_id}/test-credentials', response_model=CredentialTestResponse)
def test_credentials_endpoint(
    session_id: str,
    payload: CredentialTestRequest | None = None,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> CredentialTestResponse:
    require_role(principal, {'operator', 'admin'})
    session = store.get(session_id)

    secrets = store.get_session_secrets(session_id)
    provider_secret_map = {
        'openai': str(secrets.get('openai_api_key', '')),
        'stripe': str(secrets.get('stripe_api_key', '')),
    }

    requested = payload.providers if payload and payload.providers else list(provider_secret_map.keys())

    registry = default_registry()
    results: list[CredentialProviderResult] = []
    for provider in requested:
        secret = provider_secret_map.get(provider, '')
        result = run_provider_test(
            registry,
            ProviderCredentialInput(provider=provider, secret=secret),
        )
        results.append(
            CredentialProviderResult(
                provider=result.provider,
                status=result.status.value,
                message=result.message,
                attempts=result.attempts,
            )
        )

    response = CredentialTestResponse(session_id=session_id, results=results)
    store.add_audit_entry(
        session_id=session_id,
        actor_email=principal.email,
        actor_role=principal.role,
        action='credentials.test',
        details={'providers': ','.join(requested)},
    )
    return response


@router.post('/{session_id}/deploy', response_model=DeployResponse | DryRunResponse | MockDeployResponse)
def deploy_session_endpoint(
    session_id: str,
    idempotency_key: str | None = Header(default=None, alias='Idempotency-Key'),
    mock_scenario: str | None = Header(default=None, alias='X-Mock-Scenario'),
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> DeployResponse | DryRunResponse | MockDeployResponse:
    require_role(principal, {'operator', 'admin'})
    session = store.get(session_id)
    deploy_started = perf_counter()

    if session.execution_mode.value == 'mock':
        scenario = resolve_scenario(mock_scenario)
        client = default_mock_deploy_execution_client()
        status, events, outputs = client.execute(scenario)
        response = MockDeployResponse(
            session_id=session_id,
            execution_mode='mock',
            scenario=scenario.value,
            simulated=True,
            status=status.value,
            events=events,
            synthetic_outputs=outputs,
        )
        store.add_audit_entry(
            session_id=session_id,
            actor_email=principal.email,
            actor_role=principal.role,
            action='deploy.mock',
            details={'scenario': scenario.value, 'status': status.value},
        )
        COLLECTOR.record_deploy_result(success=status.value == 'success', duration_seconds=perf_counter() - deploy_started)
        return response

    if session.execution_mode.value == 'dry_run':
        validation = validate_session(session)
        artifacts = build_artifacts(session.config.model_dump(mode='json'), session.config.schema_version)
        simulated_status, simulated_events, simulated_outputs = execute_live_deploy(session.config.model_dump(mode='json'))
        simulated_events = [
            event.model_copy(update={'message': f'SIMULATED: {event.message}'})
            for event in simulated_events
        ]
        response = DryRunResponse(
            session_id=session_id,
            execution_mode='dry_run',
            simulated=True,
            validation_summary={
                'ready_to_deploy': validation.ready_to_deploy,
                'blocking_issue_count': validation.blocking_issue_count,
                'warning_count': validation.warning_count,
            },
            artifact_simulation=artifacts,
            deploy_simulation_status=simulated_status.value,
            deploy_simulation_events=simulated_events,
            would_do_steps=[
                DryRunStep(category='validation', action='Run schema, business, and readiness validations.'),
                DryRunStep(category='artifacts', action='Generate deterministic env/service/IaC artifacts in memory.'),
                DryRunStep(category='deploy', action='Execute deploy stage simulation without mutating cloud resources.'),
            ],
            simulated_outputs=simulated_outputs,
        )
        store.add_audit_entry(
            session_id=session_id,
            actor_email=principal.email,
            actor_role=principal.role,
            action='deploy.dry_run',
            details={'status': simulated_status.value},
        )
        COLLECTOR.record_deploy_result(success=simulated_status.value == 'success', duration_seconds=perf_counter() - deploy_started)
        return response

    if session.execution_mode.value != 'live':
        raise HTTPException(status_code=400, detail='deploy_requires_live_execution_mode')

    if _requires_two_person_approval():
        approved_by = _approved_actors(session_id, store)
        if len(approved_by) < 2:
            raise HTTPException(
                status_code=403,
                detail={
                    'code': 'approval_required',
                    'message': 'Live deploy requires two-person approval before execution.',
                    'approved_by': approved_by,
                    'required_approvals': 2,
                },
            )

    if idempotency_key:
        cached = store.get_deploy_response_by_idempotency(session_id=session_id, idempotency_key=idempotency_key)
        if cached is not None:
            return cached

    run_id = next_deploy_run_id()
    lock_acquired = store.acquire_environment_lock(
        env=session.metadata.env,
        region=session.metadata.region,
        session_id=session_id,
        run_id=run_id,
    )
    if not lock_acquired:
        raise HTTPException(
            status_code=409,
            detail={
                'code': 'environment_deploy_locked',
                'message': 'A deploy is already in progress for this environment and region.',
                'env': session.metadata.env,
                'region': session.metadata.region,
            },
        )

    try:
        store.update(session_id, DeploymentSessionUpdate(status=SessionStatus.DEPLOYING))

        result_status, events, outputs = execute_live_deploy(session.config.model_dump(mode='json'))
        store.save_deploy_events(session_id=session_id, run_id=run_id, events=events)

        final_status = SessionStatus.DEPLOYED if result_status == DeployStatus.SUCCESS else SessionStatus.FAILED
        store.update(session_id, DeploymentSessionUpdate(status=final_status))

        persisted = store.list_deploy_events(session_id=session_id, run_id=run_id)
        response = build_deploy_response(
            session_id=session_id,
            run_id=run_id,
            status=result_status,
            events=persisted,
            outputs=outputs,
        )

        if idempotency_key:
            store.save_deploy_response_idempotency(
                session_id=session_id,
                idempotency_key=idempotency_key,
                response=response,
            )

        store.add_audit_entry(
            session_id=session_id,
            actor_email=principal.email,
            actor_role=principal.role,
            action='deploy.live',
            details={'status': result_status.value, 'run_id': run_id},
        )
        COLLECTOR.record_deploy_result(success=result_status.value == 'success', duration_seconds=perf_counter() - deploy_started)
        return response
    finally:
        store.release_environment_lock(
            env=session.metadata.env,
            region=session.metadata.region,
            session_id=session_id,
            run_id=run_id,
        )


@router.post('/{session_id}/generate', response_model=GenerateArtifactsResponse)
def generate_artifacts_endpoint(
    session_id: str,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> GenerateArtifactsResponse:
    require_role(principal, {'operator', 'admin'})
    session = store.get(session_id)

    previous = store.get_latest_generation_run(session_id)
    artifacts = build_artifacts(session.config.model_dump(mode='json'), session.config.schema_version)
    diff = build_diff(artifacts, previous)

    run_id = next_run_id()
    store.save_generation_run(session_id=session_id, run_id=run_id, artifacts=artifacts)

    storage = default_artifact_storage()
    records: list[ArtifactRecord] = []
    for artifact in artifacts:
        key = build_storage_key(session_id, run_id, artifact.name)
        storage.put_text(key, artifact.content)
        records.append(
            ArtifactRecord(
                run_id=run_id,
                session_id=session_id,
                name=artifact.name,
                version=artifact.version,
                hash=artifact.hash,
                generated_at=artifact.generated_at,
                storage_key=key,
            )
        )
    store.save_artifact_records(records)

    response = GenerateArtifactsResponse(
        session_id=session_id,
        run_id=run_id,
        artifacts=artifacts,
        diff=diff,
    )
    store.add_audit_entry(
        session_id=session_id,
        actor_email=principal.email,
        actor_role=principal.role,
        action='artifacts.generate',
        details={'run_id': run_id, 'artifact_count': str(len(artifacts))},
    )
    return response


@router.get('/{session_id}/artifacts', response_model=ArtifactListResponse)
def list_artifacts_endpoint(
    session_id: str,
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> ArtifactListResponse:
    session = store.get(session_id)
    _authorize(session, principal)

    storage = default_artifact_storage()
    expires = int(time.time()) + 300
    items: list[ArtifactListItem] = []
    for rec in store.list_artifact_records(session_id):
        token = storage.create_signed_token(rec.storage_key, expires)
        query = urlencode({'token': token, 'session_id': session_id, 'run_id': rec.run_id, 'name': rec.name})
        items.append(
            ArtifactListItem(
                run_id=rec.run_id,
                name=rec.name,
                version=rec.version,
                hash=rec.hash,
                generated_at=rec.generated_at,
                signed_download_url=f'/sessions/artifacts/download?{query}',
            )
        )

    return ArtifactListResponse(session_id=session_id, artifacts=items)


@router.get('/artifacts/download', response_model=ArtifactDownloadResponse)
def download_artifact_endpoint(
    token: str = Query(...),
    session_id: str = Query(...),
    run_id: str = Query(...),
    name: str = Query(...),
    principal: Principal = Depends(get_authenticated_principal),
    store: SessionStore = Depends(get_session_store),
) -> ArtifactDownloadResponse:
    storage = default_artifact_storage()
    try:
        storage_key, exp = storage.verify_signed_token(token)
    except Exception:
        raise HTTPException(status_code=403, detail='invalid_or_expired_artifact_token') from None

    if int(time.time()) > exp:
        raise HTTPException(status_code=403, detail='invalid_or_expired_artifact_token')

    session = store.get(session_id)
    _authorize(session, principal)
    record = store.get_artifact_record(session_id=session_id, run_id=run_id, artifact_name=name)
    if record.storage_key != storage_key:
        raise HTTPException(status_code=403, detail='invalid_or_expired_artifact_token')

    content = storage.get_text(storage_key)
    return ArtifactDownloadResponse(
        session_id=session_id,
        run_id=run_id,
        artifact_name=name,
        version=record.version,
        hash=record.hash,
        content=content,
    )
