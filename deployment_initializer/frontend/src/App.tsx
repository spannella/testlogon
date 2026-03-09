import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';

type OptionalFeatures = {
  enable_helpdesk: boolean;
  enable_messaging: boolean;
  enable_filemanager: boolean;
  enable_alerting: boolean;
  enable_signature_packets: boolean;
};

type FeatureConfig = {
  helpdesk: { routing_queue: string; auto_assign: boolean };
  messaging: { retention_days: number; allow_external_sharing: boolean };
  filemanager: { max_upload_mb: number; enable_virus_scan: boolean };
  alerting: { slack_webhook_url: string; email_notifications_enabled: boolean };
  signature_packets: { reminder_interval_hours: number };
};

type RequiredFormData = {
  metadata: {
    env: string;
    region: string;
    created_by: string;
  };
  deployment_context: {
    environment: string;
    region: string;
    aws_account_id: string;
    app_name: string;
    owner_email: string;
  };
  required_secrets: {
    database_password: string;
    jwt_signing_key: string;
    internal_api_token: string;
    stripe_api_key: string;
    openai_api_key: string;
  };
  optional_features: OptionalFeatures;
  feature_config: FeatureConfig;
  deployment_options: {
    vpc_id: string;
  };
};

type SessionResponse = {
  session_id: string;
  metadata: RequiredFormData['metadata'];
  config: {
    schema_version: string;
    deployment_context: RequiredFormData['deployment_context'];
    required_secrets: RequiredFormData['required_secrets'];
    optional_features: OptionalFeatures;
    feature_config: FeatureConfig;
    deployment_options: {
      instance_count: number;
      instance_type: string;
      vpc_id: string;
      subnet_ids: string[];
      enable_multi_az: boolean;
      log_level: 'debug' | 'info' | 'warn' | 'error';
    };
  };
};

type SchemaEnvelope = {
  json_schema: {
    $defs: Record<string, { properties?: Record<string, { $ref?: string; title?: string }> }>;
  };
};

type ModuleConfigMeta = {
  id: keyof OptionalFeatures;
  configKey: keyof FeatureConfig;
  title: string;
  helpText: string;
};

type ValidationIssue = {
  code: string;
  severity: 'error' | 'warning';
  layer: 'schema' | 'business' | 'readiness' | 'ui';
  message: string;
  path?: string;
};

type SessionValidationResponse = {
  session_id: string;
  ready_to_deploy: boolean;
  blocking_issue_count: number;
  warning_count: number;
  issues: ValidationIssue[];
};

type ArtifactPreview = {
  name: string;
  version: string;
  hash: string;
  content: string;
};

type DiffEntry = {
  path: string;
  before: string;
  after: string;
};

type SessionTimelineEvent = {
  event_type: 'audit' | 'deploy_stage' | string;
  created_at: string;
  actor_email?: string | null;
  status?: string | null;
  message: string;
  details?: Record<string, string> | null;
};

type SessionEventsResponse = {
  session_id: string;
  events: SessionTimelineEvent[];
};

type IdentityProviderConfigResponse = {
  provider: {
    provider_id: string;
    provider_type: string;
    issuer: string;
    metadata_url: string | null;
    client_id: string;
    secret_ref: string;
    enabled: boolean;
  };
  config_status: 'draft' | 'validated' | 'active' | string;
};

type IdentityProviderRoleMapping = {
  mapping_id: number;
  provider_id: string;
  external_group_or_claim: string;
  internal_role: string;
  priority: number;
};

type DevDirectoryUser = {
  user_id: string;
  username: string;
  email: string | null;
  enabled: boolean;
  groups: string[];
};

type DevDirectoryUsersResponse = { users: DevDirectoryUser[] };
type DevDirectoryGroupsResponse = { groups: string[] };
type DevDirectoryActivityEvent = {
  event_id: number;
  event_type: string;
  auth_method: string;
  outcome: string;
  actor_email: string | null;
  provider_id: string | null;
  external_subject: string | null;
  external_tenant: string | null;
  mapped_role: string | null;
  failure_reason: string | null;
  troubleshooting_category: string | null;
  troubleshooting_hint: string | null;
  created_at: string;
};

type DevDirectoryActivityResponse = {
  events: DevDirectoryActivityEvent[];
};

const DRAFT_STORAGE_KEY = 'deployment_initializer.required_input_form.v1';
const SESSION_STORAGE_KEY = 'deployment_initializer.session_id.v1';
const ACTOR_ROLE_STORAGE_KEY = 'deployment_initializer.actor_role.v1';

const defaultModules: ModuleConfigMeta[] = [
  { id: 'enable_helpdesk', configKey: 'helpdesk', title: 'Helpdesk', helpText: 'Ticket routing and assignment options.' },
  { id: 'enable_messaging', configKey: 'messaging', title: 'Messaging', helpText: 'Retention and sharing controls.' },
  { id: 'enable_filemanager', configKey: 'filemanager', title: 'File Manager', helpText: 'Upload and malware scanning settings.' },
  { id: 'enable_alerting', configKey: 'alerting', title: 'Alerting', helpText: 'Notification destinations and channels.' },
  { id: 'enable_signature_packets', configKey: 'signature_packets', title: 'Signature Packets', helpText: 'E-sign reminder cadence options.' },
];

const initialDraft: RequiredFormData = {
  metadata: { env: '', region: '', created_by: '' },
  deployment_context: { environment: '', region: '', aws_account_id: '', app_name: '', owner_email: '' },
  required_secrets: {
    database_password: '',
    jwt_signing_key: '',
    internal_api_token: '',
    stripe_api_key: '',
    openai_api_key: '',
  },
  optional_features: {
    enable_helpdesk: false,
    enable_messaging: false,
    enable_filemanager: false,
    enable_alerting: true,
    enable_signature_packets: false,
  },
  feature_config: {
    helpdesk: { routing_queue: 'general', auto_assign: true },
    messaging: { retention_days: 30, allow_external_sharing: false },
    filemanager: { max_upload_mb: 100, enable_virus_scan: true },
    alerting: { slack_webhook_url: '', email_notifications_enabled: true },
    signature_packets: { reminder_interval_hours: 24 },
  },
  deployment_options: { vpc_id: '' },
};

function safeHydrateDraft(raw: unknown): RequiredFormData {
  if (!raw || typeof raw !== 'object') return initialDraft;
  const candidate = raw as Partial<RequiredFormData>;
  return {
    ...initialDraft,
    ...candidate,
    metadata: { ...initialDraft.metadata, ...candidate.metadata },
    deployment_context: { ...initialDraft.deployment_context, ...candidate.deployment_context },
    required_secrets: { ...initialDraft.required_secrets, ...candidate.required_secrets },
    optional_features: { ...initialDraft.optional_features, ...candidate.optional_features },
    feature_config: {
      ...initialDraft.feature_config,
      ...candidate.feature_config,
      helpdesk: { ...initialDraft.feature_config.helpdesk, ...candidate.feature_config?.helpdesk },
      messaging: { ...initialDraft.feature_config.messaging, ...candidate.feature_config?.messaging },
      filemanager: { ...initialDraft.feature_config.filemanager, ...candidate.feature_config?.filemanager },
      alerting: { ...initialDraft.feature_config.alerting, ...candidate.feature_config?.alerting },
      signature_packets: {
        ...initialDraft.feature_config.signature_packets,
        ...candidate.feature_config?.signature_packets,
      },
    },
    deployment_options: { ...initialDraft.deployment_options, ...candidate.deployment_options },
  };
}

function humanize(key: string): string {
  return key.replace(/^enable_/, '').replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}

function modulesFromSchema(schema: SchemaEnvelope | null): ModuleConfigMeta[] {
  if (!schema) return defaultModules;
  const defs = schema.json_schema.$defs;
  const optionalKeys = Object.keys(defs.OptionalFeatures?.properties ?? {});
  const featureProps = defs.FeatureConfig?.properties ?? {};

  const derived = optionalKeys
    .map((toggleKey) => {
      const configKey = toggleKey.replace(/^enable_/, '') as keyof FeatureConfig;
      if (!featureProps[configKey]) return null;
      return {
        id: toggleKey as keyof OptionalFeatures,
        configKey,
        title: humanize(toggleKey),
        helpText: `${humanize(toggleKey)} optional module settings.`,
      };
    })
    .filter((item): item is ModuleConfigMeta => item !== null);

  return derived.length > 0 ? derived : defaultModules;
}

function fieldErrors(draft: RequiredFormData): Record<string, string> {
  const errors: Record<string, string> = {};
  const required = (value: string, fieldKey: string, label: string) => {
    if (!value.trim()) errors[fieldKey] = `${label} is required.`;
  };

  required(draft.metadata.env, 'metadata.env', 'Session environment');
  required(draft.metadata.region, 'metadata.region', 'Session region');
  required(draft.metadata.created_by, 'metadata.created_by', 'Created by');
  required(draft.deployment_context.environment, 'deployment_context.environment', 'Deployment environment');
  required(draft.deployment_context.region, 'deployment_context.region', 'Deployment region');
  required(draft.deployment_context.aws_account_id, 'deployment_context.aws_account_id', 'AWS account ID');
  required(draft.deployment_context.app_name, 'deployment_context.app_name', 'Application name');
  required(draft.deployment_context.owner_email, 'deployment_context.owner_email', 'Owner email');
  required(draft.required_secrets.database_password, 'required_secrets.database_password', 'Database password');
  required(draft.required_secrets.jwt_signing_key, 'required_secrets.jwt_signing_key', 'JWT signing key');
  required(draft.required_secrets.internal_api_token, 'required_secrets.internal_api_token', 'Internal API token');
  required(draft.required_secrets.stripe_api_key, 'required_secrets.stripe_api_key', 'Stripe API key');
  required(draft.required_secrets.openai_api_key, 'required_secrets.openai_api_key', 'OpenAI API key');
  required(draft.deployment_options.vpc_id, 'deployment_options.vpc_id', 'VPC ID');

  if (draft.deployment_context.aws_account_id && !/^\d{12}$/.test(draft.deployment_context.aws_account_id)) {
    errors['deployment_context.aws_account_id'] = 'AWS account ID must be exactly 12 digits.';
  }

  if (draft.required_secrets.database_password && draft.required_secrets.database_password.length < 8) {
    errors['required_secrets.database_password'] = 'Database password must be at least 8 characters.';
  }

  if (draft.required_secrets.jwt_signing_key && draft.required_secrets.jwt_signing_key.length < 16) {
    errors['required_secrets.jwt_signing_key'] = 'JWT signing key must be at least 16 characters.';
  }

  if (draft.required_secrets.internal_api_token && draft.required_secrets.internal_api_token.length < 16) {
    errors['required_secrets.internal_api_token'] = 'Internal API token must be at least 16 characters.';
  }

  if (draft.optional_features.enable_helpdesk && !draft.feature_config.helpdesk.routing_queue.trim()) {
    errors['feature_config.helpdesk.routing_queue'] = 'Routing queue is required when Helpdesk is enabled.';
  }
  if (
    draft.optional_features.enable_messaging &&
    (draft.feature_config.messaging.retention_days < 1 || draft.feature_config.messaging.retention_days > 365)
  ) {
    errors['feature_config.messaging.retention_days'] = 'Retention days must be between 1 and 365.';
  }
  if (
    draft.optional_features.enable_filemanager &&
    (draft.feature_config.filemanager.max_upload_mb < 1 || draft.feature_config.filemanager.max_upload_mb > 10000)
  ) {
    errors['feature_config.filemanager.max_upload_mb'] = 'Max upload must be between 1 and 10,000 MB.';
  }
  if (
    draft.optional_features.enable_signature_packets &&
    (draft.feature_config.signature_packets.reminder_interval_hours < 1 ||
      draft.feature_config.signature_packets.reminder_interval_hours > 168)
  ) {
    errors['feature_config.signature_packets.reminder_interval_hours'] =
      'Reminder interval must be between 1 and 168 hours.';
  }

  return errors;
}

function toSessionPayload(draft: RequiredFormData) {
  return {
    metadata: draft.metadata,
    execution_mode: 'live',
    config: {
      schema_version: '1.0.0',
      deployment_context: draft.deployment_context,
      required_secrets: draft.required_secrets,
      optional_features: draft.optional_features,
      feature_config: {
        ...draft.feature_config,
        alerting: {
          ...draft.feature_config.alerting,
          slack_webhook_url: draft.feature_config.alerting.slack_webhook_url || null,
        },
      },
      deployment_options: {
        instance_count: 2,
        instance_type: 't3.medium',
        vpc_id: draft.deployment_options.vpc_id,
        subnet_ids: [],
        enable_multi_az: true,
        log_level: 'info',
      },
    },
  };
}

function simpleHash(content: string): string {
  let hash = 0;
  for (let i = 0; i < content.length; i += 1) {
    hash = (hash << 5) - hash + content.charCodeAt(i);
    hash |= 0;
  }
  return `h${Math.abs(hash).toString(16)}`;
}

function flattenObject(obj: unknown, prefix = ''): Record<string, string> {
  if (obj === null || obj === undefined) {
    return { [prefix]: String(obj) };
  }
  if (typeof obj !== 'object') {
    return { [prefix]: String(obj) };
  }

  const result: Record<string, string> = {};
  const entries = Object.entries(obj as Record<string, unknown>);
  for (const [key, value] of entries) {
    const nextPrefix = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value, nextPrefix));
    } else {
      result[nextPrefix] = Array.isArray(value) ? JSON.stringify(value) : String(value);
    }
  }
  return result;
}

function buildDiff(currentPayload: ReturnType<typeof toSessionPayload>, previousPayload: ReturnType<typeof toSessionPayload> | null): DiffEntry[] {
  const curr = flattenObject(currentPayload);
  const prev = previousPayload ? flattenObject(previousPayload) : {};
  const allKeys = Array.from(new Set([...Object.keys(curr), ...Object.keys(prev)])).sort();

  return allKeys
    .filter((key) => curr[key] !== prev[key])
    .map((key) => ({
      path: key,
      before: prev[key] ?? '(not set)',
      after: curr[key] ?? '(removed)',
    }));
}

export function App() {
  const [draft, setDraft] = useState<RequiredFormData>(initialDraft);
  const [schemaMeta, setSchemaMeta] = useState<SchemaEnvelope | null>(null);
  const [isHydrating, setIsHydrating] = useState(true);
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveMessage, setSaveMessage] = useState('');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [validationResult, setValidationResult] = useState<SessionValidationResponse | null>(null);
  const [validationLoading, setValidationLoading] = useState(false);
  const [reviewMessage, setReviewMessage] = useState('Run validation to refresh readiness summary.');
  const [artifacts, setArtifacts] = useState<ArtifactPreview[]>([]);
  const [diffEntries, setDiffEntries] = useState<DiffEntry[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<SessionTimelineEvent[]>([]);
  const [timelineMessage, setTimelineMessage] = useState('No event activity yet.');
  const [lastGeneratedPayload, setLastGeneratedPayload] = useState<ReturnType<typeof toSessionPayload> | null>(null);
  const [actorRole, setActorRole] = useState<'root' | 'admin' | 'operator' | 'viewer'>('admin');
  const [idpConfigs, setIdpConfigs] = useState<IdentityProviderConfigResponse[]>([]);
  const [idpForm, setIdpForm] = useState({
    provider_id: '',
    provider_type: 'oidc',
    issuer: '',
    metadata_url: '',
    client_id: '',
    secret_ref: '',
  });
  const [idpMappings, setIdpMappings] = useState<IdentityProviderRoleMapping[]>([]);
  const [mappingForm, setMappingForm] = useState({ external_group_or_claim: '', internal_role: 'admin', priority: 10 });
  const [selectedProviderId, setSelectedProviderId] = useState('');
  const [idpMessage, setIdpMessage] = useState('Load providers to manage Identity & SSO settings.');
  const [devDirectoryUsers, setDevDirectoryUsers] = useState<DevDirectoryUser[]>([]);
  const [devDirectoryGroups, setDevDirectoryGroups] = useState<string[]>([]);
  const [devDirectoryMessage, setDevDirectoryMessage] = useState('Load directory data to inspect local AD users/groups.');
  const [devDirectoryActivity, setDevDirectoryActivity] = useState<DevDirectoryActivityEvent[]>([]);
  const [activityFilters, setActivityFilters] = useState({ actor_email: '', provider_id: '', outcome: '', since_minutes: '60' });
  const [selectedActivityEventId, setSelectedActivityEventId] = useState<number | null>(null);
  const [devUserForm, setDevUserForm] = useState({ username: '', email: '', password: 'DevUser123!', groups: 'group-admins' });
  const [selectedDevUser, setSelectedDevUser] = useState('');
  const saveTimerRef = useRef<number | undefined>(undefined);

  const modules = useMemo(() => modulesFromSchema(schemaMeta), [schemaMeta]);
  const errors = useMemo(() => fieldErrors(draft), [draft]);

  const uiValidationIssues = useMemo<ValidationIssue[]>(
    () =>
      Object.entries(errors).map(([path, message]) => ({
        code: `ui.inline.${path.replace(/\./g, '_')}`,
        severity: 'error',
        layer: 'ui',
        message,
        path,
      })),
    [errors]
  );

  useEffect(() => {
    fetch('/schemas/deployment-config.schema.v1.json')
      .then((response) => response.json())
      .then((json) => setSchemaMeta(json as SchemaEnvelope))
      .catch(() => setSchemaMeta(null));
  }, []);

  useEffect(() => {
    const persistedDraft = window.localStorage.getItem(DRAFT_STORAGE_KEY);
    if (persistedDraft) {
      try {
        setDraft(safeHydrateDraft(JSON.parse(persistedDraft)));
      } catch {
        window.localStorage.removeItem(DRAFT_STORAGE_KEY);
      }
    }

    const persistedSessionId = window.localStorage.getItem(SESSION_STORAGE_KEY);
    if (!persistedSessionId) {
      setIsHydrating(false);
      return;
    }

    setSessionId(persistedSessionId);
    fetch(`/sessions/${persistedSessionId}`)
      .then(async (response) => {
        if (!response.ok) throw new Error('Unable to restore session from backend.');
        return (await response.json()) as SessionResponse;
      })
      .then((session) => {
        setDraft(
          safeHydrateDraft({
            metadata: session.metadata,
            deployment_context: session.config.deployment_context,
            required_secrets: session.config.required_secrets,
            optional_features: session.config.optional_features,
            feature_config: {
              ...session.config.feature_config,
              alerting: {
                ...session.config.feature_config.alerting,
                slack_webhook_url: session.config.feature_config.alerting.slack_webhook_url ?? '',
              },
            },
            deployment_options: { vpc_id: session.config.deployment_options.vpc_id },
          })
        );
      })
      .catch(() => {
        setSaveState('error');
        setSaveMessage('Could not restore existing backend session; using local draft only.');
      })
      .finally(() => setIsHydrating(false));
  }, []);

  useEffect(() => {
    const persistedRole = window.localStorage.getItem(ACTOR_ROLE_STORAGE_KEY);
    if (persistedRole === 'root' || persistedRole === 'admin' || persistedRole === 'operator' || persistedRole === 'viewer') {
      setActorRole(persistedRole);
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(ACTOR_ROLE_STORAGE_KEY, actorRole);
  }, [actorRole]);

  useEffect(() => {
    if (actorRole !== 'root' || !selectedProviderId) {
      setIdpMappings([]);
      return;
    }
    const headers = actorRole === 'root' ? { Authorization: 'Bearer root:root@example.com:root' } : { 'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': actorRole };
    fetch(`/auth/admin/sso/providers/${selectedProviderId}/role-mappings`, { headers })
      .then(async (response) => {
        if (!response.ok) return [] as IdentityProviderRoleMapping[];
        return (await response.json()) as IdentityProviderRoleMapping[];
      })
      .then((rows) => setIdpMappings(rows))
      .catch(() => setIdpMappings([]));
  }, [selectedProviderId, actorRole]);

  useEffect(() => {
    if (!isHydrating) {
      window.localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
    }
  }, [draft, isHydrating]);

  useEffect(() => {
    if (isHydrating) return;
    if (Object.keys(errors).length > 0) {
      setSaveState('idle');
      setSaveMessage('Autosave paused: fix required/active feature errors to save to backend session.');
      return;
    }

    if (saveTimerRef.current) window.clearTimeout(saveTimerRef.current);

    saveTimerRef.current = window.setTimeout(async () => {
      setSaveState('saving');
      setSaveMessage('Autosaving…');
      try {
        const payload = toSessionPayload(draft);

        if (!sessionId) {
          const createResponse = await fetch('/sessions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          if (!createResponse.ok) throw new Error('Failed to create session.');
          const created = (await createResponse.json()) as SessionResponse;
          setSessionId(created.session_id);
          window.localStorage.setItem(SESSION_STORAGE_KEY, created.session_id);
          setSaveState('saved');
          setSaveMessage(`Autosaved to session ${created.session_id}.`);
          return;
        }

        const updateResponse = await fetch(`/sessions/${sessionId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!updateResponse.ok) throw new Error('Failed to update session.');

        setSaveState('saved');
        setSaveMessage(`Autosaved to session ${sessionId}.`);
      } catch {
        setSaveState('error');
        setSaveMessage('Autosave failed. Your local draft is still stored in this browser.');
      }
    }, 600);

    return () => {
      if (saveTimerRef.current) window.clearTimeout(saveTimerRef.current);
    };
  }, [draft, errors, isHydrating, sessionId]);

  useEffect(() => {
    if (!sessionId) {
      setTimelineEvents([]);
      setTimelineMessage('No event activity yet.');
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const pollEvents = async () => {
      try {
        const response = await fetch(`/sessions/${sessionId}/events`, {
          headers: {
            'X-SSO-Email': draft.metadata.created_by || 'ops@example.com',
            'X-SSO-Role': 'admin',
          },
        });
        if (!response.ok) throw new Error('events_failed');
        const payload = (await response.json()) as SessionEventsResponse;
        if (!cancelled) {
          setTimelineEvents(payload.events);
          setTimelineMessage(payload.events.length > 0 ? 'Live timeline updated.' : 'No event activity yet.');
        }
      } catch {
        if (!cancelled) {
          setTimelineMessage('Could not load timeline events. Check backend auth/API availability.');
        }
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(pollEvents, 3000);
        }
      }
    };

    void pollEvents();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [sessionId, draft.metadata.created_by]);

  const updateTextField = (path: string, value: string) => {
    setDraft((current) => {
      const next = safeHydrateDraft(current);
      const [root, branch, leaf] = path.split('.');

      if (root === 'metadata') {
        next.metadata[branch as keyof RequiredFormData['metadata']] = value;
      } else if (root === 'deployment_context') {
        next.deployment_context[branch as keyof RequiredFormData['deployment_context']] = value;
      } else if (root === 'required_secrets') {
        next.required_secrets[branch as keyof RequiredFormData['required_secrets']] = value;
      } else if (root === 'deployment_options') {
        next.deployment_options[branch as keyof RequiredFormData['deployment_options']] = value;
      } else if (root === 'feature_config' && leaf) {
        if (branch === 'helpdesk') next.feature_config.helpdesk.routing_queue = value;
        if (branch === 'alerting') next.feature_config.alerting.slack_webhook_url = value;
      }

      return next;
    });
  };

  const updateBoolean = (path: string, checked: boolean) => {
    setDraft((current) => {
      const next = safeHydrateDraft(current);
      const [root, branch, leaf] = path.split('.');

      if (root === 'optional_features') {
        next.optional_features[branch as keyof OptionalFeatures] = checked;
      } else if (root === 'feature_config' && leaf) {
        if (branch === 'helpdesk') next.feature_config.helpdesk.auto_assign = checked;
        if (branch === 'messaging') next.feature_config.messaging.allow_external_sharing = checked;
        if (branch === 'filemanager') next.feature_config.filemanager.enable_virus_scan = checked;
        if (branch === 'alerting') next.feature_config.alerting.email_notifications_enabled = checked;
      }

      return next;
    });
  };

  const updateNumberField = (path: string, value: string) => {
    const numeric = Number(value);
    setDraft((current) => {
      const next = safeHydrateDraft(current);
      const [, branch] = path.split('.');
      if (branch === 'messaging') next.feature_config.messaging.retention_days = numeric;
      if (branch === 'filemanager') next.feature_config.filemanager.max_upload_mb = numeric;
      if (branch === 'signature_packets') next.feature_config.signature_packets.reminder_interval_hours = numeric;
      return next;
    });
  };

  const runValidationSummary = async () => {
    if (!sessionId) {
      setValidationResult(null);
      setReviewMessage('Save valid required fields first so a backend session exists for validation.');
      return;
    }

    setValidationLoading(true);
    try {
      const response = await fetch(`/sessions/${sessionId}/validate`, { method: 'POST' });
      if (!response.ok) throw new Error('validation_failed');
      const validation = (await response.json()) as SessionValidationResponse;
      setValidationResult(validation);
      setReviewMessage('Validation summary refreshed.');
    } catch {
      setReviewMessage('Could not run backend validation summary. Check backend availability and try again.');
    } finally {
      setValidationLoading(false);
    }
  };

  const generateArtifactPreview = () => {
    const payload = toSessionPayload(draft);
    const localEnv = [
      `AWS_REGION=${payload.config.deployment_context.region}`,
      `APP_NAME=${payload.config.deployment_context.app_name}`,
      `VPC_ID=${payload.config.deployment_options.vpc_id}`,
      `ENABLE_HELPDESK=${String(payload.config.optional_features.enable_helpdesk)}`,
      `ENABLE_MESSAGING=${String(payload.config.optional_features.enable_messaging)}`,
    ].join('\n');

    const serviceConfig = JSON.stringify(
      {
        schema_version: payload.config.schema_version,
        deployment_context: payload.config.deployment_context,
        optional_features: payload.config.optional_features,
        feature_config: payload.config.feature_config,
      },
      null,
      2
    );

    const iacParams = JSON.stringify(
      {
        version: payload.config.schema_version,
        region: payload.config.deployment_context.region,
        account_id: payload.config.deployment_context.aws_account_id,
        app_name: payload.config.deployment_context.app_name,
        vpc_id: payload.config.deployment_options.vpc_id,
      },
      null,
      2
    );

    const nextArtifacts: ArtifactPreview[] = [
      { name: '.env.preview', version: payload.config.schema_version, hash: simpleHash(localEnv), content: localEnv },
      { name: 'service-config.preview.json', version: payload.config.schema_version, hash: simpleHash(serviceConfig), content: serviceConfig },
      { name: 'iac-params.preview.json', version: payload.config.schema_version, hash: simpleHash(iacParams), content: iacParams },
    ];

    setArtifacts(nextArtifacts);
    setDiffEntries(buildDiff(payload, lastGeneratedPayload));
    setLastGeneratedPayload(payload);
    setReviewMessage('Generated preview artifacts and config diff.');
  };

  const blockingIssues = [
    ...uiValidationIssues,
    ...(validationResult?.issues.filter((issue) => issue.severity === 'error') ?? []),
  ];
  const warningIssues = validationResult?.issues.filter((issue) => issue.severity === 'warning') ?? [];
  const readyToDeploy = blockingIssues.length === 0;

  const inputStyle = (fieldKey: string): CSSProperties => ({
    width: '100%',
    padding: '0.5rem',
    borderRadius: 6,
    border: errors[fieldKey] ? '1px solid #c0392b' : '1px solid #cfd8dc',
    marginTop: '0.25rem',
  });

  const renderField = (
    label: string,
    fieldKey: string,
    value: string,
    onChange: (value: string) => void,
    type: 'text' | 'email' | 'password' = 'text'
  ) => (
    <label style={{ display: 'block', marginBottom: '0.9rem' }}>
      <span style={{ fontWeight: 600 }}>{label}</span>
      <input aria-label={label} type={type} value={value} onChange={(event) => onChange(event.target.value)} style={inputStyle(fieldKey)} />
      {errors[fieldKey] && <span style={{ color: '#c0392b', fontSize: '0.85rem' }}>{errors[fieldKey]}</span>}
    </label>
  );

  const selectedActivityEvent = devDirectoryActivity.find((item) => item.event_id === selectedActivityEventId) ?? null;

  const formErrorCount = Object.keys(errors).length;
  const isRootActor = actorRole === 'root';
  const rootHeaders = isRootActor ? { Authorization: 'Bearer root:root@example.com:root' } : { 'X-SSO-Email': 'admin@example.com', 'X-SSO-Role': actorRole };

  const loadIdpConfigs = async () => {
    const response = await fetch('/auth/admin/sso/providers', { headers: rootHeaders });
    if (!response.ok) {
      setIdpMessage('Unable to load provider settings. Root role is required.');
      return;
    }
    const payload = (await response.json()) as { providers: IdentityProviderConfigResponse[] };
    setIdpConfigs(payload.providers);
    const nextSelected = payload.providers[0]?.provider.provider_id ?? '';
    setSelectedProviderId(nextSelected);
    setIdpMessage(`Loaded ${payload.providers.length} provider configuration(s).`);

    if (nextSelected) {
      const mappingsResponse = await fetch(`/auth/admin/sso/providers/${nextSelected}/role-mappings`, { headers: rootHeaders });
      if (mappingsResponse.ok) {
        setIdpMappings((await mappingsResponse.json()) as IdentityProviderRoleMapping[]);
      }
    }
  };

  const saveProviderConfig = async () => {
    const response = await fetch('/auth/admin/sso/providers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...rootHeaders },
      body: JSON.stringify({
        ...idpForm,
        metadata_url: idpForm.metadata_url || null,
      }),
    });
    if (!response.ok) {
      const error = await response.json();
      setIdpMessage(`Save failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setIdpMessage('Provider saved in draft status.');
    await loadIdpConfigs();
  };

  const runProviderAction = async (action: 'test-config' | 'validate' | 'activate' | 'deactivate') => {
    if (!selectedProviderId) return;
    const response = await fetch(`/auth/admin/sso/providers/${selectedProviderId}/${action}`, {
      method: 'POST',
      headers: rootHeaders,
    });
    if (!response.ok) {
      const error = await response.json();
      setIdpMessage(`${action} failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setIdpMessage(`${action} completed for ${selectedProviderId}.`);
    await loadIdpConfigs();
  };

  const addRoleMapping = async () => {
    if (!selectedProviderId) return;
    const response = await fetch(`/auth/admin/sso/providers/${selectedProviderId}/role-mappings?external_group_or_claim=${encodeURIComponent(mappingForm.external_group_or_claim)}&internal_role=${encodeURIComponent(mappingForm.internal_role)}&priority=${mappingForm.priority}`, {
      method: 'POST',
      headers: rootHeaders,
    });
    if (!response.ok) {
      const error = await response.json();
      setIdpMessage(`Add mapping failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setIdpMessage('Role mapping added.');
    await loadIdpConfigs();
  };

  const rollbackSso = async () => {
    const response = await fetch('/auth/admin/sso/rollback', { method: 'POST', headers: rootHeaders });
    if (!response.ok) {
      const error = await response.json();
      setIdpMessage(`Rollback failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setIdpMessage('Rollback complete: SSO disabled and local-only admin login restored.');
    await loadIdpConfigs();
  };

  const isSeededDevUser = (username: string) => ['admin@example.com', 'ops@example.com'].includes(username);

  const loadDevDirectoryData = async () => {
    const params = new URLSearchParams({ limit: '50' });
    if (activityFilters.actor_email.trim()) params.set('actor_email', activityFilters.actor_email.trim());
    if (activityFilters.provider_id.trim()) params.set('provider_id', activityFilters.provider_id.trim());
    if (activityFilters.outcome.trim()) params.set('outcome', activityFilters.outcome.trim());
    if (activityFilters.since_minutes.trim()) params.set('since_minutes', activityFilters.since_minutes.trim());

    const [usersResp, groupsResp, activityResp] = await Promise.all([
      fetch('/auth/admin/sso/dev-directory/users', { headers: rootHeaders }),
      fetch('/auth/admin/sso/dev-directory/groups', { headers: rootHeaders }),
      fetch(`/auth/admin/sso/dev-directory/activity?${params.toString()}`, { headers: rootHeaders }),
    ]);

    if (!usersResp.ok || !groupsResp.ok || !activityResp.ok) {
      setDevDirectoryMessage('Unable to load dev directory data. Root role and local Keycloak mode are required.');
      return;
    }

    const usersPayload = (await usersResp.json()) as DevDirectoryUsersResponse;
    const groupsPayload = (await groupsResp.json()) as DevDirectoryGroupsResponse;
    const activityPayload = (await activityResp.json()) as DevDirectoryActivityResponse;

    setDevDirectoryUsers(usersPayload.users);
    setDevDirectoryGroups(groupsPayload.groups);
    setDevDirectoryActivity(activityPayload.events);
    setSelectedActivityEventId((prev) => prev ?? activityPayload.events[0]?.event_id ?? null);
    setSelectedDevUser((prev) => prev || usersPayload.users[0]?.username || '');
    setDevDirectoryMessage(`Loaded ${usersPayload.users.length} user(s), ${groupsPayload.groups.length} group(s), ${activityPayload.events.length} activity event(s).`);
  };

  const createDevDirectoryUser = async () => {
    const groups = devUserForm.groups.split(',').map((g) => g.trim()).filter(Boolean);
    const response = await fetch('/auth/admin/sso/dev-directory/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...rootHeaders },
      body: JSON.stringify({
        username: devUserForm.username,
        email: devUserForm.email || null,
        password: devUserForm.password,
        groups,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      setDevDirectoryMessage(`Create user failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }

    setDevDirectoryMessage(`Created/updated user ${devUserForm.username}.`);
    setDevUserForm((prev) => ({ ...prev, username: '', email: '' }));
    await loadDevDirectoryData();
  };

  const setDevDirectoryUserEnabled = async (username: string, enabled: boolean) => {
    const response = await fetch(`/auth/admin/sso/dev-directory/users/${encodeURIComponent(username)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...rootHeaders },
      body: JSON.stringify({ enabled }),
    });
    if (!response.ok) {
      const error = await response.json();
      setDevDirectoryMessage(`Update user failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setDevDirectoryMessage(`${enabled ? 'Enabled' : 'Disabled'} ${username}.`);
    await loadDevDirectoryData();
  };

  const addSelectedUserToGroup = async (groupName: string) => {
    if (!selectedDevUser) return;
    const response = await fetch(`/auth/admin/sso/dev-directory/users/${encodeURIComponent(selectedDevUser)}/groups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...rootHeaders },
      body: JSON.stringify({ group_name: groupName }),
    });
    if (!response.ok) {
      const error = await response.json();
      setDevDirectoryMessage(`Add group failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setDevDirectoryMessage(`Added ${selectedDevUser} to ${groupName}.`);
    await loadDevDirectoryData();
  };

  const removeUserFromGroup = async (username: string, groupName: string) => {
    if (!username) return;
    const response = await fetch(`/auth/admin/sso/dev-directory/users/${encodeURIComponent(username)}/groups/${encodeURIComponent(groupName)}`, {
      method: 'DELETE',
      headers: rootHeaders,
    });
    if (!response.ok) {
      const error = await response.json();
      setDevDirectoryMessage(`Remove group failed: ${error.detail ?? 'unknown_error'}`);
      return;
    }
    setDevDirectoryMessage(`Removed ${username} from ${groupName}.`);
    await loadDevDirectoryData();
  };

  const quickSeedPersona = async (persona: 'admin' | 'ops' | 'denied') => {
    const seedUser =
      persona === 'admin'
        ? { username: 'seed-admin@example.com', email: 'seed-admin@example.com', groups: ['group-admins'] }
        : persona === 'ops'
          ? { username: 'seed-ops@example.com', email: 'seed-ops@example.com', groups: ['group-ops'] }
          : { username: 'seed-denied@example.com', email: 'seed-denied@example.com', groups: [] as string[] };

    const createResp = await fetch('/auth/admin/sso/dev-directory/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...rootHeaders },
      body: JSON.stringify({ ...seedUser, password: 'DevUser123!' }),
    });
    if (!createResp.ok) {
      setDevDirectoryMessage(`Quick seed failed for ${persona}.`);
      return;
    }

    setDevDirectoryMessage(`Quick seeded ${persona} persona (${seedUser.username}).`);
    await loadDevDirectoryData();
  };

  return (
    <main style={{ fontFamily: 'Inter, Arial, sans-serif', margin: '2rem', maxWidth: 980 }}>
      <h1>Deployment Initializer UI</h1>
      <p>Required-input + optional-feature form with inline validation and backend session autosave.</p>

      <section style={{ marginBottom: '1rem', border: '1px solid #d5dce3', borderRadius: 8, padding: '0.75rem 1rem', background: '#f8fafc' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <strong>Acting Role (UI permission simulation)</strong>
          <select aria-label='Acting Role' value={actorRole} onChange={(event) => setActorRole(event.target.value as 'root' | 'admin' | 'operator' | 'viewer')}>
            <option value='root'>root</option>
            <option value='admin'>admin</option>
            <option value='operator'>operator</option>
            <option value='viewer'>viewer</option>
          </select>
        </label>
      </section>

      <section style={{ padding: '0.75rem 1rem', borderRadius: 8, background: saveState === 'error' ? '#fdecea' : '#f5f9ff', border: '1px solid #dbe5f0', marginBottom: '1rem' }}>
        <strong>Autosave status:</strong> {isHydrating ? 'Restoring session...' : saveMessage || 'Waiting for input.'}
        <div style={{ marginTop: '0.35rem', fontSize: '0.9rem' }}>Session ID: {sessionId ?? 'Not created yet (requires valid fields)'}</div>
      </section>

      <section style={{ marginBottom: '1rem', borderRadius: 8, border: formErrorCount > 0 ? '1px solid #c0392b' : '1px solid #d0d7de', background: formErrorCount > 0 ? '#fff5f5' : '#f8fafc', padding: '0.75rem 1rem' }}>
        <strong>Form validation:</strong>{' '}
        {formErrorCount > 0 ? `${formErrorCount} issue(s) need attention.` : 'All active fields currently pass inline validation.'}
      </section>

      <form>
        <h2>Session Metadata</h2>
        {renderField('Session Environment', 'metadata.env', draft.metadata.env, (v) => updateTextField('metadata.env', v))}
        {renderField('Session Region', 'metadata.region', draft.metadata.region, (v) => updateTextField('metadata.region', v))}
        {renderField('Created By (email)', 'metadata.created_by', draft.metadata.created_by, (v) => updateTextField('metadata.created_by', v), 'email')}

        <h2>Deployment Context (Required)</h2>
        {renderField('Deployment Environment', 'deployment_context.environment', draft.deployment_context.environment, (v) => updateTextField('deployment_context.environment', v))}
        {renderField('Deployment Region', 'deployment_context.region', draft.deployment_context.region, (v) => updateTextField('deployment_context.region', v))}
        {renderField('AWS Account ID (12 digits)', 'deployment_context.aws_account_id', draft.deployment_context.aws_account_id, (v) => updateTextField('deployment_context.aws_account_id', v))}
        {renderField('Application Name', 'deployment_context.app_name', draft.deployment_context.app_name, (v) => updateTextField('deployment_context.app_name', v))}
        {renderField('Owner Email', 'deployment_context.owner_email', draft.deployment_context.owner_email, (v) => updateTextField('deployment_context.owner_email', v), 'email')}

        <h2>Required Secrets</h2>
        {renderField('Database Password', 'required_secrets.database_password', draft.required_secrets.database_password, (v) => updateTextField('required_secrets.database_password', v), 'password')}
        {renderField('JWT Signing Key', 'required_secrets.jwt_signing_key', draft.required_secrets.jwt_signing_key, (v) => updateTextField('required_secrets.jwt_signing_key', v), 'password')}
        {renderField('Internal API Token', 'required_secrets.internal_api_token', draft.required_secrets.internal_api_token, (v) => updateTextField('required_secrets.internal_api_token', v), 'password')}
        {renderField('Stripe API Key', 'required_secrets.stripe_api_key', draft.required_secrets.stripe_api_key, (v) => updateTextField('required_secrets.stripe_api_key', v), 'password')}
        {renderField('OpenAI API Key', 'required_secrets.openai_api_key', draft.required_secrets.openai_api_key, (v) => updateTextField('required_secrets.openai_api_key', v), 'password')}

        <h2>Optional Features & Advanced Settings</h2>
        <p style={{ marginTop: 0, color: '#4b5563' }}>
          Toggle optional modules to reveal advanced settings. Hidden modules have validation deactivated.
        </p>

        {modules.map((module) => {
          const enabled = draft.optional_features[module.id];
          return (
            <section key={module.id} style={{ border: '1px solid #d8dee4', borderRadius: 8, padding: '0.75rem', marginBottom: '0.75rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }} title={module.helpText}>
                <input
                  type='checkbox'
                  checked={enabled}
                  onChange={(event) => updateBoolean(`optional_features.${module.id}`, event.target.checked)}
                  aria-label={`Enable ${module.title}`}
                />
                Enable {module.title}
              </label>
              <div style={{ fontSize: '0.88rem', color: '#596273', marginTop: '0.25rem' }}>{module.helpText}</div>

              {enabled && module.configKey === 'helpdesk' && (
                <div style={{ marginTop: '0.75rem' }}>
                  {renderField('Helpdesk Routing Queue', 'feature_config.helpdesk.routing_queue', draft.feature_config.helpdesk.routing_queue, (v) => updateTextField('feature_config.helpdesk.routing_queue', v))}
                  <label title='Automatically assign incoming tickets to available agents.'>
                    <input
                      type='checkbox'
                      checked={draft.feature_config.helpdesk.auto_assign}
                      onChange={(event) => updateBoolean('feature_config.helpdesk.auto_assign', event.target.checked)}
                    />{' '}
                    Auto-assign tickets
                  </label>
                </div>
              )}

              {enabled && module.configKey === 'messaging' && (
                <div style={{ marginTop: '0.75rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.9rem' }} title='Retention period in days before message archive/purge lifecycle.'>
                    <span style={{ fontWeight: 600 }}>Messaging Retention Days</span>
                    <input
                      aria-label='Messaging Retention Days'
                      type='number'
                      value={draft.feature_config.messaging.retention_days}
                      onChange={(event) => updateNumberField('feature_config.messaging.retention_days', event.target.value)}
                      style={inputStyle('feature_config.messaging.retention_days')}
                    />
                    {errors['feature_config.messaging.retention_days'] && (
                      <span style={{ color: '#c0392b', fontSize: '0.85rem' }}>{errors['feature_config.messaging.retention_days']}</span>
                    )}
                  </label>
                  <label title='Allow users to share messages with external participants.'>
                    <input
                      type='checkbox'
                      checked={draft.feature_config.messaging.allow_external_sharing}
                      onChange={(event) => updateBoolean('feature_config.messaging.allow_external_sharing', event.target.checked)}
                    />{' '}
                    Allow external sharing
                  </label>
                </div>
              )}

              {enabled && module.configKey === 'filemanager' && (
                <div style={{ marginTop: '0.75rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.9rem' }} title='Maximum upload size in MB for the file manager.'>
                    <span style={{ fontWeight: 600 }}>File Upload Max (MB)</span>
                    <input
                      aria-label='File Upload Max (MB)'
                      type='number'
                      value={draft.feature_config.filemanager.max_upload_mb}
                      onChange={(event) => updateNumberField('feature_config.filemanager.max_upload_mb', event.target.value)}
                      style={inputStyle('feature_config.filemanager.max_upload_mb')}
                    />
                    {errors['feature_config.filemanager.max_upload_mb'] && (
                      <span style={{ color: '#c0392b', fontSize: '0.85rem' }}>{errors['feature_config.filemanager.max_upload_mb']}</span>
                    )}
                  </label>
                  <label title='Enable malware scanning for uploaded files.'>
                    <input
                      type='checkbox'
                      checked={draft.feature_config.filemanager.enable_virus_scan}
                      onChange={(event) => updateBoolean('feature_config.filemanager.enable_virus_scan', event.target.checked)}
                    />{' '}
                    Enable virus scanning
                  </label>
                </div>
              )}

              {enabled && module.configKey === 'alerting' && (
                <div style={{ marginTop: '0.75rem' }}>
                  {renderField('Slack Webhook URL (optional)', 'feature_config.alerting.slack_webhook_url', draft.feature_config.alerting.slack_webhook_url, (v) => updateTextField('feature_config.alerting.slack_webhook_url', v))}
                  <label title='Send alert notifications to email recipients.'>
                    <input
                      type='checkbox'
                      checked={draft.feature_config.alerting.email_notifications_enabled}
                      onChange={(event) => updateBoolean('feature_config.alerting.email_notifications_enabled', event.target.checked)}
                    />{' '}
                    Email notifications enabled
                  </label>
                </div>
              )}

              {enabled && module.configKey === 'signature_packets' && (
                <div style={{ marginTop: '0.75rem' }}>
                  <label style={{ display: 'block', marginBottom: '0.9rem' }} title='Hours between reminder emails for pending signatures.'>
                    <span style={{ fontWeight: 600 }}>Reminder Interval (hours)</span>
                    <input
                      aria-label='Reminder Interval (hours)'
                      type='number'
                      value={draft.feature_config.signature_packets.reminder_interval_hours}
                      onChange={(event) => updateNumberField('feature_config.signature_packets.reminder_interval_hours', event.target.value)}
                      style={inputStyle('feature_config.signature_packets.reminder_interval_hours')}
                    />
                    {errors['feature_config.signature_packets.reminder_interval_hours'] && (
                      <span style={{ color: '#c0392b', fontSize: '0.85rem' }}>{errors['feature_config.signature_packets.reminder_interval_hours']}</span>
                    )}
                  </label>
                </div>
              )}
            </section>
          );
        })}

        <h2>Deployment Options (Required)</h2>
        {renderField('VPC ID', 'deployment_options.vpc_id', draft.deployment_options.vpc_id, (v) => updateTextField('deployment_options.vpc_id', v))}
      </form>

      <section style={{ marginTop: '2rem', border: '1px solid #d5dce3', borderRadius: 10, padding: '1rem' }}>
        <h2>Identity & SSO (Root Admin)</h2>
        <p style={{ marginTop: 0, color: '#4b5563' }}>
          Configure provider protocol settings, role mappings, and lifecycle actions (save, test, validate, activate, rollback).
        </p>

        {!isRootActor ? (
          <div style={{ padding: '0.75rem', borderRadius: 8, border: '1px solid #f2b8b5', background: '#fff4f4', color: '#b42318' }}>
            Root role required. Non-root users cannot access or mutate Identity & SSO settings.
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <button type='button' onClick={loadIdpConfigs}>Load Providers</button>
              <button type='button' onClick={saveProviderConfig}>Save Provider (Draft)</button>
              <button type='button' onClick={() => runProviderAction('test-config')} disabled={!selectedProviderId}>Test Config</button>
              <button type='button' onClick={() => runProviderAction('validate')} disabled={!selectedProviderId}>Validate</button>
              <button type='button' onClick={() => runProviderAction('activate')} disabled={!selectedProviderId}>Activate</button>
              <button type='button' onClick={() => runProviderAction('deactivate')} disabled={!selectedProviderId}>Deactivate</button>
              <button type='button' onClick={rollbackSso}>Rollback (Disable SSO)</button>
            </div>

            <div style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>{idpMessage}</div>

            {renderField('Provider ID', 'idp.provider_id', idpForm.provider_id, (v) => setIdpForm((prev) => ({ ...prev, provider_id: v })))}
            {renderField('Protocol (oidc|saml)', 'idp.provider_type', idpForm.provider_type, (v) => setIdpForm((prev) => ({ ...prev, provider_type: v })))}
            {renderField('Issuer', 'idp.issuer', idpForm.issuer, (v) => setIdpForm((prev) => ({ ...prev, issuer: v })))}
            {renderField('Metadata URL (required for SAML)', 'idp.metadata_url', idpForm.metadata_url, (v) => setIdpForm((prev) => ({ ...prev, metadata_url: v })))}
            {renderField('Client ID', 'idp.client_id', idpForm.client_id, (v) => setIdpForm((prev) => ({ ...prev, client_id: v })))}
            {renderField('Secret Ref', 'idp.secret_ref', idpForm.secret_ref, (v) => setIdpForm((prev) => ({ ...prev, secret_ref: v })))}

            <label style={{ display: 'block', marginBottom: '0.9rem' }}>
              <span style={{ fontWeight: 600 }}>Selected Provider</span>
              <select aria-label='Selected Provider' value={selectedProviderId} onChange={(event) => setSelectedProviderId(event.target.value)} style={{ width: '100%', padding: '0.5rem', borderRadius: 6, border: '1px solid #cfd8dc', marginTop: '0.25rem' }}>
                <option value=''>-- select provider --</option>
                {idpConfigs.map((entry) => (
                  <option key={entry.provider.provider_id} value={entry.provider.provider_id}>
                    {entry.provider.provider_id} ({entry.provider.provider_type}, {entry.config_status})
                  </option>
                ))}
              </select>
            </label>

            <h3>Role Mappings</h3>
            {renderField('External Group/Claim', 'idp.mapping.group', mappingForm.external_group_or_claim, (v) => setMappingForm((prev) => ({ ...prev, external_group_or_claim: v })))}
            {renderField('Internal Role', 'idp.mapping.role', mappingForm.internal_role, (v) => setMappingForm((prev) => ({ ...prev, internal_role: v })))}
            <label style={{ display: 'block', marginBottom: '0.9rem' }}>
              <span style={{ fontWeight: 600 }}>Priority</span>
              <input aria-label='Mapping Priority' type='number' value={mappingForm.priority} onChange={(event) => setMappingForm((prev) => ({ ...prev, priority: Number(event.target.value) || 0 }))} style={{ width: '100%', padding: '0.5rem', borderRadius: 6, border: '1px solid #cfd8dc', marginTop: '0.25rem' }} />
            </label>
            <button type='button' onClick={addRoleMapping} disabled={!selectedProviderId || !mappingForm.external_group_or_claim.trim()}>Add Mapping</button>

            {idpMappings.length > 0 && (
              <ul>
                {idpMappings.map((mapping) => (
                  <li key={mapping.mapping_id}>
                    #{mapping.priority} {mapping.external_group_or_claim} → {mapping.internal_role}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </section>

      <section data-testid='dev-directory-panel' style={{ marginTop: '1rem', border: '1px solid #d5dce3', borderRadius: 10, padding: '1rem' }}>
        <h2>Dev Directory (Local AD/Keycloak)</h2>
        <p style={{ marginTop: 0, color: '#4b5563' }}>
          Inspect local directory users/groups, provision test users, and manage group assignments for AD login testing.
        </p>

        {!isRootActor ? (
          <div style={{ color: '#7f1d1d', background: '#fff7ed', padding: '0.6rem', borderRadius: 8 }}>
            Root role required. Non-root users cannot inspect or mutate Dev Directory settings.
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <button data-testid='dev-directory-load' type='button' onClick={loadDevDirectoryData}>Load Directory Data</button>
              <button data-testid='dev-directory-seed-admin' type='button' onClick={() => quickSeedPersona('admin')}>Quick Seed Admin Persona</button>
              <button data-testid='dev-directory-seed-ops' type='button' onClick={() => quickSeedPersona('ops')}>Quick Seed Ops Persona</button>
              <button data-testid='dev-directory-seed-denied' type='button' onClick={() => quickSeedPersona('denied')}>Quick Seed Denied Persona</button>
            </div>

            <div style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>{devDirectoryMessage}</div>

            <h3>Create / Update Dev User</h3>
            {renderField('Dev Username', 'dev.user.username', devUserForm.username, (v) => setDevUserForm((prev) => ({ ...prev, username: v })))}
            {renderField('Dev Email', 'dev.user.email', devUserForm.email, (v) => setDevUserForm((prev) => ({ ...prev, email: v })), 'email')}
            {renderField('Dev Password', 'dev.user.password', devUserForm.password, (v) => setDevUserForm((prev) => ({ ...prev, password: v })))}
            {renderField('Initial Groups (comma-separated)', 'dev.user.groups', devUserForm.groups, (v) => setDevUserForm((prev) => ({ ...prev, groups: v })))}
            <button type='button' onClick={createDevDirectoryUser} disabled={!devUserForm.username.trim() || !devUserForm.password.trim()}>
              Create / Sync User
            </button>

            <h3 style={{ marginTop: '1rem' }}>Directory Users</h3>
            <label style={{ display: 'block', marginBottom: '0.9rem' }}>
              <span style={{ fontWeight: 600 }}>Selected Dev User</span>
              <select aria-label='Selected Dev User' value={selectedDevUser} onChange={(event) => setSelectedDevUser(event.target.value)} style={{ width: '100%', padding: '0.5rem', borderRadius: 6, border: '1px solid #cfd8dc', marginTop: '0.25rem' }}>
                <option value=''>-- select user --</option>
                {devDirectoryUsers.map((user) => (
                  <option key={user.user_id} value={user.username}>
                    {user.username}
                  </option>
                ))}
              </select>
            </label>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <button type='button' disabled={!selectedDevUser} onClick={() => setDevDirectoryUserEnabled(selectedDevUser, true)}>Enable User</button>
              <button type='button' disabled={!selectedDevUser} onClick={() => setDevDirectoryUserEnabled(selectedDevUser, false)}>Disable User</button>
              <button type='button' disabled={!selectedDevUser} onClick={() => addSelectedUserToGroup('group-admins')}>Add group-admins</button>
              <button type='button' disabled={!selectedDevUser} onClick={() => addSelectedUserToGroup('group-ops')}>Add group-ops</button>
            </div>

            {devDirectoryUsers.length > 0 && (
              <ul aria-label='Dev Directory Users'>
                {devDirectoryUsers.map((user) => (
                  <li key={user.user_id}>
                    <strong>{user.username}</strong> {isSeededDevUser(user.username) ? '(seeded)' : '(custom)'} · status: {user.enabled ? 'active' : 'disabled'} · groups: {user.groups.join(', ') || 'none'}
                    {user.groups.map((group) => (
                      <button key={`${user.user_id}-${group}`} type='button' style={{ marginLeft: '0.5rem' }} onClick={() => {
                        setSelectedDevUser(user.username);
                        void removeUserFromGroup(user.username, group);
                      }}>
                        remove {group}
                      </button>
                    ))}
                  </li>
                ))}
              </ul>
            )}

            {devDirectoryGroups.length > 0 && (
              <p style={{ fontSize: '0.9rem' }}>
                Available Groups: {devDirectoryGroups.join(', ')}
              </p>
            )}

            <h3 style={{ marginTop: '1rem' }}>AD Activity Explorer</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <label>
                <span style={{ fontWeight: 600 }}>Actor Email</span>
                <input
                  aria-label='Activity Filter Actor Email'
                  value={activityFilters.actor_email}
                  onChange={(event) => setActivityFilters((prev) => ({ ...prev, actor_email: event.target.value }))}
                  style={{ width: '100%', padding: '0.45rem', borderRadius: 6, border: '1px solid #cfd8dc' }}
                />
              </label>
              <label>
                <span style={{ fontWeight: 600 }}>Provider ID</span>
                <input
                  aria-label='Activity Filter Provider ID'
                  value={activityFilters.provider_id}
                  onChange={(event) => setActivityFilters((prev) => ({ ...prev, provider_id: event.target.value }))}
                  style={{ width: '100%', padding: '0.45rem', borderRadius: 6, border: '1px solid #cfd8dc' }}
                />
              </label>
              <label>
                <span style={{ fontWeight: 600 }}>Outcome</span>
                <select
                  aria-label='Activity Filter Outcome'
                  value={activityFilters.outcome}
                  onChange={(event) => setActivityFilters((prev) => ({ ...prev, outcome: event.target.value }))}
                  style={{ width: '100%', padding: '0.45rem', borderRadius: 6, border: '1px solid #cfd8dc' }}
                >
                  <option value=''>all</option>
                  <option value='success'>success</option>
                  <option value='failure'>failure</option>
                  <option value='denied'>denied</option>
                </select>
              </label>
              <label>
                <span style={{ fontWeight: 600 }}>Since Minutes</span>
                <input
                  aria-label='Activity Filter Since Minutes'
                  type='number'
                  min={1}
                  value={activityFilters.since_minutes}
                  onChange={(event) => setActivityFilters((prev) => ({ ...prev, since_minutes: event.target.value }))}
                  style={{ width: '100%', padding: '0.45rem', borderRadius: 6, border: '1px solid #cfd8dc' }}
                />
              </label>
            </div>
            <button data-testid='dev-directory-activity-apply-filters' type='button' onClick={loadDevDirectoryData}>Apply Activity Filters</button>

            {devDirectoryActivity.length > 0 && (
              <>
                <ul aria-label='AD Activity Timeline'>
                  {devDirectoryActivity.slice(0, 20).map((event) => (
                    <li key={event.event_id}>
                      <button
                        type='button'
                        onClick={() => setSelectedActivityEventId(event.event_id)}
                        style={{ marginRight: '0.5rem' }}
                      >
                        View
                      </button>
                      #{event.event_id} [{event.outcome}] {event.actor_email ?? event.external_subject ?? 'unknown'}
                      {event.failure_reason ? ` - ${event.failure_reason}` : ''}
                    </li>
                  ))}
                </ul>

                {selectedActivityEvent && (
                  <details open>
                    <summary>Activity Event Details #{selectedActivityEvent.event_id}</summary>
                    <div style={{ fontSize: '0.92rem', lineHeight: 1.5 }}>
                      <div><strong>Type:</strong> {selectedActivityEvent.event_type}</div>
                      <div><strong>Outcome:</strong> {selectedActivityEvent.outcome}</div>
                      <div><strong>Actor:</strong> {selectedActivityEvent.actor_email ?? 'n/a'}</div>
                      <div><strong>Provider:</strong> {selectedActivityEvent.provider_id ?? 'n/a'}</div>
                      <div><strong>Failure Reason:</strong> {selectedActivityEvent.failure_reason ?? 'n/a'}</div>
                      <div><strong>Troubleshooting Category:</strong> {selectedActivityEvent.troubleshooting_category ?? 'n/a'}</div>
                      <div><strong>Troubleshooting Hint:</strong> {selectedActivityEvent.troubleshooting_hint ?? 'n/a'}</div>
                      <div><strong>Timestamp:</strong> {selectedActivityEvent.created_at}</div>
                    </div>
                  </details>
                )}
              </>
            )}
          </>
        )}
      </section>

      <section style={{ marginTop: '2rem', border: '1px solid #d5dce3', borderRadius: 10, padding: '1rem' }}>
        <h2>Review & Deploy</h2>
        <p style={{ marginTop: 0, color: '#4b5563' }}>
          Final review combines validation summary, readiness checklist, and generated artifact preview/diff.
        </p>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          <button type='button' onClick={runValidationSummary} disabled={validationLoading}>
            {validationLoading ? 'Running validation…' : 'Run validation summary'}
          </button>
          <button type='button' onClick={generateArtifactPreview}>
            Generate artifact preview
          </button>
          <button
            type='button'
            onClick={() => setReviewMessage('Deploy entry point clicked. Hook this button to deploy orchestration in TKT-008+ stages.')}
            disabled={!readyToDeploy}
          >
            Deploy (entry point)
          </button>
        </div>

        <div style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>{reviewMessage}</div>

        <section style={{ marginBottom: '1rem', padding: '0.75rem', borderRadius: 8, background: readyToDeploy ? '#effaf2' : '#fff4f4', border: `1px solid ${readyToDeploy ? '#a6d8b8' : '#f2b8b5'}` }}>
          <h3 style={{ marginTop: 0 }}>Readiness checklist</h3>
          <ul>
            <li>{sessionId ? '✅ Backend session exists' : '❌ Backend session not created yet'}</li>
            <li>{validationResult ? '✅ Validation summary available' : '⚠️ Validation summary not run yet'}</li>
            <li>{blockingIssues.length === 0 ? '✅ No unresolved blocking issues' : `❌ ${blockingIssues.length} unresolved blocking issue(s)`}</li>
            <li>{artifacts.length > 0 ? `✅ Artifact preview generated (${artifacts.length})` : '⚠️ Artifact preview not generated yet'}</li>
          </ul>
        </section>

        <section style={{ marginBottom: '1rem' }}>
          <h3 style={{ marginBottom: '0.25rem' }}>Validation summary</h3>
          <div style={{ fontSize: '0.9rem', marginBottom: '0.5rem' }}>
            Blocking: {blockingIssues.length} · Warnings: {warningIssues.length} · Ready: {readyToDeploy ? 'Yes' : 'No'}
          </div>

          {blockingIssues.length > 0 && (
            <div style={{ marginBottom: '0.5rem' }}>
              <strong style={{ color: '#b42318' }}>Blocking issues</strong>
              <ul>
                {blockingIssues.map((issue) => (
                  <li key={`blocking-${issue.code}-${issue.path}`}>
                    <code>{issue.code}</code>: {issue.message}
                    {issue.path ? ` (${issue.path})` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {warningIssues.length > 0 && (
            <div>
              <strong style={{ color: '#8a5a00' }}>Warnings</strong>
              <ul>
                {warningIssues.map((issue) => (
                  <li key={`warning-${issue.code}-${issue.path}`}>
                    <code>{issue.code}</code>: {issue.message}
                    {issue.path ? ` (${issue.path})` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>

        <section style={{ marginBottom: '1rem' }}>
          <h3 style={{ marginBottom: '0.25rem' }}>Generated artifact preview</h3>
          {artifacts.length === 0 ? (
            <p style={{ marginTop: 0 }}>No preview generated yet.</p>
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '0.75rem' }}>
                {artifacts.map((artifact) => (
                  <article key={artifact.name} style={{ border: '1px solid #d8dee4', borderRadius: 8, padding: '0.75rem' }}>
                    <div>
                      <strong>{artifact.name}</strong>
                    </div>
                    <div style={{ fontSize: '0.9rem', marginBottom: '0.4rem' }}>
                      Version: <code>{artifact.version}</code> · Hash: <code>{artifact.hash}</code>
                    </div>
                    <pre style={{ whiteSpace: 'pre-wrap', margin: 0, fontSize: '0.78rem', background: '#f8fafc', padding: '0.5rem', borderRadius: 6 }}>
                      {artifact.content}
                    </pre>
                  </article>
                ))}
              </div>
            </>
          )}
        </section>

        <section style={{ marginBottom: '1rem' }}>
          <h3 style={{ marginBottom: '0.25rem' }}>Deployment event timeline</h3>
          <div style={{ fontSize: '0.9rem', marginBottom: '0.5rem' }}>{timelineMessage}</div>
          {timelineEvents.length === 0 ? (
            <p style={{ marginTop: 0 }}>No events yet.</p>
          ) : (
            <ul style={{ paddingLeft: '1.25rem', marginTop: 0 }}>
              {timelineEvents.map((event, idx) => (
                <li key={`${event.created_at}-${event.message}-${idx}`} style={{ marginBottom: '0.4rem' }}>
                  <strong>{new Date(event.created_at).toLocaleTimeString()}</strong> · <code>{event.event_type}</code> · {event.message}
                  {event.status ? ` [${event.status}]` : ''}
                  {event.actor_email ? ` by ${event.actor_email}` : ''}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 style={{ marginBottom: '0.25rem' }}>Config diff preview</h3>
          {diffEntries.length === 0 ? (
            <p style={{ marginTop: 0 }}>No config changes captured yet. Generate preview to compute diff.</p>
          ) : (
            <div style={{ maxHeight: 260, overflow: 'auto', border: '1px solid #e2e8f0', borderRadius: 8 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ background: '#f8fafc' }}>
                    <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '1px solid #e2e8f0' }}>Path</th>
                    <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '1px solid #e2e8f0' }}>Before</th>
                    <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '1px solid #e2e8f0' }}>After</th>
                  </tr>
                </thead>
                <tbody>
                  {diffEntries.map((entry) => (
                    <tr key={entry.path}>
                      <td style={{ padding: '0.4rem', borderBottom: '1px solid #f1f5f9' }}><code>{entry.path}</code></td>
                      <td style={{ padding: '0.4rem', borderBottom: '1px solid #f1f5f9' }}>{entry.before}</td>
                      <td style={{ padding: '0.4rem', borderBottom: '1px solid #f1f5f9' }}>{entry.after}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}
