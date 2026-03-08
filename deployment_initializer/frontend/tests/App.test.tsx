import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';


describe('App', () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.unstubAllGlobals();
  });
  it('renders required-input form and immediate validation state', () => {
    render(<App />);

    expect(screen.getByRole('heading', { name: /deployment initializer ui/i })).toBeDefined();
    expect(screen.getByText(/required-input \+ optional-feature form/i)).toBeDefined();
    expect(screen.getByText(/issue\(s\) need attention/i)).toBeDefined();
    expect(screen.getAllByText(/session environment is required/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/database password is required/i).length).toBeGreaterThan(0);
  });

  it('restores draft values from local storage on refresh', () => {
    const stored = {
      metadata: {
        env: 'prod',
        region: 'us-east-1',
        created_by: 'ops@example.com',
      },
      deployment_context: {
        environment: 'prod-us-east-1',
        region: 'us-east-1',
        aws_account_id: '123456789012',
        app_name: 'initializer',
        owner_email: 'ops@example.com',
      },
      required_secrets: {
        database_password: 'supersecret-password',
        jwt_signing_key: 'jwt-signing-key-12345',
        internal_api_token: 'internal-api-token-12345',
        stripe_api_key: 'sk_live_1234567890',
        openai_api_key: 'sk-live-1234567890',
      },
      deployment_options: {
        vpc_id: 'vpc-abc123',
      },
    };
    window.localStorage.setItem(
      'deployment_initializer.required_input_form.v1',
      JSON.stringify(stored)
    );

    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('no backend'))));

    render(<App />);

    const sessionEnvInputs = screen.getAllByLabelText(/session environment/i) as HTMLInputElement[];
    const appNameInputs = screen.getAllByLabelText(/application name/i) as HTMLInputElement[];
    const vpcIdInputs = screen.getAllByLabelText(/vpc id/i) as HTMLInputElement[];

    const sessionEnv = sessionEnvInputs[sessionEnvInputs.length - 1];
    const appName = appNameInputs[appNameInputs.length - 1];
    const vpcId = vpcIdInputs[vpcIdInputs.length - 1];

    expect(sessionEnv.value).toBe('prod');
    expect(appName.value).toBe('initializer');
    expect(vpcId.value).toBe('vpc-abc123');

    vi.unstubAllGlobals();
  });

  it('reveals and hides advanced settings based on feature toggle', () => {
    render(<App />);

    expect(screen.queryByLabelText(/helpdesk routing queue/i)).toBeNull();

    const helpdeskToggles = screen.getAllByLabelText(/enable helpdesk/i);
    fireEvent.click(helpdeskToggles[helpdeskToggles.length - 1]);
    const queueInput = screen.getByLabelText(/helpdesk routing queue/i) as HTMLInputElement;
    expect(queueInput).toBeDefined();

    fireEvent.change(queueInput, { target: { value: '' } });
    expect(screen.getAllByText(/routing queue is required when helpdesk is enabled/i).length).toBeGreaterThan(0);

    const helpdeskTogglesAfter = screen.getAllByLabelText(/enable helpdesk/i);
    fireEvent.click(helpdeskTogglesAfter[helpdeskTogglesAfter.length - 1]);
    expect(screen.queryByLabelText(/helpdesk routing queue/i)).toBeNull();
    expect(screen.queryByText(/routing queue is required when helpdesk is enabled/i)).toBeNull();
  });

  it('shows review section with validation summary and entry-point actions', () => {
    render(<App />);

    expect(screen.getAllByRole('heading', { name: /review & deploy/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('button', { name: /run validation summary/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('button', { name: /generate artifact preview/i }).length).toBeGreaterThan(0);
    const deployButtons = screen.getAllByRole('button', { name: /deploy \(entry point\)/i }) as HTMLButtonElement[];
    expect(deployButtons[deployButtons.length - 1].disabled).toBe(true);
    expect(screen.getAllByText(/unresolved blocking issue/i).length).toBeGreaterThan(0);
  });

  it('hides Identity & SSO controls for non-root acting role', () => {
    render(<App />);

    expect(screen.getAllByRole('heading', { name: /identity & sso \(root admin\)/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/root role required\. non-root users cannot access or mutate identity & sso settings/i).length).toBeGreaterThan(0);
  });

  it('shows Identity & SSO controls when acting role is root', () => {
    render(<App />);

    const actingRole = screen.getAllByLabelText(/acting role/i).at(-1) as HTMLSelectElement;
    fireEvent.change(actingRole, { target: { value: 'root' } });

    expect(screen.getByRole('button', { name: /load providers/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /save provider \(draft\)/i })).toBeDefined();
    expect(screen.getByRole('button', { name: /rollback \(disable sso\)/i })).toBeDefined();
  });

  it('shows Dev Directory controls for root and loads users/groups/activity', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/schemas/deployment-config.schema.v1.json')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ json_schema: { $defs: {} } }) });
      }
      if (url.includes('/sessions/') && url.endsWith('/events')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ session_id: 's1', events: [] }) });
      }
      if (url.includes('/auth/admin/sso/dev-directory/users')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ users: [{ user_id: 'u1', username: 'admin@example.com', email: 'admin@example.com', enabled: true, groups: ['group-admins'] }] }),
        });
      }
      if (url.includes('/auth/admin/sso/dev-directory/groups')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ groups: ['group-admins', 'group-ops'] }) });
      }
      if (url.includes('/auth/admin/sso/dev-directory/activity')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ events: [{ event_id: 1, auth_method: 'ad_sso', outcome: 'success', actor_email: 'admin@example.com', provider_id: null, external_subject: null, external_tenant: null, mapped_role: 'admin', failure_reason: null, created_at: '2024-01-01T00:00:00Z' }] }),
        });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve({ detail: 'not_stubbed' }) });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    const actingRole = screen.getAllByLabelText(/acting role/i).at(-1) as HTMLSelectElement;
    fireEvent.change(actingRole, { target: { value: 'root' } });

    expect(screen.getAllByTestId('dev-directory-panel').length).toBeGreaterThan(0);
    expect(screen.getAllByTestId('dev-directory-seed-admin').length).toBeGreaterThan(0);

    const loadButton = screen.getAllByTestId('dev-directory-load').at(-1) as HTMLButtonElement;
    fireEvent.click(loadButton);

    expect(await screen.findByText(/loaded 1 user\(s\), 2 group\(s\), 1 activity event\(s\)/i)).toBeDefined();
    expect(screen.getAllByText(/admin@example.com/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/\(seeded\)/i).length).toBeGreaterThan(0);
  });

  it('applies activity filters and shows troubleshooting details in explorer', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/schemas/deployment-config.schema.v1.json')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ json_schema: { $defs: {} } }) });
      }
      if (url.includes('/sessions/') && url.endsWith('/events')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ session_id: 's1', events: [] }) });
      }
      if (url.includes('/auth/admin/sso/dev-directory/users')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ users: [] }) });
      }
      if (url.includes('/auth/admin/sso/dev-directory/groups')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ groups: ['group-admins'] }) });
      }
      if (url.includes('/auth/admin/sso/dev-directory/activity')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            events: [
              {
                event_id: 42,
                event_type: 'callback',
                auth_method: 'ad_sso',
                outcome: 'failure',
                actor_email: 'alice@example.com',
                provider_id: 'local-ad',
                external_subject: 'sub-1',
                external_tenant: 'tenant-1',
                mapped_role: null,
                failure_reason: 'sso_callback_jwks_unreachable',
                troubleshooting_category: 'jwks_unreachable',
                troubleshooting_hint: 'Check JWKS endpoint reachability and refresh after key rotation.',
                created_at: '2024-01-01T00:00:00Z',
              },
            ],
          }),
        });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve({ detail: 'not_stubbed' }) });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<App />);

    const actingRole = screen.getAllByLabelText(/acting role/i).at(-1) as HTMLSelectElement;
    fireEvent.change(actingRole, { target: { value: 'root' } });

    fireEvent.change(screen.getAllByLabelText(/activity filter outcome/i).at(-1) as HTMLSelectElement, { target: { value: 'failure' } });
    fireEvent.change(screen.getAllByLabelText(/activity filter actor email/i).at(-1) as HTMLInputElement, { target: { value: 'alice@example.com' } });

    fireEvent.click(screen.getAllByTestId('dev-directory-activity-apply-filters').at(-1) as HTMLButtonElement);

    expect(await screen.findByText(/activity event details #42/i)).toBeDefined();
    expect(screen.getAllByText(/troubleshooting category:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/jwks_unreachable/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/check jwks endpoint reachability and refresh after key rotation/i).length).toBeGreaterThan(0);

    const activityCall = fetchMock.mock.calls
      .map((call) => String(call[0]))
      .find((url) => url.includes('/auth/admin/sso/dev-directory/activity?'));
    expect(activityCall).toContain('outcome=failure');
    expect(activityCall).toContain('actor_email=alice%40example.com');
  });

});
