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
});
