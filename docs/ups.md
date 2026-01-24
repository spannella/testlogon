# UPS Integration

This repository does not currently include first-party UPS API routes. We still document UPS usage here so operators know where to configure credentials and how shipping fits into the broader workflow.

## Current integration status
- **API routes**: no UPS-specific endpoints are exposed by this service today.
- **UI**: there is no UPS panel in the control panel UI.
- **Operational usage**: UPS is typically configured in the shipping or fulfillment system that sits alongside this service.

## Recommended configuration checklist
- Store UPS credentials (client ID/secret, account number, and webhook secrets if used) in your secret manager.
- Document which downstream service is responsible for:
  - Rate quoting and label creation.
  - Tracking updates and webhook handling.
  - Persisting tracking numbers back to the customer profile or order system.

## Suggested future integration points
If you plan to add UPS support directly to this service, these are the likely touch points:
- **Settings**: add UPS configuration fields to `app/core/settings.py`.
- **Service layer**: create a new module under `app/services/` for UPS API calls.
- **Routers**: expose routes for rate quoting, label creation, and webhook callbacks.
- **UI**: add a panel in `app/static/index.html` and supporting logic in `app/static/main.js`.
