# Twilio SMS Integration

This service can send SMS-based MFA codes through Twilio when configured. SMS is optional; if Twilio credentials are not set, SMS routes will return errors or be unavailable.

## Required environment variables

| Variable | Purpose |
| --- | --- |
| `TWILIO_ACCOUNT_SID` | Twilio account SID. |
| `TWILIO_AUTH_TOKEN` | Twilio auth token. |
| `TWILIO_FROM_NUMBER` | The Twilio phone number used to send SMS messages. |

## Optional environment variables

| Variable | Purpose |
| --- | --- |
| `TWILIO_VERIFY_SERVICE_SID` | Twilio Verify service SID (if using Verify API). |

## Operational notes
- Make sure the `TWILIO_FROM_NUMBER` is verified and enabled for SMS in your Twilio account.
- Set your Twilio credentials as secrets; do not commit them to the repo.
- SMS rate limits are enforced by the service (see `app/services/rate_limit.py`).

## Troubleshooting
- **SMS sends fail**: confirm credentials and that the from-number is active for SMS.
- **Rate limits**: check logs for rate limit responses; adjust limits if needed.
