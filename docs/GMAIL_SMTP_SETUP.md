# PTO Gmail / Google Workspace SMTP (test deployment)

This branch changes only email transport. It does not migrate or delete PostgreSQL data.

## Render prerequisite

**Render Free Web Services block outbound ports 25, 465 and 587.** Gmail SMTP will not work on Render Free. Check the existing instance type first; use a paid Web Service or choose an HTTPS email API instead.

## Google Account

1. Use an existing Gmail or Workspace mailbox permitted to send mail.
2. Enable 2-Step Verification.
3. In Google Account > Security > App passwords, create an app password for PTO. Workspace administrators may prohibit this feature.
4. Do not use the regular account password or paste the app password into GitHub/chat.

## Existing Render service > Environment

- `PTO_SMTP_USER`: full Gmail/Workspace email address
- `PTO_SMTP_APP_PASSWORD`: app password, stored as a secret
- `PTO_EMAIL_FROM`: same mailbox address (or a configured send-as alias)
- `PTO_SMTP_HOST`: smtp.gmail.com (default)
- `PTO_SMTP_PORT`: 587 (STARTTLS; default), or 465 (SSL)

Do not change `DATABASE_URL`, `PTO_DATA_DIR`, `PTO_SETUP_TOKEN`, or the existing Principal information. Resend keys are not used by this branch.

Do not merge until CI passes, Render plan supports SMTP, secrets are configured, and a real delivery test succeeds.