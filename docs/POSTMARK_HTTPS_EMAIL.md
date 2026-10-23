# PTO HTTPS email via Postmark (no manual DNS changes for initial testing)

This branch changes only the email-sending transport. PostgreSQL schemas, existing Principals, administrator TOTP, OTP challenge behavior and Render infrastructure remain unchanged.

## Postmark GUI configuration
1. Create a Postmark account: https://account.postmarkapp.com/
2. Add a **Sender Signature** for an email address on a private domain that you control (such as your existing business mailbox).
3. Open the confirmation email delivered to that mailbox and confirm the Sender Signature.
4. Create a Postmark Server and obtain its **Server API Token**. Make sure the account/server is approved for live sending; a sandbox token is not sufficient.
5. In the existing Render Web Service > Environment, set:
   - `PTO_EMAIL_PROVIDER=postmark`
   - `POSTMARK_SERVER_TOKEN` = Server API Token (secret)
   - `PTO_EMAIL_FROM` = exact verified Sender Signature address, e.g. `noreply@yourdomain.example` (must really exist)
6. Do not touch `DATABASE_URL`, `PTO_DATA_DIR`, encryption keys or Principal records.
7. Deploy only after CI review and test a real invitation and 6-digit email OTP to a test mailbox.

Postmark can send using a verified Sender Signature without mandatory manual DNS configuration, but domain authentication is recommended for deliverability. Account approval and mailbox verification are still necessary.

The provider uses **HTTPS (443)**; it does not require SMTP port 587/465 or Google app passwords. The previous Resend provider can be selected with `PTO_EMAIL_PROVIDER=resend`, `RESEND_API_KEY`, and `PTO_EMAIL_FROM`; it still requires a compliant verified sender/domain for sending to other recipients.

Never paste API tokens or OTPs in GitHub issues, docs, or chat.
