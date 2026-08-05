# TCM Tracker

Self-hosted transitional-care-management tracker for hospital/ED discharge
follow-up: admitting facility, admission/discharge dates, TCM contact date,
follow-up appointment, discharge diagnosis, and billing status — keyed only
to patient initials + MRN.

## Before you deploy: compliance checklist

This app stores PHI (MRN is a HIPAA identifier even without a name attached).
This is a starting point, not a compliance sign-off — talk to whoever handles
your practice's HIPAA risk analysis before putting real patient data in it.
At minimum:

- [ ] Run it only behind HTTPS (Nginx Proxy Manager + your existing Cloudflare
      setup, same as your other services) — never expose the raw HTTP port.
- [ ] Consider putting it behind Tailscale as well, so it's not reachable from
      the public internet at all, only from your practice's devices.
- [ ] Use a long random `SESSION_SECRET` and Postgres password (see below).
- [ ] Back up the `tcm_pgdata` volume regularly, and encrypt those backups.
- [ ] Review your BAA situation for the VPS host (Hostinger) — infrastructure
      providers hosting PHI typically need a Business Associate Agreement.
- [ ] Only give logins to staff who need them; deactivate accounts promptly
      when someone leaves.

## What's included

- FastAPI + PostgreSQL, single Docker Compose stack
- Username/password + mandatory TOTP 2FA (Google Authenticator, Authy, etc.) —
  no account can access patient data until 2FA is enrolled
- Dashboard that auto-flags episodes where the 2-business-day contact window
  or the 7/14-day visit window (based on TCM complexity) has passed
- Billing follow-up view: flags any episode with a completed visit that isn't
  yet marked billed, so nothing falls through the cracks on 99495/99496 claims
- Basic audit log (login, logout, record create/edit) in the `audit_log` table
- Admin-only user management screen (`/users`)

## Deploying to your Hostinger VPS

This follows the same pattern as your existing `open-webui` stack (bound to
localhost, joined to `npm-network`, proxied through NPM + Cloudflare).

1. **Copy the project to the VPS**, e.g. via `scp` or `git`, into its own
   directory alongside your other Docker projects.

2. **Create `.env`** from the template and fill in real values:
   ```bash
   cp .env.example .env
   python3 -c "import secrets; print(secrets.token_hex(32))"   # for SESSION_SECRET
   openssl rand -base64 24                                      # for POSTGRES_PASSWORD
   ```

3. **Confirm the `npm-network` external network exists** (it should already,
   from your open-webui setup):
   ```bash
   docker network ls | grep npm-network
   ```

4. **Build and start the stack**:
   ```bash
   docker compose up -d --build
   ```

5. **Create the first admin user**:
   ```bash
   docker compose exec app python create_admin.py your_admin_username
   ```
   This prints a one-time temporary password. Share it with that person
   directly (in person, or via a password manager) — not over plain email.

6. **Point Nginx Proxy Manager at it.** In the NPM UI, add a new proxy host
   for something like `tcm.macadamianet.com`:
   - If NPM runs in `network_mode: host` (as with your n8n setup), forward to
     `127.0.0.1:8020`.
   - If NPM resolves by container name over `npm-network` (as with
     open-webui), forward to `http://app:8000` instead — either works since
     this compose file sets up both paths.
   - Enable SSL (Let's Encrypt) on the proxy host, same as your other domains.
   - Cloudflare SSL/TLS mode should stay on **Full** to avoid redirect loops,
     matching your existing setup.

7. **Log in** at `https://tcm.macadamianet.com/login` with the admin username
   and temporary password. You'll be walked through 2FA enrollment (scan a QR
   code) before you get to the dashboard — this happens automatically on
   first login for every new account.

8. **Add your staff accounts** from `/users` once logged in as admin — each
   new account gets its own temporary password and goes through the same
   mandatory 2FA setup on first login.

## Day-to-day use

- **New patient discharge** → "+ New episode" on the dashboard. Fill in
  initials, MRN, facility, admission/discharge dates, discharge diagnosis,
  and complexity (moderate = 99495/14-day visit window, high = 99496/7-day
  window) if known yet.
- **When you make the TCM contact call** → edit the episode, set "TCM order /
  contact initiated date."
- **When the follow-up visit happens** → set "Appointment completed date,"
  set the billing status to "ready to bill," and fill in the CPT code.
- **Billing follow-up view** (`/billing`) → your team's punch list for
  confirming every completed visit actually gets submitted and paid.
- Mark an episode "closed" once billing is resolved so it drops off the main
  dashboard (it still shows in the full billing view).

## Local development

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec app python create_admin.py testadmin
```

Then visit `http://localhost:8020`.

## Extending this later

Some natural next steps if this proves useful:
- CSV export for your biller
- Email/Slack digest of overdue contacts each morning (could run as a
  scheduled task, or you could wire this into your existing n8n instance)
- Multi-practice / multi-location support if needed
- Proper Alembic migrations instead of `create_all` (fine for now at this
  scale, but worth adding once the schema stabilizes)
