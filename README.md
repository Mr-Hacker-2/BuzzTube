# BuzzTube

A Flask-based video-sharing web app with accounts, video uploads, comments, likes, follows, reports, and a public chat area.

## Run locally

1. Use Python 3.10 or newer.
2. Create and activate a virtual environment.
3. Install dependencies:

   ```bash
   python -m venv .venv
   # Windows: .venv\Scripts\activate
   # macOS/Linux: source .venv/bin/activate
   pip install -r requirements.txt
   ```

4. Set a strong session secret before running in production:

   ```bash
   # macOS/Linux
   export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
   export COOKIE_SECURE=true
   ```

   On Windows PowerShell, set `$env:SECRET_KEY` to a generated random value. Set `COOKIE_SECURE=true` when serving over HTTPS.

5. Start the app with `python app.py`, or use the repository's configured production process.

## Important notes

- New passwords are stored as hashes. Existing legacy plaintext passwords are converted to hashes after a successful login.
- Admin rights are based on the `is_admin` database flag, not the username. Existing admins may need to be promoted manually in the local SQLite database.
- Video uploads are limited to 100 MB and a list of common video extensions. This extension check is only a first filter, not a complete media-file security scan.
- The app is a development project. Before exposing it publicly, add CSRF protection, rate limiting, moderation controls, and a reviewed administrator-management workflow.
- Never commit real credentials, user uploads, or the production database.

## Configuration

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Persistent, random Flask session secret |
| `COOKIE_SECURE` | Set to `true` when using HTTPS |

## License

See [LICENSE](LICENSE).
