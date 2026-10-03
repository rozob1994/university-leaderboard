# Iran-resilient deployment

The app can now use either:

- PostgreSQL via `DATABASE_URL` (preferred for Liara)
- Turso via `TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN` (existing Render deployment)

For Liara:

1. Deploy this GitHub repository as a Node.js app.
2. Keep the runtime in Iran. The included `liara.json` builds dependencies in Germany to avoid package-download restrictions.
3. Create a PostgreSQL database in Liara.
4. Put the app and database in the same Liara private network where possible.
5. Configure:
   - `ADMIN_USERS_JSON` — same secure value used on Render
   - `SESSION_SECRET` — a fresh random 32+ character secret
   - `DATABASE_URL` — PostgreSQL connection string from Liara
6. Do not configure Turso on the Liara deployment unless you intentionally want it as the database.
7. Import the latest .leaderboard.json once into the new deployment. It becomes the shared master database.
8. Test all three admin logins before retiring Render.

The Render deployment can remain online as a fallback during migration.
