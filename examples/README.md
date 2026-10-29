# Next.js excerpts (not a runnable app)

Two small sets of Next.js App Router files, used as input for `audit/scan_nextjs.py` and as the
code side of the sample report. They are excerpts written for this demo: there is no
`package.json` and they are not built or run.

- `nextjs-broken/`: the service role key is exposed to the browser and used with a tenant id
  taken from the request.
- `nextjs-fixed/`: the browser and the route handlers use the user's session (anon key + RLS);
  the service role key is server-only and used after an explicit admin check.
