# PC5 Keys — reseller gateway

`/` = reseller panel. `/vips` = owner console.

Keys are minted as `PC5-` + 6 random chars and pushed into
`mranshurx/pc5-android` → `data/keys.json` in the exact record shape the
backend already reads. Every key is written with a real `startedAt`,
`activatedAt` and `expiresAt` computed from the plan length, so the license
expires on schedule and the panel shows a live countdown.

## Setup

1. Fine-grained PAT on `mranshurx/pc5-android`, `Contents: Read and write` only.
2. In `assets/config.js`: set `ADMIN_PASSWORD`, paste the PAT into `SHARED_TOKEN`.
3. Create `data/resellers.json` with `{"resellers": []}`.
4. Push, deploy. `/vips` works via `404.html` on GitHub Pages and via the
   rewrite in `render.yaml` on Render.

## Flow

- Reseller registers → gives you the username → you open them in `/vips` and
  add credits.
- Reseller signs in, saves their own token, mints keys. Credits deduct per plan:
  1h 0.5 · 3h 2 · 6h 3 · 12h 5 · 1d 7 · 3d 14 · 7d 25 · 14d 30 · 30d 80.
- "start immediately" (default on) stamps the expiry at creation. Turn it off
  to leave `startedAt: null` so the timer begins on the customer's first launch.
- `/vips` shows totals, live/expired counts, per-reseller key lists with
  countdowns, login IP history, credit add/set, ban, password reset, delete and
  per-key revoke (removes it from `keys.json`).

## Notes

- Keys are only charged after the write to `keys.json` succeeds, so a failed
  push never costs credits.
- Writes use read-modify-write with the blob `sha` and retry on 409/422, so two
  resellers minting at once do not overwrite each other.
- The `maintenance` block in `keys.json` is preserved on every write.
- Tokens live in the repo (unavoidable without a backend) — use `Contents`-only
  fine-grained PATs.
