# Campus Lost & Found Portal — Updated

A beginner-friendly Flask + SQLite B.Tech mini project.

## Features
- Student registration/login
- Lost/found item reporting with images
- Searchable home page
- Claims with claimant contact details and optional other-person contact details
- Admin-only dashboard
- Admin can manage users, items, and claims
- Admin can edit/delete records
- Admin can approve/reject/complete claims
- Admin can change their own name, email, phone and password
- SQLite database created automatically

## First run on macOS
Open Terminal in this folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

Open http://127.0.0.1:5000

## Default admin credentials
Email: admin@campus.local
Password: admin123

IMPORTANT: Immediately go to Admin → Admin Settings and change these credentials.

## Database
`instance/lost_found.db`

## Main folders
- `app.py` — backend
- `templates/` — HTML
- `static/` — CSS
- `uploads/` — uploaded item images
- `instance/` — SQLite database

## Reset database
Stop Flask first, then delete:
`instance/lost_found.db`
Restart `python3 app.py`. A fresh database and default admin are created.

## New: User-to-user conversations
After a user submits a claim, both the claimant and the person who reported the item can open a secure in-portal chat from their dashboards. They can discuss verification, handover and meeting details without exposing a personal phone number unless they choose to. The admin can review/delete messages from Admin → Manage Messages.

## Review notes (fixes applied on top of the messaging feature)
- **CSRF protection** added to every form in the app (previously none existed) — every POST now requires a per-session token, checked in `before_request`.
- **Self-claiming blocked**: you could previously submit a claim on your own report. `claim()` now checks `item["user_id"] != session["user_id"]`.
- **Claiming a non-Active item blocked**: claims could pile up on items already `Claimed`/`Returned`. Now checked before the claim form is shown.
- **Rejecting/reopening a claim reactivates the item** so other students can claim it, instead of leaving it stuck.
- **Image uploads are verified as genuine images** (via Pillow) rather than trusted purely by file extension, and requests are capped at 5 MB (`413` handled gracefully).
- **Basic validation on registration/report** (name length, email format, password length) with inline flash errors.
- **Fixed unstyled/mis-styled UI**: the admin dashboard's quick-link cards had no matching CSS class (`.card` was never defined) and the two new messaging pages used class names (`btn secondary`, `btn small`, `btn small danger`) that don't exist in the stylesheet — standardized to the existing `.btn-light` / `.btn-small` / `.btn-danger` convention and added `.card` styling.
- **Unread-message badge** now shows next to "My Dashboard" in the nav on every page, not just the dashboard.
- Added a proper `404.html` page.

## Not changed in this pass
The homepage search/filter UI is still not wired to the backend (it always shows every item), and there's no pagination anywhere — these were true in the original project too. Ask if you'd like these added; it's a moderate amount of additional work and wasn't touched here to keep this pass focused on your new messaging feature and its bugs.
