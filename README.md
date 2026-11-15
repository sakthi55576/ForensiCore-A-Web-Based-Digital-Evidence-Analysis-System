# ForensiCore: A Digital Evidence Analyzer

Digital evidence management and analysis (Flask + MySQL).

## Setup

```
pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
```

Open `.env` and fill in your MySQL details and a long random `SECRET_KEY`
(the app refuses to start without one):

```
python -c "import secrets; print(secrets.token_hex(32))"
```

Create the database once (`CREATE DATABASE forensicore;`), then:

```
python run.py
```

Tables are created automatically on first start.

## Settings (`.env`)

| Key | Default | Meaning |
|---|---|---|
| `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | - | MySQL connection |
| `SECRET_KEY` | - | **Required.** Long random value |
| `FLASK_DEBUG` | `0` | `1` only on your own machine while developing |
| `ENABLE_IP_LOOKUP` | `0` | `1` lets the email analyzer geolocate sender IPs through ipinfo.io (sends IPs to an external service) |
| `ASSUMED_LOCAL_UTC_OFFSET_MIN` | `330` | Offset used for photo times that carry no timezone (330 = IST) |
| `MAX_UPLOAD_MB` | `256` | Evidence upload limit |
| `MAX_LOGIN_ATTEMPTS` | `5` | Wrong passwords before sign-in is locked |
| `LOGIN_LOCKOUT_MINUTES` | `5` | How long the lock lasts |

## Workflow

Case -> Evidence (MD5 + SHA-256 at upload, read-only copy) -> Analyze (integrity re-checked first)
-> Findings -> Timeline (+ correlations) -> Risk -> PDF report (hashes, chain of custody, findings, timeline).

## Demo files

`demo_data/` has three harmless sample files (a photo with GPS data, a
Chrome history database and a phishing e-mail) for trying each analyzer.

## Quick self-test (demo for viva)

1. Upload a photo: the evidence receipt shows both hashes.
2. Press **Analyze**: the custody log records "Integrity verified" then "Analysis performed".
3. Change one byte of the stored file in `app/uploads/evidence/`.
4. Press **Verify**: status becomes **Tampered**, analysis is blocked, "Integrity check FAILED" is logged.

## Tests

```
pip install -r requirements-dev.txt
pytest
```

The tests use a temporary SQLite database and temporary folders, so they never
touch your MySQL data or your evidence files.

## Notes

* Risk levels: LOW < 40, MEDIUM 40-69, HIGH 70+. Overall risk = highest module score (+10 when two modules reach MEDIUM).
* Keyword / indicator matches are leads for the investigator, not proof of intent.
* All analyzer times are UTC. Photo times without a timezone are converted with the assumed offset and labelled as such.
* The audit log (chain of custody) records who did what, when and from which IP. It is append-only: no route edits or deletes entries.
* Evidence cannot be edited or deleted from the application. Changes made outside the application are caught by the hash check.

## Limitations / future work

* The hashes are stored in the database. Someone with direct database access could change a file *and* its stored hash. The hash printed in the PDF report is an independent copy; digital signatures or an external timestamp would close this gap.
* The audit log is not tamper-evident on its own (no hash chaining); it relies on the application offering no way to change it.
* Login lock-out is kept in memory and resets when the server restarts.
* Keyword and indicator matching can produce false positives and is meant to guide the investigator.
