# HCM Lite Pro — clean company setup

FastAPI + SQLite HR management prototype with Admin / HR / Employee role access, attendance, face enrollment and face-match check-in, leave, payroll, analytics, announcements and audit events.

## Important
This is a development prototype, not a certified production HR system. Face matching can make mistakes and this build does not include liveness/anti-spoofing. Obtain informed consent before biometric processing; do not use face matching as the sole basis for employment or payroll decisions. Payroll rules are simplified and must be reviewed before real use.

## Stack
- Python 3.11+ recommended
- FastAPI / Uvicorn
- SQLite
- HTML, CSS and vanilla JavaScript
- OpenCV 4.11.0.86, ONNX Runtime and ArcFace ONNX model downloaded from Hugging Face on first use
- ReportLab for PDF payslips

## First run on Windows PowerShell
1. Create the virtual environment and install dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

2. Open `.env` and set `ADMIN_EMAIL` and a strong, unique `ADMIN_PASSWORD`. The configured company admin email is `mkhan0128832@gmail.com`; the password is intentionally not included in the ZIP. Never share your `.env` file or commit it to Git. Also replace `SECRET_KEY` with a long random value.

3. Start the app:

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 and API docs at http://127.0.0.1:8000/docs.

## Clean database / no demo data
A fresh database is created with **only the company admin account**. There are no demo employee accounts, seeded departments, sample attendance, sample announcements, or sample CSV. Admin creates departments and HR accounts; HR creates employees and enrolls their face templates.

If you are replacing a previously run demo copy, stop the server and back up anything you need, then delete `data/hcm_lite.db` before restarting to get a completely blank company database. This deletes all data in that local database. Do not delete it if it contains real company records you need to keep.

## Role flow
- Admin: email + password. Creates HR accounts and manages company-wide data.
- HR: email + password, then face verification and attendance check-in before dashboard access. Admin enrolls the HR face.
- Employee: email + password, then face verification and attendance check-in before dashboard access. HR enrolls employee faces.

## Face recognition
The ArcFace model is downloaded from Hugging Face (`garavv/arcface-onnx`, `arc.onnx`) at first use. Internet access is needed for the first enrollment/verification. Model licensing, preprocessing, and threshold must be reviewed and calibrated before real deployment. Camera frames are processed transiently; the app stores the embedding template, not the uploaded image.

## Environment variables
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`: first-run admin bootstrap; set locally in `.env`.
- `SECRET_KEY`: long random secret for session tokens.
- `DATABASE_URL`: local SQLite by default.
- `SEED_DEMO_DATA=false`: demo seeding is removed.
- `FACE_MODEL_REPO`, `FACE_MODEL_FILE`, `FACE_MATCH_THRESHOLD`: face model configuration.
- `OFFICE_GEOFENCE_ENABLED`: GPS geofence is reserved and not implemented in this prototype.

## Tests
```powershell
pytest -q
python -m compileall app
```
Smoke tests validate empty-database admin bootstrap and basic authentication. Webcam + real model matching must still be tested on the target machine.
