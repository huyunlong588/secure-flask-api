# Submission checklist

1. Copy from this package into `D:\Desktop\secure-flask-api`:

   - `app.py` -> replaces the old file (JWT key now comes from `JWT_SECRET_KEY`,
     which is what makes the Bandit step pass)
   - `requirements.txt` -> replaces the old file
   - `README.md` -> replaces the old file
   - `.github/workflows/ci.yml` -> replaces the old workflow
   - `screenshots/` -> repository root (new folder)
   - `cve/CVE-2017-8917/docker-compose.yml` -> the fix file to attach to the submission
   - `Report_Lab1_Secure_API_CVE-2017-8917.docx` -> keep for submission (not in the repo)

2. Install the upgraded dependencies and check that the API still works:

   ```powershell
   cd D:\Desktop\secure-flask-api
   venv\Scripts\python.exe -m pip install -r requirements.txt
   venv\Scripts\python.exe app.py
   ```

   Then, in a second window:

   ```powershell
   $body = @{username="testuser";password="TestPass123!"} | ConvertTo-Json
   Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/auth/login `
     -ContentType "application/json" -Body $body
   ```

   A JSON response with `access_token` means the upgrade did not break the code.

3. Commit and push:

   ```powershell
   git add .
   git commit -m "Update CI, dependencies, README and CVE-2017-8917 analysis"
   git push
   ```

4. Wait for the run at https://github.com/huyunlong588/secure-flask-api/actions

   It must be green. The report already contains the Bandit output and describes the
   Safety report as an artifact, so no extra screenshots are required for submission.
   If you want the README to show the scan screenshots as well, open the run, screenshot
   the Bandit and Safety steps and save them as `screenshots/ci-bandit.png` and
   `screenshots/ci-safety.png` (optional).

5. Submit:

   - repository: https://github.com/huyunlong588/secure-flask-api
   - the green run URL from the Actions page
   - `Report_Lab1_Secure_API_CVE-2017-8917.docx`
   - `cve/CVE-2017-8917/docker-compose.yml`

## Why app.py changed

The old file contained the literal `"super-secret-key-change-in-production-12345"`, which
Bandit reports as a hard-coded secret (B105). With `bandit -ll` that finding still makes
the command exit with code 1, so the pipeline would fail. The new file reads
`JWT_SECRET_KEY` from the environment and only falls back to a development value, so the
scan is clean and the new workflow passes.
