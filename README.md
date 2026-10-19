# Secure REST API Development with CI/CD and CVE Analysis
Lab Work 1 | HDU Computer Science

## Project Overview
This project implements a secure REST API using Python Flask.
The API includes JWT authentication, protection against SQL injection and XSS, and CI/CD pipeline with SAST and SCA security scanning.

### Endpoints
1. `POST /auth/login`
   - Accept JSON payload: `{"username":"testuser","password":"TestPass123!"}`
   - Returns JWT access token when credentials are valid.
2. `GET /api/data`
   - Protected endpoint, requires Bearer JWT token in Authorization header.
   - Returns list of registered users.
3. `POST /api/post`
   - Custom protected endpoint. Requires JWT token.
   - Accept post content and returns sanitized post data.

### How to run locally
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
