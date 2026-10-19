# Secure REST API Development with Flask
Work 1: Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

## Project Purpose
Build a secure Flask REST API with authentication, protection against OWASP Top10 risks, integrate SAST & SCA security scanning in GitHub Actions CI/CD pipeline.
This project covers SQL injection prevention, XSS mitigation, JWT authentication and password hashing.

## API Endpoints
1. `POST /auth/login`
- Description: User login, returns JWT access token
- Request body (JSON):
```json
{
  "username": "admin",
  "password": "Password123"
}
