# Project overview, setup, and run instructions


## Overview
This project is a Steganography-as-a-Service (SaaS) platform. It provides a Flask-based backend API to:
- Embed encrypted messages into images using LSB steganography
- Extract and decrypt hidden messages from images
- Optionally sign stego-objects and verify signatures
- Run a simple chi-square steganalysis

Technologies: `Flask`, `Flask-SQLAlchemy`, `Flask-JWT-Extended`, `Flask-Cors`, `Pillow`, `PyCryptodome`.
A React frontend can be added later to consume these APIs.


## Repository Layout
- `backend/`
  - `app/`
    - `__init__.py`: App factory; initializes DB, JWT, CORS
    - `config.py`: Configuration and defaults
    - `models.py`: `User` and `Message` models
    - `routes.py`: Auth and steganography API endpoints
    - `security.py`: AES-GCM encryption, hashing, Ed25519 signing
    - `steganography.py`: LSB image embed/extract (PNG)
    - `steganalysis.py`: Chi-square LSB heuristic
  - `manage.py`: Create database tables
  - `requirements.txt`: Backend dependencies
  - `run.py`: Run Flask server
- `frontend/` (placeholder for React app)


## Prerequisites
- Python 3.10+
- A virtual environment (recommended)
- SQLite (default) or PostgreSQL if configuring `DATABASE_URL`


## Setup
1. Create and activate a virtual environment
   - Windows (PowerShell):
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```
2. Install backend dependencies
   ```powershell
   pip install -r backend/requirements.txt
   # python -m pip install -r requirements.txt
   ```
3. Create a `.env` file in `backend/` (optional; defaults provided)
   ```env
   SECRET_KEY=change-me
   JWT_SECRET_KEY=change-me-jwt
   DATABASE_URL=sqlite:///app.db
   UPLOAD_FOLDER=uploads
   STEGO_TEMP_FOLDER=stego_tmp
   ALLOWED_EXTENSIONS=png,jpg,jpeg,bmp
   REDIS_URL=redis://localhost:6379/0
   ```
4. Initialize the database
   ```powershell
   python backend/manage.py
   ```
5. Run the backend
   ```powershell
   python backend/run.py
   ```
   The API will be available at `http://localhost:5000/api`.


## API Summary
- `POST /api/register`
  - JSON: `{ "username": "u", "email": "e@x", "password": "p" }`
- `POST /api/login`
  - JSON: `{ "username": "u", "password": "p" }`
  - Returns: `{ "access_token": "..." }`
- `POST /api/stego/embed` (multipart/form-data)
  - Fields: `file` (image), `message` (text), `passphrase` (text)
  - Optional: `sign` (true/false), `canary` (true/false), `expires_in_seconds` (int)
  - Returns: metadata and a `download_path` for the stego image
- `GET /api/stego/download/<message_id>`
  - Downloads the generated stego image
- `POST /api/stego/extract` (multipart/form-data)
  - Fields: `file` (image), `passphrase` (text)
  - Optional: `message_id` (to enable tamper/expiry checks and optional signature verification)
- `POST /api/stego/analysis` (multipart/form-data)
  - Field: `file` (image)
  - Returns: `{ chi_square_score: <float> }`


## Notes
- The image output is saved as PNG to preserve pixel data for reliable LSB embedding.
- Redis is planned for message expiration jobs but is not required to run the current features.
- This is a baseline LSB implementation; adaptive steganography can be added by selecting high-variance regions.
