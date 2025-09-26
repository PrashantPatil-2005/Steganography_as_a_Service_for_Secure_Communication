# Steganography as a Service - Setup Instructions

## Issue Identified and Fixed ✅

The upload error you were experiencing has been **fixed**. The issue was a configuration problem between the frontend and backend services.

### What was the problem?
- The React frontend was making API calls to relative URLs (`/api/stego/embed`)
- When running separately, these requests weren't reaching the backend server on port 5000
- This caused upload errors when trying to hide messages in images

### What was fixed?
1. **Added proxy configuration** in `package.json` to redirect API calls to the backend
2. **Made API URLs configurable** using environment variables
3. **Updated all API endpoints** to use the correct base URL

## How to Run the Application

### 1. Start the Backend Server
```bash
cd backend
python run.py
```
The backend will start on http://localhost:5000

### 2. Start the Frontend
```bash
cd frontend
npm install  # if not already done
npm start
```
The frontend will start on http://localhost:3001

### 3. Test the Application
1. Open your browser to http://localhost:3001
2. Select the "Hide Message" tab
3. Choose an image file (PNG, JPG, JPEG, BMP)
4. Enter a secret message
5. Enter a passphrase
6. Click "Hide Message"

The upload should now work correctly! ✅

## Backend Test Results
- ✅ Core steganography functions working
- ✅ File upload endpoint working (tested with API calls)
- ✅ Message embedding working  
- ✅ Message extraction working
- ✅ File download working
- ✅ Error handling working (invalid files, missing fields)

## Configuration Files Added/Modified
- `frontend/package.json` - Added proxy configuration
- `frontend/.env` - Added environment variables
- `frontend/src/App.js` - Updated API URLs to be configurable

Your steganography application is now ready to use! 🎉