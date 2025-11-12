# Vercel Deployment Guide

This guide explains how to deploy the Steganography as a Service application to Vercel.

## Prerequisites

1. A Vercel account (sign up at [vercel.com](https://vercel.com))
2. Vercel CLI installed (optional, for CLI deployment):
   ```bash
   npm i -g vercel
   ```

## Deployment Steps

### 1. Environment Variables

Before deploying, you need to set the following environment variables in your Vercel project:

1. Go to your Vercel project dashboard
2. Navigate to **Settings** → **Environment Variables**
3. Add the following variables:

   - `SECRET_KEY`: A secure random string for Flask session encryption
   - `JWT_SECRET_KEY`: A secure random string for JWT token signing (can be same as SECRET_KEY)
   - `MAX_CONTENT_LENGTH`: Maximum file upload size in bytes (default: 16777216 = 16MB)
   - `ALLOWED_EXTENSIONS`: Comma-separated list of allowed file extensions (default: png,jpg,jpeg,bmp)

   **Note**: The `VERCEL` environment variable is automatically set by Vercel, which triggers the app to use `/tmp` for file storage.

### 2. Deploy via Vercel Dashboard

1. Push your code to a Git repository (GitHub, GitLab, or Bitbucket)
2. Import your repository in Vercel:
   - Go to [vercel.com/new](https://vercel.com/new)
   - Import your Git repository
   - Vercel will automatically detect the configuration from `vercel.json`
3. Configure build settings (if needed):
   - **Root Directory**: Leave as root (`.`)
   - **Build Command**: `cd frontend && npm install && npm run build`
   - **Output Directory**: `frontend/build`
4. Click **Deploy**

### 3. Deploy via Vercel CLI

```bash
# Install Vercel CLI (if not already installed)
npm i -g vercel

# Login to Vercel
vercel login

# Deploy (follow prompts)
vercel

# For production deployment
vercel --prod
```

## Project Structure

The deployment is configured as follows:

- **Frontend**: React app built from `frontend/` directory
- **Backend API**: Python Flask app served as serverless function from `api/index.py`
- **Static Files**: Served from `frontend/build/` directory
- **File Storage**: Uses `/tmp` directory on Vercel (ephemeral, files are lost after function execution)

## Important Notes

### File Storage Limitations

⚠️ **Important**: Vercel serverless functions have ephemeral file storage. Files stored in `/tmp` are:
- Only available during the function execution
- Automatically cleaned up after the function completes
- Not shared between function invocations

**Implications**:
- Uploaded images and generated stego files are temporary
- Users should download files immediately after generation
- Consider using external storage (S3, Cloudinary, etc.) for production use

### API Routes

All API endpoints are prefixed with `/api`:
- `POST /api/stego/embed` - Embed message in image
- `POST /api/stego/extract` - Extract message from image
- `POST /api/stego/analysis` - Analyze image for steganography
- `GET /api/stego/download/<message_id>` - Download stego image
- `GET /api/health` - Health check endpoint

### Build Process

1. Frontend build: React app is built using `npm run build` in the `frontend/` directory
2. Python dependencies: Installed from `api/requirements.txt` (which mirrors `backend/requirements.txt`)
3. Serverless function: Flask app is wrapped in `api/index.py` for Vercel's Python runtime

## Troubleshooting

### Build Failures

- **Frontend build fails**: Check that all dependencies are in `frontend/package.json`
- **Python function fails**: Verify all dependencies are in `api/requirements.txt`

### Runtime Errors

- **File not found errors**: Ensure paths use `/tmp` for file operations
- **Import errors**: Check that `backend/` directory is accessible from `api/index.py`

### Environment Variables

- Verify all required environment variables are set in Vercel dashboard
- Check that `VERCEL=1` is set (automatically set by Vercel)

## Production Recommendations

1. **External File Storage**: Use AWS S3, Cloudinary, or similar for persistent file storage
2. **Database**: Consider using a managed database service (Vercel Postgres, Supabase, etc.)
3. **CDN**: Vercel automatically provides CDN for static assets
4. **Monitoring**: Set up Vercel Analytics and error tracking
5. **Rate Limiting**: Consider implementing rate limiting for API endpoints

## Support

For issues specific to Vercel deployment, refer to:
- [Vercel Documentation](https://vercel.com/docs)
- [Vercel Python Runtime](https://vercel.com/docs/concepts/functions/serverless-functions/runtimes/python)

