"""
Vercel serverless function wrapper for Flask app
"""
import sys
import os
from io import BytesIO

# Add backend directory to Python path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
sys.path.insert(0, backend_path)

# Set Vercel environment variable
os.environ['VERCEL'] = '1'

from app import create_app

# Create Flask app instance
app = create_app()

def handler(request):
    """
    Vercel serverless function handler using Flask WSGI
    """
    from vercel import Response
    
    # Extract request data from Vercel request object
    method = request.method
    # Keep the full path including /api since Flask blueprint is registered with url_prefix='/api'
    path = request.path
    
    query_string = getattr(request, 'query_string', '') or ''
    headers = dict(request.headers) if hasattr(request, 'headers') else {}
    body = request.body if hasattr(request, 'body') else b''
    
    # Create WSGI environ
    environ = {
        'REQUEST_METHOD': method,
        'SCRIPT_NAME': '',
        'PATH_INFO': path,
        'QUERY_STRING': query_string,
        'CONTENT_TYPE': headers.get('Content-Type', ''),
        'CONTENT_LENGTH': str(len(body)),
        'SERVER_NAME': headers.get('Host', 'localhost'),
        'SERVER_PORT': '443',
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': 'https',
        'wsgi.input': BytesIO(body),
        'wsgi.errors': sys.stderr,
        'wsgi.multithread': False,
        'wsgi.multiprocess': True,
        'wsgi.run_once': False,
    }
    
    # Add HTTP headers
    for key, value in headers.items():
        key = key.upper().replace('-', '_')
        if key not in ('CONTENT_TYPE', 'CONTENT_LENGTH'):
            environ[f'HTTP_{key}'] = value
    
    # Response data
    response_data = []
    status_code = [200]
    response_headers = []
    
    def start_response(status, headers_list):
        status_code[0] = int(status.split()[0])
        response_headers[:] = headers_list
    
    # Call Flask app
    app_iter = app(environ, start_response)
    
    try:
        for chunk in app_iter:
            response_data.append(chunk)
    finally:
        if hasattr(app_iter, 'close'):
            app_iter.close()
    
    # Build response
    body = b''.join(response_data)
    headers_dict = dict(response_headers)
    
    return Response(
        body,
        status=status_code[0],
        headers=headers_dict
    )

