"""Local-only ASGI application; bind to 127.0.0.1 and use a single worker."""
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import secrets

from fastapi import FastAPI, Request, Depends, Security
from fastapi.security import APIKeyHeader
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.routers.v1 import router
from api.security.policy import ServiceError
from api.services.forensics import ForensicsService
from api.services.jobs import JobManager

ROOT = Path(__file__).resolve().parents[1]
log = logging.getLogger('aegis.api')
ORIGINS = ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:8000', 'http://127.0.0.1:8000']
session_header = APIKeyHeader(name='X-Aegis-Token', auto_error=False, scheme_name='Local session token',
    description='Copy csrf_token from /api/v1/health. This is a loopback CSRF guard, not multi-user authentication.')


def session_documentation(token: str | None = Security(session_header)):
    """Advertise the header in OpenAPI; middleware enforces it on mutations."""


def create_app(root=ROOT, approved_roots=None, testing=False):
    service = ForensicsService(root, approved_roots if approved_roots is not None else json.loads(os.getenv('AEGIS_APPROVED_ROOTS', '{}')))
    jobs = JobManager()

    @asynccontextmanager
    async def lifespan(app):
        yield
        jobs.close()

    class PublicJSONResponse(JSONResponse):
        def render(self, content):
            replacements = [(str(service.root), '[workspace]'), (str(Path.home()), '[local user]')]
            replacements += [(str(path), '[approved root: ' + key + ']') for key, path in service.approved_roots.items()]
            def redact(value):
                if isinstance(value, str):
                    for source, replacement in replacements:
                        value = value.replace(source, replacement).replace(source.replace('\\', '/'), replacement)
                    return value
                if isinstance(value, list):
                    return [redact(item) for item in value]
                if isinstance(value, dict):
                    return {key: redact(item) for key, item in value.items()}
                return value
            return super().render(redact(content))

    app = FastAPI(title='Aegis Forensics Local API', version='1.0.0', lifespan=lifespan, default_response_class=PublicJSONResponse,
        dependencies=[Depends(session_documentation)],
        description='Single local operator. Immutable evidence, verified cases, reviewed checkpoints. Not a multi-tenant service.')
    app.state.service, app.state.jobs, app.state.token = service, jobs, secrets.token_urlsafe(32)
    app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=['GET', 'POST'],
        allow_headers=['Content-Type', 'X-Aegis-Token'], expose_headers=['Content-Disposition'])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '[::1]'] + (['testserver'] if testing else []))

    @app.middleware('http')
    async def local_boundary(request: Request, call_next):
        origin = request.headers.get('origin')
        if origin and origin not in ORIGINS:
            return JSONResponse({'detail': 'This origin is not allowed.'}, status_code=403)
        if not testing and request.client and request.client.host not in {'127.0.0.1', '::1'}:
            return JSONResponse({'detail': 'This application accepts loopback clients only.'}, status_code=403)
        if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
            if not secrets.compare_digest(request.headers.get('x-aegis-token', ''), app.state.token):
                return JSONResponse({'detail': 'A valid local session token is required.'}, status_code=403)
        length = request.headers.get('content-length')
        if length and (not length.isdigit() or int(length) > 21*1024*1024):
            return JSONResponse({'detail': 'Request exceeds the upload limit.'}, status_code=413)
        received = 0
        original_receive = request.receive
        async def bounded_receive():
            nonlocal received
            message = await original_receive()
            received += len(message.get('body', b''))
            if received > 21*1024*1024:
                from starlette.exceptions import HTTPException
                raise HTTPException(status_code=413, detail='Request exceeds the upload limit.')
            return message
        request._receive = bounded_receive
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.exception_handler(ServiceError)
    async def service_error(request, exc):
        return JSONResponse({'detail': str(exc)}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse({'detail': 'Invalid request.', 'errors': [dict(field='.'.join(map(str, e['loc'])), message=e['msg']) for e in exc.errors()]}, status_code=422)

    @app.exception_handler(Exception)
    async def internal_error(request, exc):
        log.warning('request_failed method=%s type=%s', request.method, type(exc).__name__)
        return JSONResponse({'detail': 'Operation unavailable. Check evidence integrity, input schema and local capability.'}, status_code=409 if isinstance(exc, (ValueError, OSError)) else 500)

    app.include_router(router)
    return app


app = create_app()
