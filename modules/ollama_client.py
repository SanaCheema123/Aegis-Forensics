"""Bounded local Ollama transport; incomplete generations are never report text."""
import http.client
import json
import socket
import time
from urllib.parse import urlsplit


class OllamaError(RuntimeError):
    def __init__(self, category, message, diagnostics):
        self.category = category
        self.diagnostics = dict(diagnostics, error_category=category)
        super().__init__(message)


def generate(endpoint, model, prompt, *, num_ctx, max_tokens, timeout,
             deadline, keep_alive, max_prompt_bytes, connect_timeout=3):
    """Read NDJSON using public socket/read1 APIs and a monotonic wall budget.

    There is no model download, model substitution or partial-response return.
    The final server metrics distinguish loading, prompt evaluation and decoding.
    """
    started = time.monotonic()
    diagnostic = dict(requested_model=model, endpoint=endpoint, num_ctx=num_ctx,
                      num_predict=max_tokens, prompt_bytes=len(prompt.encode('utf-8')),
                      keep_alive=keep_alive, first_token_seconds=None)
    connection = None
    phase = 'connect'
    text = []

    def fail(category, message):
        diagnostic['elapsed_seconds'] = round(time.monotonic() - started, 3)
        diagnostic['phase'] = phase
        raise OllamaError(category, message, diagnostic)

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            fail('timeout', f'Ollama generation exceeded the total time budget during {phase}; partial output discarded.')
        return value

    if diagnostic['prompt_bytes'] > max_prompt_bytes:
        fail('prompt_budget', f'Ollama prompt is {diagnostic["prompt_bytes"]} bytes; the configured safe budget is '
             f'{max_prompt_bytes} bytes for {num_ctx} context tokens. No evidence was truncated; using deterministic reporting.')
    url = urlsplit(endpoint)
    if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password or url.fragment:
        fail('configuration', 'Ollama endpoint must be an HTTP(S) URL without credentials or a fragment.')
    payload = dict(model=model, prompt=prompt, stream=True, keep_alive=keep_alive,
                   options=dict(temperature=0.1, num_predict=max_tokens, num_ctx=num_ctx))
    try:
        cls = http.client.HTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
        connection = cls(url.hostname, url.port, timeout=min(connect_timeout, remaining()))
        connection.connect()
        # Retain the socket while HTTPResponse owns its file reference, including
        # Connection: close responses. Never reach into urllib3 private objects.
        transport = connection.sock
        diagnostic['connect_seconds'] = round(time.monotonic() - started, 3)
        transport.settimeout(min(timeout, remaining()))
        connection.request('POST', url.path + ('?' + url.query if url.query else ''),
                           body=json.dumps(payload).encode('utf-8'),
                           headers={'Content-Type': 'application/json', 'Accept': 'application/x-ndjson'})
        phase = 'waiting for first token (model loading or prompt evaluation)'
        transport.settimeout(min(timeout, remaining()))
        response = connection.getresponse()
        diagnostic['http_status'] = response.status
        diagnostic['headers_seconds'] = round(time.monotonic() - started, 3)
        if response.status != 200:
            if response.status == 404:
                fail('model_unavailable', f"Selected Ollama model '{model}' or generate endpoint is unavailable (HTTP 404). No model was replaced or downloaded.")
            fail('http_error', f'Ollama returned HTTP {response.status}; no response was accepted.')
        pending = bytearray()
        received = 0
        final = None
        while True:
            transport.settimeout(min(timeout, remaining()))
            chunk = response.read1(4096)
            remaining()
            if not chunk:
                break
            received += len(chunk)
            if received > 256 * 1024:
                fail('malformed_response', 'Ollama response exceeded the bounded response size; output discarded.')
            pending.extend(chunk)
            while b'\n' in pending:
                line, _, tail = pending.partition(b'\n')
                pending = bytearray(tail)
                if not line.strip():
                    continue
                item = json.loads(line)
                if not isinstance(item, dict):
                    fail('malformed_response', 'Ollama returned a non-object stream event.')
                if item.get('error'):
                    fail('server_error', 'Ollama generation failed: ' + str(item['error'])[:300])
                if final is not None:
                    fail('malformed_response', 'Ollama returned data after its completed response.')
                returned_model = item.get('model')
                if returned_model not in {model, model + ':latest' if ':' not in model else model}:
                    fail('model_mismatch', 'Ollama returned a different or missing model identity; output discarded.')
                fragment = item.get('response')
                if not isinstance(fragment, str) or type(item.get('done')) is not bool:
                    fail('malformed_response', 'Ollama stream lacks a text response or boolean completion flag.')
                if fragment:
                    if diagnostic['first_token_seconds'] is None:
                        diagnostic['first_token_seconds'] = round(time.monotonic() - started, 3)
                    phase = 'token generation'
                    text.append(fragment)
                if item['done']:
                    final = item
            if final is not None:
                break
        if pending.strip():
            # A complete JSON object without the required NDJSON line terminator
            # is treated as an incomplete transport, rather than guessed complete.
            fail('malformed_response', 'Ollama stream ended with an unterminated event; output discarded.')
        for key in ('total_duration', 'load_duration', 'prompt_eval_duration', 'eval_duration'):
            value = (final or {}).get(key)
            if type(value) is int and value >= 0:
                diagnostic[key.replace('_duration', '_seconds')] = round(value / 1e9, 4)
        for key in ('prompt_eval_count', 'eval_count', 'done_reason', 'model'):
            diagnostic[key] = (final or {}).get(key)
        if final is None or final.get('done_reason') != 'stop':
            reason = final.get('done_reason') if final else 'missing completion'
            fail('incomplete_response', f'Ollama did not finish normally ({reason}); partial or token-limited output discarded.')
        result = ''.join(text).strip()
        if not result:
            fail('malformed_response', 'Ollama completed with an empty response.')
        diagnostic['elapsed_seconds'] = round(time.monotonic() - started, 3)
        diagnostic['phase'] = 'complete'
        return result, diagnostic
    except OllamaError:
        raise
    except (socket.timeout, TimeoutError):
        if phase == 'connect':
            fail('connection_timeout', 'Could not connect to the Ollama service within the connection timeout; no generation response received.')
        fail('timeout', f'Ollama timed out during {phase}; partial output discarded. '
             'Check available RAM and the configured context/output limits.')
    except (ValueError, UnicodeError) as exc:
        fail('malformed_response', f'Ollama returned malformed JSON/encoding: {type(exc).__name__}.')
    except (OSError, http.client.HTTPException) as exc:
        fail('connection', f'Ollama connection failed during {phase}: {type(exc).__name__}: {exc}')
    finally:
        if connection is not None:
            connection.close()
