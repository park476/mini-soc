"""Optional, Git-excluded overrides for a few non-secret RESPONSE_* settings.

The backend container reads .env only when it is created. To change these values without recreating
it, write KEY=VALUE lines to backend/.response-overrides.env (bind-mounted at /app) and touch
config/settings.py so runserver reloads. Only ALLOWED_KEYS are read: no passwords, keys or hosts.
Any other key, a malformed line or an unreadable file is an error, and every block switch is then
turned off so no block command can be sent. Unblocking is left as it was.
"""
import os
from pathlib import Path

ALLOWED_KEYS = ('RESPONSE_ALLOWLIST', 'RESPONSE_WEB_BLOCK_EXECUTE', 'RESPONSE_WEB_PRIVATE_RANGES',
                'RESPONSE_SSH_PRIVATE_RANGES', 'RESPONSE_MANUAL_BLOCK_EXECUTE', 'RESPONSE_AUTO_WEB_EXECUTE')
BOOLEAN_KEYS = ('RESPONSE_WEB_BLOCK_EXECUTE', 'RESPONSE_MANUAL_BLOCK_EXECUTE', 'RESPONSE_AUTO_WEB_EXECUTE')
BLOCK_SWITCHES = ('RESPONSE_EXECUTE', 'RESPONSE_MANUAL_BLOCK_EXECUTE', 'RESPONSE_WEB_BLOCK_EXECUTE',
                  'RESPONSE_AUTO_WEB_EXECUTE')


class OverrideError(Exception):
    pass


def load(path):
    """Values from the override file; {} when it does not exist."""
    path = Path(path)
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        raise OverrideError(f'{path.name} could not be read: {exc}') from exc
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not sep or key not in ALLOWED_KEYS:
            raise OverrideError(f'{path.name} line {number}: only {", ".join(ALLOWED_KEYS)} may be set.')
        if key in values:
            raise OverrideError(f'{path.name} line {number}: {key} is set twice.')
        if key in BOOLEAN_KEYS:
            if value.lower() not in ('true', 'false'):
                raise OverrideError(f'{path.name} line {number}: {key} must be true or false.')
            value = value.lower() == 'true'
        values[key] = value
    return values


def apply(namespace, path):
    """Apply the override file to a settings namespace (settings.py passes globals())."""
    try:
        values = load(path)
    except OverrideError as exc:
        for switch in BLOCK_SWITCHES:
            namespace[switch] = False
        namespace['RESPONSE_OVERRIDES_ERROR'] = str(exc)
        return
    namespace['RESPONSE_OVERRIDES_ERROR'] = ''
    namespace.update(values)


def _env_baseline():
    """The managed keys as the container's environment (.env) defines them, parsed like settings.py."""
    base = {}
    for key in ALLOWED_KEYS:
        raw = os.environ.get(key, '')
        base[key] = (raw.strip().lower() == 'true') if key in BOOLEAN_KEYS else raw
    return base


def refresh():
    """Re-read the override file onto the live Django settings. The long-lived run_analysis process
    uses this each cycle so a switch can be toggled without restarting it. Each managed key is first
    reset to its environment baseline and then the file is applied, so removing a key's line (or the
    whole file) reverts that key to its .env default (every *_EXECUTE default is off) instead of
    leaving a stale True. A broken file turns every block switch off, exactly like startup.
    Disabled in tests via RESPONSE_OVERRIDES_REFRESH=False so it never clobbers override_settings."""
    from django.conf import settings
    if not getattr(settings, 'RESPONSE_OVERRIDES_REFRESH', True):
        return
    path = getattr(settings, 'RESPONSE_OVERRIDES_FILE', None)
    if not path:
        return
    try:
        values = load(path)
    except OverrideError as exc:
        for switch in BLOCK_SWITCHES:
            setattr(settings, switch, False)
        settings.RESPONSE_OVERRIDES_ERROR = str(exc)
        return
    settings.RESPONSE_OVERRIDES_ERROR = ''
    baseline = _env_baseline()
    baseline.update(values)
    for key, value in baseline.items():
        setattr(settings, key, value)
