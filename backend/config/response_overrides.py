"""Optional, Git-excluded overrides for a few non-secret RESPONSE_* settings.

The backend container reads .env only when it is created. To change these values without recreating
it, write KEY=VALUE lines to backend/.response-overrides.env (bind-mounted at /app) and touch
config/settings.py so runserver reloads. Only ALLOWED_KEYS are read: no passwords, keys or hosts.
Any other key, a malformed line or an unreadable file is an error, and every block switch is then
turned off so no block command can be sent. Unblocking is left as it was.
"""
from pathlib import Path

ALLOWED_KEYS = ('RESPONSE_ALLOWLIST', 'RESPONSE_WEB_BLOCK_EXECUTE', 'RESPONSE_WEB_PRIVATE_RANGES',
                'RESPONSE_SSH_PRIVATE_RANGES', 'RESPONSE_MANUAL_BLOCK_EXECUTE')
BOOLEAN_KEYS = ('RESPONSE_WEB_BLOCK_EXECUTE', 'RESPONSE_MANUAL_BLOCK_EXECUTE')
BLOCK_SWITCHES = ('RESPONSE_EXECUTE', 'RESPONSE_MANUAL_BLOCK_EXECUTE', 'RESPONSE_WEB_BLOCK_EXECUTE')


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
