"""Which addresses an administrator may block by hand, shared by the SSH (UFW 22/tcp) and Nginx web panels.

A normal public address is blockable. A private address only inside an explicitly configured lab range
(empty by default; one setting per block type). Never: loopback, link-local, reserved, multicast,
unspecified, anything in RESPONSE_ALLOWLIST, or the requesting administrator's own address.
The caller checks fixture/documentation addresses and which Alert is required.
"""
import ipaddress

from django.conf import settings

from .response import ResponseConfigError, parse_allowlist


def never_blockable(ip):
    return ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def private_ranges(setting):
    """Explicitly allowed private lab networks from the named setting (comma-separated CIDRs).
    Every entry must be a private network; a public, loopback or link-local entry is an error."""
    networks = []
    for entry in (e.strip() for e in getattr(settings, setting).split(',')):
        if not entry:
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ResponseConfigError(f'Invalid {setting} entry {entry!r}: {exc}') from exc
        if not network.is_private or never_blockable(network.network_address) or never_blockable(network.broadcast_address):
            raise ResponseConfigError(f'{setting} entry {entry!r} is not a private lab network.')
        networks.append(network)
    return networks


def _same_ip(ip, other):
    try:
        return ip == ipaddress.ip_address(str(other))
    except ValueError:
        return False


def address_refusal(ip, private_setting, requester_ip=None, verb='blocked'):
    """'' when `ip` (an ip_address) may be blocked; otherwise (kind, reason)."""
    if never_blockable(ip):
        return 'not_public', f'{ip} is a loopback, link-local, reserved, multicast or unspecified address; never {verb}.'
    if not ip.is_global:
        try:
            lab = next((n for n in private_ranges(private_setting) if ip.version == n.version and ip in n), None)
        except ResponseConfigError as exc:
            return 'config', str(exc)
        if lab is None:
            return 'not_public', f'{ip} is not a public address and not in {private_setting}; never {verb}.'
    try:
        match = next((n for n in parse_allowlist(settings.RESPONSE_ALLOWLIST) if ip.version == n.version and ip in n), None)
    except ResponseConfigError as exc:
        return 'config', f'Allowlist could not be checked: {exc}'
    if match:
        return 'allowlisted', f'{ip} is protected by allowlist entry {match}; never {verb}.'
    if requester_ip and _same_ip(ip, requester_ip):
        return 'self', f"{ip} is the requesting administrator's own address; never {verb}."
    return ''
