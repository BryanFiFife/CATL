"""Conservative Hermes protected-CLI profile configuration checks.

Grounded in NousResearch/hermes-agent current cli-config.yaml.example and
hermes_cli/tools_config.py (read 2026-11-07). Current top-level 'toolsets' is
ignored; platform_toolsets.<platform> is authoritative. This is NOT OS isolation.
"""
from __future__ import annotations

# Known Hermes surfaces. Defaults for absent platform keys are broad toolsets;
# explicitly select zero toolsets on non-CLI surfaces for a CLI-only lab profile.
KNOWN_PLATFORMS = ('cli', 'telegram', 'discord', 'whatsapp', 'slack',
                   'signal', 'qqbot', 'teams', 'google_chat')

# Defence-in-depth against native and newly recovered built-in toolsets.
# Unknown future/plugin toolsets still require a runtime inventory and OS
# sandbox; this is not a complete allowlist enforcement mechanism.
NATIVE_DISABLED_TOOLSETS = (
    'a2a', 'browser', 'catalog', 'clarify', 'code_execution', 'computer_use',
    'connections', 'context_engine', 'cronjob', 'delegation', 'discord',
    'discord_admin', 'file', 'image_gen', 'kanban', 'memory', 'messaging',
    'search', 'session_search', 'skills', 'skills_hub', 'terminal', 'todo',
    'tts', 'video', 'video_gen', 'vision', 'web', 'x_search',
)


def expected_platform_toolsets(server_name: str) -> dict[str, list[str]]:
    if not server_name or any(not (c.isascii() and (c.isalnum() or c == '_')) for c in server_name):
        raise ValueError('unreviewed_server_name')
    return {platform: ([f'mcp-{server_name}'] if platform == 'cli' else [])
            for platform in KNOWN_PLATFORMS}


def validate_restricted_profile(config: object, name: str) -> list[str]:
    """Fail closed for demonstrable config bypasses. Never claim live proof."""
    failures=[]
    if not isinstance(config,dict):
        return ['Hermes config not a mapping']
    if 'toolsets' in config:
        failures.append('top-level toolsets is deprecated/ignored and must not be used as a security control')
    expected = expected_platform_toolsets(name)
    actual = config.get('platform_toolsets')
    if actual != expected:
        failures.append('protected profile must use exact platform_toolsets: cli=mcp-'+name+', all documented messaging platforms=[]')
    context=config.get('context')
    if isinstance(context,dict) and context.get('engine') not in (None,'compressor'):
        failures.append('non-default context engine may register native bypass tools')
    if context is not None and not isinstance(context,dict):
        failures.append('unrecognised context configuration')
    agent=config.get('agent',{})
    if not isinstance(agent,dict):
        failures.append('agent must be a mapping')
    elif agent.get('disabled_toolsets') != list(NATIVE_DISABLED_TOOLSETS):
        failures.append('protected profile must explicitly disable reviewed native toolsets as defence-in-depth')
    # Unknown plugin / executable registration is not a static proof; users
    # must inspect the runtime registry and enforce Linux OS containment.
    return failures
