"""Conservative, bounded loader for changing security-relevant Hermes configuration.

Reject duplicate mapping keys, YAML aliases/merges, and oversized documents rather
than silently rewriting the user's existing config with a different meaning.
"""
from __future__ import annotations

import yaml

MAX_CONFIG_BYTES = 1024 * 1024


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise yaml.constructor.ConstructorError(None, None,
                'YAML aliases are not accepted for security-sensitive configuration edits',
                self.peek_event().start_mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(None, None, 'Expected mapping', node.start_mark)
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == 'tag:yaml.org,2002:merge':
                raise yaml.constructor.ConstructorError(None, None,
                    'YAML merges are not accepted for security-sensitive configuration edits',
                    key_node.start_mark)
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise yaml.constructor.ConstructorError(None, None,
                        f'Duplicate YAML key: {key!r}', key_node.start_mark)
                seen.add(key)
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(None, None,
                    'Unhashable YAML mapping key', key_node.start_mark) from exc
        return super().construct_mapping(node, deep=deep)


def load_config(source: bytes | str | None) -> object:
    if source is None:
        return {}
    if isinstance(source, bytes):
        if len(source) > MAX_CONFIG_BYTES:
            raise ValueError('Hermes config exceeds 1 MiB safety limit')
        text = source.decode('utf-8')
    else:
        if len(source.encode('utf-8')) > MAX_CONFIG_BYTES:
            raise ValueError('Hermes config exceeds 1 MiB safety limit')
        text = source
    return yaml.load(text, Loader=StrictLoader)
