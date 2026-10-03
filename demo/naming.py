"""Tool name mapping between the policy and the OpenAI wire format.

The policy (policy/bouncer.yaml) names tools with dots: ``crm.lookup_customer``.
OpenAI function names must match ``^[a-zA-Z0-9_-]{1,64}$``, so dots cannot travel
on the wire. Rule, in both directions:

    wire name   = policy name with every "." replaced by "__"   (crm__lookup_customer)
    policy name = wire name with every "__" replaced by "."     (crm.lookup_customer)

Single underscores inside a segment (lookup_customer) are left alone, so the mapping
is unambiguous as long as policy names never contain "__". Both functions are
idempotent: a dotted name passed to ``to_policy_name`` and a wire name passed to
``to_wire_name`` come back unchanged.

MCP allows dots in tool names, so the demo MCP server uses the policy names directly.

No third-party imports: the gateway can import this module or copy the two functions.
"""

from __future__ import annotations

SEPARATOR = "__"


def to_wire_name(policy_name: str) -> str:
    """crm.lookup_customer -> crm__lookup_customer (OpenAI function name)."""
    return policy_name.replace(".", SEPARATOR)


def to_policy_name(wire_name: str) -> str:
    """crm__lookup_customer -> crm.lookup_customer (name used in the policy)."""
    return wire_name.replace(SEPARATOR, ".")


# Aliases used in the task description.
to_function_name = to_wire_name
