"""Quality of Blocking (QoB) — flow-based packet counting for black-holed IPs.

See plan-netflow-counting.md for the design. Deployment is source-based RTBH,
so attacker traffic is matched on the flow SOURCE address.
"""

__all__ = ["models", "scoring", "join_flows"]
