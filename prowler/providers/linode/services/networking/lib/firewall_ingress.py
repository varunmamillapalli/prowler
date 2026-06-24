"""Helpers for Linode networking firewall checks."""

from prowler.providers.linode.services.networking.networking_service import Firewall

# CIDRs that represent "the entire internet"
INTERNET_CIDRS_IPV4 = {"0.0.0.0/0"}
INTERNET_CIDRS_IPV6 = {"::/0"}


def _ports_overlap(rule_ports: str, target_ports: set[int]) -> bool:
    """Return True if any port in *target_ports* falls within *rule_ports*.

    ``rule_ports`` uses the Linode format: ``""`` (all ports), ``"22"``,
    ``"1-65535"``, or ``"80, 443"``.
    """
    if not rule_ports or rule_ports.strip() == "":
        # Empty string means all ports are matched
        return True

    for segment in rule_ports.split(","):
        segment = segment.strip()
        if not segment:
            continue
        if "-" in segment:
            parts = segment.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError:
                continue
            if any(lo <= p <= hi for p in target_ports):
                return True
        else:
            try:
                if int(segment) in target_ports:
                    return True
            except ValueError:
                continue
    return False


def firewall_allows_port_from_internet(
    fw: Firewall,
    target_ports: set[int],
    protocol: str = "TCP",
) -> bool:
    """Return ``True`` if *fw* effectively allows traffic from the whole internet
    to any of the *target_ports* on the given protocol.

    The check considers both explicit rules and the default inbound policy:
    - If an ACCEPT rule exists matching the port/protocol from the internet → True
    - If a DROP rule exists matching the port/protocol from the internet → False
    - If no rule covers the port, the default inbound policy decides:
      ACCEPT → True, DROP → False.

    Args:
        fw: Parsed ``Firewall`` model from the networking service.
        target_ports: Set of port numbers to look for.
        protocol: Protocol to match (``"TCP"`` or ``"UDP"``).

    Returns:
        ``True`` when traffic to the target ports from the internet is allowed.
    """
    port_covered = False
    for rule in fw.inbound_rules:
        if protocol and rule.protocol.upper() != protocol.upper():
            continue
        if not _ports_overlap(rule.ports, target_ports):
            continue
        from_internet = bool(
            INTERNET_CIDRS_IPV4 & set(rule.addresses_ipv4)
            or INTERNET_CIDRS_IPV6 & set(rule.addresses_ipv6)
        )
        if not from_internet:
            continue
        # An explicit rule from the internet covers this port
        port_covered = True
        if rule.action.upper() == "ACCEPT":
            return True

    # No explicit ACCEPT rule found; if no rule covers the port at all,
    # the default inbound policy determines whether traffic is allowed.
    if not port_covered:
        return fw.inbound_policy.upper() == "ACCEPT"

    # Rules exist that cover the port but none are ACCEPT (all DROP/REJECT)
    return False
