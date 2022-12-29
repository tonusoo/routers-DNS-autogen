"""Collection of functions for interacting with DNS servers.
"""

import re
import sys
import socket
import logging
from typing import TYPE_CHECKING, Any, Dict, Optional
import dns.name
import dns.zone
import dns.query
import dns.update
import dns.resolver
import dns.tsigkeyring
from dns.exception import DNSException


# Import DNSdata type alias only in case of type checking.
# https://peps.python.org/pep-0484/#runtime-or-type-checking
if TYPE_CHECKING:
    from routers_dns_autogen import DNSdata


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


def query_ns_servers(query_type: str, zone: str = "") -> list[str]:
    """Finds the DNS servers for a zone.

    Makes a SOA or NS query to system-defined NS servers to
    find DNS servers for zone.

    Args:
        query_type: DNS query type.

        zone: Zone name.

    Returns:
        answer_list: List of name servers as strings.

    Raises:
        ValueError: Invalid query type or no name servers
            for the zone were found.
    """

    if query_type not in ("SOA", "NS"):
        logger.error(f'"{query_type}" is an unsupported DNS query type')
        raise ValueError

    answer_list: list[str] = []

    try:
        logger.info(f"DNS {query_type} query for the {zone} zone")
        answer = dns.resolver.resolve(zone, query_type)
    except DNSException as err:
        logger.error(f"DNS {query_type} query for zone {zone} failed: {err!r}")
        return answer_list

    if answer:
        for rdata in answer:
            if query_type == "SOA":
                answer_list.append(rdata.mname.to_text())
            elif query_type == "NS":
                answer_list.append(rdata.to_text())

    if not answer_list:
        logger.error("No name servers")
        raise ValueError

    return answer_list


def get_zone_content(
    zone_name: str, axfr_loose: bool, ns_ips_list: Optional[list[str]] = None
) -> Optional[dns.zone.Zone]:
    """Makes an AXFR query for zone.

    Args:
        zone_name: Zone name.

        axfr_loose: Whether the AXFR query of the zone is
            allowed to fail.

        ns_ips_list: List of DNS servers IPv4 addresses.

    Returns:
        zone: DNS zone object.

    Raises:
        ValueError: None of the zone transfers succeeded.
    """

    if ns_ips_list is None:
        ns_ips_list = []

    zone = None
    for ns_ip in ns_ips_list:

        ns_port = 53

        try:
            zone = dns.zone.Zone(zone_name)
            # dns.query.inbound_xfr() expects the DNS
            # server IP address and not the DNS server name.
            dns.query.inbound_xfr(ns_ip, zone, port=ns_port)  # type: ignore

        # In case of inbound_xfr() the current version 2.2.1 of
        # dnspython does not wrap exception when there is for
        # example a connection timeout.
        # pylint: disable-next=broad-except
        except Exception as err:
            logger.error(
                f"AXFR query of the {zone_name} zone from DNS "
                f"server {ns_ip}(TCP port {ns_port}) "
                f"failed: {err!r}"
            )

        if zone is not None and zone.to_text():
            logger.debug(
                f"AXFR query of the {zone_name} zone from DNS "
                f"server {ns_ip} succeeded"
            )
            break

    if (zone is None or not zone.to_text()) and not axfr_loose:
        logger.error(
            "None of the name servers replied to "
            f"zone transfer request for zone {zone_name}"
        )
        raise ValueError

    return zone


def names_to_ips(names_list: list[str]) -> list[str]:
    """Translates host names to IPv4 addresses.

    Args:
        names_list: List of host names.

    Returns:
        ips_list: List of IPv4 addresses.
    """

    ips_list = []
    for name in names_list:
        # If the host name is an IPv4 address, then it is
        # returned unchanged.
        try:
            ip_addr = socket.gethostbyname(name)
        except socket.gaierror as err:
            logger.warning(f"Failed to resolve {name} into IP: {err!r}")
            continue

        ips_list.append(ip_addr)

    return ips_list


def send_ddns_update(
    ns_ips_list: list[str], update: dns.update.Update
) -> None:
    """Sends the DDNS update message to DDNS server.

    Args:
        ns_ips_list: A list of DDNS servers IPv4 addresses.

        update: DDNS update message.
    """

    ns_port = 53

    for ns_ip in ns_ips_list:
        logger.info(f"Attempt DDNS update to {ns_ip} TCP port {ns_port}")
        # If the DDNS update fails, then the batch of updates
        # is simply lost and the script starts building a new
        # set of updates. One might want to use a different
        # logic here.
        try:
            response: Any = dns.query.tcp(update, ns_ip, port=ns_port)
            if response.rcode() != dns.rcode.NOERROR:
                logger.error(
                    f"DDNS update to {ns_ip} "
                    "failed. Server returned: "
                    f"{dns.rcode.to_text(response.rcode())}"
                )
            else:
                logger.info(f"DDNS update to {ns_ip} succeeded")

                # Usually the DDNS updates are sent to primary
                # nameserver for the zone, which applies the update
                # and sends NOTIFY to slave servers, which triggers
                # these to AXFR/IXFR. That's the reason for the
                # break statement here.
                break
        # dns.query.tcp() does not wrap connection timeout,
        # connection refusal or for example network unreachable
        # exceptions. Use a broad exception here.
        # pylint: disable-next=broad-except
        except Exception as err:
            logger.error(f"DDNS update to {ns_ip} failed: {err!r}")


def ddns(
    ns_per_zone: Dict[str, list[str]],
    key_name: str,
    key_value: str,
    zones_updates: Dict[str, "DNSdata"],
    ns_list: Optional[list[str]] = None,
) -> None:
    """Populates the DDNS messages zone by zone with records.

    Args:
        ns_per_zone: A dict mapping zone name to the list
            of primary name server of the zone resolved into IPv4
            address.

        key_name: TSIG(transaction signature) key name.

        key_value: TSIG(transaction signature) key.

        zones_updates: A dict mapping zone name to the list of
            dicts containing the zone 'A', 'AAAA', 'CNAME' and 'PTR'
            type records plus an action whether to add this record
            or delete the record.

        ns_list: List of DNS servers used for AXFR queries.
    """

    keyring = dns.tsigkeyring.from_text({key_name: key_value})
    key_algorithm = dns.tsig.HMAC_SHA512

    # Update the name server zone by zone.
    # Zone serial is incremented automatically in case of
    # DDNS, i.e there is no need to prepare a SOA record
    # with updated serial.
    for zone, dns_updates in zones_updates.items():

        logger.info(f"Processing updates for zone {zone}")
        update = dns.update.Update(
            zone, keyring=keyring, keyalgorithm=key_algorithm
        )

        if (ns_ips_list := ns_per_zone.get(zone)) is None:
            # As the IP address of the primary master server was
            # not found during the AXFR queries, then try to find
            # the address here if the nameservers were not manually
            # set.
            ns_servers = ns_list if ns_list else query_ns_servers("SOA", zone)
            ns_ips_list = names_to_ips(ns_servers)

        if not ns_ips_list:
            logger.error(
                f"Ignore DDNS updates for zone {zone} because "
                "primary nameserver IP for the zone is unknown"
            )
            continue

        for dns_update in dns_updates:
            if dns_update["action"] == "add":
                try:
                    update.add(
                        dns.name.from_text(dns_update["name"]),
                        dns_update["ttl"],
                        dns_update["type"],
                        dns_update["value"],
                    )
                # Catch errors like too long(> 63 octets) DNS label,
                # too long DNS name(> 255 octets) or invalid DNS RR
                # type. In case the TTL is not an int, then the
                # ValueError is thrown.
                except (DNSException, ValueError) as err:
                    logger.error(
                        f'Adding DNS record {dns_update["name"]} '
                        f"failed: {err!r}"
                    )
                    continue

            elif dns_update["action"] == "delete":
                try:
                    update.delete(
                        dns.name.from_text(dns_update["name"]),
                        dns_update["type"],
                        dns_update["value"],
                    )
                except DNSException as err:
                    logger.error(
                        "Deleting DNS record "
                        f'{dns_update["name"]} failed: {err!r}'
                    )
                    continue

            # If the dnspython update in compressed wire format is
            # larger than 64 KiB, then the 'dns.exception.TooBig'
            # (The DNS message is too big) exception is raised.
            # This workaround sends the update in ~32 KiB chunks.
            if sys.getsizeof(update.to_wire()) > 32 * 1024:
                logger.debug(
                    "Dnspython update in compressed wire format "
                    f"was {sys.getsizeof(update.to_wire())} bytes "
                    "which exceeds 32 KiB"
                )

                send_ddns_update(ns_ips_list, update)

                # Reinitialize a new DNS Update object.
                update = dns.update.Update(
                    zone, keyring=keyring, keyalgorithm=key_algorithm
                )

        # Check that the update contains added or deleted records.
        # There should be no point to make this check in the previous
        # "for" loop because if the sys.getsizeof(update.to_wire()) is
        # larger than 32 KiB, then it should definitely include some
        # added or deleted records.
        pattern = " IN A| NONE A| IN CNAME | NONE CNAME | IN PTR | NONE PTR "
        if any(
            line
            for line in str(update).splitlines()
            # re.search() will return None if there is no match.
            if re.search(pattern, line)
        ):
            # Send the only or the last chunk of updates to DDNS server.
            send_ddns_update(ns_ips_list, update)
        else:
            logger.info(
                "No updates to send to name "
                f'servers: {", ".join(ns_ips_list)}'
            )
