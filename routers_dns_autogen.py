#!/usr/bin/env python3

"""Handles DNS records for Juniper and Cisco routers.

Reads the latest revisions of the Juniper and Cisco routers
files from git and finds all the IP addresses configured on
the routers interfaces plus VRRP VIPs and BGP neighbors.
Generates DNS records based on this information plus adds
manual overrides. DNS records are pushed to name server(s)
using DDNS(rfc2136).

Script is meant to be run as a cron job or systemd timer,
but can be manually executed from shell or as a CGI script.
Logging severity level can be specified as a command line argument.
Rest of the configuration is in the conf.ini file.

Some of the type checks and most of the isinstance() checks
scattered around the script are for helping the type checkers
like mypy.

Script has several expectations like:

    * /24 type DNS reverse zones for IPv4 and /64 type
      reverse zones for IPv6 which are predefined in the
      DNS servers with AXFR queries allowed

    * Routers hostnames are expected to consist
      of "<ISO 3166-1 two-letter country code>",
      "<city code>", "<PoP name>" and "<device_
      type><device_nr>" fields separated by "-"
      character

    * routers lists are text files in git

    * server running the script makes connections
      to network devices and DNS servers over IPv4

    * Python 3.8 or newer
"""

import os
import re
import sys
import socket
import logging
import configparser
from threading import Lock
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, NamedTuple, Optional, Dict, Union, Tuple, cast
from ipaddress import ip_network, IPv4Network, IPv6Network
from ipaddress import ip_address, IPv4Address, IPv6Address, AddressValueError
import dns.name
import dns.reversename
from lxml import etree
from git import GitError
from requests.exceptions import RequestException
from verctrl_interacts.git_vc import git
from rir_interacts.ripe import ripe_db_allocs
from routers_interacts.cisco import get_c_data
from routers_interacts.juniper import get_j_data
from dns_interacts.ddns import ddns, names_to_ips
from dns_interacts.ddns import query_ns_servers, get_zone_content
from config_handlers.configuration_handler import process_cfg_options


logger = logging.getLogger("routers_dns_autogen")

# Unix domain socket for get_lock() function.
lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

# Type aliases.
RTRdata = list[Dict[str, Union[str, bool]]]
DNSdata = list[Dict[str, Union[str, int]]]
OWdata = list[Dict[str, Union[str, bool, int]]]


def configure_logging(
    config: configparser.ConfigParser,
    conf_file: str,
    script_name: str,
    script_dir: str,
) -> None:
    """Configures logging to console and file.

    Args:
        config: Config instance.

        conf_file: Full path of the configuration file.

        script_name: Name of the script.

        script_dir: Current working directory of the script.

    Raises:
        configparser.Error: Error parsing conf file.

        OSError: Error opening conf file or creating log dir/file.

        socker.error: Unable to bind to Unix domain socket. There
            is another instance of the sript running.
    """

    # Logger severity level determines which messages are
    # passed to handlers. Send all messages to handlers.
    logger.setLevel("DEBUG")

    c_handler = logging.StreamHandler(sys.stdout)

    # "%(name)s" would also print the module name.
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S %Z %d-%m-%Y",
    )
    c_handler.setFormatter(formatter)

    # Add console logging handler to the logger.
    logger.addHandler(c_handler)

    # Stop the script if there is another instance of the
    # script running at a time. This check is done as early
    # as possible even before configuring logging to a file
    # in order to avoid possible conflicts like two processes
    # trying to write into the same log file.
    get_lock(script_name)

    # Read the configuration file and process logging
    # related config after setting up the console logging.
    # As suggested by configparser documentation, use the
    # read_file() instead of read() as the script can't
    # function without configuration.
    try:
        with open(conf_file, encoding="utf-8") as conf_f:
            try:
                config.read_file(conf_f)
            except configparser.Error as err:
                logger.error(f'Error parsing "{conf_file}": {err.message!r}')
                raise
    except OSError as err:
        logger.error(f'Unable to open config file "{conf_file}": {err!r}')
        raise

    if config.has_option("logging", "logdir"):
        logdir = config["logging"]["logdir"]
    else:
        logger.debug(
            '"logdir" configuration option under "logging" section '
            f'in "{conf_file}" is missing. Use the "{script_dir}" '
            "directory for logging."
        )
        logdir = script_dir

    if not os.path.exists(logdir):
        try:
            os.makedirs(logdir)
        except OSError as err:
            logger.error(
                f'Unable to create logging directory "{logdir}": {err!r}'
            )
            raise

    logging_levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

    if (
        config.has_option("logging", "level")
        and config["logging"]["level"] in logging_levels
    ):
        f_severity_level = config["logging"]["level"]
    else:
        f_severity_level = "INFO"

    c_severity_level = f_severity_level

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = os.path.join(
        logdir, f"{os.path.splitext(script_name)[0]}_{timestamp}.log"
    )

    try:
        with open(logfile, "w", encoding="utf-8"):
            pass
    except OSError as err:
        logger.error(f'Unable to create logging file "{logfile}": {err!r}')
        raise

    f_handler = logging.FileHandler(logfile, mode="w", delay=True)

    # Allows user to override console logging level with a command
    # line argument.
    if len(sys.argv) > 1 and sys.argv[1] in logging_levels:
        c_severity_level = sys.argv[1]

    c_handler.setLevel(c_severity_level)
    f_handler.setLevel(f_severity_level)

    # Add file logging handler to logger.
    f_handler.setFormatter(formatter)
    logger.addHandler(f_handler)


def get_lock(process_name: str) -> None:
    """Ensures that a single instance of the script runs at a time.

    Function binds to Unix domain socket in Linux-specific
    abstract namespace. If the lock is set, then the socket
    can be seen with "ss -xl src @routers_dns_autogen.py" if
    the function was called with the "routers_dns_autogen.py"
    argument.
    Based on https://stackoverflow.com/a/7758075/1053143

    Args:
        process_name: Script name used as a socket name.

    Raises:
        socker.error: Unable to bind to Unix domain socket.
    """

    try:
        # The null byte (\0) means the socket is created
        # in the abstract namespace instead of being created
        # on the file system itself.
        # Works only in Linux.
        lock_socket.bind(f"\0{process_name}")
    except socket.error:
        logger.error(f"Another instance of {process_name} is running.")
        raise


def file_to_list(
    file: str, re_pattern: Optional[re.Pattern[str]] = None
) -> list[str]:
    """Reads the content of the file into list.

    Reads the content of the file into list while
    ignoring empty lines and comment lines. Adds
    only the substring that was matched by the
    regex if the regex is specified. Possible
    duplicate lines in the returned list are removed.

    Args:
        file: Name of the file.

        re_pattern: Regex for the re module.

    Returns:
        lines: A list of unique lines read from the file.
    """

    with open(file, "r", encoding="utf-8") as file_object:
        lines = []
        for line in file_object:
            line = line.strip()
            if line and not line.startswith("#"):
                if re_pattern is not None:
                    if match := re.match(re_pattern, line):
                        lines.append(match.group())
                    continue
                lines.append(line)

    # Remove possible duplicates.
    lines = list(dict.fromkeys(lines))

    return lines


def list_to_file(lst: list[str], file: str) -> None:
    """Writes the list items into file separated by newlines.

    Args:
        lst: Name of the list.

        file: Name of the file.

    Raises:
        OSError: Error opening the file for writing.
    """

    try:
        with open(file, "w", encoding="utf-8") as file_object:
            for element in lst:
                file_object.write(f"{element}\n")
    except OSError as err:
        raise OSError(f'File "{file}" write error: {err!r}') from err


class Overrides(NamedTuple):
    """Overrides variables."""

    value_type: str
    name: str
    value: str
    router_ip: Optional[str]
    ttl: int


def overrides_to_list(file: str, default_dns_ttl: int) -> list[Overrides]:
    """Parses the content of the overrides file.

    Args:
        file: Full path of the overrides file.

        default_dns_ttl: Default value for the DNS time
            to live setting.

    Returns:
        List of Overrides objects.
    """

    logger.info(f'Read in the manual overrides from "{file}" file')

    with open(file, "r", encoding="utf-8") as file_object:

        overrides = []

        for line_nr, line in enumerate(file_object, start=1):
            line = line.strip()
            if line and not line.startswith("#"):

                ttl = default_dns_ttl
                name = ip_addr = cname = r_ip = None

                try:
                    # '<name> <IPv[46] addr>'
                    name, ip_addr = line.split()

                    if not is_valid_hostname(name):
                        raise ValueError from None
                    ip_compressed = ip_address(ip_addr).compressed

                except ValueError:
                    try:
                        # '<name> <IPv[46] addr>
                        # <optional TTL for this record>'
                        name = ip_addr = None
                        name, ip_addr, ttl_str = line.split()

                        if not is_valid_hostname(name):
                            raise ValueError from None
                        ip_compressed = ip_address(ip_addr).compressed
                        ttl = int(ttl_str)

                    except ValueError:
                        try:
                            # '<name> <CNAME>'
                            ttl = default_dns_ttl
                            name = ip_addr = None
                            name, cname = line.split()

                            if not is_valid_hostname(name):
                                raise ValueError from None

                            if not is_valid_hostname(cname):
                                raise ValueError from None

                        except ValueError:
                            try:
                                # '<name> <CNAME>
                                # <optional router IPv4 addr>'
                                name = cname = None
                                name, cname, r_ip = line.split()

                                if not is_valid_hostname(name):
                                    raise ValueError from None

                                if not is_valid_hostname(cname):
                                    raise ValueError from None

                                # <optional router IPv4 addr> is used
                                # as a destination address for NETCONF
                                # or SNMP sessions. As NETCONF and SNMP
                                # sessions are sourced from the address
                                # in the IPv4 management network, then
                                # consider only IPv4 addresses. In
                                # addition, the Easy SNMP library
                                # does not support IPv6 addresses as an
                                # hostname(https://github.com/
                                # kamakazikamikaze/easysnmp/issues/47).
                                if not isinstance(
                                    ip_address(r_ip), IPv4Address
                                ):
                                    raise ValueError from None

                            except ValueError:
                                try:
                                    # '<name> <CNAME>
                                    # <optional router IPv4 addr>
                                    # <optional TTL for this record>'
                                    name = cname = r_ip = None
                                    name, cname, r_ip, ttl_str = line.split()

                                    if not is_valid_hostname(name):
                                        raise ValueError from None

                                    if not is_valid_hostname(cname):
                                        raise ValueError from None

                                    if not isinstance(
                                        ip_address(r_ip), IPv4Address
                                    ):
                                        raise ValueError from None

                                    ttl = int(ttl_str)

                                except ValueError:
                                    logger.error(
                                        f"{file}: error on line "
                                        f"number {line_nr}"
                                    )
                                    continue

                if ip_addr:
                    if isinstance(ip_address(ip_addr), IPv4Address):
                        value_type = "inet"
                    elif isinstance(ip_address(ip_addr), IPv6Address):
                        value_type = "inet6"

                elif cname:
                    value_type = "cname"

                # According to RFC2181, the min TTL value is 0 and
                # max TTL value allowed is 2^31 - 1. DNS TTL 0 should
                # disable caching if properly supported.
                if not 0 <= ttl <= 2**31 - 1:
                    ttl = default_dns_ttl

                if value_type in ("inet", "inet6"):
                    overrides.append(
                        Overrides(value_type, name, ip_compressed, None, ttl)
                    )
                elif value_type == "cname" and cname is not None:
                    overrides.append(
                        Overrides(value_type, name, cname, r_ip, ttl)
                    )

    # Remove possible duplicates.
    return list(dict.fromkeys(overrides))


def is_valid_hostname(hostname: str) -> bool:
    """Checks whether the hostname is valid or not.

    https://stackoverflow.com/questions/2532053/validate-a-hostname-string

    Args:
        hostname: Hostname string.

    Returns:
        True or False.
    """

    if hostname[-1] == ".":
        # Strip exactly one dot from the right, if present.
        hostname = hostname[:-1]

    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # The TLD must be not all-numeric.
    if re.match(r"\d+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)


def filter_overrides_entries(overrides: list[Overrides]) -> list[Overrides]:
    """Filters out specific entries.

    List of rules/filters to remove certain entries found
    from overrides file.

    Args:
        overrides: List of Overrides objects.

    Returns:
        filtered_overrides: List of Overrides objects.
    """

    # Rule nr 1:
    # A CNAME record is not allowed to coexist with any other data.
    # RFC1912 section 2.4.
    filtered_overrides = []

    for item_l in overrides:
        ignore_override = False
        for item_r in overrides:
            if (
                item_l.value_type in ("inet", "inet6")
                and item_r.value_type == "cname"
                and item_l.name == item_r.name
            ):

                ignore_override = True
                logger.info(
                    f"Ignore {item_l.value_type} type entry "
                    f"because {item_r.value_type} type entry "
                    f"for alias {item_l.name} exists. RFC1912 "
                    "section 2.4"
                )

        if not ignore_override:
            filtered_overrides.append(item_l)

    return filtered_overrides


def filter_routers_entries(routers_dns_data: RTRdata) -> RTRdata:
    """Filters out specific entries.

    List of rules/filters to remove certain entries found
    from network devices.

    Args:
        routers_dns_data: A list of dicts containing interface
            name associated with the IP address, router name, IP
            address type, etc.

    Returns:
        filtered_routers_dns_data: A list of dicts containing
            interface name associated with the IP address, router name,
            IP address type, etc.
    """

    filtered_routers_dns_data = routers_dns_data[:]

    # Rule nr 1:
    # Ignore entries related to certain network interfaces.
    re_pattern = re.compile(
        r"""
            ^EOBC|
            ^lc-|
            ^tunnel-te|
            ^dwdm|
            ^Tunnel|
            ^unrouted VLAN|
            ^Virtual-Access|
            ^em[01]|
            ^jsrv
            """,
        re.X,
    )

    for dns_data in routers_dns_data:

        if isinstance(dns_data["int"], str):
            if re.match(re_pattern, dns_data["int"]):
                try:
                    filtered_routers_dns_data.remove(dns_data)
                    logger.debug(
                        f'Ignore {dns_data["ip"]} found in '
                        f'{dns_data["source"]} because the '
                        f'{dns_data["int"]} interface is '
                        f"ignored"
                    )
                except ValueError:
                    continue

    # Rule nr 2:
    # If there are duplicate entries for an IP address where one
    # entry has the 'peer_as' set and the other one does not, then
    # prefer the one without 'peer_as'. Entries with 'peer_as' set
    # are always the BGP neighbors. Typical example is a redundant
    # direct Internet connection service where BGP neighbors are
    # discovered from the PE routers and the same address is also
    # found from the CPE.
    for i, dict_l in enumerate(routers_dns_data, start=1):
        for dict_r in routers_dns_data[i:]:
            if dict_l["ip"] == dict_r["ip"]:
                if dict_l["peer_as"] and not dict_r["peer_as"]:
                    logger.debug(
                        f'Ignore BGP neigh addr {dict_l["ip"]} '
                        f'found in {dict_l["source"]} because the '
                        f'same addr was found on {dict_r["source"]} '
                        f'int {dict_r["int"]}'
                    )
                    try:
                        filtered_routers_dns_data.remove(dict_l)
                    except ValueError:
                        continue
                elif dict_r["peer_as"] and not dict_l["peer_as"]:
                    logger.debug(
                        f'Ignore BGP neigh addr {dict_r["ip"]} '
                        f'found in {dict_r["source"]} because the '
                        f'same addr was found on {dict_l["source"]} '
                        f'int {dict_l["int"]}'
                    )
                    try:
                        filtered_routers_dns_data.remove(dict_r)
                    except ValueError:
                        continue

    # Rule nr 3:
    # Do not touch IPv4 networks delegated(rfc2317) to customers.
    for delegated_net in ("172.16.0.8/29",):
        for dns_data in routers_dns_data:
            try:
                if IPv4Address(dns_data["ip"]) in IPv4Network(delegated_net):
                    try:
                        filtered_routers_dns_data.remove(dns_data)
                        logger.debug(
                            f'Ignore {dns_data["ip"]} found in '
                            f'{dns_data["source"]} because the '
                            f"{delegated_net} is delegated "
                            f"to customer"
                        )
                    except ValueError:
                        continue
            except AddressValueError:
                # IPv6 address.
                continue

    return filtered_routers_dns_data


def convert_int_names(routers_dns_data: RTRdata) -> RTRdata:
    """Converts the interface names suitable for DNS.

    Args:
        routers_dns_data: A list of dicts containing
            interface name associated with the IP address,
            router name, IP address type, etc.

    Returns:
        routers_dns_data: A list of dicts containing
            DNS-friendly interface name associated with the
            IP address, router name, IP address type, etc.
    """

    logger.info("Convert the interface names suitable for DNS")

    for dns_data in routers_dns_data:

        # Narrow the type for type checking.
        if isinstance(dns_data["int"], str):
            dns_data["int"] = dns_data["int"].replace("Port-channel", "po")
            dns_data["int"] = dns_data["int"].replace(
                "TenGigabitEthernet", "te"
            )
            dns_data["int"] = dns_data["int"].replace("TenGigE", "te")
            dns_data["int"] = dns_data["int"].replace("GigabitEthernet", "gi")
            dns_data["int"] = dns_data["int"].replace("FastEthernet", "fe")
            dns_data["int"] = dns_data["int"].replace("Ethernet", "e")
            dns_data["int"] = dns_data["int"].replace("Loopback", "lo")
            dns_data["int"] = dns_data["int"].replace("Vlan", "vl")
            dns_data["int"] = dns_data["int"].replace(
                "MgmtEth0/RSP0/CPU0/0", "RSP0-0"
            )
            dns_data["int"] = dns_data["int"].replace(
                "MgmtEth0/RSP1/CPU0/0", "RSP1-0"
            )
            dns_data["int"] = dns_data["int"].replace("-802.1Q vLAN subif", "")
            dns_data["int"] = dns_data["int"].replace("ServiceInstance.", "")
            dns_data["int"] = dns_data["int"].replace("/", "-")
            dns_data["int"] = dns_data["int"].replace(".", "-")
            dns_data["int"] = dns_data["int"].replace(":", "-")
            dns_data["int"] = dns_data["int"].replace(" ", "")

    return routers_dns_data


def check_against_allocs(
    allocs_list: list[str], routers_dns_data: RTRdata
) -> RTRdata:
    """Filters out entries which do not belong to LIR allocations.

    Args:
        allocs_list: A list of IPv4 and IPv6
            allocations as strings.

        routers_dns_data: A list of dicts containing
            DNS-friendly interface name associated with the
            IP address, router name, IP address type, etc.

    Returns:
        filtered_routers_dns_data: A list of dicts containing
            DNS-friendly interface name associated with the
            IP address, router name, IP address type, etc.
    """

    logger.info("Filter out IP addresses which are not from our allocations")

    filtered_routers_dns_data = []

    for dns_data in routers_dns_data:

        is_ours = False

        for alloc in allocs_list:

            try:

                if isinstance(ip_network(alloc), IPv4Network):

                    # Make sure, that IP is also v4 type as alloc.
                    ipv4_address = IPv4Network(dns_data["ip"])
                    if ipv4_address.subnet_of(IPv4Network(alloc)):
                        is_ours = True

                elif isinstance(ip_network(alloc), IPv6Network):

                    ipv6_address = IPv6Network(dns_data["ip"])
                    if ipv6_address.subnet_of(IPv6Network(alloc)):
                        is_ours = True

            except AddressValueError:
                continue

        if is_ours:
            filtered_routers_dns_data.append(dns_data)
        else:
            logger.debug(
                f"IP addr {dns_data['ip']} is not from our allocations"
            )

    return filtered_routers_dns_data


def overwrite(
    overrides: list[Overrides], routers_dns_data: RTRdata, default_dns_ttl: int
) -> DNSdata:
    """Overwrites the automatically gathered info with manual overrides.

    Combines the automatically gathered data with manual
    overrides by overwriting the former when needed.

    Args:
        overrides: List of Overrides objects.

        routers_dns_data: A list of dicts containing
            DNS-friendly interface name associated with the
            IP address, router name, IP address type, etc.

        default_dns_ttl: Default value for the DNS time
            to live setting.

    Returns:
        overwritten_list: A list of dicts containing
            source data for building the DNS records.
    """

    overwritten_list: DNSdata = []

    logger.info("Overwrite automatically gathered info with manual entries")

    # Add the default DNS TTL to automatically gathered data.
    routers_dns_data_w_ttl: OWdata = [
        {**dns_data, "dns_ttl": default_dns_ttl}
        for dns_data in routers_dns_data
    ]

    # If the dynamically discovered IP address matches
    # with the IP address in the overrides, then
    # add the entry or entries in the overrides instead.
    for dns_data in routers_dns_data_w_ttl:
        for override in overrides:
            if dns_data.get("ip") == override.value:

                override_dict: Dict[str, Union[str, int]] = {
                    "value": override.value,
                    "type": override.value_type,
                    "name": override.name,
                    "dns_ttl": override.ttl,
                }

                # Same IP address can repeat. For example a BGP
                # neighbor for multiple routers. There is no point
                # to add the override entry multiple times.
                if override_dict not in overwritten_list:
                    overwritten_list.append(override_dict)
                    logger.info(
                        f"IP addr {override.value} "
                        "has a manual override of "
                        f"{override.name}"
                    )

    # If the IP address in the overrides
    # was not dynamically discovered, then
    # add the entry from the overrides.
    for override in overrides:

        # Add all the aliases from the overrides file.
        if override.value_type == "cname":
            overwritten_list.append(
                {
                    "value": override.value,
                    "type": "cname",
                    "name": override.name,
                    "dns_ttl": override.ttl,
                }
            )
            logger.info(
                f"Added alias {override.name} pointing to "
                f"{override.value} from the overrides file"
            )
            continue

        if not any(
            dns_data.get("ip") == override.value
            for dns_data in routers_dns_data_w_ttl
        ):

            overwritten_list.append(
                {
                    "value": override.value,
                    "type": override.value_type,
                    "name": override.name,
                    "dns_ttl": override.ttl,
                }
            )
            logger.info(
                f"Added IP addr {override.value} "
                f"({override.name}) from the overrides file"
            )

    # Finally add all the dynamically discovered entries which
    # did not have an override.
    for dns_data in routers_dns_data_w_ttl:
        if not any(
            dns_data.get("ip") == overwritten_element.get("value")
            for overwritten_element in overwritten_list
        ):

            overwritten_list.append(
                {
                    "value": dns_data["ip"],
                    "type": dns_data["type"],
                    "name": get_dns_name(dns_data),
                    "dns_ttl": dns_data["dns_ttl"],
                }
            )

    return overwritten_list


def build_dns_records(domain: str, dns_data: DNSdata) -> Dict[str, DNSdata]:
    """Builds the DNS entries for the fwd zone and for each rev zone.

    Args:
        domain: Name of the forward zone.

        dns_data: A list of dicts containing
            source data for building the DNS records.

    Returns:
        new_records: A dict mapping zone name to the list of
            dicts containing the zone 'A', 'AAAA' and 'CNAME'
            type records in case of forward zone and 'PTR'
            records in case of reverse zones.
    """

    new_records: Dict[str, DNSdata] = {}

    origin = dns.name.from_text(domain)
    fwd_zone = origin.to_text()

    for dns_data_dict in dns_data:

        if isinstance(dns_data_dict["name"], str):
            dns_name = dns_data_dict["name"]

        if isinstance(dns_data_dict["value"], str):
            dns_value = dns_data_dict["value"]

        # Sanity check the DNS name. Dot character is allowed
        # because of possible subdomain entries in overrides
        # and also for BGP neighbors and VRRP entries.
        if not re.match(r"^[A-Za-z0-9\.-]+$", dns_name):
            logger.error(f"Invalid DNS name {dns_name}")
            continue

        if dns_data_dict["type"] == "inet":
            dns_type = "A"
        elif dns_data_dict["type"] == "inet6":
            dns_type = "AAAA"
        elif dns_data_dict["type"] == "cname":
            dns_type = "CNAME"

        if fwd_zone not in new_records:
            new_records[fwd_zone] = []

        new_records[fwd_zone].append(
            {
                "name": dns.name.from_text(dns_name, origin=origin).to_text(),
                "ttl": dns_data_dict["dns_ttl"],
                "type": dns_type,
                "value": dns_value,
            }
        )

        if (rev_zone := find_rev_zone(dns_type, dns_value)) is not None:
            if rev_zone not in new_records:
                new_records[rev_zone] = []

            new_records[rev_zone].append(
                {
                    "name": dns.reversename.from_address(dns_value).to_text(),
                    "ttl": dns_data_dict["dns_ttl"],
                    "type": "PTR",
                    "value": f"{dns_name}.{fwd_zone}",
                }
            )

    # Since Python 3.7, the dicts preserve insertion order. This means
    # that if for example the entries in overrides file change the
    # position, then new revision for the records debug file is
    # committed to git. In order to avoid this, then sort the records.
    # This ensures that the records debug file does not change if there
    # has been no records added or removed.
    new_records = {
        zone_name: sorted(
            new_records[zone_name], key=lambda k: (k["name"], k["value"])
        )
        for zone_name in sorted(new_records)
    }

    return new_records


def write_records(records_dict: Dict[str, DNSdata], file: str) -> None:
    """Writes the per-zone DNS records into a file.

    Args:
        records_dict: A dict mapping zone name to the list
            of dicts containing the zone 'A', 'AAAA' and
            'CNAME' type records in case of forward zone
            and 'PTR' records in case of reverse zones.

        file: Full path of the debug file.

    Raises:
        OSError: Error opening the file for writing.
    """

    logger.info(f'Write discovered DNS entries to "{file}"')

    try:
        with open(file, "w", encoding="utf-8") as file_object:
            file_object.write("# DO NOT EDIT MANUALLY!\n")
            file_object.write(
                "# THIS FILE IS FOR TROUBLESHOOTING PURPOSES ONLY.\n\n"
            )
            # Write one record per line which keeps the file easily
            # grepable. However, one might prefer for example the
            # output provided by pprint.pprint() or json.dumps()
            # which is easier to read.
            for key in records_dict:
                file_object.write(
                    "\n".join(f"{key} zone: {e}" for e in records_dict[key])
                )
                file_object.write("\n\n")

    except OSError as err:
        raise OSError(f'File "{file}" write error: {err!r}') from err


def get_zones_content(
    domain: str, axfr_loose: bool, ns_list: list[str]
) -> Tuple[Dict[str, DNSdata], Dict[str, list[str]]]:
    """Fetches the content of the forward zone and reverse zones.

    Makes an AXFR query for the forward zone. For each 'A' and 'AAAA'
    address record a corresponding /24 or /64 type reverse zone name
    is found and zone transfer per reverse zone is made.

    Args:
        domain: Forward zone name. For example 'example.net'.

        axfr_loose: Whether the AXFR query of the zone can fail.

        ns_list: List of DNS servers used for AXFR queries.

    Returns:
        existing_records: A dict mapping zone name to the
            list of dicts containing the zone 'A', 'AAAA'
            and 'CNAME' type records in case of forward
            zone and 'PTR' records in case of reverse
            zones.

        ns_per_zone: A dict mapping zone name to the list
            of primary name server of the zone resolved
            into IPv4 address.
    """

    # ns_per_zone holds the IP of the primary nameserver for the zone.
    # This is the server where DDNS updates are later sent.
    ns_per_zone = {}

    fwd_zone = dns.name.from_text(domain).to_text()

    # Find the authoritative name servers for the zone if the
    # servers were not manually defined.
    ns_servers = ns_list if ns_list else query_ns_servers("NS", fwd_zone)
    ns_ips_list = names_to_ips(ns_servers)
    zone_content = get_zone_content(fwd_zone, axfr_loose, ns_ips_list)

    existing_records: Dict[str, DNSdata] = {}
    rev_zones = []

    if zone_content:
        rdata: Any
        for name, ttl, rdata in zone_content.iterate_rdatas():
            rdtype = dns.rdatatype.to_text(rdata.rdtype)
            if rdtype == "SOA":
                mname = rdata.mname.to_text()
                ns_per_zone[fwd_zone] = names_to_ips([mname])
            elif rdtype in ("A", "AAAA", "CNAME"):
                logger.debug(
                    f'Received existing record: "{name.to_text()}" '
                    f'"{ttl}" "IN" "{rdtype}" "{rdata.to_text()}"'
                )

                # Put forward records into the existing_records
                # dictionary.
                if fwd_zone not in existing_records:
                    existing_records[fwd_zone] = []

                existing_records[fwd_zone].append(
                    {
                        "name": f"{name.to_text()}.{fwd_zone}",
                        "ttl": ttl,
                        "type": rdtype,
                        "value": rdata.to_text(),
                    }
                )

                if (
                    rev_zone := find_rev_zone(rdtype, rdata.to_text())
                ) is not None and rev_zone not in rev_zones:
                    rev_zones.append(rev_zone)

    # Put reverse records into the existing_records dictionary.
    for rev_zone in rev_zones:

        if rev_zone not in existing_records:
            existing_records[rev_zone] = []

        # Proceed if the reverse zone was not already queried.
        if not existing_records[rev_zone]:

            ns_servers = (
                ns_list if ns_list else query_ns_servers("NS", rev_zone)
            )
            ns_ips_list = names_to_ips(ns_servers)
            zone_content = get_zone_content(rev_zone, axfr_loose, ns_ips_list)

            if zone_content:
                for name, ttl, rdata in zone_content.iterate_rdatas():
                    rdtype = dns.rdatatype.to_text(rdata.rdtype)
                    if rdtype == "SOA":
                        mname = rdata.mname.to_text()
                        ns_per_zone[rev_zone] = names_to_ips([mname])
                    elif rdtype == "PTR":
                        logger.debug(
                            "Received existing record: "
                            f'"{name.to_text()}.{rev_zone}" "{ttl}" '
                            f'"IN" "{rdtype}" "{rdata.to_text()}"'
                        )

                        existing_records[rev_zone].append(
                            {
                                "name": f"{name.to_text()}.{rev_zone}",
                                "ttl": ttl,
                                "type": "PTR",
                                "value": rdata.to_text(),
                            }
                        )

    return existing_records, ns_per_zone


def find_zones_updates(
    desired_dns_records: Dict[str, DNSdata],
    existing_dns_records: Dict[str, DNSdata],
) -> Dict[str, DNSdata]:
    """Finds the DNS records which have to be added or deleted.

    Function compares the desired DNS records with existing DNS records.
    This results with list of records per zone which either has to be
    added or removed.

    Args:
        desired_dns_records: A dict mapping zone name
            to the list of dicts containing the zone 'A',
            'AAAA' and 'CNAME' type records in case of
            forward zone and 'PTR' records in case of reverse
            zones.

        existing_dns_records: A dict mapping zone name
            to the list of dicts containing the zone 'A',
            'AAAA' and 'CNAME' type records in case of
            forward zone and 'PTR' records in case of reverse
            zones.

    Returns:
        zones_updates: A dict mapping zone name to the
            list of dicts containing the zone 'A', 'AAAA' and
            'CNAME' type records in case of forward zone and
            'PTR' type records in case of reverse zones. In
            addition, each dict is updated with an instruction
            whether to add this record or delete the record.
    """

    zones_updates: Dict[str, DNSdata] = {}

    logger.info("Find the DNS records which should be removed")
    for zone_name_existing, records_existing in existing_dns_records.items():

        for record_existing in records_existing:
            remove_record = True
            try:
                for record_desired in desired_dns_records[zone_name_existing]:
                    # For example PowerDNS does not preserve the case in
                    # AXFR responses for A and AAAA records. Example
                    # with PowerDNS version 4.4.1:
                    #
                    # $ grep -i test /var/lib/powerdns/example.net
                    # TeSt   IN A 192.0.2.234
                    # $
                    # $ dig @localhost -t AXFR example.net -p 5353 | \
                    # > grep -i test
                    # test.example.net.  180 IN  A  192.0.2.234
                    # $
                    #
                    # Make sure, that names are converted to lowercase
                    # for comparison.
                    # cast() in generator expression helps mypy to
                    # understand that casefold() method is used only
                    # on strings.
                    if all(
                        v == record_desired[k]
                        if k != "name"
                        else cast(str, v).casefold()
                        == cast(str, record_desired[k]).casefold()
                        for k, v in record_existing.items()
                    ):

                        remove_record = False

            # Proceed with deleting the existing record if the
            # desired DNS records does not contain the existing
            # zone.
            except KeyError:
                pass

            if remove_record:

                if record_existing["type"] == "PTR":
                    logger.debug(
                        "Delete PTR record "
                        f'{record_existing["name"]} '
                        f'pointing to {record_existing["value"]}'
                    )

                elif record_existing["type"] == "CNAME":
                    logger.debug(
                        "Delete alias "
                        f'{record_existing["name"]} pointing '
                        f'to cname {record_existing["value"]} '
                        f"from DNS zone {zone_name_existing}"
                    )

                else:
                    logger.debug(
                        f'Delete {record_existing["type"]} record '
                        f'{record_existing["name"]}'
                        f'({record_existing["value"]}) from '
                        f"DNS zone {zone_name_existing}"
                    )

                if zone_name_existing not in zones_updates:
                    zones_updates[zone_name_existing] = []

                zones_updates[zone_name_existing].append(
                    {
                        "action": "delete",
                        "name": record_existing["name"],
                        "ttl": record_existing["ttl"],
                        "type": record_existing["type"],
                        "value": record_existing["value"],
                    }
                )

    logger.info("Find the DNS records which should be added")
    for zone_name_desired, records_desired in desired_dns_records.items():

        for record_desired in records_desired:
            add_record = True
            try:
                for record_existing in existing_dns_records[zone_name_desired]:

                    if all(
                        v == record_existing[k]
                        if k != "name"
                        else cast(str, v).casefold()
                        == cast(str, record_existing[k]).casefold()
                        for k, v in record_desired.items()
                    ):

                        add_record = False

            # Proceed with adding the desired record if the
            # existing DNS records does not contain the desired
            # zone.
            except KeyError:
                pass

            if add_record:

                if record_desired["type"] == "PTR":
                    logger.debug(
                        f'Add PTR record {record_desired["name"]} '
                        f'pointing to {record_desired["value"]}'
                    )
                elif record_desired["type"] == "CNAME":
                    logger.debug(
                        f'Add alias {record_desired["name"]} '
                        "pointing to cname "
                        f'{record_desired["value"]} '
                        f"to DNS zone {zone_name_desired}"
                    )
                else:
                    logger.debug(
                        f'Add {record_desired["type"]} record '
                        f'{record_desired["name"]}'
                        f'({record_desired["value"]}) to '
                        f"DNS zone {zone_name_desired}"
                    )

                if zone_name_desired not in zones_updates:
                    zones_updates[zone_name_desired] = []

                zones_updates[zone_name_desired].append(
                    {
                        "action": "add",
                        "name": record_desired["name"],
                        "ttl": record_desired["ttl"],
                        "type": record_desired["type"],
                        "value": record_desired["value"],
                    }
                )

    return zones_updates


def get_dns_name(dns_data: Dict[str, Union[str, bool, int]]) -> str:
    """Constructs the DNS name.

    Args:
        dns_data: Dict containing DNS-friendly interface
            name associated with the IP address, router
            name, IP address type, etc.

    Returns:
        dns_name: Constructed DNS name.
    """

    dns_name = f'{dns_data["source"]}-{dns_data["int"]}'

    if "peer_as" in dns_data and dns_data["peer_as"]:
        dns_name = f'as{dns_data["peer_as"]}.{dns_data["type"]}.{dns_name}'
    elif "is_vrrp" in dns_data and dns_data["is_vrrp"]:
        dns_name = f'vrrp.{dns_data["type"]}.{dns_name}'

    return dns_name


def find_rev_zone(record_type: str, addr: str) -> Optional[str]:
    """Finds a corresponding DNS reverse zone for IP address.

    Finds a /24 type reverse zone for the IPv4 address if the
    record type is 'A' and /64 type reverse zone for the IPv6
    address if the record type is 'AAAA'.

    Args:
        record_type: DNS record type.

        addr: IPv4 or IPv6 address.

    Returns:

        rev_zone: Reverse zone for the IP address. For example
            '114.168.192.in-addr.arpa.' in case of IPv4 address or
            '8.8.0.0.0.9.7.c.c.e.d.3.5.d.d.f.ip6.arpa.' in case of
            IPv6 address. If the record is not an A/AAAA type or record
            type does not match with IP address type, then None is
            returned.
    """

    rev_zone = None
    if record_type == "A":
        if not isinstance(ip_address(addr), IPv4Address):
            logger.error(
                'DNS record type "A" does not match with the '
                f"address {addr}"
            )
            return rev_zone
        rev_name_list = dns.reversename.from_address(addr).to_text().split(".")
        rev_zone = ".".join(rev_name_list[1:])

    elif record_type == "AAAA":
        if not isinstance(ip_address(addr), IPv6Address):
            logger.error(
                'DNS record type "AAAA" does not match with the '
                f"address {addr}"
            )
            return rev_zone
        rev_name_list = dns.reversename.from_address(addr).to_text().split(".")
        rev_zone = ".".join(rev_name_list[16:])

    return rev_zone


def main() -> None:
    """Main function of the script.

    Calls functions, handles possible exceptions
    and defines variables which are often used as
    arguments for the functions.
    """

    script_name = os.path.basename(__file__)
    script_dir = os.path.dirname(os.path.realpath(__file__))
    server_name = socket.gethostname().split(".")[0]
    conf_file = os.path.join(script_dir, "conf.ini")

    config = configparser.ConfigParser()
    try:
        configure_logging(config, conf_file, script_name, script_dir)
    except (OSError, configparser.Error, socket.error):
        sys.exit(1)

    # For example, by default the cron environment does not
    # have the USER variable set.
    if (user := os.environ.get("USER")) is None:
        user = "UNKNOWN"

    logger.info(
        f'{script_name} is executed by user "{user}" in '
        f'"{server_name}" server'
    )

    # Process rest of the configuration options.
    try:
        cfg = process_cfg_options(config, conf_file, script_dir)
    except (ValueError, KeyError):
        sys.exit(1)

    # Get the latest revision of "routerslists" repo.
    try:
        repo_dir = git("pull", cfg.repos_dir, cfg.routerslists_url)
    except (GitError, ValueError):
        sys.exit(1)

    jr_file = os.path.join(repo_dir, cfg.jr_file_name)
    cr_file = os.path.join(repo_dir, cfg.cr_file_name)

    # Get the latest revision on "dnsautogen" repo.
    try:
        repo_dir = git("pull", cfg.repos_dir, cfg.dnsautogen_url)
    except (GitError, ValueError):
        sys.exit(1)

    allocs_file = os.path.join(repo_dir, cfg.allocs_file_name)
    overrides_file = os.path.join(repo_dir, cfg.overrides_file_name)

    debug_file = os.path.join(
        repo_dir, f"{os.path.splitext(script_name)[0]}.debug"
    )

    # Sanity check the routers names.
    #
    # Routers naming format:
    # "<ISO 3166-1 alpha-2 country code>-<city code>-
    #  <PoP name>-<device type><device nr>"
    #
    # <city code> and <PoP name> can contain numbers.
    # <device type> will be "r".
    re_pattern = re.compile(
        r"""
          ^[A-Z]{2}-\w+-\w+-r\d+$      # routers
          """,
        re.X,
    )

    try:
        jr_list = file_to_list(jr_file, re_pattern)
    except FileNotFoundError:
        logger.error(f'File not found: "{jr_file}"')
        sys.exit(1)

    try:
        cr_list = file_to_list(cr_file, re_pattern)
    except FileNotFoundError:
        logger.error(f'File not found: "{cr_file}"')
        sys.exit(1)

    if cfg.api_keys_list:
        try:
            allocs_list = ripe_db_allocs(cfg.api_keys_list)
        # pylint: disable-next=c-extension-no-member
        except (RequestException, etree.XMLSyntaxError, ValueError):
            sys.exit(1)

        if allocs_list:
            logger.info(f'Write allocations to "{allocs_file}" file')

            # Do not stop when git commit fails. However, one might
            # prefer a different logic here.
            try:
                list_to_file(allocs_list, allocs_file)
                git(
                    "commit",
                    cfg.repos_dir,
                    cfg.dnsautogen_url,
                    f"{script_name}@{cfg.domain}",
                )
            except OSError as err:
                logger.error(f"{err!r}")

            except (GitError, ValueError):
                # GitError and ValueError exceptions come from
                # git() which logs an appropriate error message.
                pass

        # Something went wrong with the RIPE API call, parsing the
        # XML or the API returned erroneously an empty list of prefixes.
        # Proceed with the previously committed prefixes.
        else:
            logger.error(
                "No allocations found. Proceed with "
                "the previously committed allocations"
            )

            try:
                allocs_list = file_to_list(allocs_file)
            except FileNotFoundError:
                logger.error(f'File not found: "{allocs_file}"')
                sys.exit(1)

    # Read in the manual overrides.
    try:
        overrides = overrides_to_list(overrides_file, cfg.default_dns_ttl)
    except FileNotFoundError:
        logger.error(f'File not found: "{overrides_file}"')
        sys.exit(1)

    overrides = filter_overrides_entries(overrides)

    # Slow connections to network devices are executed concurrently.
    # Data returned by network devices is processed sequentially
    # in order to keep the log messages grouped by thread.
    # Based on https://docs.python.org/3/library/concurrent.futures.html
    # "ThreadPoolExecutor" example.
    lock = Lock()
    logger.info("Processing Juniper routers")
    with ThreadPoolExecutor() as executor:
        j_futures = {
            executor.submit(
                get_j_data,
                overrides,
                cfg.juniper_username,
                cfg.juniper_password,
                juniper,
                lock,
            ): juniper
            for juniper in jr_list
        }

        try:
            # Cycle through completed futures, get the list of dicts
            # returned by each get_j_data() call and build a flat list
            # of dicts for all Juniper routers data.
            j_data_list = [
                j_data
                for j_future in as_completed(j_futures)
                for j_data in j_future.result()
            ]
        # pylint: disable-next=broad-except
        except Exception as err:
            logger.error(
                "Asynchronous(using threads) get_j_data() "
                f"execution error: {err!r}"
            )
            sys.exit(1)

    # Fail-safe.
    if not j_data_list:
        logger.error("No data from Juniper routers. Something went wrong.")
        sys.exit(1)

    logger.info("Processing Cisco routers")
    with ThreadPoolExecutor() as executor:
        c_futures = {
            executor.submit(
                get_c_data, overrides, cfg.cisco_snmp_community, cisco, lock
            ): cisco
            for cisco in cr_list
        }

        try:
            c_data_list = [
                c_data
                for c_future in as_completed(c_futures)
                for c_data in c_future.result()
            ]
        # pylint: disable-next=broad-except
        except Exception as err:
            logger.error(
                "Asynchronous(using threads) get_c_data() "
                f"execution error: {err!r}"
            )
            sys.exit(1)

    if not c_data_list:
        logger.error("No data from Cisco routers. Something went wrong.")
        sys.exit(1)

    routers_dns_data = filter_routers_entries(j_data_list + c_data_list)
    routers_dns_data = convert_int_names(routers_dns_data)

    # Routers in ISP networks often have addresses configured
    # for example from IXPs or peering partners networks. Do
    # not try to create DNS records for those addresses.
    if cfg.api_keys_list:
        routers_dns_data = check_against_allocs(allocs_list, routers_dns_data)
    else:
        logger.info(
            "RIPE API keys were not configured. Discovered networks "
            "are not checked against the allocations in RIPE "
            "database"
        )

    dns_data = overwrite(overrides, routers_dns_data, cfg.default_dns_ttl)

    new_records = build_dns_records(cfg.domain, dns_data)

    # Dump new DNS records into a file for possible
    # troubleshooting purposes.
    try:
        write_records(new_records, debug_file)
        git(
            "commit",
            cfg.repos_dir,
            cfg.dnsautogen_url,
            f"{script_name}@{cfg.domain}",
        )
    except OSError as err:
        logger.error(f"{err!r}")

    except (GitError, ValueError):
        pass

    try:
        existing_records, ns_per_zone = get_zones_content(
            cfg.domain, cfg.axfr_loose, cfg.ns_list
        )
    except ValueError:
        sys.exit(1)

    zones_updates = find_zones_updates(new_records, existing_records)

    if not zones_updates:
        logger.info("No updates to send")
        sys.exit(0)

    ddns(
        ns_per_zone,
        cfg.tsig_key_name,
        cfg.tsig_key,
        zones_updates,
        cfg.ns_list,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted")
        sys.exit(1)
