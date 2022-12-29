"""Collection of functions for interacting with Junos NOS.
"""

import logging
from threading import Lock
from typing import TYPE_CHECKING, Any
from ipaddress import IPv4Network, IPv6Network
from ipaddress import ip_address, IPv4Address, IPv6Address, AddressValueError
from jnpr.junos import Device  # type: ignore
from jnpr.junos.exception import RpcError, ConnectError  # type: ignore


# Import Overrides class and RTRdata type alias only in
# case of type checking.
# https://peps.python.org/pep-0484/#runtime-or-type-checking
if TYPE_CHECKING:
    from routers_dns_autogen import Overrides, RTRdata


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


def int_data(interface_information: Any) -> "RTRdata":
    """Finds the interfaces IP addresses and related info.

    Args:
        interface_information (lxml.etree._Element):
            "interface-information" element containing Junos
            interface information.

    Returns:
        int_data_list: A list of dicts containing IP address
            associated with the interface name, netmask, IP
            address type, etc.
    """

    int_data_list = []

    # Ignore IFDs and IFLs which are administratively disabled.
    ifl_xpath = (
        'physical-interface[admin-status != "down"]/'
        "logical-interface[not(if-config-flags/iff-down)]"
    )
    ifl_objects = interface_information.xpath(ifl_xpath)

    ip_xpath = (
        'address-family[address-family-name = "inet" or '
        'address-family-name = "inet6"]/interface-address'
    )

    for ifl_object in ifl_objects:
        ifl = ifl_object.findtext("name")

        ip_objects = ifl_object.xpath(ip_xpath)
        for ip_object in ip_objects:

            addr_family = ip_object.findtext("../address-family-name")
            ip_addr = ip_object.findtext("ifa-local")

            # Sanity check.
            # This test should not be necessary as Junos should
            # return only a valid IPv6 address represented according
            # to RFC 5952(A Recommendation for IPv6 Address Text
            # Representation) and a valid IPv4 address without
            # unnecessary data like leading zeros.
            try:
                ip_addr_comp = ip_address(ip_addr).compressed
            except ValueError:
                continue

            # Junos has loopback addresses configured on IFLs under lo0
            # by default.
            if (
                not ip_address(ip_addr_comp).is_link_local
                and not ip_address(ip_addr_comp).is_loopback
            ):

                # As "ifa-destination" can contain the network address
                # in an abbreviated format(for example 9.9.8/22), then
                # use it only to get the subnet mask.
                ip_netaddr = ip_object.findtext("ifa-destination")

                if not ip_netaddr and addr_family == "inet":
                    ip_sm = "32"
                elif not ip_netaddr and addr_family == "inet6":
                    ip_sm = "128"
                else:
                    ip_sm = ip_netaddr.split("/")[1]

                if not ip_addr_comp or not ip_sm:
                    logger.debug(f"Unable to find IP addr or netmask on {ifl}")
                    continue

                logger.debug(f"Found {ip_addr_comp}/{ip_sm} on {ifl}")

                int_data_list.append(
                    {
                        "int": ifl,
                        "is_vrrp": False,
                        "type": addr_family,
                        "ip": ip_addr_comp,
                        "sm": ip_sm,
                        "peer_as": "",
                    }
                )

    return int_data_list


def vrrp_data(vrrp_information: Any) -> "RTRdata":
    """Finds the VRRP VIP addresses and related info.

    Args:
        vrrp_information (lxml.etree._Element): "vrrp-information"
            element containing Junos Virtual Router Redundancy Protocol
            information.

    Returns:
        vrrp_data_list: A list of dicts containing VRRP VIP
            address associated with the interface name, netmask,
            IP address type, etc.
    """

    vrrp_data_list: "RTRdata" = []

    # Return if the VRRP subsystem wasn't running.
    if vrrp_information is None:
        return vrrp_data_list

    # In case of VRRP split brain there will be multiple
    # reverse records for the same address pointing to
    # different names and multiple different forward
    # records pointing to same address. This is permitted by DNS.
    vrrp_int_xpath = 'vrrp-interface[vrrp-state = "master"]'
    vrrp_int_objects = vrrp_information.xpath(vrrp_int_xpath)

    for vrrp_int_object in vrrp_int_objects:
        ifl = vrrp_int_object.findtext("interface")

        # There can be multiple VIPs.
        vip_xpath = "virtual-ip-address"
        vip_objects = vrrp_int_object.xpath(vip_xpath)

        for vip_object in vip_objects:

            vip_addr = vip_object.findtext(".")

            try:
                vip_addr_compressed = ip_address(vip_addr).compressed
            except ValueError:
                continue

            try:
                if isinstance(ip_address(vip_addr_compressed), IPv4Address):
                    vip_type = "inet"
                    vip_netmask = "32"
                elif isinstance(ip_address(vip_addr_compressed), IPv6Address):
                    vip_type = "inet6"
                    vip_netmask = "128"
            except ValueError:
                continue

            if not ip_address(vip_addr_compressed).is_link_local:

                logger.debug(f"Found VRRP VIP {vip_addr_compressed} on {ifl}")

                vrrp_data_list.append(
                    {
                        "int": ifl,
                        "is_vrrp": True,
                        "type": vip_type,
                        "ip": vip_addr_compressed,
                        "sm": vip_netmask,
                        "peer_as": "",
                    }
                )

    return vrrp_data_list


def bgp_neigh_data(
    bgp_information: Any, int_data_list: "RTRdata"
) -> "RTRdata":
    """Finds the BGP neighbors addresses and related info.

    Finds the BGP IPv4 and IPv6 neighbors which are from
    one of the networks found on router interfaces.

    Args:
        bgp_information (lxml.etree._Element): "bgp-information"
            element containing Junos Border Gateway Protocol
            summary information.

        int_data_list: A list of dicts containing IP address
            associated with the interface name, netmask, IP address
            type, etc.

    Returns:
        bgp_neigh_data_list: A list of dicts containing BGP
            neighbor associated with the interface name, AS
            number, IP address type, etc.
    """

    bgp_neigh_data_list = []

    bgp_objects = bgp_information.xpath("bgp-peer")

    for int_data_item in int_data_list:

        ip_network = f'{int_data_item["ip"]}/{int_data_item["sm"]}'

        for bgp_object in bgp_objects:

            neigh_ip = bgp_object.findtext("peer-address")

            # Check that the BGP neighbor address belongs to
            # IP network configured on the interface.
            net_found = False
            try:
                if IPv4Address(neigh_ip) in IPv4Network(
                    ip_network, strict=False
                ):
                    net_found = True
            except AddressValueError:
                try:
                    if IPv6Address(neigh_ip) in IPv6Network(
                        ip_network, strict=False
                    ):
                        net_found = True
                except AddressValueError:
                    continue

            if net_found:

                peer_as = bgp_object.findtext("peer-as")

                bgp_neigh_data_item = {
                    "int": int_data_item["int"],
                    "is_vrrp": False,
                    "type": int_data_item["type"],
                    "ip": neigh_ip,
                    "sm": int_data_item["sm"],
                    "peer_as": peer_as,
                }

                # Avoid duplicate entries. For example, this could
                # happen if the interface has multiple addresses
                # from the same subnet.
                if bgp_neigh_data_item not in bgp_neigh_data_list:
                    logger.debug(
                        "Found BGP neigh address "
                        f"{neigh_ip} (ASN {peer_as})"
                    )
                    bgp_neigh_data_list.append(bgp_neigh_data_item)

    return bgp_neigh_data_list


def get_j_data(
    overrides: list["Overrides"],
    username: str,
    password: str,
    juniper: str,
    lock: Lock,
) -> "RTRdata":
    """Finds the IP addresses and related info from Juniper device.

    Finds the IPv4 and IPv6 addresses configured either on interfaces
    or as a VRRP VIP addresses in Juniper device. In addition, BGP
    neighbors addresses are found. Addresses are associated with network
    interfaces.
    NETCONF is used for gathering the data from the router. As an
    alternative, Junos REST API could be used.

    Args:
        overrides: A list of NamedTuples containing info from
            the overrides file.

        username: Username for the Juniper router.

        password: Password for the Juniper router.

        juniper: Name of the Juniper router.

        lock: Lock in unlocked state.

    Returns:
        j_data_list: A list of dicts containing interface name
            associated with the IP address, router name, IP address
            type, etc.
    """

    j_data_list: "RTRdata" = []

    juniper_ip = None
    for override in overrides:
        if override.value_type == "cname" and override.name == juniper:
            juniper_ip = override.router_ip

    if juniper_ip is not None:
        juniper_host = juniper_ip
    else:
        juniper_host = juniper

    try:

        # In case the connection has to be sourced from a specific
        # address, then one can pass a "sock_fd" argument to
        # Device() call instead of "host". Example where connection
        # will be sourced from 192.0.2.1 and OS-assigned ephemeral port:
        #
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.bind(('192.0.2.1', 0))
        # s.connect((juniper_host, 22))
        # fd = s.fileno()
        # dev = Device(sock_fd=fd, ...)
        dev = Device(
            host=juniper_host,
            user=username,
            password=password,
            gather_facts=False,
            normalize=True,
            port=22,
        )
        dev.open()
        dev.timeout = 180
        interface_information = dev.rpc.get_interface_information()
        bgp_information = dev.rpc.get_bgp_summary_information()
        # As "vrrp subsystem not running" RPC error is allowed to
        # pass, then "get-vrrp-information" RPC has to be called
        # after "get-interface-information" and "get-bgp-summary-
        # information" RPCs.
        vrrp_information = dev.rpc.get_vrrp_information(summary=True)

    except ConnectError as err:
        # Raised if dev.open() fails.
        logger.error(f"{juniper}: connection error: {err!r}")
        return j_data_list

    except RpcError as err:
        # In case the VRRP subsystem is not running, the Junos returns
        # a <xnm:warning>. This is not the case for BGP, i.e. if there
        # is no BGP configuration, then Junos does not return a warning.
        if "vrrp subsystem not running" in err.rpc_error["message"]:
            vrrp_information = None
        else:
            logger.error(f"{juniper}: NETCONF error: {err!r}")
            return j_data_list

    finally:
        dev.close()

    with lock:
        if juniper_ip is not None:
            logger.info(
                f"Established NETCONF session to {juniper} "
                f"using address {juniper_ip}"
            )
        else:
            logger.info(f"Established NETCONF session to {juniper}")

        int_data_list = int_data(interface_information)
        vrrp_data_list = vrrp_data(vrrp_information)
        bgp_neigh_data_list = bgp_neigh_data(bgp_information, int_data_list)

        # At least some Junos releases(for example 16.1R7.8) show the
        # VRRP virtual IP in the output of "show interfaces" if the
        # router is a VRRP master. Remove those entries in order to
        # avoid duplicate(one with "vrrp.inet" or "vrrp.inet6" prefix
        # and the other one without it) DNS entries.
        vrrp_ips = {vrrp_ip["ip"] for vrrp_ip in vrrp_data_list}
        int_data_list = [
            int_data
            for int_data in int_data_list
            if int_data["ip"] not in vrrp_ips
        ]

        # Add the router name to each dict and extend the j_data_list.
        j_data_list.extend(
            [
                {**data_item, "source": juniper}
                for data_item in int_data_list
                + vrrp_data_list
                + bgp_neigh_data_list
            ]
        )

        return j_data_list
