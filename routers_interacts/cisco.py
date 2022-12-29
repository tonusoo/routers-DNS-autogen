"""Collection of functions for interacting with IOS/IOS-XE NOS.
"""

import logging
from threading import Lock
from typing import TYPE_CHECKING, Any, Dict
from ipaddress import IPv4Network, IPv6Network
from ipaddress import ip_address, IPv4Address, IPv6Address, AddressValueError
from easysnmp import Session, EasySNMPError  # type: ignore


# Import Overrides class and RTRdata type alias only in
# case of type checking.
# https://peps.python.org/pep-0484/#runtime-or-type-checking
if TYPE_CHECKING:
    from routers_dns_autogen import Overrides, RTRdata


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


def ipv4_data_2011(
    ipv4_addresses: Any,
    ipv4_netmasks: Any,
    ipv4_ifindexes: Any,
    disabled_ints: list[str],
) -> list[Dict[str, str]]:
    """Finds the interfaces IPv4 addresses and related info.

    Processes data from obsolete RFC2011 IP-MIB.
    The function essentially processes the results of three
    different SNMP queries. If any of those queries has returned
    invalid data, then the results of the three queries can no
    longer be combined and the function will raise an exception.

    Args:
        ipv4_addresses (easysnmp.variables.SNMPVariableList): List of
            objects containing IPv4 addresses information.

        ipv4_netmasks (easysnmp.variables.SNMPVariableList): List of
            objects containing netmasks information.

        ipv4_ifindexes (easysnmp.variables.SNMPVariableList): List of
            objects containing ifindexes information.

        disabled_ints: List of ifindexes which are
            administratively disabled.

    Returns:
        ipv4_data_list: A list of dicts containing IPv4 address,
            its netmask, ifindex of the interface where the IPv4 address
            is configured and IP type.

    Raises:
        ValueError: Router returned invalid data.
    """

    ipv4_data_list = []

    ip_ad_ent_addrs = []
    ip_ad_ent_masks = []
    ip_ad_ent_ifindexes = []
    ip_ad_ents = []

    for ipv4_address in ipv4_addresses:

        try:
            # Convert the IPv4 address into string.
            addr = IPv4Address(ipv4_address.value).compressed
        except ValueError as err:
            raise ValueError(f"IP err: {ipv4_address.value!r}") from err

        ip_ad_ent_addrs.append((addr, ipv4_address.oid_index))

    for ipv4_netmask in ipv4_netmasks:

        try:
            prefixlen = str(
                IPv4Network(f"0.0.0.0/{ipv4_netmask.value}").prefixlen
            )
        except ValueError as err:
            raise ValueError(f"Netmask err: {ipv4_netmask.value!r}") from err

        ip_ad_ent_masks.append((prefixlen, ipv4_netmask.oid_index))

    for ipv4_ifindex in ipv4_ifindexes:

        try:
            # Make sure, that ifindex is an int.
            ifindex = str(int(ipv4_ifindex.value))
        except ValueError as err:
            raise ValueError(f"Ifindex err: {ipv4_ifindex.value!r}") from err

        ip_ad_ent_ifindexes.append((ifindex, ipv4_ifindex.oid_index))

    # All three lists have to have the same number of elements.
    if (
        len(
            set(
                map(
                    len,
                    [ip_ad_ent_addrs, ip_ad_ent_masks, ip_ad_ent_ifindexes],
                )
            )
        )
        != 1
    ):
        raise ValueError("Failure in SNMP legacy IP-MIB queries")

    # 'ipAdEntAddr', 'ipAdEntNetMask' and 'ipAdEntIfIndex'
    # can be combined by OID index. Find unique OID indexes
    # and build a list where elements are lists containing
    # IP addr, netmask and ifindex.
    unique_oid_indexes = {
        t[1] for t in ip_ad_ent_addrs + ip_ad_ent_masks + ip_ad_ent_ifindexes
    }

    ip_ad_ents = [
        [
            ip_ad_ent_val
            for ip_ad_ent_val, ip_ad_ent_oid in ip_ad_ent_addrs
            + ip_ad_ent_masks
            + ip_ad_ent_ifindexes
            if ip_ad_ent_oid == oid_index
        ]
        for oid_index in unique_oid_indexes
    ]

    for ip_ad_ent_addr, ip_ad_ent_mask, ip_ad_ent_ifindex in ip_ad_ents:

        # Ignore link-local IPv4 addresses and addresses on
        # administratively disabled interfaces.
        if (
            ip_address(ip_ad_ent_addr).is_link_local
            or ip_ad_ent_ifindex in disabled_ints
        ):
            continue

        ipv4_data_item = {
            "ip": ip_ad_ent_addr,
            "sm": ip_ad_ent_mask,
            "ifindex": ip_ad_ent_ifindex,
            "type": "inet",
        }

        if ipv4_data_item not in ipv4_data_list:
            ipv4_data_list.append(ipv4_data_item)

    return ipv4_data_list


def ipv4_data_4293(
    ipv4_prefixes: Any, disabled_ints: list[str]
) -> list[Dict[str, str]]:
    """Finds the interfaces IPv4 addresses and related info.

    Processes data from RFC4293 IP-MIB.

    Args:
        ipv4_prefixes (easysnmp.variables.SNMPVariableList): List of
            objects containing IPv4 address, netmask and ifindex
            information.

        disabled_ints: List of ifindexes which are
            administratively disabled.

    Returns:
        ipv4_data_list: A list of dicts containing IPv4 address,
            its netmask, ifindex of the interface where the IPv4 address
            is configured and IP type.
    """

    ipv4_data_list = []

    for ipv4_prefix in ipv4_prefixes:

        # Example 'ipv4_prefix.value':
        # ipAddressPrefixOrigin.9.1.4.192.0.2.0.30
        # The field after the 'ipAddressPrefixOrigin' is ifIndex(9).
        # After the IfIndex field is protocol family(IPv4, 1). Last
        # field is subnet mask. /30 in this example.

        try:
            # Last 4 fields of OID is IPv4 address.
            addr = IPv4Address(
                ".".join(ipv4_prefix.oid_index.split(".")[-4:])
            ).compressed
        except ValueError:
            continue

        try:
            prefixlen = str(
                IPv4Network(
                    f'0.0.0.0/{ipv4_prefix.value.split(".")[-1]}'
                ).prefixlen
            )
        except ValueError:
            continue

        try:
            ifindex = str(int(ipv4_prefix.value.split(".")[1]))
        except ValueError:
            continue

        if ip_address(addr).is_link_local or ifindex in disabled_ints:
            continue

        ipv4_data_item = {
            "ip": addr,
            "sm": prefixlen,
            "ifindex": ifindex,
            "type": "inet",
        }

        if ipv4_data_item not in ipv4_data_list:
            ipv4_data_list.append(ipv4_data_item)

    return ipv4_data_list


def ipv6_data(
    ipv6_prefixes: Any, disabled_ints: list[str]
) -> list[Dict[str, str]]:
    """Finds the interfaces IPv6 addresses and related info.

    Processes data from RFC4293 IP-MIB.

    Args:
        ipv6_prefixes (easysnmp.variables.SNMPVariableList): List of
            objects containing IPv6 address, netmask and ifindex
            information.

        disabled_ints: List of ifindexes which are
            administratively disabled.

    Returns:
        ipv6_data_list: A list of dicts containing IPv6 address,
            its netmask, ifindex of the interface where the IPv6 address
            is configured and IP type.
    """

    ipv6_data_list = []

    for ipv6_prefix in ipv6_prefixes:

        # Example 'ipv6_prefix.value':
        # ipAddressPrefixOrigin.11.2.16.42.1.0.128.1.35.0.0.0.0.0.0.0.0.1.18.12
        try:
            # Last 16 fields of OID are IPv6 address.
            addr_hex = "".join(
                f"{int(d):02x}" for d in ipv6_prefix.oid_index.split(".")[-16:]
            )
            addr = ip_address(int(addr_hex, 16)).compressed
        except ValueError:
            continue

        try:
            prefixlen = str(
                IPv6Network(f'::/{ipv6_prefix.value.split(".")[-1]}').prefixlen
            )
        except ValueError:
            continue

        try:
            # Make sure, that ifindex is an int.
            ifindex = str(int(ipv6_prefix.value.split(".")[1]))
        except ValueError:
            continue

        if ip_address(addr).is_link_local or ifindex in disabled_ints:
            continue

        if not ip_address(addr).is_link_local:
            ipv6_data_item = {
                "ip": addr,
                "sm": prefixlen,
                "ifindex": ifindex,
                "type": "inet6",
            }

            if ipv6_data_item not in ipv6_data_list:
                ipv6_data_list.append(ipv6_data_item)

    return ipv6_data_list


def int_data(
    ports: dict[str, str],
    ip_data_list: list[Dict[str, str]],
    ipv4_addr_macs: Any,
    ipv6_addr_origins: Any,
) -> "RTRdata":
    """Finds the interfaces IP addresses and related info.

    Args:
        ports: Ifindex and port name mappings.

        ip_data_list: A list of dicts containing IP address,
            its netmask, ifindex of the interface where the IP
            address is configured and IP type.

        ipv4_addr_macs (easysnmp.variables.SNMPVariableList): List of
            objects containing IPv4 and MAC addresses mappings.
            Essentially, the ARP table.

        ipv6_addr_origins (easysnmp.variables.SNMPVariableList): List of
            objects containing IPv6 addresses and their origin mappings.

    Returns:
        int_and_vrrp_data_list: A list of dicts containing IP
            address associated with the interface name, netmask,
            IP address type, etc.
    """

    int_and_vrrp_data_list: "RTRdata" = []

    for ip_data_item in ip_data_list:

        ifindex = ip_data_item["ifindex"]
        addr = ip_data_item["ip"]
        netmask = ip_data_item["sm"]
        ip_type = ip_data_item["type"]
        port_name = ports[ifindex]

        is_vrrp = False
        if ip_type == "inet":

            # Detect if the IPv4 address is a VRRP VIP
            # using the ARP table entries.
            #
            # MAC address is formatted differently depending on
            # the MIB used. In case of RFC1213-MIB, the six bytes
            # of the MAC address are separated with space characters
            # and upper case letters are used. Value type is octet
            # string. Example: '"00 00 5E 00 01 7A "'. In case of
            # IP-MIB, the bytes of the MAC address are separated with
            # colon character, lower case letters are used and leading
            # zeros are stripped. Value type is string. Example:
            # '0:0:5e:0:1:7a'. Both formats are supported.
            for ipv4_addr_mac in ipv4_addr_macs:
                # Three most significant bytes of the VRRP virtual
                # router MAC address are 00:00:5e.
                if (
                    ipv4_addr_mac.oid_index.split(".")[0] == ifindex
                    and ".".join(ipv4_addr_mac.oid_index.split(".")[1:])
                    == addr
                    and ipv4_addr_mac.value.startswith(("0:0:5e", '"00 00 5E'))
                ):

                    is_vrrp = True
                    netmask = "32"

        elif ip_type == "inet6":

            # Detect if the IPv6 address is a VRRP VIP.
            for ipv6_addr_origin in ipv6_addr_origins:

                # Example 'ipv6_addr_origin.oid_index':
                # 2.16.42.1.0.128.1.34.0.0.0.0.0.0.0.0.0.3
                try:
                    # Last 16 fields of OID are IPv6 address.
                    ipv6_addr_hex = "".join(
                        f"{int(d):02x}"
                        for d in ipv6_addr_origin.oid_index.split(".")[-16:]
                    )
                    ipv6_addr = ip_address(int(ipv6_addr_hex, 16)).compressed
                except ValueError:
                    continue

                if addr == ipv6_addr and ipv6_addr_origin.value == "other":
                    is_vrrp = True
                    netmask = "128"

        if is_vrrp:
            logger.debug(f"Found VRRP VIP {addr} on {port_name}")
        else:
            logger.debug(f"Found {addr}/{netmask} on {port_name}")

        int_and_vrrp_data_list.append(
            {
                "int": port_name,
                "is_vrrp": is_vrrp,
                "type": ip_type,
                "ip": addr,
                "sm": netmask,
                "peer_as": "",
            }
        )

    return int_and_vrrp_data_list


def bgp_neigh_data(
    ports: dict[str, str],
    ip_data_list: list[Dict[str, str]],
    ipv4_as_numbers: Any,
    all_as_numbers: Any,
) -> "RTRdata":
    """Finds the BGP neighbors addresses and related info.

    Finds the BGP IPv4 and IPv6 neighbors which are from
    one of the networks found on router interfaces.

    Args:
        ports: Ifindex and port name mappings.

        ip_data_list: A list of dicts containing IP address,
            its netmask, ifindex of the interface where the
            IP address is configured and IP type.

        ipv4_as_numbers (easysnmp.variables.SNMPVariableList): List of
            objects containing 16 bit AS numbers and BGP IPv4 neighbors
            mappings.

        all_as_numbers (easysnmp.variables.SNMPVariableList): List of
            objects containing 16/32 bit AS numbers and IPv4/IPv6
            neighbors mappings.

    Returns:
        bgp_neigh_data_list: A list of dicts containing BGP neighbor
            associated with the interface name, AS number, IP address
            type, etc.
    """

    bgp_neigh_data_list = []

    for ip_data_item in ip_data_list:

        ifindex = ip_data_item["ifindex"]
        ip_network = f'{ip_data_item["ip"]}/{ip_data_item["sm"]}'

        for as_number_item in ipv4_as_numbers + all_as_numbers:

            if len(as_number_item.oid_index.split(".")) < 16:
                # IPv4 neighbor.
                try:
                    # Last 4 fields of OID are neigh IPv4 address.
                    neigh_ip = IPv4Address(
                        ".".join(as_number_item.oid_index.split(".")[-4:])
                    ).compressed
                except ValueError:
                    continue

            elif len(as_number_item.oid_index.split(".")) >= 16:
                # IPv6 neighbor.
                try:
                    # Last 16 fields of OID are neigh IPv6 address.
                    neigh_ip_hex = "".join(
                        f"{int(d):02x}"
                        for d in as_number_item.oid_index.split(".")[-16:]
                    )
                    neigh_ip = ip_address(int(neigh_ip_hex, 16)).compressed
                except ValueError:
                    continue

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

            port_name = ports.get(ifindex)

            # Proceed if the BGP neighbor is from a network configured
            # on interface and the name of this interface is known. In
            # addition, sanity check the ASN. For example, on IOS XE
            # version 17.03.03 'bgpPeerRemoteAs' returns a negative
            # value if the IPv4 neighbor ASN is a 32-bit one.
            if (
                net_found
                and port_name
                and 0 <= int(as_number_item.value) <= 2**32
            ):

                bgp_neigh_data_item = {
                    "int": port_name,
                    "is_vrrp": False,
                    "type": ip_data_item["type"],
                    "ip": neigh_ip,
                    "sm": ip_data_item["sm"],
                    "peer_as": as_number_item.value,
                }

                if bgp_neigh_data_item not in bgp_neigh_data_list:
                    logger.debug(
                        f"Found BGP neigh address {neigh_ip} "
                        f"(ASN {as_number_item.value})"
                    )
                    bgp_neigh_data_list.append(bgp_neigh_data_item)

    return bgp_neigh_data_list


def get_c_data(
    overrides: list["Overrides"], community: str, cisco: str, lock: Lock
) -> "RTRdata":
    """Finds the IP addresses and related info from Cisco device.

    Finds the IPv4 and IPv6 addresses configured either on interfaces
    or as a VRRP VIP addresses in Cisco device. In addition, BGP
    neighbors addresses are found. Addresses are associated with network
    interfaces.
    SNMP is used for gathering the data from the router. As an
    alternative, NETCONF or even REST API could be used if there
    is no need to support the older hardware.

    Args:
        overrides: A list of NamedTuples containing info from
            the overrides file.

        community: SNMP community for the Cisco router.

        cisco: Name of the the Cisco router.

        lock: Lock in unlocked state.

    Returns:
        c_data_list: A list of dicts containing interface name
            associated with the IP address, router name, IP address
            type, etc.
    """

    c_data_list: "RTRdata" = []

    cisco_ip = None
    for override in overrides:
        if override.value_type == "cname" and override.name == cisco:
            cisco_ip = override.router_ip

    if cisco_ip is not None:
        cisco_host = cisco_ip
    else:
        cisco_host = cisco

    try:

        # In case the connection has to be sourced from a specific
        # address, then one can specify the source IP with "clientaddr"
        # directive in snmp.conf.
        session = Session(
            hostname=cisco_host,
            community=community,
            version=2,
            use_sprint_value=True,
        )

        int_names = session.bulkwalk("ifDescr")
        int_adm_statuses = session.bulkwalk("ifAdminStatus")

        # IP-MIB / RFC2011 (obsolete)
        # Does not support IPv6, but seems to work both on old
        # and latest IOS releases.
        ipv4_addresses = session.bulkwalk("ipAdEntAddr")
        ipv4_netmasks = session.bulkwalk("ipAdEntNetMask")
        ipv4_ifindexes = session.bulkwalk("ipAdEntIfIndex")

        # IP-MIB / RFC4293
        # Supports IPv6 addresses. Not supported on older IOS releases.
        # https://github.com/kamakazikamikaze/easysnmp/issues/123
        ipv4_prefixes = session.bulkwalk(("ipAddressPrefix", 1))
        ipv6_prefixes = session.bulkwalk(("ipAddressPrefix", 2))

        # VRRPv3 supports IPv6 besides IPv4. However, according to Cisco
        # "VRRPv3 Protocol Support" documentation, "VRRPv3 for IPv6
        # requires that a primary virtual link-local IPv6 address is
        # configured to allow the group to operate. After the primary
        # link-local IPv6 address is established on the group, you
        # can add the secondary global addresses". Example on
        # Cisco IOS XR 17.03.03:
        #
        # r(config)#int gi7.122
        # r(config-subif)#vrrp 122 address-family ipv6
        # r(config-if-vrrp)#address 2001:DB8:122::1 ?
        # primary  Primary Address
        #
        # r(config-if-vrrp)#address 2001:DB8:122::1 primary
        # % You must specify a prefix for a non link-local address.
        # r(config-if-vrrp)#address 2001:DB8:122::1/48 ?
        # <cr>  <cr>
        #
        # r(config-if-vrrp)#address 2001:DB8:122::1/48
        # r(config-if-vrrp)#
        #
        # As seen above, only the link-local IPv6 address can be a
        # primary address. The problem is, that VRRPv3 operations OID
        # '1.3.6.1.2.1.207.1.1.1'(VRRPV3-MIB, RFC6527) returns only
        # the primary addresses. Secondary VIPs are not shown under
        # the VRRPv3 operations OID. This means that it is not possible
        # to determine whether an IP address found with
        # 'ipAddressPrefix' is a VRRP VIP or not using the VRRPv3
        # operations OID.
        #
        # Following hacky workarounds are used:
        #
        # Every IPv6 address listed under 'ipAddressPrefix.ipv6'
        # is checked against 'ipAddressOrigin.ipv6'. For VRRP IPv6 VIPs
        # the address origin seems to be 'other'. Details can be found
        # in the RFC4293 searching for 'IpAddressOriginTC'.
        #
        # At least in IOS XR 17.03.03, the IPv4 VIPs listed under
        # 'ipAddressOrigin.ipv4' are 'manual'. This means that the
        # method used for IPv6 addresses does not work. Instead,
        # every IPv4 address listed under 'ipAddressOrigin.ipv4'
        # is checked against 'ipNetToMediaPhysAddress' and if the
        # first three most significant octets are '0:0:5e', then
        # it's a VRRP VIP.
        #
        # This is a good example how broken/inconsistent the SNMP
        # interface can be.
        #
        ipv6_addr_origins = session.bulkwalk(("ipAddressOrigin", 2))
        ipv4_addr_macs = session.bulkwalk("ipNetToMediaPhysAddress")

        # VRRP-MIB / RFC2787
        # If the VRRP2 is enabled instead of VRRP3, then
        # the 'vrrpAssoIpAddrRowStatus' lists the
        # primary IPv4 VIP and all the secondary
        # VIPs.
        # However, there is no point to use it as ARP
        # table method described above works both in
        # case of VRRPv2(monolith configuration) and
        # VRRPv3("fhrp version vrrp v3" config).
        # ipv4_vips = session.bulkwalk('vrrpAssoIpAddrRowStatus')

        # BGP4-MIB / RFC4273
        # Does not support IPv6 neighbors and 32-bit AS numbers.
        # For example, on IOS XE version 17.03.03 'bgpPeerRemoteAs'
        # simply ignores the IPv6 neighbors and returns a negative
        # value if the IPv4 neighbor ASN is a 32-bit one.
        ipv4_as_numbers = session.bulkwalk("bgpPeerRemoteAs")

        # CISCO-BGP4-MIB
        # Supports both IPv4 and IPv6 neighbors and
        # both 16-bit and 32-bit AS numbers. However, it
        # does not seem to be supported on older IOS releases.
        # For example, IOS 12.3(15a) running on 7200 series router
        # supports 'bgpPeerRemoteAs' while does not support
        # 'cbgpPeer2RemoteAs'.
        all_as_numbers = session.bulkwalk("cbgpPeer2RemoteAs")

    except EasySNMPError as err:
        logger.error(f"{cisco}: SNMP error: {err!r}")
        return c_data_list
    # https://github.com/easysnmp/easysnmp/issues/108
    except SystemError as err:
        logger.error(f"{cisco}: Device unreachable?: {err!r}")
        return c_data_list

    with lock:
        if cisco_ip is not None:
            logger.info(
                f"Established SNMP session to {cisco} "
                f"using address {cisco_ip}"
            )
        else:
            logger.info(f"Established SNMP session to {cisco}")

        # List of interface ifindexes(str type)
        # which are administratively shutdown.
        disabled_ints = [
            int_adm_status.oid_index
            for int_adm_status in int_adm_statuses
            if int_adm_status.value == "down"
        ]

        # Dict with ifindex and port name mappings.
        ports = {int_name.oid_index: int_name.value for int_name in int_names}

        try:

            # Both the obsolete RFC2011 IP-MIB and current, RFC4293
            # IP-MIB return essentially the same data for IPv4, but
            # present it in a different way.
            ipv4_data_list_2011 = ipv4_data_2011(
                ipv4_addresses, ipv4_netmasks, ipv4_ifindexes, disabled_ints
            )

            ipv4_data_list_4293 = ipv4_data_4293(ipv4_prefixes, disabled_ints)

            # Combine the IPv4 addresses related data from
            # obsolete RFC2011 IP-MIB and current RFC4293
            # IP-MIB without duplicates.
            ipv4_data_list = ipv4_data_list_2011 + [
                d for d in ipv4_data_list_4293 if d not in ipv4_data_list_2011
            ]

            ipv6_data_list = ipv6_data(ipv6_prefixes, disabled_ints)
        except ValueError as err:
            logger.error(f"{cisco}: {err!r}")
            return c_data_list

        # Combine the IPv4 addresses and IPv6 addresses lists.
        ip_data_list = ipv4_data_list + ipv6_data_list

        int_and_vrrp_data_list = int_data(
            ports, ip_data_list, ipv4_addr_macs, ipv6_addr_origins
        )
        bgp_neigh_data_list = bgp_neigh_data(
            ports, ip_data_list, ipv4_as_numbers, all_as_numbers
        )

        # Add the router name to each dict and extend the c_data_list.
        c_data_list.extend(
            [
                {**data_item, "source": cisco}
                for data_item in int_and_vrrp_data_list + bgp_neigh_data_list
            ]
        )

        return c_data_list
