"""Processes configuration options found in INI type conf file.
"""

import logging
import configparser
from typing import NamedTuple


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


class Config(NamedTuple):
    """Configuration variables."""

    default_dns_ttl: int
    domain: str
    ns_list: list[str]
    tsig_key_name: str
    tsig_key: str
    overrides_file_name: str
    axfr_loose: bool
    api_keys_list: list[str]
    allocs_file_name: str
    juniper_username: str
    juniper_password: str
    jr_file_name: str
    cisco_snmp_community: str
    cr_file_name: str
    routerslists_url: str
    dnsautogen_url: str
    repos_dir: str


def process_cfg_options(
    config: configparser.ConfigParser,
    conf_file: str,
    script_dir: str,
) -> Config:
    """Processes configuration options.

    Args:
        config: Parsed configuration.

        conf_file: Full path of the configuration file.

        script_dir: Current working directory of the script.

    Returns:
        Config object.

    Raises:
        ValueError: Configuration option has an invalid value.

        KeyError: Mandatory configuration option is missing.
    """

    logger.info(f"Processing the conf file named {conf_file}")

    logger.info("Read the DNS related options")

    if config.has_option("dns", "default_dns_ttl"):
        try:
            default_dns_ttl = config["dns"].getint("default_dns_ttl")
        except ValueError:
            logger.error(
                'Value of the "default_dns_ttl" configuration '
                f'option under "dns" section in "{conf_file}" '
                "is not an integer."
            )
            raise
    else:
        logger.info(
            '"default_dns_ttl" configuration option under "dns" '
            f'section in "{conf_file}" is missing. Proceed with the '
            "default DNS TTL"
        )
        default_dns_ttl = 43200

    if config.has_option("dns", "domain"):
        domain = config["dns"]["domain"].rstrip(".")
    else:
        logger.error(
            '"domain" configuration option under "dns" section '
            f'in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("dns", "nameservers"):
        ns_list = [
            ns.strip() for ns in config["dns"]["nameservers"].split(",")
        ]
    else:
        logger.info(
            '"nameservers" configuration option under "dns" section '
            f'in "{conf_file}" is missing.'
        )
        ns_list = []

    if config.has_option("dns", "tsig_key_name"):
        tsig_key_name = config["dns"]["tsig_key_name"]
    else:
        logger.error(
            '"tsig_key_name" configuration option under "dns" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("dns", "tsig_key"):
        tsig_key = config["dns"]["tsig_key"]
    else:
        logger.error(
            '"tsig_key" configuration option under "dns" section '
            f'in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("dns", "overrides_file"):
        overrides_file_name = config["dns"]["overrides_file"]
    else:
        logger.error(
            '"overrides_file" configuration option under "dns" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("dns", "axfr_loose"):
        try:
            axfr_loose = config["dns"].getboolean("axfr_loose")
        except ValueError:
            logger.error(
                '"axfr_loose" configuration option under "dns" '
                f'section in "{conf_file}" has to have a value '
                'of "yes" or "no"'
            )
            raise
    else:
        logger.error(
            '"axfr_loose" configuration option under "dns" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    logger.info("Read the RIPE related options")

    if config.has_option("ripe", "api_keys"):
        logger.info("Read the RIPE API keys")
        api_keys_list = [
            k.strip() for k in config["ripe"]["api_keys"].split(",")
        ]
    else:
        logger.info(
            '"api_keys" configuration option under "ripe" section '
            f'in "{conf_file}" is missing'
        )
        api_keys_list = []

    if config.has_option("ripe", "allocs_file"):
        allocs_file_name = config["ripe"]["allocs_file"]
    else:
        logger.error(
            '"allocs_file" configuration option under "ripe" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    logger.info("Read the Junipers related options")

    if config.has_option("juniper", "username"):
        juniper_username = config["juniper"]["username"]
    else:
        logger.error(
            '"username" configuration option under "juniper" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("juniper", "password"):
        juniper_password = config["juniper"]["password"]
    else:
        logger.error(
            '"password" configuration option under "juniper" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("juniper", "routers_file"):
        jr_file_name = config["juniper"]["routers_file"]
    else:
        logger.error(
            '"routers_file" configuration option under "juniper" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    logger.info("Read the Ciscos related options")

    if config.has_option("cisco", "snmp_community"):
        cisco_snmp_community = config["cisco"]["snmp_community"]
    else:
        logger.info(
            '"snmp_community" configuration option under "cisco" '
            f'section in "{conf_file}" is missing. Proceed with '
            "the default RO community"
        )
        cisco_snmp_community = "public"

    if config.has_option("cisco", "routers_file"):
        cr_file_name = config["cisco"]["routers_file"]
    else:
        logger.error(
            '"routers_file" configuration option under "cisco" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    logger.info("Read the Git related options")

    if config.has_option("git", "routerslists_url"):
        routerslists_url = config["git"]["routerslists_url"]
    else:
        logger.error(
            '"routerslists_url" configuration option under "git" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("git", "dnsautogen_url"):
        dnsautogen_url = config["git"]["dnsautogen_url"]
    else:
        logger.error(
            '"dnsautogen_url" configuration option under "git" '
            f'section in "{conf_file}" is missing.'
        )
        raise KeyError

    if config.has_option("git", "repos_dir"):
        repos_dir = config["git"]["repos_dir"]
    else:
        logger.info(
            '"repos_dir" configuration option under "git" section '
            f'in "{conf_file}" is missing.'
        )
        repos_dir = script_dir

    return Config(
        default_dns_ttl,
        domain,
        ns_list,
        tsig_key_name,
        tsig_key,
        overrides_file_name,
        axfr_loose,
        api_keys_list,
        allocs_file_name,
        juniper_username,
        juniper_password,
        jr_file_name,
        cisco_snmp_community,
        cr_file_name,
        routerslists_url,
        dnsautogen_url,
        repos_dir,
    )
