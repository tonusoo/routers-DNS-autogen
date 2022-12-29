"""Interactions with RIPE LIR Portal "My Resources" API.
"""

import logging
from typing import cast
import requests
from lxml import etree
from requests.exceptions import HTTPError, RequestException


logger = logging.getLogger(f"routers_dns_autogen.{__name__}")


def ripe_db_allocs(api_keys_list: list[str]) -> list[str]:
    """Finds the IP allocations from RIPE database.

    Requests the IPv4 and IPv6 allocations from RIPE
    database in XML using the RIPE "My Resources" API.

    Args:
        api_keys_list: A list of RIPE API keys as strings.

    Returns:
        allocations_list: A list of IPv4 and IPv6
            allocations as strings.

    Raises:
        HTTPError: An HTTP error occurred.

        RequestException: Ambiguous exception during the
            HTTP GET request.

        ValueError: Response status code of the HTTP GET
            request was not 200.

        etree.XMLSyntaxError: Syntax error while parsing
            an XML document.
    """

    allocations_list = []

    # RIPE "My Resources" API main service URL.
    api_url = "https://lirportal.ripe.net/myresources/v1/resources/"

    logger.info(
        "DNS records are made only for addresses within our "
        "allocations in RIPE db"
    )

    for ripe_api_key in api_keys_list:
        for addr_family in "ipv4", "ipv6":

            try:
                logger.info(f"Request {addr_family} allocations from RIPE db")
                response = requests.get(
                    f"{api_url}{addr_family}"
                    "/allocations?format=xml&jsonCallback=?",
                    headers={"ncc-api-authorization": ripe_api_key},
                )
                response.raise_for_status()

            except HTTPError as err:
                logger.error(f"Requests HTTP error: {err!r}")
                raise

            except RequestException as err:
                logger.error(f"Requests error: {err!r}")
                raise

            if response.status_code == 200:

                logger.info(
                    f"Successfully requested {addr_family} allocations"
                )
                try:
                    # https://lxml.de/tutorial.html describes the
                    # fromstring() function.
                    # pylint: disable-next=c-extension-no-member
                    root = etree.fromstring(response.content)
                    prefixes = root.xpath("//prefix")
                    # According to https://github.com/lxml/
                    # lxml-stubs/blob/master/lxml-stubs/etree.pyi#L43
                    # the root.xpath() can return a non-iterable like
                    # bool or float besides list. Cast to subtype:
                    # https://mypy.readthedocs.io/en/stable/
                    # type_narrowing.html#casts
                    # cast() has no runtime affect.
                    prefixes = cast(list, prefixes)
                    for prefix in prefixes:
                        # pylint: disable=protected-access
                        # pylint: disable-next=c-extension-no-member
                        prefix = cast(etree._Element, prefix)
                        # prefix.text would be None if the <prefix>
                        # element is empty.
                        if prefix.text is not None:
                            logger.debug(
                                f"Received {addr_family} "
                                f"allocation {prefix.text}"
                            )
                            allocations_list.append(prefix.text)
                # pylint: disable-next=c-extension-no-member
                except etree.XMLSyntaxError as err:
                    logger.error(f"XML parsing error: {err!r}")
                    raise
            else:
                logger.error("Requests HTTP status code was not 200(OK)")
                raise ValueError

    return allocations_list
