# Auto-generated DNS records for Juniper and Cisco routers interfaces

Generates DNS forward and reverse records for Juniper and Cisco routers interfaces. Records are pushed to DNS with DDNS([RFC2136](https://datatracker.ietf.org/doc/html/rfc2136)). One can override automatically generated records or add additional records by modifying the overrides file.

**This system is built with a specific ISP network in mind. It has several expectations ranging from network devices hostname format or authentication methods to predefined zones in DNS servers. It's almost certain that some code adjustment is needed when using it in some other network.**


### High-level overview of the script operations

* Get the latest revision of the Juniper and Cisco routers lists from the git
* Get the latest revision of the overrides file from the git
* Get LIR allocations from the RIR database
* Find the IP addresses configured in Juniper routers using NETCONF. This includes VRRP VIPs and BGP neighbors.
* Find the IP addresses configured in Cisco routers using SNMP. This includes VRRP VIPs and BGP neighbors.
* Convert interface names suitable for DNS
* Discard the entries which are not from LIR allocations
* Override the dynamically found entries with ones in the overrides file
* Add entries from the overrides file
* Commit forward and reverse records into git for debugging purposes
* Add or remove records in DNS using DDNS

Connections to network devices are executed concurrently. SNMP is used for gathering the data from the Cisco routers in order to support the older hardware.


### Installation example

```
usr@nms-svr:~$ cat /etc/issue
Debian GNU/Linux 11 \n \l

usr@nms-svr:~$ # "snmp-mibs-downloader" package requires, that "non-free" packages in "/etc/apt/sources.list" are allowed
usr@nms-svr:~$ sudo apt install python3-pip python3-venv libsnmp-dev snmp-mibs-downloader
/* output removed for brevity */
usr@nms-svr:~$ 
usr@nms-svr:~$ mkdir -p ~/.snmp/mibs && echo "mibs +ALL" >> ~/.snmp/snmp.conf
usr@nms-svr:~$ # download Cisco enterprise MIBs to ~/.snmp/mibs as it's part of the default list of MIB directories:
usr@nms-svr:~$ net-snmp-config --default-mibdirs
/home/usr/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
usr@nms-svr:~$ 
usr@nms-svr:~$ wget -qP ~/.snmp/mibs https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/CISCO-SMI.my https://raw.githubusercontent.com/cisco/cisco-mibs/main/v2/CISCO-BGP4-MIB.my
usr@nms-svr:~$ 
usr@nms-svr:~$ python3 -m venv dns-autogen
usr@nms-svr:~$ cd dns-autogen
usr@nms-svr:~/dns-autogen$ source bin/activate
(dns-autogen) usr@nms-svr:~/dns-autogen$ 
(dns-autogen) usr@nms-svr:~/dns-autogen$ pip install requests dnspython gitpython lxml junos-eznc easysnmp -q
(dns-autogen) usr@nms-svr:~/dns-autogen$ 
(dns-autogen) usr@nms-svr:~/dns-autogen$ git clone https://github.com/tonusoo/routers-DNS-autogen.git -q
(dns-autogen) usr@nms-svr:~/dns-autogen$ routers-DNS-autogen/routers_dns_autogen.py DEBUG
```

As seen above, the [routers_dns_autogen.py](https://github.com/tonusoo/routers-DNS-autogen/blob/main/routers_dns_autogen.py) can take a logging severity level as a command line argument. The rest of the configuration is in the [conf.ini](https://github.com/tonusoo/routers-DNS-autogen/blob/main/conf.ini) file. The script is meant to be run as a cron job or systemd timer, but can be manually executed from a shell or as a CGI script.


### Test environment

![routers-DNS-autogen test setup](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/test_setup.png)

[Log file](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/routers_dns_autogen_20221229_173547.log) of the run where `EE-Tll-Lab-r1` interface `ge-0/0/6.0` was administratively disabled and `test.core    fdd5:3dec:c790:99::844    1800` line was added to [overrides file](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/dns_autogen_overrides) should give a good overview of the script operations.

Example traceroute from `cpe-a` connected to `EE-Tll-Lab-r1` router interface `ge-0/0/3.0` to `cpe-b` connected to `FI-Hel-DC1-r7` router interface `GigabitEthernet3`:

```
martin@lab-svr:~$ sudo ip netns exec cpe-a traceroute cpe-b.example.net
traceroute to cpe-b.example.net (172.16.0.65), 30 hops max, 60 byte packets
 1  EE-Tll-Lab-r1-ge-0-0-3-0.example.net (172.16.0.32)  122.590 ms  122.793 ms  122.790 ms
 2  EE-Tll-Lab-r2-gi7-124.example.net (192.168.115.1)  1.392 ms  1.439 ms  1.469 ms
 3  FI-Hel-DC1-r7-gi5.example.net (172.16.2.9)  4.270 ms  4.273 ms  4.275 ms
 4  cpe-b.example.net (172.16.0.65)  1.489 ms  1.503 ms  1.508 ms
martin@lab-svr:~$ 
```

For the sake of completeness, the test setup management can be seen below:

![routers-DNS-autogen test setup management](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/test_setup_mgnt.png)

Zone definition example in `dns-svr1`:
```
root@dns-svr1:/var/lib/bind# tail /etc/bind/named.conf.local
zone "0.0.1.0.0.9.7.c.c.e.d.3.5.d.d.f.ip6.arpa" {
        type master;
        file "/var/lib/bind/fdd5-3dec-c790-100-64.rev6";
        # https://bind9.readthedocs.io/en/v9_16_5/advanced.html#tsig-based-access-control
        allow-update {
                !{ !10.5.5.101; any; };
                key ddnsupdate;
        };
        allow-transfer { 10.5.5.101; localhost; };
};
root@dns-svr1:/var/lib/bind# 
```

`user` and `class` configuration example in `EE-Tll-Lab-r1` Juniper router:

```
martint@EE-Tll-Lab-r1> show configuration system login user dns_autogen
uid 2000;
class dns_autogen;
authentication {
    encrypted-password "$6$3xd5lDb/$JAe.XK.B2Wd/..tbVCWhYhzSg/a8.CstMv6Jg.UPGanfGNSdQWxJoB8giQV6S/v1pYIhQIrOSSf33ukJMqexf/"; ## SECRET-DATA
}

martint@EE-Tll-Lab-r1> show configuration system login class dns_autogen
idle-timeout 1;
permissions view;
allow-commands "show interfaces|show vrrp summary|show bgp summary|exit|quit|xml-mode|.*netconf|.*need-trailer|.*close-session|junoscript";
deny-commands .*;

martint@EE-Tll-Lab-r1>
```


### Explanation of the overrides file

[Overrides file](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/dns_autogen_overrides) allows one to override automatically generated records or add records that were not automatically discovered. DNS autogen script gets the latest revision of the overrides file from the git and reads in the file line by line. Empty lines or lines starting with a hash character(`#`) are ignored. Fields on lines are separated with whitespace. Overrides file supports three kinds of entries:

```
<name>    <IPv4 addr>    <optional DNS TTL for this record>
<name>    <IPv6 addr>    <optional DNS TTL for this record>
<name>    <CNAME>        <optional router IPv4 addr>           <optional DNS TTL for this record>
```

The first two entries are pretty self-explanatory: add the entry if the IPv4 or IPv6 address was not automatically discovered from the routers or if the DNS autogen script did discover the IPv4 or IPv6 address from the routers, then this discovery is ignored and the entry in the overrides file is used instead. Both `A` or `AAAA` and `PTR` records are made.

The third entry type allows one to make `CNAME` records. This entry has an `<optional router IPv4 addr>` field which instructs the script to establish the NETCONF or SNMP session to this specific IPv4 address if the `<name>` field matches with the router name in the [Juniper routers](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/junipers) or [Cisco routers](https://github.com/tonusoo/routers-DNS-autogen/blob/main/docs/ciscos) files. This functionality is needed to initiate DNS autogen for new routers. Pointer record and `A` or `AAAA` record for the canonical name(e.g `EE-Tll-Lab-r1-fxp0-0`) is made by the script automatically.


## License
[GNU General Public License v3.0](https://github.com/tonusoo/routers-DNS-autogen/blob/main/LICENSE)
