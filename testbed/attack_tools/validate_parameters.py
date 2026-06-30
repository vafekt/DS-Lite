# Generate a random IPv4 address as a string
def generate_random_ipv4():
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))
#!/usr/bin/python
import argparse
import ipaddress
import os
import random
import re

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None


def is_valid_ipv6(ip):
    """Validates IPv6 addresses using the kernel's own parser.
    Accepts all valid forms including full EUI-64 SLAAC addresses
    (e.g. 2001:db8:cafe:0:a4ba:d9ff:fe5e:6fd6) that the old regex rejected.
    """
    import socket
    try:
        socket.inet_pton(socket.AF_INET6, ip.strip())
        return True
    except (socket.error, AttributeError):
        return False


def is_valid_mac(str):
    # Regex to check valid
    # MAC address
    regex = ("^([0-9A-Fa-f]{2}[:-])" +
             "{5}([0-9A-Fa-f]{2})|" +
             "([0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4})$")
    # Compile the ReGex
    p = re.compile(regex)
    # If the string is empty
    # return false
    if (str == None):
        return False
    # Return if the string
    # matched the ReGex
    if (re.search(p, str)):
        return True
    else:
        return False


def is_valid_num(num):
    if int(num) >= 0:
        return True
    else:
        return False


def is_valid_port(port):
    if 0 <= int(port) <= 65535:
        return True
    else:
        return False


def mac2ipv6(mac):
    # only accept MACs separated by a colon
    parts = mac.split(":")

    # modify parts to match IPv6 value
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)

    # format output
    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i + 2]))
    ipv6 = "fe80::%s" % (":".join(ipv6Parts))
    return ipv6


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


def validate_file(f):
    if not os.path.exists(f):
        # Argparse uses the ArgumentTypeError to give a rejection message like:
        # error: argument input: x does not exist
        raise argparse.ArgumentTypeError("{0} does not exist".format(f))
    return f


def payload(length):
    if length == 0:
        return ''
    if length > 0:
        data = ''
        j = 97
        for i in range(length):
            if j == 120:
                j = 97
            data += (chr(j))
            j = j + 1
        return data


def get_ipv6_multicast_solicited_address(ipv6_address):
    """
    Given an IPv6 address, generate the corresponding multicast solicited address.
    """
    ipv6 = ipaddress.IPv6Address(ipv6_address)
    # The multicast solicited address prefix is ff02::1:ff00:0/104
    multicast_prefix = ipaddress.IPv6Address("ff02::1:ff00:0")
    # Extract the last 24 bits (the lower 24 bits) of the IPv6 address
    lower_bits = ipv6.packed[-3:]
    # Combine the multicast prefix with the lower 24 bits to form the multicast solicited address
    multicast_address = multicast_prefix._ip | int.from_bytes(lower_bits, "big")
    return str(ipaddress.IPv6Address(multicast_address))


def convert_mld(rtype):
    if rtype == 1:
        return "MODE_IS_INCLUDE"
    elif rtype == 2:
        return "MODE_IS_EXCLUDE"
    elif rtype == 3:
        return "CHANGE_TO_INCLUDE_MODE"
    elif rtype == 4:
        return "CHANGE_TO_EXCLUDE_MODE"
    elif rtype == 5:
        return "ALLOW_NEW_SOURCES"
    elif rtype == 6:
        return "BLOCK_OLD_SOURCES"
    else:
        return "UNKNOWN"


def convert_flag(flag):
    if flag == 1:
        return "Yes"
    if flag == 0:
        return "No"
    else:
        return "Unknown"


def convert_preference(prf):
    if prf == 1:
        return "High"
    elif prf == 0:
        return "Medium"
    elif prf == 3:
        return "Low"
    else:
        return "Reserved"


def convert_paramProblem(code):
    if code == 0:
        return "Erroneous header field encountered"
    elif code == 1:
        return "Unrecognized Next Header type encountered"
    elif code == 2:
        return "Unrecognized IPv6 option encountered"
    else:
        return "Unknown"


def convert_destUnrechable(code):
    if code == 0:
        return "No route to destination"
    elif code == 1:
        return "Communication with destination administratively prohibited"
    elif code == 2:
        return "Beyond scope of source address"
    elif code == 3:
        return "Address unreachable"
    elif code == 4:
        return "Port unreachable"
    elif code == 5:
        return "Source address failed ingress/egress policy"
    elif code == 6:
        return "Reject route to destination"
    else:
        return "Unknown"


def convert_timeExceeded(code):
    if code == 0:
        return "Hop limit exceeded in transit"
    if code == 1:
        return "Fragment reassembly time exceeded"


def convert_tcpFlags(flag):
    if flag == "U":
        return "Urgent"
    if flag == "A":
        return "Acknowledgement"
    if flag == "P":
        return "Push"
    if flag == "R":
        return "Reset"
    if flag == "S":
        return "Syn"
    if flag == "F":
        return "Fin"


def convert_solicited(addr):
    addr_full_form = addr.exploded
    addr_cut = addr_full_form[-7:]

    prefix = "ff02::1:ff"
    result = prefix + addr_cut
    result = ipaddress.ip_address(result)
    return result
