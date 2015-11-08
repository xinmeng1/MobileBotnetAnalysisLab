import struct
import socket

__author__ = 'Xin Meng'


####################################################
# FUNCTION: ip2int
# INPUT:    IP
# RETURN:   int of the IP
####################################################
def ip2int(ip):
    try:
        ip = struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        print "Error: illegal IP address string"
    else:
        return ip


####################################################
# FUNCTION: int2ip
# INPUT:    int of IP
# RETURN:   IP
####################################################
def int2ip(i):
    try:
        ip = socket.inet_ntoa(struct.pack("!I", i))
    except:
        print "Error: illegal IP address int"
    else:
        return ip


####################################################
# FUNCTION: change the IP/subset to IP range
# Input: "216.239.32.0/19"
# Return: IP range IP ip_min ip_max  216.239.32.0 216.239.63.255
####################################################
def subnet_mask_to_ip_range(ip_list):
    global ip_min, ip_max
    data = ip_list.split('/')
    ip = data[0]
    ti = int(data[1])
    # TODO: validate the data
    if ti >= 32:
        ti = 31
    if ti <= 0:
        ti = 1
    d = int(ti / 8)
    c = 256 / (2 ** (ti % 8))
    ip_items = ip.split('.')
    if len(ip_items[d:]) == 1:
        if ti % 8 == 0:
            ip_min = '%s.%s' % ('.'.join(ip_items[:d]), '0')
            ip_max = '%s.%s' % ('.'.join(ip_items[:d]), '255')
        else:
            for i in range(2 ** (ti % 8)):
                my_max = (i + 1) * c - 1
                my_min = i * c
                data = int(''.join(ip_items[d:]))
                if my_max > data >= my_min:
                    ip_min = '%s.%s' % ('.'.join(ip_items[:d]), my_min)
                    ip_max = '%s.%s' % ('.'.join(ip_items[:d]), my_max)
    else:
        if ti % 8 == 0:
            ip_min = '%s.%s.%s' % ('.'.join(ip_items[:d]), '0', ('0.' * (len(ip_items) - d - 1))[:-1])
            ip_max = '%s.%s.%s' % ('.'.join(ip_items[:d]), '255', ('255.' * (len(ip_items) - d - 1))[:-1])
        else:
            for i in range(2 ** (ti % 8)):
                my_max = (i + 1) * c - 1
                my_min = i * c
                data = int(''.join(ip_items[d]))
                if my_max > data >= my_min:
                    ip_min = '%s.%s.%s' % ('.'.join(ip_items[:d]), my_min, ('0.' * (len(ip_items) - d - 1))[:-1])
                    ip_max = '%s.%s.%s' % ('.'.join(ip_items[:d]), my_max, ('255.' * (len(ip_items) - d - 1))[:-1])
    # print  ip_min, ip_max
    return ip_min, ip_max


####################################################
# FUNCTION: decision for whether the IP in a IP range
# Input: IP range string "216.239.32.0/19" (string) , IP (int) to decide
# Return: 1 in the range
#         0 not in the range
####################################################
def in_ip_range(subnet_mask_ip, ip):
    ip_range_lower, ip_range_upper = subnet_mask_to_ip_range(subnet_mask_ip)
    int_ip_lower = ip2int(ip_range_lower)
    int_ip_upper = ip2int(ip_range_upper)
    # print(int_ip_lower)
    # print(int_ip_upper)
    # print(ip)
    # print(ip_range_lower)
    # print(ip_range_upper)
    # print(int2ip(ip))
    if int_ip_upper >= ip >= int_ip_lower:
        return 1
    else:
        return 0
