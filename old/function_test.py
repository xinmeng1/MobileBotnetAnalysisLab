__author__ = 'Xin'

####################################################
########## FUNCTION: change the IP/subset to IP range
########## Input: "216.239.32.0/19"
########## Return: IP range IP cmin cmax  216.239.32.0 216.239.63.255
####################################################
def subnet_mask_to_ip_range(iplist):
    data = iplist.split('/')
    ip = data[0]
    ti = int(data[1])
    d = int(ti / 8)
    c = 256 / (2 ** (ti % 8))
    ip_items = ip.split('.')
    if len(ip_items[d:]) == 1:
        if ti % 8 == 0:
            cmin = '%s.%s' % ('.'.join(ip_items[:d]), '0')
            cmax = '%s.%s' % ('.'.join(ip_items[:d]), '255')
        else:
            for i in range(2 ** (ti % 8)):
                mymax = (i + 1) * c - 1
                mymin = i * c
                data = int(''.join(ip_items[d:]))
                if data < mymax and data >= mymin:
                    cmin = '%s.%s' % ('.'.join(ip_items[:d]), mymin)
                    cmax = '%s.%s' % ('.'.join(ip_items[:d]), mymax)
    else:
        if ti % 8 == 0:
            cmin = '%s.%s.%s' % ('.'.join(ip_items[:d]), '0', ('0.' * (len(ip_items) - d - 1))[:-1])
            cmax = '%s.%s.%s' % ('.'.join(ip_items[:d]), '255', ('255.' * (len(ip_items) - d - 1))[:-1])
        else:
            for i in range(2 ** (ti % 8)):
                mymax = (i + 1) * c - 1
                mymin = i * c
                data = int(''.join(ip_items[d]))
                if data < mymax and data >= mymin:
                    cmin = '%s.%s.%s' % ('.'.join(ip_items[:d]), mymin, ('0.' * (len(ip_items) - d - 1))[:-1])
                    cmax = '%s.%s.%s' % ('.'.join(ip_items[:d]), mymax, ('255.' * (len(ip_items) - d - 1))[:-1])
    print  cmin, cmax
    return (cmin,cmax)

####################################################
########## FUNCTION: decision for whether the IP in a IP range
########## Input: IP range string "216.239.32.0/19" (string) , IP (int) to decide
########## Return: 1 in the range
##########         0 not in the range
####################################################
def in_ip_range(subnet_mask_ip,ip):
    ip_range_lower,ip_range_upper = subnet_mask_to_ip_range(subnet_mask_ip)
    int_ip_lower = ip2int(ip_range_lower)
    int_ip_upper = ip2int(ip_range_upper)
    print(int_ip_lower)
    print(int_ip_upper)
    print(ip)
    print(ip_range_lower)
    print(ip_range_upper)
    print(int2ip(ip))
    if ip <= int_ip_upper and ip >= int_ip_lower:
        return 1
    else:
        return 0

def int2ip(i):
    import socket
    import struct

    return socket.inet_ntoa(struct.pack("!I", i))

def ip2int(ip):
    import struct
    import socket

    return struct.unpack("!I", socket.inet_aton(ip))[0]

print("test:")
subnet_mask_to_ip_range("216.239.32.0/19")
result = in_ip_range("216.239.32.0/19",3639550052)
print(result)
result2 = in_ip_range("216.239.32.0/19",3639549796)
print(result2)