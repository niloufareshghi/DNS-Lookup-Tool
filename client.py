import socket
from random import randint
from csv import reader
import csv


def ask(name_address, udp_server):
    if udp_server in servers:
        return False, "No IP Found!"
    servers.add(udp_server)
    UDP_IP = udp_server
    UDP_PORT = 53

    header = []  # header of dns message
    header += [randint(0, 255), randint(0, 255)]  # ID
    header += [0x00, 0x00]  # flag
    header += [0x00, 0x01]  # QDcount
    header += [0x00, 0x00]  # ANcount
    header += [0x00, 0x00]  # NScount
    header += [0x00, 0x00]  # ARcount

    message = []
    message += header
    for st in name_address.split("."):
        message += [len(st)]
        message += list(st.encode('ascii'))
    message += [0x00]  # end of this name address
    message += [0x00, 0x01]  # query is A type
    message += [0x00, 0x01]  # query is class IN(internet address)

    try:
        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        sock.settimeout(3)
        sock.sendto(bytes(message), (UDP_IP, UDP_PORT))
        resp, addr = sock.recvfrom(1024)
    except:
        return False, "No IP Found!"
    finally:
        sock.close()

    QDcount = resp[4] << 8 | resp[5]
    ANcount = resp[6] << 8 | resp[7]
    NScount = resp[8] << 8 | resp[9]
    ARcount = resp[10] << 8 | resp[11]

    i = 12

    def name_skip():
        nonlocal i
        while True:
            if int(resp[i]) == 0:
                i += 1
                return
            if (int(resp[i]) & 0xc0) == 0xc0:
                i += 2
                return
            i += int(resp[i]) + 1

    for j in range(QDcount):
        name_skip()
        i += 2  # Qtypr
        i += 2  # Qclass

    def read_dns_answer():
        nonlocal i
        name_skip()
        Type = resp[i] << 8 | resp[i + 1]
        i += 2
        Class = resp[i] << 8 | resp[i + 1]
        i += 2
        i += 4  # Time to Live
        RDlength = resp[i] << 8 | resp[i + 1]
        i += 2
        return Type, Class, RDlength

    if ANcount > 0:
        read_dns_answer()
        return True, '.'.join([str(i) for i in resp[i:i + 4]])

    for j in range(NScount):
        Type, Class, RDlength = read_dns_answer()
        i += RDlength

    for j in range(ARcount):
        Type, Class, RDlength = read_dns_answer()
        if Type == 1:
            ip = '.'.join([str(i) for i in resp[i:i + 4]])
            found, ans = ask(name_address, ip)
            if found:
                return True, ans
        i += RDlength
    return False, "No IP Found!"


servers = set()
count = dict()
cache = dict()
out = open('output.csv', 'w')
csv_writer = csv.writer(out, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

with open('input.csv', 'r') as reader_obj:
    csv_reader = reader(reader_obj)
    header = next(csv_reader)
    if header != None:
        for row in csv_reader:
            na = "".join(row)
            servers.clear()
            if na not in count:
                count[na] = 0
            count[na] += 1
            if count[na] >= 3:
                print("finding " + na)
                csv_writer.writerow([cache[na]])
            else:
                print("finding " + na)
                found, ans = ask(na, "a.root-servers.net")
                cache[na] = ans
                csv_writer.writerow([ans])
