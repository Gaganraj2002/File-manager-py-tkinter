# udp_server.py
import socket

bind_host = '127.0.0.1'
bind_port = 7210

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_host, bind_port))

meta_data, addr = sock.recvfrom(4096)
meta_ack = sock.sendto('meta_ack'.encode(), (addr[0], addr[1]))
data = b""
meta_data = meta_data.decode()

print(meta_data, addr[0], ':', addr[1])

for i in range(int(meta_data.split()[0])-1):
    text, addr = sock.recvfrom(4096)
    data += text
    nBytes = sock.sendto('ack'.encode(), (addr[0], addr[1]))
    print(i)
nBytes = sock.sendto('ack'.encode(), (addr[0], addr[1]))

print(len(data))

fname = "test_"+meta_data.split()[-1]
with open(fname, 'wb') as t:
    t.write(data)
print(f"{fname} file is received")
