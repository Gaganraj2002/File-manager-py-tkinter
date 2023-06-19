# udp_client.py
import socket
from tkinter import filedialog


def sendFileClient(host, port, fname):
    target_host = host
    target_port = port
    fname = fname  # "TEP.jpg"
    with open(fname, 'rb') as f:
        data = f.read()
    frame = []
    prev = 0
    for i in range(4096, len(data), 4096):
        frame.append(data[prev:i])
        prev = i
    frame.append(data[prev:])
    fname = fname.split("/")[-1]
    meta_data = f"{len(frame)} {fname}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        while True:
            try:
                nBytes = client.sendto(meta_data.encode(),
                                       (target_host, target_port))
                text, addr = client.recvfrom(4096)
                if text.decode() == "meta_ack":
                    break
            except TimeoutError as te:
                continue
        total, count = 0, 0
        #nameBytes = client.sendto(fname.encode(), (target_host, target_port))
        for i in frame:
            # sleep(0.1)
            nBytes = client.sendto(i, (target_host, target_port))
            text, addr = client.recvfrom(4096)
            percent = (total/len(data))*100
            total += nBytes
            print(percent, end=" ")

        print(total)


sendFileClient("127.0.0.1", 7210, "abcd.png")
