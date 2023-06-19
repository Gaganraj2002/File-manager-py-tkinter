from tkinter import *
from tkinter import simpledialog, filedialog, messagebox as mb
from tkinter import ttk
import socket
import threading


class FileSharingSend():
    def __init__(self, parent):
        self.window = parent
        self.window.geometry("1200x300")
        self.window.title("Send File")
        self.window.maxsize(1280, 800)
        self.main_frame = Frame(self.window)
        self.main_frame.place(relx=0, rely=0,
                              relheight=1, relwidth=1)
        self.send_addr = StringVar()
        self.send_port = StringVar()
        self.file_name = StringVar()
        self.create_widgets(self.main_frame)
        self.place_widgets()

    def create_widgets(self, top):
        self.label = Label(top, text='File sharing:(send)')
        self.send_btn = Button(top, text='Send')
        self.send_btn['command'] = self.send_file
        self.address_lbl = Label(top, text='Address:')
        self.addr_ent = Entry(top, textvariable=self.send_addr)
        self.port_lbl = Label(top, text='port:')
        self.port_ent = Entry(top, textvariable=self.send_port)
        self.file_lbl = Label(top, text='Select file:')
        self.file_ent = Entry(top, textvariable=self.file_name)
        self.brows_btn = Button(top, text='Browse', command=self.brows)
        self.progress = ttk.Progressbar(top, length=100)

    def place_widgets(self):
        self.progress.place(relx=0.1, rely=0.9, relwidth=0.8)
        self.send_btn.place(relx=0.45, rely=0.8)
        self.address_lbl.place(relx=0.35, rely=0.2)
        self.addr_ent.place(relx=0.45, rely=0.2)
        self.port_lbl.place(relx=0.35, rely=0.3)
        self.port_ent.place(relx=0.45, rely=0.3)
        self.label.place(relx=0.45, rely=0.01)
        self.file_lbl.place(relx=0.35, rely=0.5)
        self.file_ent.place(relx=0.45, rely=0.5)
        self.brows_btn.place(relx=0.62, rely=0.5)

    def send_file(self):
        self.send_btn["state"] = "disabled"
        addr = self.send_addr.get()
        port = int(self.send_port.get())
        filename = self.file_name.get()
        t1 = threading.Thread(target=self.sendFileClient, args=(
            addr, port, filename, self.progress, self.send_btn,))
        t1.start()

    def sendFileClient(self, host, port, fname, progress: ttk.Progressbar, btn: Button):
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
        rep = ""
        for i in fname:
            if i == " ":
                rep += "_"
            else:
                rep += i
        fname = rep
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
                progress["value"] = percent
        self.send_btn["state"] = "normal"

    def brows(self):
        name = filedialog.askopenfilename()
        self.file_name.set(name)

    def all_children(self):
        _list = self.window.winfo_children()

        for item in _list:
            if item.winfo_children():
                _list.extend(item.winfo_children())

        return _list

    def forget_all(self):
        widget_list = self.all_children()
        for item in widget_list:
            try:
                item.forget_grid()
            except AttributeError:
                item.destroy()


class FileSharingReceive():
    def __init__(self, parent):
        self.window = parent
        self.window.geometry("1200x300")
        self.window.title("Send File")
        self.window.maxsize(1280, 800)
        self.main_frame = Frame(self.window)
        self.main_frame.place(relx=0, rely=0,
                              relheight=1, relwidth=1)
        self.send_addr = StringVar()
        self.send_port = StringVar()
        self.file_name = StringVar()
        self.create_widgets(self.main_frame)
        self.place_widgets()

    def create_widgets(self, top):
        self.label = Label(top, text='File sharing:(send)')
        self.send_btn = Button(top, text='Send')
        self.send_btn['command'] = self.send_file
        self.address_lbl = Label(top, text='Address:')
        self.addr_ent = Entry(top, textvariable=self.send_addr)
        self.port_lbl = Label(top, text='port:')
        self.port_ent = Entry(top, textvariable=self.send_port)
        self.file_lbl = Label(top, text='Select file:')
        self.file_ent = Entry(top, textvariable=self.file_name)
        self.brows_btn = Button(top, text='Browse', command=self.brows)
        self.progress = ttk.Progressbar(top, length=100)

    def place_widgets(self):
        self.progress.place(relx=0.1, rely=0.9, relwidth=0.8)
        self.send_btn.place(relx=0.45, rely=0.8)
        self.address_lbl.place(relx=0.35, rely=0.2)
        self.addr_ent.place(relx=0.45, rely=0.2)
        self.port_lbl.place(relx=0.35, rely=0.3)
        self.port_ent.place(relx=0.45, rely=0.3)
        self.label.place(relx=0.45, rely=0.01)
        self.file_lbl.place(relx=0.35, rely=0.5)
        self.file_ent.place(relx=0.45, rely=0.5)
        self.brows_btn.place(relx=0.62, rely=0.5)

    def send_file(self):
        self.send_btn["state"] = "disabled"
        addr = self.send_addr.get()
        port = int(self.send_port.get())
        filename = self.file_name.get()
        t1 = threading.Thread(target=self.sendFileClient, args=(
            addr, port, filename, self.progress, self.send_btn,))
        t1.start()

    def sendFileClient(self, host, port, fname, progress: ttk.Progressbar, btn: Button):
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
        rep = ""
        for i in fname:
            if i == " ":
                rep += "_"
            else:
                rep += i
        fname = rep
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
                progress["value"] = percent
        self.send_btn["state"] = "normal"

    def brows(self):
        name = filedialog.askopenfilename()
        self.file_name.set(name)

    def all_children(self):
        _list = self.window.winfo_children()

        for item in _list:
            if item.winfo_children():
                _list.extend(item.winfo_children())

        return _list

    def forget_all(self):
        widget_list = self.all_children()
        for item in widget_list:
            try:
                item.forget_grid()
            except AttributeError:
                item.destroy()


if __name__ == "__main__":
    root = Tk()
    app = FileSharingSend(root)
    root.mainloop()
