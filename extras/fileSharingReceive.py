from tkinter import *
from tkinter import simpledialog, filedialog, messagebox as mb
from tkinter import ttk
import socket
import threading


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


class FileSharingReceive():
    def __init__(self, parent):
        self.window = parent
        self.window.geometry("1200x300")
        self.window.title("Receive File")
        self.window.maxsize(1280, 800)
        self.main_frame = Frame(self.window)
        self.main_frame.place(relx=0, rely=0,
                              relheight=1, relwidth=1)
        self.receive_addr = StringVar()
        self.receive_port = StringVar()
        # self.file_name = StringVar()
        self.IPAddr = get_ip()

        self.create_widgets(self.main_frame)
        self.place_widgets()

    def create_widgets(self, top):
        self.label = Label(top, text='File sharing:(receive)')
        self.receive_btn = Button(top, text='Receive')
        self.receive_btn['command'] = self.receive_clicked
        self.address_lbl = Label(top, text='Address:')
        self.addr_lb = Label(top, textvariable=self.receive_addr)
        self.port_lbl = Label(top, text='port:')
        self.port_ent = Entry(top, textvariable=self.receive_port)
        self.label = Label(top, text="File Sharing:(Receive)")
        self.shw_address = Label(top, text=self.IPAddr)
        self.status = Label(top, text="")
        # self.file_lbl = Label(top, text='Select file:')
        # self.file_ent = Entry(top, textvariable=self.file_name)
        # self.brows_btn = Button(top, text='Browse')
        self.progress = ttk.Progressbar(top, length=100)

    def place_widgets(self):
        self.progress.place(relx=0.1, rely=0.9, relwidth=0.8)
        self.receive_btn.place(relx=0.45, rely=0.5)
        self.address_lbl.place(relx=0.35, rely=0.2)
        self.addr_lb.place(relx=0.45, rely=0.2)
        self.port_lbl.place(relx=0.35, rely=0.3)
        self.port_ent.place(relx=0.45, rely=0.3)
        self.label.place(relx=0.45, rely=0.01)
        self.shw_address.place(relx=0.45, rely=0.2)
        self.status.place(relx=0.45, rely=0.8)
        # self.file_lbl.place(relx=0.35, rely=0.5)
        # self.file_ent.place(relx=0.45, rely=0.5)
        # self.brows_btn.place(relx=0.62, rely=0.5)

    def receive_clicked(self):
        self.receive_btn["state"] = "disabled"
        self.receive_btn["text"] = "Receiving..."
        bind_host = self.IPAddr
        bind_port = self.port_ent.get()
        if bind_port.isnumeric():
            print(bind_host, bind_port)
            bind_port = int(bind_port)
            t1 = threading.Thread(target=self.receiver, args=(
                bind_host, bind_port,))
            t1.start()
        else:
            self.receive_btn["state"] = "normal"
            mb.showerror(
                "Port Error", "Port entered is not a number or its blank")

    def receiver(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        meta_data, addr = sock.recvfrom(4096)
        meta_ack = sock.sendto('meta_ack'.encode(), (addr[0], addr[1]))
        data = b""
        meta_data = meta_data.decode()
        print(meta_data, addr[0], ':', addr[1])
        for i in range(int(meta_data.split()[0])):
            text, addr = sock.recvfrom(4096)
            data += text
            nBytes = sock.sendto('ack'.encode(), (addr[0], addr[1]))
            percent = (i/(int(meta_data.split()[0])-1))*100
            self.progress["value"] = percent
        nBytes = sock.sendto('ack'.encode(), (addr[0], addr[1]))

        print(len(data))

        fname = "test_"+meta_data.split()[-1]
        with open(fname, 'wb') as t:
            t.write(data)
        print(f"{fname} file is received")
        self.receive_btn["text"] = "Receive"
        self.receive_btn["state"] = "normal"

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
    app = FileSharingReceive(root)
    root.mainloop()
