from tkinter import *
from tkinter import ttk, simpledialog, filedialog, messagebox as mb
import os
import shutil
import pickle
from datetime import datetime, timedelta
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


class LoginWindow():
    def __init__(self, parent):
        self.window = parent
        self.window.geometry("1200x400")
        self.window.title("Log in")
        self.main_frame = Frame(self.window)
        self.main_frame.place(relx=0, rely=0,
                              relheight=1, relwidth=1)
        self.username = StringVar()
        self.password = StringVar()
        self.create_widgets(self.main_frame)
        self.place_widgets()
        self.data = self.get_user_data()
        self.current_user_details = []

    def create_widgets(self, top):
        self.label = Label(top, text='User Login')
        self.login_btn = Button(top, text='Login')
        self.login_btn['command'] = self.login_user
        self.reg_btn = Button(top, text='Register')
        self.reg_btn['command'] = self.register_user_clicked
        self.user_lbl = Label(top, text='Username:')
        self.user_ent = Entry(top, textvariable=self.username)
        self.pwd_lbl = Label(top, text='Password:')
        self.pwd_ent = Entry(top, textvariable=self.password, show="*")

    def place_widgets(self):
        self.login_btn.place(relx=0.45, rely=0.5)
        self.reg_btn.place(relx=0.45, rely=0.6)
        self.user_lbl.place(relx=0.35, rely=0.2)
        self.user_ent.place(relx=0.45, rely=0.2)
        self.pwd_lbl.place(relx=0.35, rely=0.3)
        self.pwd_ent.place(relx=0.45, rely=0.3)
        self.label.place(relx=0.45, rely=0.01)

    def get_user_data(self):
        try:
            with open('userData.pickle', 'rb') as handle:
                b = pickle.load(handle)
            return b
        except Exception:
            return {"admin": ["admin", "admin"]}

    def register_user_clicked(self):
        self.forget_all()
        global app, root
        app = UserRegistrationWindow(root)

    def login_user(self):
        uname = self.username.get()
        pwd = self.password.get()
        if uname in self.data and pwd == self.data[uname][0]:
            self.forget_all()
            self.current_user_details = [uname, self.data[uname][1]]
            global app, root
            app = Main_GUI(root, self.current_user_details)
        else:
            mb.showinfo("Error Login", "Incorrect username or password")

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


class UserRegistrationWindow():
    def __init__(self, parent):
        self.window = parent
        self.window.geometry("1200x400")
        self.window.title("Registration")
        self.main_frame = Frame(self.window)
        self.main_frame.place(relx=0, rely=0,
                              relheight=1, relwidth=1)
        self.reg_frame = Frame(self.main_frame)
        self.username = StringVar()
        self.password = StringVar()
        self.admin_username = StringVar()
        self.admin_password = StringVar()
        self.user_data = self.get_user_data()
        self.create_widgets_reg(self.reg_frame)
        self.place_widgets_reg()
        self.create_widgets_admin(self.main_frame)
        self.place_widgets_admin()

    def create_widgets_admin(self, top):
        self.admin_label = Label(top, text='Admin login')
        self.admin_login_btn = Button(top, text='login')
        self.admin_login_btn['command'] = self.admin_login
        self.login_screen_btn = Button(top, text='existing user?')
        self.login_screen_btn['command'] = self.existing_user_clicked
        self.admin_user_lbl = Label(top, text='Username:')
        self.admin_user_ent = Entry(top, textvariable=self.admin_username)
        self.admin_pwd_lbl = Label(top, text='Password:')
        self.admin_pwd_ent = Entry(
            top, textvariable=self.admin_password, show="*")

    def place_widgets_admin(self):
        self.admin_label.place(relx=0.45, rely=0)
        self.login_screen_btn.place(relx=0.9, rely=0.1)
        self.admin_login_btn.place(relx=0.8, rely=0.1)
        self.admin_user_ent.place(relx=0.2, rely=0.1)
        self.admin_user_lbl.place(relx=0.1, rely=0.1)
        self.admin_pwd_ent.place(relx=0.6, rely=0.1)
        self.admin_pwd_lbl.place(relx=0.5, rely=0.1)

    def create_widgets_reg(self, top):
        self.login_btn = Button(top, text='Register')
        self.login_btn['command'] = self.register_user
        self.user_lbl = Label(top, text='Username:')
        self.user_ent = Entry(top, textvariable=self.username)
        self.pwd_lbl = Label(top, text='Password:')
        self.pwd_ent = Entry(top, textvariable=self.password, show="*")
        self.user_type_lbl = Label(top, text='User type:')
        self.user_type_cb = ttk.Combobox(top, values=["admin", "standard"])
        self.user_type_cb.current(1)

    def place_widgets_reg(self):
        self.user_type_cb.place(relx=0.45, rely=0.4)
        self.user_type_lbl.place(relx=0.35, rely=0.4)
        self.login_btn.place(relx=0.45, rely=0.5)
        self.user_lbl.place(relx=0.35, rely=0.2)
        self.user_ent.place(relx=0.45, rely=0.2)
        self.pwd_lbl.place(relx=0.35, rely=0.3)
        self.pwd_ent.place(relx=0.45, rely=0.3)

    def admin_login(self):
        if self.admin_login_btn.cget('text') == "login":
            user = self.admin_username.get().strip().lower()
            pwd = self.admin_password.get()
            if user in self.user_data and pwd == self.user_data[user][0] and self.user_data[user][1] == "admin":
                self.reg_frame.place(
                    relx=0, rely=0.2, relwidth=1, relheight=0.8)
                self.admin_login_btn.config(text="logout")
            else:
                mb.showinfo("Error Login", "Incorrect username or password")
        else:
            self.reg_frame.place_forget()
            self.admin_login_btn.config(text="login")

    def existing_user_clicked(self):
        self.forget_all()
        app = LoginWindow(root)

    def register_user(self):
        uname = self.username.get().strip().lower()
        pwd = self.password.get().strip()
        account_type = self.user_type_cb.get().strip()
        self.user_data[uname] = [pwd, account_type]
        self.save_user_data()
        self.forget_all()
        app = LoginWindow(root)

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

    def get_user_data(self):
        try:
            with open('userData.pickle', 'rb') as handle:
                b = pickle.load(handle)
            return b
        except Exception:
            return {"admin": ["admin", "admin"]}

    def save_user_data(self):
        with open('userData.pickle', 'wb') as handle:
            pickle.dump(self.user_data, handle,
                        protocol=pickle.HIGHEST_PROTOCOL)


class Main_GUI():
    def __init__(self, parent, details):
        self.window = parent
        self.window.geometry("1200x400")
        self.window.title("File Manager")
        self.details = details
        self.current_usr = details[0]
        self.current_usr_type = details[1]
        text_user = f"user:{self.current_usr}\ntype:{self.current_usr_type}"
        self.main_frame = Frame(self.window)
        self.main_frame.place(relx=0, rely=0,
                              relheight=0.6, relwidth=1)
        self.usr_lbl = Label(self.window, text=text_user)
        self.usr_lbl.place(relx=0.85, rely=0.01)
        self.copy_move_frame(self.main_frame)
        self.sharing_main_frame(self.main_frame)
        self.sensitiveFiles = self.get_sensitive_files()
        if self.current_usr_type == "admin":
            self.admin_panel = Frame(self.window)
            self.admin_panel.place(relx=0, rely=0.6,
                                   relheight=0.4, relwidth=1)
            self.admin_panel_create(self.admin_panel)
            self.show_sensitive()
        self.create_btns(self.main_frame)
        self.check_delete()

    def open_file(self):
        string = filedialog.askopenfilename()
        try:
            os.startfile(string)
            mb.showinfo('confirmation', "File opened successfully!")
        except:
            mb.showinfo('confirmation', "File not found!")

    def delete_file(self):
        del_file = filedialog.askopenfilename()
        if os.path.exists(del_file):
            os.remove(del_file)
            mb.showinfo('confirmation', "File deleted successfully!")
        else:
            mb.showinfo('confirmation', "File not found !")

    def rename_file(self):
        chosenFile = filedialog.askopenfilename()
        path1 = os.path.dirname(chosenFile)
        extension = os.path.splitext(chosenFile)[1]
        newName = simpledialog.askstring(
            title="File Name", prompt="Enter new name for the chosen file")
        try:
            path = os.path.join(path1, newName+extension)
            print(path)
            os.rename(chosenFile, path)
            mb.showinfo('confirmation', "File Renamed !")
        except Exception as e:
            message_text = "file not renamed !\n"+str(e)
            mb.showinfo('Error', message_text)

    def copy_move(self):
        if self.sharing_frame.winfo_manager():
            self.sharing_frame.place_forget()
        self.cp_mv_frame.place_forget() if self.cp_mv_frame.winfo_manager(
        ) else self.cp_mv_frame.place(relx=0.5, rely=0.5, relheight=0.4, relwidth=0.5)

    def create_folder(self):
        newFolderPath = filedialog.askdirectory()
        print("Enter name of new folder")
        newFolder = simpledialog.askstring(
            title="Folder Name", prompt="Enter new name for the folder")
        try:
            path = os.path.join(newFolderPath, newFolder)
            os.mkdir(path)
            mb.showinfo('confirmation', "Folder created !")
        except Exception as e:
            message_text = "Folder not Deleted !\n"+str(e)
            mb.showinfo('Error', message_text)

    def delete_folder(self):
        delFolder = filedialog.askdirectory()
        try:
            os.rmdir(delFolder)
            mb.showinfo('confirmation', "Folder Deleted !")
        except Exception as e:
            message_text = "Folder not Deleted !\n"+str(e)
            mb.showinfo('Error', message_text)

    def rename_folder(self):
        chosenFile = filedialog.askdirectory()
        path1 = os.path.dirname(chosenFile)
        newName = simpledialog.askstring(
            title="File Name", prompt="Enter new name for the chosen folder")
        try:
            path = os.path.join(path1, newName)
            print(path)
            os.rename(chosenFile, path)
            mb.showinfo('confirmation', "File Renamed !")
        except Exception as e:
            message_text = "Folder not renamed !\n"+str(e)
            mb.showinfo('Error', message_text)

    def create_btns(self, top):
        self.open_file_btn = ttk.Button(top, text='Open file')
        self.open_file_btn['command'] = self.open_file
        self.delete_file_btn = ttk.Button(top, text='Delete file')
        self.delete_file_btn['command'] = self.delete_file
        self.rename_file_btn = ttk.Button(top, text='Rename file')
        self.rename_file_btn['command'] = self.rename_file
        self.copy_move_btn = ttk.Button(top, text='Copy/Move file')
        self.copy_move_btn['command'] = self.copy_move
        self.create_folder_btn = ttk.Button(top, text='Create folder')
        self.create_folder_btn['command'] = self.create_folder
        self.delete_folder_btn = ttk.Button(top, text='Delete folder')
        self.delete_folder_btn['command'] = self.delete_folder
        self.rename_folder_btn = ttk.Button(top, text='Rename Folder')
        self.rename_folder_btn['command'] = self.rename_folder
        self.exit_btn = ttk.Button(top, text='Exit')
        self.exit_btn['command'] = exit
        self.share_file = ttk.Button(top, text="Share files")
        self.share_file['command'] = self.sharing_frame_clicked
        self.logout_btn = ttk.Button(top, text="logout")
        self.logout_btn['command'] = self.logout
        self.place_btns()

    def sharing_main_frame(self, top):
        self.sharing_frame = Frame(top)
        self.receive_btn = ttk.Button(self.sharing_frame, text='Receive')
        self.send_btn = ttk.Button(self.sharing_frame, text='Send')
        self.receive_btn['command'] = self.file_receiving_frame
        self.send_btn['command'] = self.file_sending_frame
        self.cancel_sf_btn = ttk.Button(self.sharing_frame, text='Cancel')
        self.cancel_sf_btn['command'] = self.sharing_frame_clicked
        self.receive_btn.place(relx=0.1, rely=0.0)
        self.send_btn.place(relx=0.1, rely=0.3)
        self.cancel_sf_btn.place(relx=0.1, rely=0.6)

    def sharing_frame_clicked(self):
        if self.cp_mv_frame.winfo_manager():
            self.cp_mv_frame.place_forget()
        self.sharing_frame.place_forget() if self.sharing_frame.winfo_manager(
        ) else self.sharing_frame.place(relx=0.5, rely=0.5, relheight=0.4, relwidth=0.5)

    def logout(self):
        self.check_delete()
        self.forget_all()
        app = LoginWindow(root)

    def file_receiving_frame(self):
        self.check_delete()
        self.forget_all()
        app = FileSharingReceive(root, self.details)

    def file_sending_frame(self):
        self.check_delete()
        self.forget_all()
        app = FileSharingSend(root, self.details)

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

    def admin_panel_create(self, top: Frame):
        self.label = Label(top, text="Sensitive files:")
        self.label.place(relx=0.1, rely=0)
        self.listbox = Listbox(top, selectmode=SINGLE)
        self.listbox.place(relx=0.1, rely=0.2, relheight=0.7, relwidth=0.4)
        self.mark_sensitive_btn = ttk.Button(
            top, text="Mark File Sensitive", command=self.mark_sensitive)
        self.unmark_sensitive_btn = ttk.Button(
            top, text="UnMark File Sensitive", command=self.unmark_sensitive)
        self.mark_sensitive_btn.place(relx=0.55, rely=0.2)
        self.unmark_sensitive_btn.place(relx=0.55, rely=0.4)

    def get_sensitive_files(self):
        try:
            with open('adminData.pickle', 'rb') as handle:
                b = pickle.load(handle)
            return b
        except Exception:
            return dict()

    def save_sensitive_files(self):
        with open('adminData.pickle', 'wb') as handle:
            pickle.dump(self.sensitiveFiles, handle,
                        protocol=pickle.HIGHEST_PROTOCOL)

    def unmark_sensitive(self):
        fname = self.listbox.get(ACTIVE)
        print(fname)
        del self.sensitiveFiles[fname]
        self.save_sensitive_files()
        self.check_delete()

    def mark_sensitive(self):
        delete_date = (datetime.now() + timedelta(days=7)
                       ).strftime('%d/%m/%Y')
        mark_date = datetime.now().date().strftime('%d/%m/%Y')
        fname = filedialog.askopenfilename()
        if fname not in self.sensitiveFiles.keys():
            self.sensitiveFiles[fname] = {
                "marked": mark_date, "deleteOn": delete_date}
            self.save_sensitive_files()
        self.check_delete()

    def check_delete(self):
        rem_list = []
        for i, j in self.sensitiveFiles.items():
            deldate = datetime.strptime(j["deleteOn"], '%d/%m/%Y').date()
            if datetime.now().date() >= deldate:
                os.remove(i)
                rem_list.append(i)
        for i in rem_list:
            del self.sensitiveFiles[i]
        self.save_sensitive_files()
        self.show_sensitive()

    def show_sensitive(self):
        if self.current_usr_type == "admin":
            if self.sensitiveFiles != dict():
                count = 0
                self.listbox.delete(0, END)
                for i in list(self.sensitiveFiles.keys()):
                    self.listbox.insert(count, i)

    def place_btns(self):
        self.open_file_btn.place(relx=0.1, rely=0.1)
        self.delete_file_btn.place(relx=0.3, rely=0.1)
        self.rename_file_btn.place(relx=0.5, rely=0.1)
        self.copy_move_btn.place(relx=0.7, rely=0.1)
        self.create_folder_btn.place(relx=0.15, rely=0.3)
        self.delete_folder_btn.place(relx=0.35, rely=0.3)
        self.rename_folder_btn.place(relx=0.55, rely=0.3)
        self.exit_btn.place(relx=0.45, rely=0.5)
        self.logout_btn.place(relx=0.85, rely=0.2)
        self.share_file.place(relx=0.75, rely=0.3)

    def copy_move_frame(self, top):
        self.cp_mv_frame = Frame(top)
        self.copy_lbl = Label(self.cp_mv_frame, text="Select file to copy:")
        self.dest_lbl = Label(self.cp_mv_frame, text="Select destination:")
        self.cp_path = StringVar()
        self.dest_path = StringVar()
        self.copy_ent = Entry(self.cp_mv_frame, textvariable=self.cp_path)
        self.dest_ent = Entry(self.cp_mv_frame,
                              textvariable=self.dest_path)
        self.copy_brows_btn = ttk.Button(self.cp_mv_frame, text='Browse')
        self.dest_brows_btn = ttk.Button(self.cp_mv_frame, text='Browse')
        self.copy_brows_btn['command'] = self.cp_brows_clicked
        self.dest_brows_btn['command'] = self.dest_brows_clicked
        self.copy_btn = ttk.Button(self.cp_mv_frame, text='Copy')
        self.copy_btn['command'] = self.copy_file
        self.cancel_btn = ttk.Button(self.cp_mv_frame, text='Cancel')
        self.cancel_btn['command'] = self.copy_move
        self.move_btn = ttk.Button(self.cp_mv_frame, text='Move')
        self.move_btn['command'] = self.move_btn
        self.copy_lbl.place(relx=0.1, rely=0.1)
        self.dest_lbl.place(relx=0.1, rely=0.3)
        self.copy_ent.place(relx=0.3, rely=0.1)
        self.dest_ent.place(relx=0.3, rely=0.3)
        self.copy_brows_btn.place(relx=0.7, rely=0.1)
        self.dest_brows_btn.place(relx=0.7, rely=0.3)
        self.copy_btn.place(relx=0.1, rely=0.6)

    def copy_file(self):
        source1 = self.cp_path.get()
        destination1 = self.dest_path.get()
        if (source1 == destination1):
            mb.showinfo('confirmation', "Source and destination are same")
        else:
            shutil.copy(source1, destination1)
            mb.showinfo('confirmation', "File Copied !")

    def move_file(self):
        source = self.cp_path.get()
        destination = self.dest_path.get()
        if (source == destination):
            mb.showinfo('confirmation', "Source and destination are same")
        else:
            shutil.move(source, destination)
            mb.showinfo('confirmation', "File Moved !")

    def cp_brows_clicked(self):
        path = filedialog.askopenfilename()
        self.cp_path.set(path)

    def dest_brows_clicked(self):
        path = filedialog.askdirectory()
        self.dest_path.set(path)


class FileSharingSend():
    def __init__(self, parent, details):
        self.window = parent
        self.details = details
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

    def back_btn_clicked(self):
        self.forget_all()
        app = Main_GUI(root, self.details)

    def create_widgets(self, top):
        self.label = Label(top, text='File sharing:(send)')
        self.send_btn = Button(top, text='Send')
        self.send_btn['command'] = self.send_file
        self.back_btn = Button(top, text='back')
        self.back_btn['command'] = self.back_btn_clicked
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
        self.back_btn.place(relx=0.45, rely=0.65)
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
            # nameBytes = client.sendto(fname.encode(), (target_host, target_port))
            for i in frame:
                # sleep(0.1)
                nBytes = client.sendto(i, (target_host, target_port))
                text, addr = client.recvfrom(4096)
                total += nBytes
                percent = (total/len(data))*100
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
    def __init__(self, parent, details):
        self.window = parent
        self.details = details
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
        self.back_btn = Button(top, text='Back')
        self.back_btn['command'] = self.back_btn_clicked
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

    def back_btn_clicked(self):
        self.forget_all()
        app = Main_GUI(root, self.details)

    def place_widgets(self):
        self.progress.place(relx=0.1, rely=0.9, relwidth=0.8)
        self.receive_btn.place(relx=0.45, rely=0.5)
        self.back_btn.place(relx=0.45, rely=0.7)
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
    app = LoginWindow(root)
    # root.title("test")
    root.mainloop()
