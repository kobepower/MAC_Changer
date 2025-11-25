import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
import random
import winreg
import os
import sys
import json
import ctypes
from datetime import datetime

CONFIG_FILE = "mac_gui_config.json"
LOG_FILE = "mac_gui_history.log"

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def log_action(action):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} :: {action}\n")

def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE) as f:
        return json.load(f)

def is_valid_mac(mac):
    mac_clean = mac.replace(':', '').replace('-', '').upper()
    if len(mac_clean) != 12 or not all(c in '0123456789ABCDEF' for c in mac_clean):
        return False
    # Locally administered/unicast check
    first_octet = int(mac_clean[0:2], 16)
    return (first_octet & 0x02) != 0 and (first_octet & 0x01) == 0

def ou_lookup(mac):
    # Dummy Vendor Lookup for demo (would use external OUI data in full app)
    vendor_oui = {
        '00:1A:2B': 'DemoTech Inc.',
        '02:00:00': 'Local/Random MAC'
    }
    first3 = ':'.join(mac.split(':')[:3])
    return vendor_oui.get(first3, 'Unknown')

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)
    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         bg="#e0e0e0", relief=tk.SOLID, borderwidth=1,
                         font=("Arial", 9))
        label.pack(ipadx=1)
    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

class MACChangerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MAC Address Changer - One Click")
        self.root.geometry("900x650")
        self.root.configure(bg='#f8f8fa')

        if not is_admin():
            messagebox.showerror("Admin Required", "Please run as Administrator!")
            sys.exit(1)

        self.adapters = {}
        self.selected_adapter = None
        self.adapter_details = {}
        self.load_user_config()
        self.create_widgets()
        self.refresh_adapters()
        log_action("App Launched")

    def load_user_config(self):
        self.user_config = load_config()
        self.theme = self.user_config.get("theme", "light")

    def create_widgets(self):
        title = tk.Label(self.root, text="MAC Address Changer",
                         font=("Segoe UI", 19, "bold"), bg='#f8f8fa')
        title.pack(pady=10)

        main_frame = tk.Frame(self.root, bg='#f8f8fa')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        left_frame = tk.LabelFrame(main_frame, text="Network Adapters",
                                   font=("Segoe UI", 11, "bold"), bg='#f0f0f6')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,14))

        self.tree = ttk.Treeview(left_frame, columns=('MAC', 'Status'),
                                 show='tree headings', height=16)
        self.tree.heading('#0', text='Network Connection')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Status', text='Status')
        self.tree.column('#0', width=220)
        self.tree.column('MAC', width=160)
        self.tree.column('Status', width=110)

        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind('<<TreeviewSelect>>', self.on_adapter_select)

        right_frame = tk.Frame(main_frame, bg='#f8f8fa')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10,0))

        info_frame = tk.LabelFrame(right_frame, text="Adapter Info",
                                  font=("Segoe UI", 11, "bold"), bg='white')
        info_frame.pack(fill=tk.X, pady=(0,12))

        tk.Label(info_frame, text="Current MAC:", bg='white', font=("Segoe UI", 9)).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.current_mac_label = tk.Label(info_frame, text="--:--:--:--:--:--", bg='white', font=("Segoe UI", 9, "bold"))
        self.current_mac_label.grid(row=0, column=1, sticky='w', padx=10, pady=5)

        tk.Label(info_frame, text="Adapter Name:", bg='white', font=("Segoe UI", 9)).grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.adapter_name_label = tk.Label(info_frame, text="None Selected", bg='white', font=("Segoe UI", 9))
        self.adapter_name_label.grid(row=1, column=1, sticky='w', padx=10, pady=5)

        tk.Label(info_frame, text="IP Address:", bg='white', font=("Segoe UI", 9)).grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.adapter_ip_label = tk.Label(info_frame, text="N/A", bg='white', font=("Segoe UI", 9))
        self.adapter_ip_label.grid(row=2, column=1, sticky='w', padx=10, pady=5)

        tk.Label(info_frame, text="Vendor:", bg='white', font=("Segoe UI", 9)).grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.vendor_label = tk.Label(info_frame, text="N/A", bg='white', font=("Segoe UI", 9))
        self.vendor_label.grid(row=3, column=1, sticky='w', padx=10, pady=5)

        mac_frame = tk.LabelFrame(right_frame, text="MAC Tools",
                                  font=("Segoe UI", 11, "bold"), bg='white')
        mac_frame.pack(fill=tk.X, pady=(0,12))

        tk.Label(mac_frame, text="Random MAC:", bg='white', font=("Segoe UI", 9)).grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.random_mac_label = tk.Label(mac_frame, text="--:--:--:--:--:--", bg='white', font=("Segoe UI", 9, "bold"), fg='blue')
        self.random_mac_label.grid(row=0, column=1, sticky='w', padx=10, pady=5)
        generate_btn = tk.Button(mac_frame, text="Generate Random", command=self.generate_random_mac, bg='#02a862', fg='white', font=("Segoe UI", 9))
        generate_btn.grid(row=1, column=0, columnspan=2, pady=5, padx=10, sticky='ew')
        ToolTip(generate_btn, "Generate a locally administered and valid MAC address")

        tk.Label(mac_frame, text="Custom MAC:", bg='white', font=("Segoe UI", 9)).grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.custom_mac_entry = tk.Entry(mac_frame, font=("Segoe UI", 9))
        self.custom_mac_entry.grid(row=2, column=1, sticky='ew', padx=10, pady=5)
        self.custom_mac_entry.insert(0, "00:00:00:00:00:00")
        ToolTip(self.custom_mac_entry, "Enter any valid MAC: must be 12 hex digits, locally-administered")

        button_frame = tk.Frame(right_frame, bg='#f8f8fa')
        button_frame.pack(fill=tk.X, pady=6)
        self.change_btn = tk.Button(button_frame, text="🔄 CHANGE MAC (Random)", command=self.change_mac_random,
                                    bg='#2186d6', fg='white', font=("Segoe UI", 12, "bold"), height=2)
        self.change_btn.pack(fill=tk.X, pady=5)
        ToolTip(self.change_btn, "Set adapter MAC to the generated random MAC")
        self.custom_btn = tk.Button(button_frame, text="Change to Custom MAC", command=self.change_mac_custom,
                                    bg='#f5a623', fg='white', font=("Segoe UI", 10, "bold"))
        self.custom_btn.pack(fill=tk.X, pady=5)
        ToolTip(self.custom_btn, "Set adapter MAC to your custom entry")
        self.restore_btn = tk.Button(button_frame, text="↺ Restore Original MAC", command=self.restore_mac,
                                     bg='#d0021b', fg='white', font=("Segoe UI", 10, "bold"))
        self.restore_btn.pack(fill=tk.X, pady=5)
        ToolTip(self.restore_btn, "Remove custom MAC, revert to hardware MAC on the adapter")
        refresh_btn = tk.Button(button_frame, text="🔃 Refresh Adapters", command=self.refresh_adapters,
                                bg='#7f8c8d', fg='white', font=("Segoe UI", 9))
        refresh_btn.pack(fill=tk.X, pady=5)
        ToolTip(refresh_btn, "Scan system for network adapters")
        help_btn = tk.Button(button_frame, text="?", bg='#ededed', fg='black', command=self.show_help)
        help_btn.pack(fill=tk.X, pady=5)
        ToolTip(help_btn, "Help, notes and troubleshooting tips")

        log_frame = tk.LabelFrame(right_frame, text="MAC Change History", font=("Segoe UI", 11, "bold"), bg='white')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(8,0))
        self.log_text = tk.Text(log_frame, height=8, bg="#f8f8fa", font=("Segoe UI", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=3)
        self.display_log()

        self.status_label = tk.Label(self.root, text="Ready - Select an adapter",
                                    bg='#e0e0e0', anchor='w', font=("Segoe UI", 9), relief=tk.SUNKEN)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)
        self.generate_random_mac()

    def display_log(self):
        try:
            with open(LOG_FILE) as f:
                lines = f.readlines()
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, ''.join(lines[-30:]))
        except:
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, "No logs recorded yet.")

    def refresh_adapters(self):
        self.tree.delete(*self.tree.get_children())
        self.adapters = {}
        self.adapter_details = {}
        try:
            result = subprocess.run(['getmac', '/v', '/fo', 'csv'],
                                   capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:]
            for line in lines:
                parts = line.replace('"', '').split(',')
                if len(parts) >= 3:
                    name = parts[0]
                    mac = parts[2]
                    status = parts[3] if len(parts) > 3 else "Connected"
                    # Only skip if MAC itself is invalid or N/A
                    if mac and mac != "N/A" and len(mac.replace('-','').replace(':','')) == 12:
                        # Get extra details
                        ip_addr = self.get_adapter_ip(name)
                        self.adapters[name] = {
                            'mac': mac,
                            'status': status,
                            'id': None,  # Will get registry ID when needed
                            'ip': ip_addr
                        }
                        self.tree.insert('', 'end', text=name,
                                         values=(mac, status))
            self.status_label.config(text=f"Found {len(self.adapters)} adapters")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get adapters: {str(e)}")
        self.display_log()

    def get_adapter_registry_name(self, mac):
        try:
            mac_clean = mac.replace('-', '').replace(':', '').upper()
            reg_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(reg_key, i)
                    if subkey_name.isdigit():  # Only check numbered keys
                        subkey = winreg.OpenKey(reg_key, subkey_name)
                        try:
                            # Check NetworkAddress first (if already spoofed)
                            try:
                                adapter_mac = winreg.QueryValueEx(subkey, "NetworkAddress")[0]
                                if adapter_mac.upper() == mac_clean:
                                    winreg.CloseKey(subkey)
                                    winreg.CloseKey(reg_key)
                                    return subkey_name
                            except:
                                pass
                            # Check original MAC from driver
                            try:
                                driver_desc = winreg.QueryValueEx(subkey, "DriverDesc")[0]
                                # This is a network adapter, check if it matches
                                # We'll match by trying to set it and see if it works
                                winreg.CloseKey(subkey)
                            except:
                                pass
                        except:
                            pass
                        try:
                            winreg.CloseKey(subkey)
                        except:
                            pass
                    i += 1
                except:
                    break
            winreg.CloseKey(reg_key)
            return None
        except Exception as e:
            return None

    def get_adapter_ip(self, name):
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            blocks = result.stdout.split("\n\n")
            for block in blocks:
                if name.lower() in block.lower():
                    ip_match = re.search(r'IPv4 Address\S*:\s*(\d+\.\d+\.\d+\.\d+)', block)
                    if ip_match:
                        return ip_match.group(1)
            return "N/A"
        except:
            return "N/A"

    def on_adapter_select(self, event):
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            adapter_name = item['text']
            if adapter_name in self.adapters:
                self.selected_adapter = adapter_name
                adapter_info = self.adapters[adapter_name]
                self.current_mac_label.config(text=adapter_info['mac'])
                self.adapter_name_label.config(text=adapter_name)
                self.adapter_ip_label.config(text=adapter_info['ip'])
                self.vendor_label.config(text=ou_lookup(adapter_info['mac']))
                self.status_label.config(text=f"Selected: {adapter_name}")
                # Get registry ID now
                if not adapter_info['id']:
                    adapter_info['id'] = self.get_adapter_registry_name(adapter_info['mac'])

    def generate_random_mac(self):
        first_octet = random.choice([0x02, 0x06, 0x0A, 0x0E])
        mac = [first_octet] + [random.randint(0x00, 0xff) for _ in range(5)]
        mac_str = ':'.join(f'{b:02X}' for b in mac)
        self.random_mac_label.config(text=mac_str)
        return mac_str

    def change_mac_random(self):
        if not self.selected_adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first!")
            return
        new_mac = self.random_mac_label.cget('text')
        self.change_mac(new_mac)

    def change_mac_custom(self):
        if not self.selected_adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first!")
            return
        new_mac = self.custom_mac_entry.get()
        self.change_mac(new_mac)

    def change_mac(self, new_mac):
        try:
            adapter_info = self.adapters[self.selected_adapter]
            
            # Get registry ID if we don't have it
            if not adapter_info['id']:
                adapter_info['id'] = self.get_adapter_registry_name(adapter_info['mac'])
            
            adapter_id = adapter_info['id']
            if not adapter_id:
                messagebox.showerror("Error", "Could not find adapter in registry!\nThis adapter may not support MAC spoofing.")
                return
            
            new_mac_clean = new_mac.replace(':', '').replace('-', '').upper()
            if not is_valid_mac(new_mac):
                messagebox.showerror("Invalid MAC", "MAC address must be 12 hex digits, unicast, locally-administered!")
                return
            
            reg_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{adapter_id}"
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(reg_key, "NetworkAddress", 0, winreg.REG_SZ, new_mac_clean)
            winreg.CloseKey(reg_key)
            
            self.status_label.config(text="Restarting adapter...")
            self.root.update()
            
            subprocess.run(['netsh', 'interface', 'set', 'interface',
                            self.selected_adapter, 'disable'],
                           capture_output=True)
            subprocess.run(['netsh', 'interface', 'set', 'interface',
                            self.selected_adapter, 'enable'],
                           capture_output=True)
            
            messagebox.showinfo("Success", f"MAC address changed to: {new_mac}\n\nAdapter restarted!")
            log_action(f"MAC changed for [{self.selected_adapter}] to {new_mac}")
            self.refresh_adapters()
            self.generate_random_mac()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change MAC: {str(e)}")
            self.status_label.config(text="Error changing MAC")
            log_action(f"ERROR changing MAC: {str(e)}")

    def restore_mac(self):
        if not self.selected_adapter:
            messagebox.showwarning("No Adapter", "Please select a network adapter first!")
            return
        try:
            adapter_info = self.adapters[self.selected_adapter]
            
            # Get registry ID if we don't have it
            if not adapter_info['id']:
                adapter_info['id'] = self.get_adapter_registry_name(adapter_info['mac'])
            
            adapter_id = adapter_info['id']
            if not adapter_id:
                messagebox.showerror("Error", "Could not find adapter in registry!")
                return
            
            reg_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{adapter_id}"
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_WRITE)
            try:
                winreg.DeleteValue(reg_key, "NetworkAddress")
            except:
                pass
            winreg.CloseKey(reg_key)
            
            self.status_label.config(text="Restoring original MAC...")
            self.root.update()
            
            subprocess.run(['netsh', 'interface', 'set', 'interface',
                            self.selected_adapter, 'disable'],
                           capture_output=True)
            subprocess.run(['netsh', 'interface', 'set', 'interface',
                            self.selected_adapter, 'enable'],
                           capture_output=True)
            
            messagebox.showinfo("Success", "Original MAC address restored!\n\nAdapter restarted!")
            log_action(f"MAC restored for [{self.selected_adapter}]")
            self.refresh_adapters()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore MAC: {str(e)}")
            log_action(f"ERROR restoring MAC: {str(e)}")

    def show_help(self):
        help_text = (
            "MAC Changer Help / Notes\n"
            "------------------------\n"
            "• Program requires administrator rights to change registry & restart adapters.\n"
            "• Only locally-administered MACs are generated and accepted for changes.\n"
            "• Use the Change MAC buttons only after selecting your active network adapter.\n"
            "• Always verify and reconnect your internet after making MAC changes.\n"
            "• All changes are logged for review in the history panel.\n"
            "• For advanced troubleshooting, check Windows Event Viewer for network errors."
        )
        messagebox.showinfo("Help", help_text)

if __name__ == "__main__":
    root = tk.Tk()
    app = MACChangerGUI(root)
    root.mainloop()