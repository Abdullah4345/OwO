import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from threading import Thread
from tkinter import ttk
import csv
import itertools
import random
import shutil


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller bundle."""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def get_real_python_executable():
    # If running as a PyInstaller bundle, use system Python
    if getattr(sys, 'frozen', False):
        # Try to find python in PATH
        for py in ("python3.exe", "python.exe"):
            python_path = shutil.which(py)
            if python_path:
                return python_path
        # Fallback: just 'python'
        return "python"
    else:
        return sys.executable


def get_user_data_dir():
    # Use a user-writable directory for settings
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "MemoryApp")
    else:
        return os.path.join(os.path.expanduser("~"), ".memory_app")


class MemoryCaptureTab(tk.Frame):
    def __init__(self, parent, set_dump_callback):
        super().__init__(parent, bg="#000")
        self.set_dump_callback = set_dump_callback

        self.tips = [
            "Tip: Always verify your memory dump hash!",
            "Tip: Run Volatility with the right profile.",
            "Tip: Use 'pslist' to see running processes.",
            "Tip: Save your work frequently.",
            "Tip: Use CTF search for quick flag hunting.",
            "Tip: Analyze suspicious network connections.",
            "Tip: Try 'malfind' for malware detection.",
            "Tip: Use 'yara' rules for custom scans.",
            "Tip: Don't forget to check clipboard artifacts!",
            "Tip: Use the search box to find keywords fast.",
            "Joke :What do skeletons say before eating? Bone appétit!.",
            "Because you know, in a moment, it could all… poow!",
            "What's you favorite singer? mine is Dua Lipa",
            "what's your favorite song? mine is 'Don't Start Now'",
            "what's your favorite Show? Mine is Arcane",
            "JINX JINX JINX JINX JINX JINX JINX ",
        ]

        self.cloud_label = tk.Label(
            self,
            text="",
            font=("Courier", 9, "bold"),
            fg="#ff4444",
            bg="#000",
            justify="left"
        )

        self.cloud_label.pack(pady=(5, 0))

        self.skull_frames = [
            r"""
   .-.
  (o o)
  | O \
   \   \
    `~~~'
""",
            r"""
    .-.
   (o o)
   / O |
  /   /
 '~~~'
""",
            r"""
    .-.
   (o o)
  / O |
 /   /
'~~~'
""",
            r"""
   .-.
  (o o)
  | O \
   \   \
    `~~~'
"""
        ]
        self.current_frame = 0

        self.skull_label = tk.Label(
            self,
            text=self.skull_frames[0],
            font=("Courier", 18, "bold"),
            fg="#ff4444",
            bg="#000",
            justify="left"
        )

        self.skull_label.pack(expand=True, fill=tk.BOTH, pady=(0, 0))

        self.animate_skull()

    def animate_skull(self):
        self.current_frame = (self.current_frame + 1) % len(self.skull_frames)
        self.skull_label.config(text=self.skull_frames[self.current_frame])
        self.after(200, self.animate_skull)

    def capture_memory(self):

        path = filedialog.asksaveasfilename(
            title="Save Memory Dump As",
            defaultextension=".raw",
            filetypes=[("Raw Memory Dump", "*.raw"), ("All files", "*.*")]
        )
        if not path:
            return
        self.status_var.set(
            "Starting memory capture. This may require admin privileges and may take a while...")
        self.progress.start(10)
        self.capture_btn.config(state='disabled')
        Thread(target=self._capture_thread, args=(path,), daemon=True).start()

    def _capture_thread(self, path):
        try:

            script = f'''
            do shell script "echo 'Simulated memory dump' > '{path}'" with administrator privileges
            '''
            osa_cmd = ['osascript', '-e', script]
            result = subprocess.run(osa_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.set_dump_callback(path)
                self._update_status(f"Memory dump saved to: {path}", done=True)
            else:
                self._update_status(
                    f"Error: {result.stderr.strip()}", done=True)
        except Exception as e:
            self._update_status(f"Error: {e}", done=True)

    def _update_status(self, msg, done=False):
        def update():
            self.status_var.set(msg)
            if done:
                self.progress.stop()
                self.capture_btn.config(state='normal')
        self.after(0, update)

    def log(self, msg):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def show_random_tip(self):
        tip = random.choice(self.tips)

        cloud = f"""
                             .------------------------.
                        .--(                            )--.
                    .--(                                   )--.
                .--({tip.center(28)})--.
             .-(                                           )-.
           (_____________________________________________)
           ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
                      \ 
                       \\
                        \\
                         \\
                          \\
                           \\
                            \\
                             \\
                              \\
                               v
"""
        self.cloud_label.config(text=cloud)

        self.cloud_label.update_idletasks()


class VolatilityAnalyzer:
    def __init__(self, root):
        self.root = root
        self.volatility_path = self.load_volatility_path()
        self.memory_dump = ""

        self.create_widgets()

        self.search_matches = []
        self.current_match = -1

    def load_volatility_path(self):
        user_data_dir = get_user_data_dir()
        csv_path = os.path.join(user_data_dir, "vol_path.csv")
        if os.path.exists(csv_path):
            try:
                with open(csv_path, "r") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row:
                            return row[0]
            except Exception:
                pass
        # If not found, just return empty string and wait for user input
        return ""

    def save_volatility_path(self, path):
        user_data_dir = get_user_data_dir()
        os.makedirs(user_data_dir, exist_ok=True)
        csv_path = os.path.join(user_data_dir, "vol_path.csv")
        try:
            with open(csv_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([path])
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to save Volatility path: {e}")

    def find_volatility(self):
        possible_paths = [
            "/usr/local/bin/vol",
            os.path.expanduser("~/.local/bin/vol"),
            os.path.expanduser("~/Library/Python/3.9/bin/vol"),
            "vol"
        ]
        for path in possible_paths:
            try:
                subprocess.run([path, "--help"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return path
            except:
                continue
        return ""

    def create_widgets(self):

        self.root.configure(bg="#000")

        style = ttk.Style()
        style.theme_use('default')
        style.configure("Black.TButton",
                        background="#000", foreground="#ff4444",
                        font=("Courier", 9, "bold"),
                        borderwidth=1)
        style.map("Black.TButton",
                  background=[('active', '#222')],
                  foreground=[('active', '#fff')])

        style.configure("Black.TCombobox",
                        fieldbackground="#111",
                        background="#111",
                        foreground="#ff4444",
                        selectbackground="#222",
                        selectforeground="#ff4444",
                        arrowcolor="#ff4444",
                        bordercolor="#ff4444",
                        lightcolor="#111",
                        darkcolor="#111",
                        borderwidth=1,
                        font=("Courier", 9, "bold"))
        style.map("Black.TCombobox",
                  fieldbackground=[('readonly', '#111')],
                  foreground=[('readonly', '#ff4444')],
                  background=[('readonly', '#111')],
                  selectbackground=[('readonly', '#222')],
                  selectforeground=[('readonly', '#ff4444')])

        style.configure("Black.TNotebook", background="#000", borderwidth=0)
        style.configure("Black.TNotebook.Tab",
                        background="#000", foreground="#ff4444",
                        font=("Courier", 9, "bold"),
                        lightcolor="#000", borderwidth=0, padding=6)
        style.map("Black.TNotebook.Tab",
                  background=[("selected", "#222")],
                  foreground=[("selected", "#fff")])

        style.configure("Black.Vertical.TScrollbar", background="#111",
                        troughcolor="#000", bordercolor="#000", arrowcolor="#ff4444")
        style.map("Black.Vertical.TScrollbar",
                  background=[('active', '#222')],
                  arrowcolor=[('active', '#fff')])

        self.plugin_options = [
            ("Process List", "windows.pslist.PsList"),
            ("Process Scan", "windows.psscan.PsScan"),
            ("DLL List", "windows.dlllist.DllList"),
            ("Network Scan", "windows.netscan.NetScan"),
            ("Malfind", "windows.malfind.Malfind"),
            ("Yara Scan", "windows.yarascan.YaraScan"),
            ("Callbacks", "windows.callbacks.Callbacks"),
            ("Driver Scan", "windows.driverscan.DriverScan"),
            ("Handles", "windows.handles.Handles"),
            ("CmdLine", "windows.cmdline.CmdLine"),
            ("Envars", "windows.envars.Envars"),
            ("Filescan", "windows.filescan.FileScan"),
            ("Registry Hives", "windows.registry.hivelist.HiveList"),
            ("Registry Printkey", "windows.registry.printkey.PrintKey"),
            ("SSDT", "windows.ssdt.SSDT"),
            ("Modules", "windows.modules.Modules"),
            ("Services Scan", "windows.svcscan.SvcScan"),
            ("Get SIDs", "windows.getsids.GetSIDs"),
            ("MFT Parser", "windows.mftparser.MFTParser"),
            ("Shellbags", "windows.shellbags.ShellBags"),
            ("UserAssist", "windows.userassist.UserAssist"),
            ("Amcache", "windows.amcache.Amcache"),
            ("Shimcache", "windows.shimcache.ShimCache"),
            ("Timeliner", "windows.timeliner.TimeLiner"),
            ("Clipboard", "windows.clipboard.Clipboard"),
            ("CmdScan", "windows.cmdscan.CmdScan"),
            ("Consoles", "windows.consoles.Consoles"),
            ("Hashdump", "windows.hashdump.Hashdump"),
            ("LSA Dump", "windows.lsadump.Lsadump"),
            ("Dump Files", "windows.dumpfiles.DumpFiles"),
            ("ProcDump", "windows.procdump.ProcDump"),
            ("List Plugins", "list_plugins")
        ]

        info_frame = tk.Frame(self.root, bg="#000", padx=10, pady=10)
        info_frame.pack(fill=tk.X)
        tk.Label(info_frame, text="Memory Dump:", font=("Courier", 9, "bold"),
                 fg="#ff4444", bg="#000").grid(row=0, column=0, sticky=tk.W)
        self.dump_entry = tk.Entry(
            info_frame, width=50, bg="#000", fg="#ff4444", insertbackground="#ff4444", font=("Courier", 9))
        self.dump_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        ttk.Button(info_frame, text="Browse", command=self.browse_dump,
                   style="Black.TButton").grid(row=0, column=2, padx=5)

        tk.Label(info_frame, text="Volatility Path:", font=(
            "Courier", 9, "bold"), fg="#ff4444", bg="#000").grid(row=1, column=0, sticky=tk.W)
        self.vol_entry = tk.Entry(
            info_frame, width=50, bg="#000", fg="#ff4444", insertbackground="#ff4444", font=("Courier", 9))
        self.vol_entry.grid(row=1, column=1, sticky=tk.EW, padx=5)
        self.vol_entry.insert(0, self.volatility_path)
        ttk.Button(info_frame, text="Browse", command=self.browse_volatility,
                   style="Black.TButton").grid(row=1, column=2, padx=5)
        info_frame.columnconfigure(1, weight=1)

        options_frame = tk.Frame(self.root, bg="#000", padx=10, pady=10)
        options_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        options_frame.columnconfigure(98, weight=1)

        tk.Label(options_frame, text="Select:", font=("Courier", 9, "bold"),
                 fg="#ff4444", bg="#000").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.selected_plugin = tk.StringVar()
        plugin_names = [name for name, _ in self.plugin_options]
        self.plugin_combobox = ttk.Combobox(
            options_frame, textvariable=self.selected_plugin, values=plugin_names,
            state="readonly", style="Black.TCombobox", width=25, font=("Courier", 9))
        self.plugin_combobox.current(0)
        self.plugin_combobox.grid(row=0, column=1, padx=(0, 10), sticky=tk.W)
        ttk.Button(options_frame, text="Run",
                   command=self.run_selected_plugin, style="Black.TButton").grid(row=0, column=2, padx=(0, 10), sticky=tk.W)

        tk.Label(options_frame, text="Custom Plugin:", font=("Courier", 9),
                 fg="#ff4444", bg="#000").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(8, 0))
        self.custom_cmd = tk.Entry(
            options_frame, width=25, bg="#000", fg="#ff4444", insertbackground="#ff4444", font=("Courier", 9))
        self.custom_cmd.grid(row=1, column=1, padx=(
            0, 10), sticky=tk.W, pady=(8, 0))
        ttk.Button(options_frame, text="Run",
                   command=self.run_custom_command, style="Black.TButton").grid(row=1, column=2, sticky=tk.W, padx=(0, 10), pady=(8, 0))

        tk.Label(options_frame, text="""

         .AMMMMMMMMMMA.          
       .AV. :::.:.:.::MA.        
      A' :..        : .:`A       
     A'..              . `A.     
    A' :.    :::::::::  : :`A    
    M  .    :::.:.:.:::  . .M    
    M  :   ::.:.....::.:   .M    
    V : :.::.:........:.:  :V    
   A  A:    ..:...:...:.   A A   
  .V  MA:.....:M.::.::. .:AM.M   
 A'  .VMMMMMMMMM:.:AMMMMMMMV: A  
:M .  .`VMMMMMMV.:A `VMMMMV .:M: 
 V.:.  ..`VMMMV.:AM..`VMV' .: V  
  V.  .:. .....:AMMA. . .:. .V   
   VMM...: ...:.MMMM.: .: MMV    
       `VM: . ..M.:M..:::M'      
         `M::. .:.... .::M       
          M:.  :. .... ..M       
          V:  M:. M. :M .V       
     `V.:M.. M. :M.V'


""", font=("Courier", 4, "bold"),
            fg="#ff4444", bg="#000"
        ).grid(row=0, column=99, rowspan=3, sticky=tk.NE, padx=(0, 0), pady=(10, 0))

        output_frame = tk.Frame(self.root, bg="#000", padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True)

        out_ctrl_frame = tk.Frame(output_frame, bg="#000")
        out_ctrl_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(out_ctrl_frame, text="Clear Output", command=lambda: self.set_output(
            "", clear=True), style="Black.TButton").pack(side=tk.LEFT, padx=2)
        ttk.Button(out_ctrl_frame, text="Copy Output",
                   command=self.copy_output, style="Black.TButton").pack(side=tk.LEFT, padx=2)

        self.output_text = tk.Text(
            output_frame,
            wrap=tk.WORD,
            font=('Menlo', 8),
            height=10,  # <-- Add this line to make the terminal output shorter
            undo=True,
            state='disabled',
            bg="#000",
            fg="#ff4444",
            insertbackground="#ff4444",
            selectbackground="#440000",
            selectforeground="#fff"
        )
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(output_frame, orient="vertical",
                            command=self.output_text.yview, style="Black.Vertical.TScrollbar")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.configure(yscrollcommand=vsb.set)

        search_frame = tk.Frame(self.root, bg="#000", padx=10, pady=5)
        search_frame.pack(fill=tk.X)
        tk.Label(search_frame, text="Search Output:", font=(
            "Courier", 9), fg="#ff4444", bg="#000").pack(side=tk.LEFT)
        self.search_entry = tk.Entry(
            search_frame, width=30, bg="#000", fg="#ff4444", insertbackground="#ff4444", font=("Courier", 9))
        self.search_entry.insert(0, "Type to search...")
        self.search_entry.bind(
            "<FocusIn>", lambda e: self._clear_placeholder())
        self.search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Find",
                   command=self.search_output, style="Black.TButton").pack(side=tk.LEFT)
        ttk.Button(search_frame, text="Next", command=self.next_match,
                   style="Black.TButton").pack(side=tk.LEFT, padx=2)
        ttk.Button(search_frame, text="Previous", command=self.prev_match,
                   style="Black.TButton").pack(side=tk.LEFT, padx=2)
        ttk.Button(search_frame, text="CTF", command=self.ctf_search,
                   style="Black.TButton").pack(side=tk.LEFT, padx=8)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        tk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN,
                 anchor="w", bg="#000", fg="#ff4444", font=("Courier", 9),
                 borderwidth=0, highlightthickness=0).pack(fill=tk.X)

    def set_output(self, text, clear=False):
        self.output_text.config(state='normal')
        if clear:
            self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')

    def append_output(self, text):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')

    def browse_dump(self):
        filepath = filedialog.askopenfilename(
            title="Select Memory Dump",
            filetypes=[
                ("Memory dumps", "*.dmp *.img *.mem *.raw *.vmem"), ("All files", "*.*")]
        )
        if filepath:
            self.memory_dump = filepath
            self.dump_entry.delete(0, tk.END)
            self.dump_entry.insert(0, filepath)

    def browse_volatility(self):
        filepath = filedialog.askopenfilename(
            title="Select Volatility Executable",
            filetypes=[("All files", "*")]
        )
        if filepath:
            self.volatility_path = filepath
            self.vol_entry.delete(0, tk.END)
            self.vol_entry.insert(0, filepath)
            self.save_volatility_path(filepath)

    def run_analysis(self, plugin):
        if not self.validate_inputs():
            return

        self.set_output(f"=== {plugin.upper()} ===\n", clear=True)
        self.status_var.set(f"Running {plugin}...")
        self.root.update()
        Thread(target=self._run_command_thread,
               args=(plugin,), daemon=True).start()

    def run_custom_command(self):
        plugin = self.custom_cmd.get().strip()
        if not plugin:
            messagebox.showwarning("Warning", "Please enter a plugin name")
            return
        self.run_analysis(plugin)

    def list_plugins(self):
        if not self.validate_volatility():
            return
        self.status_var.set("Listing plugins...")
        self.root.update()
        Thread(target=self._list_plugins_thread, daemon=True).start()

    def run_malware_scan(self):
        plugins = [
            "windows.pslist.PsList",
            "windows.psscan.PsScan",
            "windows.dlllist.DllList",
            "windows.netscan.NetScan",
            "windows.malfind.Malfind",
            "windows.yarascan.YaraScan",
            "windows.callbacks.Callbacks",
            "windows.driverscan.DriverScan"
        ]
        for plugin in plugins:
            self.run_analysis(plugin)

    def _run_command_thread(self, plugin):
        try:
            if self.volatility_path.lower().endswith('.py'):
                python_exec = get_real_python_executable()
                cmd = [python_exec, self.volatility_path,
                       "-f", self.memory_dump, plugin]
            else:
                cmd = [self.volatility_path, "-f", self.memory_dump, plugin]
            kwargs = dict(capture_output=True, text=True)
            if sys.platform == "win32":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, **kwargs)
            if result.returncode == 0:
                self.append_output(result.stdout)
            else:
                self.append_output(f"Error:\n{result.stderr}")
            self.status_var.set(f"Completed {plugin}")
        except Exception as e:
            self.append_output(
                f"\nError running {plugin}: {str(e)}\n")
            self.status_var.set(f"Error running {plugin}")

    def _list_plugins_thread(self):
        try:
            self.set_output("=== AVAILABLE PLUGINS ===\n", clear=True)
            kwargs = dict(capture_output=True, text=True)
            if sys.platform == "win32":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                [self.volatility_path, "--help"], **kwargs)
            if result.returncode == 0:
                output = result.stdout
                if "The available plugins are:" in output:
                    plugins = output.split("The available plugins are:")[
                        1].split("\n\n")[0]
                    self.append_output(plugins)
                else:
                    self.append_output(output)
            else:
                self.append_output(f"Error:\n{result.stderr}")
            self.status_var.set("Plugin list completed")
        except Exception as e:
            self.append_output(
                f"\nError listing plugins: {str(e)}\n")
            self.status_var.set("Plugin list error")

    def validate_inputs(self):
        if not self.validate_volatility():
            return False
        if not self.memory_dump or not os.path.exists(self.memory_dump):
            messagebox.showerror("Error", "Invalid memory dump file")
            return False
        return True

    def validate_volatility(self):
        if not self.volatility_path:
            messagebox.showerror("Error", "Volatility path not specified")
            return False
        try:
            if self.volatility_path.lower().endswith('.py'):
                python_exec = get_real_python_executable()
                cmd = [python_exec, self.volatility_path, "--help"]
            else:
                cmd = [self.volatility_path, "--help"]
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except Exception:
            messagebox.showerror(
                "Error", f"Cannot run volatility at: {self.volatility_path}")
            return False

    def search_output(self):
        self.output_text.config(state='normal')
        self.output_text.tag_remove("search_match", "1.0", tk.END)
        self.output_text.config(state='disabled')
        self.search_matches = []
        self.current_match = -1
        query = self.search_entry.get()
        if not query:
            return
        start = "1.0"
        while True:
            idx = self.output_text.search(
                query, start, stopindex=tk.END, nocase=1)
            if not idx:
                break
            end = f"{idx}+{len(query)}c"
            self.output_text.config(state='normal')
            self.output_text.tag_add("search_match", idx, end)
            self.output_text.config(state='disabled')
            self.search_matches.append((idx, end))
            start = end
        self.output_text.config(state='normal')
        self.output_text.tag_config(
            "search_match", background="#ffe066", foreground="#222")
        self.output_text.config(state='disabled')
        if self.search_matches:
            self.current_match = 0
            self.highlight_current_match()

    def highlight_current_match(self):
        if not self.search_matches:
            return
        self.output_text.config(state='normal')
        self.output_text.tag_remove("current_match", "1.0", tk.END)
        idx, end = self.search_matches[self.current_match]
        self.output_text.tag_add("current_match", idx, end)
        self.output_text.tag_config(
            "current_match", background="#3399ff", foreground="#fff")
        self.output_text.see(idx)
        self.output_text.config(state='disabled')

    def next_match(self):
        if not self.search_matches:
            return
        self.current_match = (self.current_match +
                              1) % len(self.search_matches)
        self.highlight_current_match()

    def prev_match(self):
        if not self.search_matches:
            return
        self.current_match = (self.current_match -
                              1) % len(self.search_matches)
        self.highlight_current_match()

    def copy_output(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get("1.0", tk.END))

    def _clear_placeholder(self):
        if self.search_entry.get() == "Type to search...":
            self.search_entry.delete(0, tk.END)

    def run_selected_plugin(self):

        selected_name = self.selected_plugin.get()
        for name, plugin in self.plugin_options:
            if name == selected_name:
                if plugin == "list_plugins":
                    self.list_plugins()
                else:
                    self.run_analysis(plugin)
                break

    def ctf_search(self):
        ctf_terms_path = resource_path(
            os.path.join("data", "ctf_flag_terms.csv"))
        if not os.path.exists(ctf_terms_path):
            messagebox.showerror(
                "Error", f"CTF terms file not found: {ctf_terms_path}")
            return

        terms = set()
        with open(ctf_terms_path, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                for term in row:
                    term = term.strip()
                    if term:
                        terms.add(term)
        if not terms:
            messagebox.showinfo(
                "CTF Search", "No terms found in CTF terms file.")
            return

        self.output_text.config(state='normal')
        self.output_text.tag_remove("ctf_match", "1.0", tk.END)
        match_count = 0
        for term in terms:
            start = "1.0"
            while True:
                idx = self.output_text.search(
                    term, start, stopindex=tk.END, nocase=1)
                if not idx:
                    break
                end = f"{idx}+{len(term)}c"
                self.output_text.tag_add("ctf_match", idx, end)
                match_count += 1
                start = end
        self.output_text.tag_config(
            "ctf_match", background="#00ff44", foreground="#000")
        self.output_text.config(state='disabled')
        messagebox.showinfo(
            "CTF Search", f"Found {match_count} matches for CTF terms.")


class VolatilityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Memory Forensic Toolkit or smth idk")
        self.geometry("850x700")

        style = ttk.Style()
        style.theme_use('default')
        style.configure("Black.TNotebook", background="#000", borderwidth=0)
        style.configure("Black.TNotebook.Tab",
                        background="#000", foreground="#ff4444",
                        font=("Arial", 9, "bold"),
                        lightcolor="#000", borderwidth=0, padding=6)
        style.map("Black.TNotebook.Tab",
                  background=[("selected", "#222")],
                  foreground=[("selected", "#fff")])

        self.notebook = ttk.Notebook(self, style="Black.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Update window and set minimum size to current size
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        self.wm_minsize(width, height)

        self.memory_capture_tab = MemoryCaptureTab(
            self.notebook, self.set_memory_dump)
        self.notebook.add(self.memory_capture_tab, text="Freaky ahh Jeff")

        self.analyzer_tab = tk.Frame(self.notebook)
        self.notebook.add(self.analyzer_tab, text="Volatility Analyzer")
        self.analyzer = VolatilityAnalyzer(self.analyzer_tab)
        self.memory_dump = ""
        if self.notebook.index(self.notebook.select()) == 0:
            self.memory_capture_tab.show_random_tip()

    def set_memory_dump(self, path):
        self.memory_dump = path
        self.analyzer.memory_dump = path
        self.analyzer.dump_entry.delete(0, tk.END)
        self.analyzer.dump_entry.insert(0, path)


if __name__ == "__main__":
    app = VolatilityApp()
    app.mainloop()
