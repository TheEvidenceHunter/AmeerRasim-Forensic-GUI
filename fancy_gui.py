import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import os

# -----------------------------
# Run Volatility plugin
# -----------------------------
def run_plugin(plugin):
    mem_file = mem_entry.get()
    if not mem_file or not os.path.isfile(mem_file):
        messagebox.showerror("Error", "Select a valid memory file first!")
        return

    cmd = ["python3", "vol.py", "-f", mem_file, plugin]
    output_text.config(state='normal')
    output_text.delete(1.0, tk.END)
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        output_text.insert(tk.END, output)
    except subprocess.CalledProcessError as e:
        output_text.insert(tk.END, e.output)
    output_text.config(state='disabled')

# -----------------------------
# Save results
# -----------------------------
def save_results():
    content = output_text.get(1.0, tk.END).strip()
    if not content:
        messagebox.showinfo("Info", "No results to save.")
        return

    file = filedialog.asksaveasfilename(defaultextension=".txt",
                                        filetypes=[("Text files", "*.txt")])
    if file:
        with open(file, "w") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"Results saved to {file}")

# -----------------------------
# Main Window
# -----------------------------
root = tk.Tk()
root.title("Memory Forensics GUI - Ameer")
root.geometry("1000x700")
root.configure(bg="#1c1c1c")  # Dark background

# Style for buttons
style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Helvetica', 12, 'bold'), padding=8, foreground='white', background='#4a90e2')
style.map('TButton', background=[('active', '#357ABD')])

# Memory file selection
tk.Label(root, text="Memory File:", bg="#1c1c1c", fg="white", font=('Helvetica', 14)).pack(pady=5)
mem_entry = tk.Entry(root, width=60, font=('Helvetica', 12))
mem_entry.pack(padx=5)
ttk.Button(root, text="Browse", command=lambda: mem_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

# Plugin buttons
tk.Label(root, text="Plugins:", bg="#1c1c1c", fg="white", font=('Helvetica', 14)).pack(pady=10)

plugins = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.handles",
    "windows.dlllist"
]

btn_frame = tk.Frame(root, bg="#1c1c1c")
btn_frame.pack(pady=5)

for p in plugins:
    ttk.Button(btn_frame, text=p, width=18, command=lambda plugin=p: run_plugin(plugin)).pack(side=tk.LEFT, padx=5, pady=5)

# Output text area with Scrollbar
output_frame = tk.Frame(root)
output_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(output_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output_text = tk.Text(output_frame, wrap='none', yscrollcommand=scrollbar.set, font=('Consolas', 11), bg="#222222", fg="#00FF00")
output_text.pack(fill=tk.BOTH, expand=True)
output_text.config(state='disabled')

scrollbar.config(command=output_text.yview)

# Save button
ttk.Button(root, text="Save Results", command=save_results).pack(pady=10)

# Author label
tk.Label(root, text="Author: Ameer Rasim", bg="#1c1c1c", fg="#ffcc00", font=('Helvetica', 12, 'bold')).pack(pady=2)

root.mainloop()
