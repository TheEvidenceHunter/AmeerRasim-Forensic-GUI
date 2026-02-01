import tkinter as tk
from tkinter import filedialog, messagebox
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
    output_text.delete(1.0, tk.END)
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        output_text.insert(tk.END, output)
    except subprocess.CalledProcessError as e:
        output_text.insert(tk.END, e.output)

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
# Main window
# -----------------------------
root = tk.Tk()
root.title("Memory Forensics GUI - Ameer")

# Memory file selection
tk.Label(root, text="Memory File:").pack(pady=2)
mem_entry = tk.Entry(root, width=60)
mem_entry.pack(padx=5)
tk.Button(root, text="Browse", command=lambda: mem_entry.insert(0, filedialog.askopenfilename())).pack(pady=2)

# Plugin buttons
tk.Label(root, text="Plugins:").pack(pady=5)

plugins = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.handles",
    "windows.dlllist"
]

btn_frame = tk.Frame(root)
btn_frame.pack()

for p in plugins:
    tk.Button(btn_frame, text=p, width=15, command=lambda plugin=p: run_plugin(plugin)).pack(side=tk.LEFT, padx=2, pady=2)

# Output text area
output_text = tk.Text(root, height=25, width=100)
output_text.pack(padx=5, pady=5)

# Save button
tk.Button(root, text="Save Results", command=save_results, bg="lightgreen").pack(pady=5)

# Author label
tk.Label(root, text="Author: Ameer Rasim", fg="blue").pack(pady=2)

root.mainloop()

