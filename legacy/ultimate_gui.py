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
                                        filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])
    if file:
        with open(file, "w") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"Results saved to {file}")

# -----------------------------
# Gradient background helper
# -----------------------------
def draw_gradient(canvas, color1, color2):
    width = canvas.winfo_width()
    height = canvas.winfo_height()
    limit = height
    (r1,g1,b1) = canvas.winfo_rgb(color1)
    (r2,g2,b2) = canvas.winfo_rgb(color2)
    r_ratio = float(r2-r1)/limit
    g_ratio = float(g2-g1)/limit
    b_ratio = float(b2-b1)/limit
    for i in range(limit):
        nr = int(r1 + (r_ratio*i))
        ng = int(g1 + (g_ratio*i))
        nb = int(b1 + (b_ratio*i))
        color = f'#{nr>>8:02x}{ng>>8:02x}{nb>>8:02x}'
        canvas.create_line(0,i,width,i,fill=color)

# -----------------------------
# Main window
# -----------------------------
root = tk.Tk()
root.title("Memory Forensics Ultimate GUI - Ameer Rasim")
root.geometry("1100x750")

# Canvas for gradient background
bg_canvas = tk.Canvas(root, width=1100, height=750)
bg_canvas.pack(fill=tk.BOTH, expand=True)
bg_canvas.bind("<Configure>", lambda e: draw_gradient(bg_canvas, "#1c1c1c", "#0f4c81"))

# Frame on top of canvas
main_frame = tk.Frame(bg_canvas, bg="#000000", bd=0)
main_frame.place(relwidth=1, relheight=1)

# Fonts
title_font = ("Helvetica", 20, "bold")
label_font = ("Helvetica", 14)
button_font = ("Helvetica", 12, "bold")
text_font = ("Consolas", 11)

# Title
tk.Label(main_frame, text="Memory Forensics Ultimate GUI", font=title_font, fg="#ffcc00", bg="#000000").pack(pady=10)
tk.Label(main_frame, text="Author: Ameer", font=("Helvetica",12,"italic"), fg="#00ffff", bg="#000000").pack(pady=2)

# Memory file selection
tk.Label(main_frame, text="Memory File:", font=label_font, fg="white", bg="#000000").pack(pady=5)
mem_entry = tk.Entry(main_frame, width=60, font=("Helvetica",12))
mem_entry.pack(pady=2)
ttk.Button(main_frame, text="Browse", command=lambda: mem_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

# Plugin buttons
tk.Label(main_frame, text="Plugins:", font=label_font, fg="white", bg="#000000").pack(pady=5)

plugins = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.handles",
    "windows.dlllist"
]

btn_frame = tk.Frame(main_frame, bg="#000000")
btn_frame.pack(pady=5)

for p in plugins:
    b = ttk.Button(btn_frame, text=p, width=18, command=lambda plugin=p: run_plugin(plugin))
    b.pack(side=tk.LEFT, padx=5, pady=5)

# Output text area with scrollbar
output_frame = tk.Frame(main_frame)
output_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(output_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output_text = tk.Text(output_frame, wrap='none', yscrollcommand=scrollbar.set, font=text_font, bg="#111111", fg="#00ff00", insertbackground="white")
output_text.pack(fill=tk.BOTH, expand=True)
output_text.config(state='disabled')

scrollbar.config(command=output_text.yview)

# Save results button
ttk.Button(main_frame, text="Save Results", command=save_results).pack(pady=10)

root.mainloop()
