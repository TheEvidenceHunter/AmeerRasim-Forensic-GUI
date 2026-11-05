import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import os
import random

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
# Animated background
# -----------------------------
class AnimatedBG:
    def __init__(self, canvas, width, height):
        self.canvas = canvas
        self.width = width
        self.height = height
        self.lines = []
        for _ in range(40):
            x = random.randint(0, width)
            y = random.randint(0, height)
            dx = random.uniform(-0.5,0.5)
            dy = random.uniform(1,3)
            line = {'x':x, 'y':y, 'dx':dx, 'dy':dy, 'id':canvas.create_line(x, y, x+2, y+10, fill="#00FF00")}
            self.lines.append(line)
        self.animate()

    def animate(self):
        for line in self.lines:
            line['x'] += line['dx']
            line['y'] += line['dy']
            if line['y'] > self.height:
                line['y'] = 0
                line['x'] = random.randint(0, self.width)
            self.canvas.coords(line['id'], line['x'], line['y'], line['x']+2, line['y']+10)
        self.canvas.after(50, self.animate)

# -----------------------------
# Main Window
# -----------------------------
root = tk.Tk()
root.title("Memory Forensics Ultimate GUI - Ameer Rasim")
root.geometry("1100x750")
root.configure(bg="#000000")

# Canvas for animated background
bg_canvas = tk.Canvas(root, width=1100, height=750, bg="#000000", highlightthickness=0)
bg_canvas.pack(fill=tk.BOTH, expand=True)
animated_bg = AnimatedBG(bg_canvas, 1100, 750)

# Main frame on top of canvas
main_frame = tk.Frame(bg_canvas, bg="#111111", bd=0)
main_frame.place(relwidth=0.95, relheight=0.95, relx=0.025, rely=0.025)

# Fonts
title_font = ("Helvetica", 20, "bold")
label_font = ("Helvetica", 14)
button_font = ("Helvetica", 12, "bold")
text_font = ("Consolas", 11)

# Title
tk.Label(main_frame, text="Memory Forensics Ultimate GUI", font=title_font, fg="#ffcc00", bg="#111111").pack(pady=10)
tk.Label(main_frame, text="Author: Ameer Rasim", font=("Helvetica",14,"italic"), fg="#00ffff", bg="#111111").pack(pady=2)

# Memory file selection
tk.Label(main_frame, text="Memory File:", font=label_font, fg="white", bg="#111111").pack(pady=5)
mem_entry = tk.Entry(main_frame, width=60, font=("Helvetica",12))
mem_entry.pack(pady=2)
ttk.Button(main_frame, text="Browse", command=lambda: mem_entry.insert(0, filedialog.askopenfilename())).pack(pady=5)

# Plugin buttons
tk.Label(main_frame, text="Plugins:", font=label_font, fg="white", bg="#111111").pack(pady=5)

plugins = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.netscan",
    "windows.handles",
    "windows.dlllist"
]

btn_frame = tk.Frame(main_frame, bg="#111111")
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

