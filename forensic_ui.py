import tkinter as tk
import random

# -----------------------------
# Animated background class
# -----------------------------
class AnimatedBG:
    def __init__(self, canvas, width, height, num_particles=60):
        self.canvas = canvas
        self.width = width
        self.height = height
        self.particles = []
        colors = ["#00FF00", "#00FFFF", "#FF00FF"]
        for _ in range(num_particles):
            x = random.randint(0, width)
            y = random.randint(0, height)
            dx = random.uniform(-0.5,0.5)
            dy = random.uniform(1,3)
            color = random.choice(colors)
            p = {'x':x, 'y':y, 'dx':dx, 'dy':dy, 'id':canvas.create_line(x, y, x+2, y+10, fill=color, width=2)}
            self.particles.append(p)
        self.animate()

    def animate(self):
        for p in self.particles:
            p['x'] += p['dx']
            p['y'] += p['dy']
            if p['y'] > self.height:
                p['y'] = 0
                p['x'] = random.randint(0, self.width)
            self.canvas.coords(p['id'], p['x'], p['y'], p['x']+2, p['y']+10)
        self.canvas.after(40, self.animate)

# -----------------------------
# Main Window
# -----------------------------
root = tk.Tk()
root.title("Crime Analysis Lab - Ameer Rasim")
root.geometry("1400x900")
root.configure(bg="#000000")

# Fullscreen canvas for background
bg_canvas = tk.Canvas(root, width=1400, height=900, bg="#000000", highlightthickness=0)
bg_canvas.pack(fill=tk.BOTH, expand=True)

# Animated background
animated_bg = AnimatedBG(bg_canvas, 1400, 900, num_particles=100)

# Foreground frame for name and title
fg_frame = tk.Frame(bg_canvas, bg="#111111", bd=0)
fg_frame.place(relwidth=0.9, relheight=0.2, relx=0.05, rely=0.05)

# Neon style labels
title_label = tk.Label(fg_frame, text="CRIME ANALYSIS LAB", font=("Courier New", 40, "bold"), fg="#00FF00", bg="#111111")
title_label.pack(pady=10)

name_label = tk.Label(fg_frame, text="Ameer Rasim", font=("Courier New", 30, "italic"), fg="#00FFFF", bg="#111111")
name_label.pack(pady=5)

# Glow effect simulation by layering slightly offset labels
for offset in range(1,5):
    tk.Label(fg_frame, text="CRIME ANALYSIS LAB", font=("Courier New", 40, "bold"), fg="#00FF00", bg="#111111").place(x=offset, y=offset)
    tk.Label(fg_frame, text="Ameer Rasim", font=("Courier New", 30, "italic"), fg="#00FFFF", bg="#111111").place(x=offset, y=offset+50)

# Random small "forensic icons" simulation (like dots or tiny squares)
for _ in range(50):
    x = random.randint(0, 1400)
    y = random.randint(200, 900)
    size = random.randint(5,10)
    color = random.choice(["#FF00FF", "#00FFFF", "#00FF00"])
    bg_canvas.create_oval(x, y, x+size, y+size, fill=color, outline="")

root.mainloop()
