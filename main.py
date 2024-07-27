import tkinter as tk
from tkinter import messagebox, ttk
import random
import string
import re
import urllib.parse


class SecurityApp:
    def __init__(self, master):
        self.master = master
        self.master.title("AGV Secure Pass")
        self.master.geometry("360x640")  # Common mobile phone resolution
        self.master.config(padx=10, pady=10)

        # Color scheme
        self.bg_color = "#2C3E50"  # Dark blue-gray
        self.fg_color = "#ECF0F1"  # Light gray
        self.accent_color = "#3498DB"  # Bright blue
        self.warning_color = "#E74C3C"  # Red
        self.success_color = "#2ECC71"  # Green

        self.master.configure(bg=self.bg_color)

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.fg_color, font=('Arial', 14))
        self.style.configure('TButton', font=('Arial', 14), background=self.accent_color, foreground=self.fg_color)
        self.style.map('TButton',
                       foreground=[('active', self.fg_color)],
                       background=[('active', self.success_color)])
        self.style.configure('TEntry', font=('Arial', 14))

        self.show_login_screen()

    def show_login_screen(self):
        self.clear_window()
        self.login_frame = ttk.Frame(self.master)
        self.login_frame.pack(expand=True, fill='both')

        self.img = tk.PhotoImage(file="App Logo 1.png")
        self.img = self.img.subsample(1, 1)  # Resize image
        ttk.Label(self.login_frame, image=self.img, background=self.bg_color).pack(pady=40)

        ttk.Label(self.login_frame, text="Enter Password:", font=('Arial', 18, 'bold')).pack(pady=20)
        self.password_entry = ttk.Entry(self.login_frame, show="*", font=('Arial', 16), width=20)
        self.password_entry.pack(pady=20)
        ttk.Button(self.login_frame, text="Login", command=self.check_password, width=15).pack(pady=30)

    def check_password(self):
        if self.password_entry.get() == "agvpm":
            self.show_choice_screen()
        else:
            messagebox.showerror("Error", "Incorrect password")

    def show_choice_screen(self):
        self.clear_window()
        choice_frame = ttk.Frame(self.master)
        choice_frame.pack(expand=True, fill='both')

        ttk.Label(choice_frame, text="Choose an option:", font=('Arial', 20, 'bold')).pack(pady=40)

        button_frame = ttk.Frame(choice_frame)
        button_frame.pack(pady=30)

        ttk.Button(button_frame, text="Password Manager", command=self.show_main_screen, width=25).pack(pady=15)
        ttk.Button(button_frame, text="Phishing Link Checker", command=self.show_phishing_checker, width=25).pack(
            pady=15)
        ttk.Button(button_frame, text="Logout", command=self.show_login_screen, width=25).pack(pady=15)

    def show_main_screen(self):
        self.clear_window()
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.pack(expand=True, fill='both')

        ttk.Label(self.main_frame, text="Password Manager", font=('Arial', 20, 'bold')).pack(pady=20)

        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(fill='x', padx=10, pady=10)

        ttk.Label(input_frame, text="Website:").pack(anchor='w')
        self.website_entry = ttk.Entry(input_frame, width=30)
        self.website_entry.pack(fill='x', pady=5)

        ttk.Label(input_frame, text="Email/Username:").pack(anchor='w')
        self.email_entry = ttk.Entry(input_frame, width=30)
        self.email_entry.pack(fill='x', pady=5)

        ttk.Label(input_frame, text="Password:").pack(anchor='w')
        self.password_entry = ttk.Entry(input_frame, width=30)
        self.password_entry.pack(fill='x', pady=5)

        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Generate", command=self.generate_password, width=12).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Add", command=self.add_password, width=12).pack(side='left', padx=5)

        ttk.Button(self.main_frame, text="Show Saved Passwords", command=self.show_saved_passwords, width=25).pack(
            pady=10)
        ttk.Button(self.main_frame, text="Back", command=self.show_choice_screen, width=25).pack(pady=10)

    def generate_password(self):
        password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def add_password(self):
        website = self.website_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()

        if len(website) == 0 or len(email) == 0 or len(password) == 0:
            messagebox.showwarning("Warning", "Please fill in all fields")
        else:
            is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered: \nEmail: {email} "
                                                                  f"\nPassword: {password} \nIs it ok to save?")
            if is_ok:
                with open("passwords.txt", "a") as data_file:
                    data_file.write(f"{website} | {email} | {password}\n")
                    self.website_entry.delete(0, tk.END)
                    self.password_entry.delete(0, tk.END)

    def show_saved_passwords(self):
        self.clear_window()
        saved_passwords_frame = ttk.Frame(self.master)
        saved_passwords_frame.pack(expand=True, fill='both')

        ttk.Label(saved_passwords_frame, text="Saved Passwords", font=('Arial', 20, 'bold')).pack(pady=20)

        list_frame = ttk.Frame(saved_passwords_frame)
        list_frame.pack(expand=True, fill='both', padx=10, pady=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.password_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=('Arial', 14),
                                           bg=self.fg_color, fg=self.bg_color)
        self.password_listbox.pack(side=tk.LEFT, expand=True, fill='both')

        scrollbar.config(command=self.password_listbox.yview)

        try:
            with open("passwords.txt", "r") as data_file:
                for line in data_file:
                    self.password_listbox.insert(tk.END, line.strip())
        except FileNotFoundError:
            self.password_listbox.insert(tk.END, "No passwords saved yet.")

        button_frame = ttk.Frame(saved_passwords_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Delete Selected", command=self.delete_password, width=15).pack(side=tk.LEFT,
                                                                                                      padx=5)
        ttk.Button(button_frame, text="Back", command=self.show_main_screen, width=15).pack(side=tk.LEFT, padx=5)

    def delete_password(self):
        try:
            selected_index = self.password_listbox.curselection()[0]
            selected_password = self.password_listbox.get(selected_index)

            self.password_listbox.delete(selected_index)

            with open("passwords.txt", "r") as f:
                lines = f.readlines()
            with open("passwords.txt", "w") as f:
                for line in lines:
                    if line.strip() != selected_password:
                        f.write(line)

            messagebox.showinfo("Success", "Password deleted successfully.")
        except IndexError:
            messagebox.showwarning("Warning", "Please select a password to delete.")

    def show_phishing_checker(self):
        self.clear_window()
        phishing_frame = ttk.Frame(self.master)
        phishing_frame.pack(expand=True, fill='both')

        ttk.Label(phishing_frame, text="Phishing Link Checker", font=('Arial', 20, 'bold')).pack(pady=20)

        ttk.Label(phishing_frame, text="Enter URL:").pack()
        self.url_entry = ttk.Entry(phishing_frame, width=30)
        self.url_entry.pack(pady=10)

        ttk.Button(phishing_frame, text="Check URL", command=self.check_phishing, width=20).pack(pady=20)

        self.result_label = ttk.Label(phishing_frame, text="", font=('Arial', 14), wraplength=300)
        self.result_label.pack(pady=20)

        ttk.Button(phishing_frame, text="Back", command=self.show_choice_screen, width=20).pack(pady=20)

    def check_phishing(self):
        url = self.url_entry.get()
        if not url:
            self.result_label.config(text="Please enter a URL")
            return

        suspicious_words = ['secure', 'account', 'login', 'bank', 'verify', 'update']
        parsed_url = urllib.parse.urlparse(url)

        if any(word in parsed_url.netloc.lower() for word in suspicious_words):
            self.result_label.config(text="Warning: This URL might be suspicious.", foreground=self.warning_color)
        elif parsed_url.netloc.split('.')[-1] not in ['com', 'org', 'net', 'edu', 'gov']:
            self.result_label.config(text="Caution: Unusual top-level domain detected.", foreground=self.warning_color)
        elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed_url.netloc):
            self.result_label.config(text="Caution: IP address used instead of domain name.",
                                     foreground=self.warning_color)
        else:
            self.result_label.config(text="No obvious signs of phishing detected.\nHowever, always be cautious.",
                                     foreground=self.success_color)

    def clear_window(self):
        for widget in self.master.winfo_children():
            widget.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()