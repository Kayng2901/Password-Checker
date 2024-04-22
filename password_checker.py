import tkinter as tk
from tkinter import ttk, messagebox
import requests
import hashlib

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5char)
    return get_password_leaks_count(response, tail)

def check_password():
    password = password_entry.get()
    count = pwned_api_check(password)
    if count:
        messagebox.showwarning('Password Check', f'{password} was found {count} times... Time for a change.')
    else:
        messagebox.showinfo('Password Check', f'{password} was not found. Safe to go.')

# Create main window
root = tk.Tk()
root.title('Password Checker')

# Create a label and entry widget for password input
ttk.Label(root, text="Enter Password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = ttk.Entry(root, show="*")
password_entry.grid(row=0, column=1, padx=10, pady=10)

# Create a button to trigger password check
check_button = ttk.Button(root, text="Check Password", command=check_password)
check_button.grid(row=1, columnspan=2, padx=10, pady=10)

# Run the Tkinter event loop
root.mainloop()
