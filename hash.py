import hashlib
import tkinter as tk
from tkinter import filedialog

print("Select an option (1 or 2):")
user_choice = input("1. Calculate hash of a file\n" + "2. Calculate hash of a text line\n")

def calculate_hash(file_path):
    with open(file_path, 'rb') as file:
        hash = hashlib.sha256()
        while chunk := file.read(8192): # The walrus operator := is used to assign the result of the expression file.read(8192) to the variable  chunk  while also checking if the value is truthy (i.e., not empty or  None ). It combines the assignment and the truth check in a single expression.
            hash.update(chunk)
    return hash.hexdigest()

def select_file():
    global result_hash
    file_path = filedialog.askopenfilename(title="Select file")
    
    if file_path:
        result_hash = calculate_hash(file_path)
        
    root.destroy() # close the root window

def calculate_string_hash(user_input):
    hash = hashlib.sha256()
    hash.update(user_input.encode('utf-8'))
    return hash.hexdigest()

if user_choice == "1":
    root = tk.Tk() # initializes a new instance of the Tk class, which creates a new window (this is the main or "root" window)

    # Center the window on the screen
    root.geometry('{0}x{1}+{2}+{3}'.format(150, 50, root.winfo_screenwidth() // 2 - 150 // 2, root.winfo_screenheight() // 2 - 50 // 2))
    root.attributes('-topmost', True)  # Keep the window on top
    tk.Button(root, text="Select file", command=select_file).pack() # creates a button widget inside the button_window
    root.mainloop() # the mainloop() method keeps the window open and responsive until it's explicitly closed
          
elif user_choice == "2":
    user_input = input("Enter text:\n")
    result_hash = calculate_string_hash(user_input)

print('Calculated hash:', result_hash)