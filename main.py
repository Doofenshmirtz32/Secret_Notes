from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_notes():
    title = entry_1.get()
    message = text_1.get("1.0", END)
    secret = entry_2.get()

    if len(title) == 0 or len(message) == 0 or len(secret) == 0:
        messagebox.showwarning(title="Error!", message="Please enter all info.")

    else:
        message_encrypted = encode(secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            entry_1.delete(0, END)
            entry_2.delete(0, END)
            text_1.delete(1.0, END)

def decrypt_notes():
    message_encrypted = text_1.get("1.0", END)
    master_secret = entry_2.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showwarning(title="Error!", message="Please enter all info.")
    else:
        try:
            decrypt_message = decode(master_secret, message_encrypted)
            text_1.delete("1.0", END)
            text_1.insert("1.0", decrypt_message)
        except:
            messagebox.showwarning(title="Error!", message="Please enter encrypted text.")




window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=20)


label_1 = Label(text="Enter your title", font=('Bahnschrift SemiBold', 12, "normal"))
label_1.config(padx=10, pady=10)
label_1.pack()

entry_1 = Entry(width=40)
entry_1.pack()

label_2 = Label(text="Enter your secret", font=('Bahnschrift SemiBold', 12, "normal"))
label_2.config(padx=10, pady=10)
label_2.pack()

text_1 = Text(width=35, height=20)
text_1.pack()

label_3 = Label(text="Enter master key", font=('Bahnschrift SemiBold', 12, "normal"))
label_3.config(padx=10, pady=10)
label_3.pack()

entry_2 = Entry(width=40)
entry_2.pack()

button_save = Button(text="Save & Encrypt", command=save_notes)
button_save.pack()

button_decrypt = Button(text="Decrypt", command=decrypt_notes)
button_decrypt.pack()

window.mainloop()