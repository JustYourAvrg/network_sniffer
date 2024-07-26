import customtkinter as ctk


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class MessageBox:
    def showerror(title: str, message: str):
        master = ctk.CTk()
        master.title(title)
        master.geometry('400x200')
        master.resizable(0, 0)

        error_frame = ctk.CTkFrame(master, width=400, height=200)
        error_frame.grid(row=0, column=0)
        error_frame.grid_propagate(0)

        error_frame.grid_rowconfigure(0, weight=1)
        error_frame.grid_columnconfigure(0, weight=1)

        error_message = ctk.CTkTextbox(error_frame, font=ctk.CTkFont(size=10, weight='bold'))
        error_message.insert(ctk.END, message)
        error_message.configure(state='disabled')
        error_message.grid(row=0, column=0, sticky='ew', padx=10, pady=10)
        
        master.mainloop()