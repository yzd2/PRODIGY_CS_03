"""
Password Strength Checker
By Yazeed Alghamdi
"""

import re
import os
from tkinter import *
from tkinter import ttk, messagebox

class PasswordChecker:
    """Password strength checker with simplified logic"""
    
    def __init__(self, password_file="10-million-password-list-top-1000000.txt"):
        self.password_file = password_file
        self.leaked_passwords = self.load_common_passwords()
        
    def load_common_passwords(self):
        """Load common passwords from file if exists"""
        passwords = set()
        if os.path.exists(self.password_file):
            try:
                with open(self.password_file, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = {line.strip() for line in f}
            except Exception:
                pass  # If file can't be read, continue without it
        return passwords
    
    def check_password_leak(self, password):
        """Check if password is in leaked passwords database"""
        return password in self.leaked_passwords
    
    def check_length_score(self, password):
        """Calculate score based on password length"""
        length = len(password)
        if length < 8:
            return 0
        elif length < 12:
            return 1
        elif length < 16:
            return 2
        elif length < 20:
            return 3
        else:
            return 4
    
    def check_character_score(self, password):
        """Calculate score based on character variety"""
        score = 0
        if re.search(r'[A-Z]', password):  # Uppercase letters
            score += 1
        if re.search(r'[a-z]', password):  # Lowercase letters
            score += 1
        if re.search(r'[0-9]', password):  # Numbers
            score += 1
        if re.search(r'[^A-Za-z0-9]', password):  # Special characters
            score += 1
        return score
    
    def check_repetition(self, password):
        """Check for repeated characters"""
        return 0 if re.search(r'(.)\1{2,}', password) else 1
    
    def check_sequences(self, password):
        """Check for common sequences"""
        sequences = ['123', 'abc', 'qwerty', 'password', 'admin']
        password_lower = password.lower()
        for seq in sequences:
            if seq in password_lower:
                return 0
        return 1
    
    def calculate_total_score(self, password):
        """Calculate total password score"""
        if not password:
            return 0
            
        # Check if password is too common
        if self.check_password_leak(password):
            return 0
            
        # Calculate individual scores
        scores = [
            self.check_length_score(password),
            self.check_character_score(password),
            self.check_repetition(password),
            self.check_sequences(password)
        ]
        
        return sum(scores)
    
    def get_strength_level(self, score):
        """Convert score to strength level"""
        if score <= 2:
            return "Very Weak", "red"
        elif score <= 4:
            return "Weak", "orange"
        elif score <= 6:
            return "Moderate", "yellow"
        elif score <= 8:
            return "Strong", "green"
        else:
            return "Very Strong", "#00FF00"
    
    def get_feedback(self, password):
        """Get detailed feedback about password"""
        feedback = []
        
        # Length feedback
        length = len(password)
        if length < 8:
            feedback.append("❌ Password too short (min 8 characters)")
        elif length < 12:
            feedback.append("⚠️ Consider longer password (12+ characters)")
        else:
            feedback.append("✓ Good password length")
        
        # Character variety feedback
        if not re.search(r'[A-Z]', password):
            feedback.append("❌ Add uppercase letters")
        else:
            feedback.append("✓ Contains uppercase letters")
            
        if not re.search(r'[a-z]', password):
            feedback.append("❌ Add lowercase letters")
        else:
            feedback.append("✓ Contains lowercase letters")
            
        if not re.search(r'[0-9]', password):
            feedback.append("❌ Add numbers")
        else:
            feedback.append("✓ Contains numbers")
            
        if not re.search(r'[^A-Za-z0-9]', password):
            feedback.append("❌ Add special characters")
        else:
            feedback.append("✓ Contains special characters")
        
        # Repetition check
        if re.search(r'(.)\1{2,}', password):
            feedback.append("❌ Avoid repeating characters")
        
        # Common sequences check
        if any(seq in password.lower() for seq in ['123', 'abc', 'qwerty']):
            feedback.append("❌ Avoid common sequences")
        
        return feedback


class PasswordCheckerApp:
    """GUI Application for Password Strength Checker"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("500x550")
        self.root.configure(bg="#1C1C1C")
        
        # Initialize password checker
        self.checker = PasswordChecker()
        
        # Setup GUI
        self.setup_gui()
        
        # Bind Enter key to check password
        self.password_entry.bind('<Return>', lambda event: self.check_password())
    
    def setup_gui(self):
        """Setup the user interface"""
        
        # Header
        header_frame = Frame(self.root, bg="#1C1C1C")
        header_frame.pack(pady=20)
        
        Label(
            header_frame,
            text="🔐 Password Strength Checker",
            font=("Arial", 20, "bold"),
            bg="#1C1C1C",
            fg="cyan"
        ).pack()
        
        Label(
            header_frame,
            text="Check how strong your password is",
            font=("Arial", 10),
            bg="#1C1C1C",
            fg="lightblue"
        ).pack()
        
        # Password Entry
        entry_frame = Frame(self.root, bg="#1C1C1C")
        entry_frame.pack(pady=20, padx=20, fill=X)
        
        Label(
            entry_frame,
            text="Enter Password:",
            font=("Arial", 12),
            bg="#1C1C1C",
            fg="white"
        ).pack(side=LEFT, padx=(0, 10))
        
        self.password_var = StringVar()
        self.password_var.trace('w', self.on_password_change)
        
        self.password_entry = Entry(
            entry_frame,
            textvariable=self.password_var,
            font=("Arial", 12),
            width=30,
            show="•"
        )
        self.password_entry.pack(side=LEFT, fill=X, expand=True)
        
        # Show/Hide Password Button
        self.show_password_var = BooleanVar(value=False)
        Checkbutton(
            entry_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            bg="#1C1C1C",
            fg="white",
            selectcolor="#1C1C1C",
            activebackground="#1C1C1C"
        ).pack(side=LEFT, padx=(10, 0))
        
        # Strength Display
        strength_frame = Frame(self.root, bg="#1C1C1C")
        strength_frame.pack(pady=10, padx=20, fill=X)
        
        self.strength_label = Label(
            strength_frame,
            text="Enter a password above",
            font=("Arial", 14, "bold"),
            bg="#1C1C1C",
            fg="white"
        )
        self.strength_label.pack()
        
        # Score Display
        self.score_label = Label(
            strength_frame,
            text="Score: 0/10",
            font=("Arial", 10),
            bg="#1C1C1C",
            fg="white"
        )
        self.score_label.pack()
        
        # Progress Bar
        self.progress_bar = ttk.Progressbar(
            strength_frame,
            length=300,
            mode='determinate',
            maximum=10
        )
        self.progress_bar.pack(pady=5)
        
        # Check Button
        Button(
            self.root,
            text="Check Password Strength",
            command=self.check_password,
            font=("Arial", 12, "bold"),
            bg="#2980B9",
            fg="white",
            padx=20,
            pady=8,
            cursor="hand2"
        ).pack(pady=10)
        
        # Feedback Area
        feedback_frame = Frame(self.root, bg="#1C1C1C")
        feedback_frame.pack(pady=10, padx=20, fill=BOTH, expand=True)
        
        Label(
            feedback_frame,
            text="Password Analysis:",
            font=("Arial", 12, "bold"),
            bg="#1C1C1C",
            fg="white"
        ).pack(anchor=W, pady=(0, 5))
        
        # Scrollable Text for Feedback
        feedback_scroll = Scrollbar(feedback_frame)
        feedback_scroll.pack(side=RIGHT, fill=Y)
        
        self.feedback_text = Text(
            feedback_frame,
            height=8,
            width=50,
            wrap=WORD,
            bg="#2C2C2C",
            fg="white",
            font=("Arial", 10),
            yscrollcommand=feedback_scroll.set,
            state=DISABLED
        )
        self.feedback_text.pack(side=LEFT, fill=BOTH, expand=True)
        feedback_scroll.config(command=self.feedback_text.yview)
        
        # Footer
        footer_frame = Frame(self.root, bg="#1C1C1C")
        footer_frame.pack(pady=10)
        
        Label(
            footer_frame,
            text="💡 Tips: Use at least 12 characters with mix of letters, numbers, and symbols",
            font=("Arial", 9),
            bg="#1C1C1C",
            fg="#888888",
            wraplength=400
        ).pack()
        
        # Generate Password Button
        Button(
            footer_frame,
            text="Generate Strong Password",
            command=self.generate_password,
            font=("Arial", 10),
            bg="#27AE60",
            fg="white",
            padx=10,
            pady=5,
            cursor="hand2"
        ).pack(pady=(10, 0))
    
    def toggle_password_visibility(self):
        """Toggle between showing and hiding password"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def on_password_change(self, *args):
        """Real-time password strength checking"""
        password = self.password_var.get()
        
        # Don't check empty passwords
        if not password:
            self.strength_label.config(text="Enter a password above", fg="white")
            self.score_label.config(text="Score: 0/10")
            self.progress_bar['value'] = 0
            self.update_feedback_text([])
            return
        
        # Check password
        self.check_password(update_only=True)
    
    def check_password(self, update_only=False):
        """Check password strength and update display"""
        password = self.password_var.get()
        
        if not password:
            if not update_only:
                messagebox.showwarning("No Password", "Please enter a password to check.")
            return
        
        # Check if password is in leaked database
        if self.checker.check_password_leak(password):
            self.strength_label.config(text="❌ Password Found in Leaks", fg="red")
            self.score_label.config(text="Score: 0/10")
            self.progress_bar['value'] = 0
            self.update_feedback_text(["❌ This password has been compromised in data breaches!"])
            return
        
        # Calculate score and get feedback
        score = self.checker.calculate_total_score(password)
        strength, color = self.checker.get_strength_level(score)
        feedback = self.checker.get_feedback(password)
        
        # Update display
        self.strength_label.config(text=strength, fg=color)
        self.score_label.config(text=f"Score: {score}/10")
        self.progress_bar['value'] = score
        
        # Update feedback
        self.update_feedback_text(feedback)
        
        if not update_only:
            # Show message for weak passwords
            if score <= 4:
                messagebox.showwarning("Weak Password", 
                    "Your password is weak. Consider making it stronger.")
    
    def update_feedback_text(self, feedback_items):
        """Update the feedback text widget"""
        self.feedback_text.config(state=NORMAL)
        self.feedback_text.delete(1.0, END)
        
        if not feedback_items:
            self.feedback_text.insert(END, "No password entered")
        else:
            for item in feedback_items:
                self.feedback_text.insert(END, item + "\n")
        
        self.feedback_text.config(state=DISABLED)
    
    def generate_password(self):
        """Generate a strong random password"""
        import random
        import string
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"
        
        # Generate password with at least one of each type
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Add more random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend(random.choice(all_chars) for _ in range(8))
        
        # Shuffle the password
        random.shuffle(password)
        
        # Convert to string
        password = ''.join(password)
        
        # Update the password field
        self.password_var.set(password)
        self.check_password()


def main():
    """Main function to run the application"""
    root = Tk()
    app = PasswordCheckerApp(root)
    
    # Center the window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    # Test the password checker in console
    print("Password Strength Checker")
    print("=" * 50)
    
    checker = PasswordChecker()
    
    # Test some passwords
    test_passwords = [
 
    ]
    
    for pwd in test_passwords:
        score = checker.calculate_total_score(pwd)
        strength, _ = checker.get_strength_level(score)
        print(f"Password: {pwd}")
        print(f"Score: {score}/10 - Strength: {strength}")
        print("-" * 50)
    
    # Run GUI application
    main()
