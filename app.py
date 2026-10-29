import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from tkinter import messagebox, ttk

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from fpdf import FPDF


APP_TITLE = "EduTrack | Student Result Management System"
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "student_results.db")
PASS_MARK = 35


class InvalidMarksError(ValueError):
    """Raised when marks are outside the valid range."""


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Return a salted PBKDF2 hash in a format suitable for SQLite storage."""
    if not isinstance(password, str) or len(password) < 4:
        raise ValueError("Password must contain at least 4 characters.")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, digest_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def calculate_grade(percentage: float) -> str:
    if percentage >= 90:
        return "A+"
    if percentage >= 80:
        return "A"
    if percentage >= 70:
        return "B"
    if percentage >= 60:
        return "C"
    if percentage >= 50:
        return "D"
    if percentage >= PASS_MARK:
        return "E"
    return "F"


def validate_marks(value, max_marks=100) -> int:
    try:
        marks = int(value)
    except (TypeError, ValueError):
        raise InvalidMarksError("Marks must be a whole number.")
    if not 0 <= marks <= max_marks:
        raise InvalidMarksError(f"Marks must be between 0 and {max_marks}.")
    return marks


class DatabaseManager:
    """Owns the SQLite connection and all persistence operations."""

    def __init__(self, db_path=DB_FILE):
        self.connection = sqlite3.connect(db_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.create_tables()
        self.seed_default_admin()

    def create_tables(self):
        with self.connection:
            self.connection.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'student'))
                );
                CREATE TABLE IF NOT EXISTS students (
                    student_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE,
                    name TEXT NOT NULL,
                    department TEXT NOT NULL,
                    email TEXT,
                    attendance_pct REAL NOT NULL DEFAULT 0 CHECK(attendance_pct >= 0 AND attendance_pct <= 100),
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS subjects (
                    subject_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_name TEXT NOT NULL UNIQUE,
                    max_marks INTEGER NOT NULL DEFAULT 100 CHECK(max_marks > 0)
                );
                CREATE TABLE IF NOT EXISTS results (
                    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    student_id INTEGER NOT NULL,
                    subject_id INTEGER NOT NULL,
                    marks INTEGER NOT NULL CHECK(marks >= 0 AND marks <= 100),
                    updated_at TEXT NOT NULL,
                    UNIQUE(student_id, subject_id),
                    FOREIGN KEY(student_id) REFERENCES students(student_id) ON DELETE CASCADE,
                    FOREIGN KEY(subject_id) REFERENCES subjects(subject_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS activity_log (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS app_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL
                );
            """)
        # Safe migration for databases created by earlier versions.
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(students)")}
        if "attendance_pct" not in columns:
            self.connection.execute("ALTER TABLE students ADD COLUMN attendance_pct REAL NOT NULL DEFAULT 0")

    def seed_default_admin(self):
        row = self.connection.execute(
            "SELECT user_id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if not row:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO users(username, password, role) VALUES (?, ?, ?)",
                    ("admin", hash_password("admin"), "admin"),
                )

        # Apply the requested demo credentials once, including to an existing DB.
        # The marker prevents overriding passwords again on every future launch.
        migrated = self.connection.execute(
            "SELECT setting_value FROM app_settings WHERE setting_key = ?",
            ("demo_credentials_v1",),
        ).fetchone()
        if not migrated:
            with self.connection:
                admin_id = self.connection.execute(
                    "SELECT user_id FROM users WHERE username = ?", ("admin",)
                ).fetchone()["user_id"]
                self.connection.execute(
                    "UPDATE users SET password = ? WHERE user_id = ?",
                    (hash_password("admin"), admin_id),
                )
                self.connection.execute(
                    "UPDATE users SET password = ? WHERE role = 'student'",
                    (hash_password("root"),),
                )
                self.connection.execute(
                    "INSERT INTO app_settings(setting_key, setting_value) VALUES (?, ?)",
                    ("demo_credentials_v1", "complete"),
                )

    def authenticate(self, username, password):
        row = self.connection.execute(
            "SELECT * FROM users WHERE username = ?", (username.strip(),)
        ).fetchone()
        if row and verify_password(password, row["password"]):
            return dict(row)
        return None

    def add_student(self, name, department, email):
        name = name.strip()
        department = department.strip()
        email = email.strip()
        if not name or not department:
            raise ValueError("Student name and department are required.")
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Enter a valid email address.")
        with self.connection:
            cursor = self.connection.execute(
                "INSERT INTO students(name, department, email) VALUES (?, ?, ?)",
                (name, department, email),
            )
            numeric_id = cursor.lastrowid
            student_code = f"STU{numeric_id:04d}"
            # Create the login after the student ID is known.
            user_cursor = self.connection.execute(
                "INSERT INTO users(username, password, role) VALUES (?, ?, ?)",
                (student_code, hash_password("root"), "student"),
            )
            self.connection.execute(
                "UPDATE students SET user_id = ? WHERE student_id = ?",
                (user_cursor.lastrowid, numeric_id),
            )
        self.log_activity("admin", "ADD_STUDENT", f"Added {student_code}: {name}")
        return numeric_id, student_code

    def update_student(self, student_id, name, department, email):
        name, department, email = name.strip(), department.strip(), email.strip()
        if not name or not department:
            raise ValueError("Student name and department are required.")
        if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise ValueError("Enter a valid email address.")
        with self.connection:
            self.connection.execute(
                "UPDATE students SET name=?, department=?, email=? WHERE student_id=?",
                (name, department, email, student_id),
            )
        self.log_activity("admin", "UPDATE_STUDENT", f"Updated student ID {student_id}")

    def delete_student(self, student_id):
        with self.connection:
            row = self.connection.execute(
                "SELECT user_id FROM students WHERE student_id=?", (student_id,)
            ).fetchone()
            if row:
                self.connection.execute("DELETE FROM students WHERE student_id=?", (student_id,))
                if row["user_id"]:
                    self.connection.execute("DELETE FROM users WHERE user_id=?", (row["user_id"],))
        self.log_activity("admin", "DELETE_STUDENT", f"Deleted student ID {student_id}")

    def list_students(self):
        return self.connection.execute("""
            SELECT s.student_id, s.name, s.department, s.email,
                   u.username AS login_username
            FROM students s LEFT JOIN users u ON s.user_id=u.user_id
            ORDER BY s.student_id DESC
        """).fetchall()

    def get_student(self, student_id):
        return self.connection.execute(
            "SELECT * FROM students WHERE student_id=?", (student_id,)
        ).fetchone()

    def get_student_for_user(self, user_id):
        return self.connection.execute(
            "SELECT * FROM students WHERE user_id=?", (user_id,)
        ).fetchone()

    def add_subject(self, subject_name, max_marks=100):
        subject_name = subject_name.strip()
        if not subject_name:
            raise ValueError("Subject name is required.")
        try:
            maximum = int(max_marks)
        except (ValueError, TypeError):
            raise ValueError("Maximum marks must be a whole number.")
        if maximum != 100:
            raise ValueError("This project currently supports a maximum of 100 marks per subject.")
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO subjects(subject_name, max_marks) VALUES (?, ?)",
                    (subject_name, maximum),
                )
        except sqlite3.IntegrityError:
            raise ValueError("That subject already exists.")
        self.log_activity("admin", "ADD_SUBJECT", f"Added subject: {subject_name}")

    def list_subjects(self):
        return self.connection.execute(
            "SELECT * FROM subjects ORDER BY subject_name"
        ).fetchall()

    def delete_subject(self, subject_id):
        row = self.connection.execute("SELECT subject_name FROM subjects WHERE subject_id=?", (subject_id,)).fetchone()
        with self.connection:
            self.connection.execute("DELETE FROM subjects WHERE subject_id=?", (subject_id,))
        self.log_activity("admin", "DELETE_SUBJECT", f"Deleted subject: {row['subject_name'] if row else subject_id}")

    def save_marks(self, student_id, subject_id, marks):
        subject = self.connection.execute(
            "SELECT max_marks FROM subjects WHERE subject_id=?", (subject_id,)
        ).fetchone()
        if not subject:
            raise ValueError("Select a valid subject.")
        mark_value = validate_marks(marks, subject["max_marks"])
        with self.connection:
            self.connection.execute("""
                INSERT INTO results(student_id, subject_id, marks, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(student_id, subject_id)
                DO UPDATE SET marks=excluded.marks, updated_at=excluded.updated_at
            """, (student_id, subject_id, mark_value, datetime.now().isoformat(timespec="seconds")))
        self.log_activity("admin", "SAVE_MARKS", f"Student {student_id}, subject {subject_id}, marks {mark_value}")

    def result_for_student(self, student_id):
        rows = self.connection.execute("""
            SELECT sub.subject_id, sub.subject_name, sub.max_marks, res.marks, res.updated_at
            FROM subjects sub
            LEFT JOIN results res
              ON res.subject_id=sub.subject_id AND res.student_id=?
            ORDER BY sub.subject_name
        """, (student_id,)).fetchall()
        entered = [row for row in rows if row["marks"] is not None]
        total = sum(row["marks"] for row in entered)
        maximum = sum(row["max_marks"] for row in entered)
        percentage = (total / maximum * 100) if maximum else 0.0
        passed = bool(entered) and all(row["marks"] >= PASS_MARK for row in entered)
        return {
            "rows": rows,
            "entered": entered,
            "total": total,
            "maximum": maximum,
            "percentage": percentage,
            "grade": calculate_grade(percentage) if entered else "-",
            "status": ("PASS" if passed else "FAIL") if entered else "NOT ENTERED",
        }

    def class_analytics(self):
        students = self.list_students()
        summaries = []
        for student in students:
            result = self.result_for_student(student["student_id"])
            if result["entered"]:
                summaries.append({
                    "student_id": student["student_id"],
                    "name": student["name"],
                    "percentage": result["percentage"],
                    "status": result["status"],
                })
        if not summaries:
            return {"summaries": [], "average": 0.0, "passed": 0, "failed": 0}
        average = sum(s["percentage"] for s in summaries) / len(summaries)
        return {
            "summaries": summaries,
            "average": average,
            "passed": sum(s["status"] == "PASS" for s in summaries),
            "failed": sum(s["status"] == "FAIL" for s in summaries),
        }

    def change_password(self, user_id, current_password, new_password):
        row = self.connection.execute(
            "SELECT password FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not verify_password(current_password, row["password"]):
            raise ValueError("Current password is incorrect.")
        if len(new_password) < 8:
            raise ValueError("New password must contain at least 8 characters.")
        with self.connection:
            self.connection.execute(
                "UPDATE users SET password = ? WHERE user_id = ?",
                (hash_password(new_password), user_id),
            )
        self.log_activity("user", "CHANGE_PASSWORD", f"Password changed for user ID {user_id}")

    def reset_student_password(self, student_id):
        row = self.connection.execute(
            "SELECT user_id FROM students WHERE student_id = ?", (student_id,)
        ).fetchone()
        if not row or not row["user_id"]:
            raise ValueError("Student account was not found.")
        with self.connection:
            self.connection.execute(
                "UPDATE users SET password = ? WHERE user_id = ?",
                (hash_password("root"), row["user_id"]),
            )
        self.log_activity("admin", "RESET_PASSWORD", f"Reset password for student ID {student_id}")

    def log_activity(self, actor, action, details):
        with self.connection:
            self.connection.execute(
                "INSERT INTO activity_log(actor, action, details, created_at) VALUES (?, ?, ?, ?)",
                (str(actor), str(action), str(details), datetime.now().isoformat(timespec="seconds")),
            )

    def list_activity(self, limit=200):
        return self.connection.execute(
            "SELECT actor, action, details, created_at FROM activity_log ORDER BY log_id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()

    def set_attendance(self, student_id, percentage):
        try:
            value = float(percentage)
        except (TypeError, ValueError):
            raise ValueError("Attendance must be a number from 0 to 100.")
        if not 0 <= value <= 100:
            raise ValueError("Attendance must be between 0 and 100.")
        with self.connection:
            self.connection.execute("UPDATE students SET attendance_pct=? WHERE student_id=?", (value, student_id))
        self.log_activity("admin", "UPDATE_ATTENDANCE", f"Student {student_id}: attendance {value:.1f}%")

    def subject_analytics(self):
        rows = self.connection.execute("""
            SELECT sub.subject_name, sub.max_marks,
                   COUNT(res.result_id) AS completed,
                   AVG(res.marks * 100.0 / sub.max_marks) AS average_pct,
                   MAX(res.marks) AS highest,
                   SUM(CASE WHEN res.marks >= 35 THEN 1 ELSE 0 END) AS passed
            FROM subjects sub LEFT JOIN results res ON sub.subject_id=res.subject_id
            GROUP BY sub.subject_id, sub.subject_name, sub.max_marks
            ORDER BY sub.subject_name
        """).fetchall()
        output=[]
        for row in rows:
            completed = row["completed"] or 0
            output.append({
                "subject_name": row["subject_name"], "max_marks": row["max_marks"],
                "completed": completed, "average": float(row["average_pct"] or 0),
                "highest": row["highest"] if row["highest"] is not None else "-",
                "pass_rate": (row["passed"] or 0) / completed * 100 if completed else 0.0,
            })
        return output

    def close(self):
        self.connection.close()


class Subject:
    def __init__(self, subject_id, subject_name, max_marks=100):
        self.subject_id = subject_id
        self.subject_name = subject_name
        self.max_marks = max_marks


class Result:
    def __init__(self, marks, max_marks=100):
        self.__marks = validate_marks(marks, max_marks)
        self.max_marks = max_marks

    @property
    def marks(self):
        return self.__marks

    @property
    def percentage(self):
        return self.__marks / self.max_marks * 100

    @property
    def grade(self):
        return calculate_grade(self.percentage)


class User(ABC):
    def __init__(self, user_id, username, role, db):
        self._user_id = user_id
        self._username = username
        self._role = role
        self._db = db

    @property
    def username(self):
        return self._username

    @property
    def role(self):
        return self._role

    @abstractmethod
    def get_dashboard(self):
        """Return the dashboard appropriate to the role."""
        raise NotImplementedError


class Admin(User):
    def get_dashboard(self):
        return "admin"


class Student(User):
    def __init__(self, user_id, username, db):
        super().__init__(user_id, username, "student", db)
        self._student_record = db.get_student_for_user(user_id)

    def get_dashboard(self):
        return "student"


class StudentResultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        self.title(APP_TITLE)
        self.geometry("1240x800")
        self.minsize(1020, 680)
        self.db = DatabaseManager()
        self.current_user = None
        self.current_student_id = None
        self.selected_student_id = None
        self.selected_subject_id = None
        self._configure_ttk()
        self.show_login()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _configure_ttk(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", rowheight=32, font=("Segoe UI", 10),
                        background="#FFFFFF", fieldbackground="#FFFFFF", foreground="#263445",
                        borderwidth=0)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"),
                        background="#E8EFF8", foreground="#203B5C", padding=(8, 10),
                        relief="flat")
        style.map("Treeview", background=[("selected", "#CFE2FF")],
                  foreground=[("selected", "#10243A")])
        style.configure("TScrollbar", arrowsize=14)

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_window()
        self.configure(fg_color=("#F2F5FA", "#101827"))

        page = ctk.CTkFrame(self, fg_color="transparent")
        page.pack(fill="both", expand=True, padx=28, pady=28)

        brand = ctk.CTkFrame(page, corner_radius=20, fg_color=("#17365D", "#142A45"))
        brand.pack(side="left", fill="both", expand=True, padx=(0, 18))

        ctk.CTkLabel(
            brand, text="EDUTRACK", text_color="#FFFFFF",
            font=ctk.CTkFont(family="Segoe UI", size=30, weight="bold")
        ).pack(anchor="w", padx=34, pady=(48, 8))
        ctk.CTkLabel(
            brand, text="ACADEMIC MANAGEMENT SYSTEM",
            text_color="#BFD7F2", font=ctk.CTkFont(size=12, weight="bold")
        ).pack(anchor="w", padx=36, pady=(0, 24))
        ctk.CTkLabel(
            brand, text="One place for student records,\nresults and academic insights.",
            text_color="#FFFFFF", justify="left",
            font=ctk.CTkFont(size=25, weight="bold")
        ).pack(anchor="w", padx=36, pady=(0, 18))
        ctk.CTkLabel(
            brand, text="Manage student profiles, assessment marks, attendance,\nclass performance and printable reports.",
            text_color="#D7E3F2", justify="left",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", padx=36, pady=(0, 30))
        feature_strip = ctk.CTkFrame(brand, fg_color="#244A75", corner_radius=12)
        feature_strip.pack(fill="x", padx=34, pady=(4, 30))
        for label in ("STUDENT RECORDS", "RESULTS", "ANALYTICS"):
            ctk.CTkLabel(feature_strip, text=label, text_color="#FFFFFF",
                         font=ctk.CTkFont(size=10, weight="bold")).pack(
                             side="left", expand=True, padx=6, pady=15
                         )
        ctk.CTkLabel(
            brand, text="Python  •  CustomTkinter  •  SQLite",
            text_color="#BFD7F2", font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=36, pady=(0, 24))

        panel = ctk.CTkFrame(page, corner_radius=20, fg_color=("white", "#1B2638"),
                             border_width=1, border_color=("#DCE4EF", "#2B3B52"))
        panel.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(
            panel, text="Welcome back",
            font=ctk.CTkFont(size=27, weight="bold")
        ).pack(anchor="w", padx=38, pady=(62, 5))
        ctk.CTkLabel(
            panel, text="Sign in to continue to your workspace.",
            text_color=("gray40", "gray75"), font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=38, pady=(0, 28))

        ctk.CTkLabel(panel, text="USERNAME", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=("gray30", "gray75")).pack(anchor="w", padx=38, pady=(0, 6))
        self.login_username = ctk.CTkEntry(
            panel, placeholder_text="Enter your username", height=44, corner_radius=9
        )
        self.login_username.pack(fill="x", padx=38, pady=(0, 17))

        ctk.CTkLabel(panel, text="PASSWORD", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=("gray30", "gray75")).pack(anchor="w", padx=38, pady=(0, 6))
        self.login_password = ctk.CTkEntry(
            panel, placeholder_text="Enter your password", show="*", height=44, corner_radius=9
        )
        self.login_password.pack(fill="x", padx=38, pady=(0, 20))
        self.login_password.bind("<Return>", lambda _event: self.login())

        ctk.CTkButton(
            panel, text="Sign In", height=44, corner_radius=9,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2367A8", hover_color="#174A7A",
            command=self.login
        ).pack(fill="x", padx=38, pady=(0, 18))

        note = ctk.CTkFrame(panel, corner_radius=10, fg_color=("#EEF4FB", "#22344B"))
        note.pack(fill="x", padx=38, pady=(4, 0))
        ctk.CTkLabel(
            note, text="DEMO ADMIN ACCOUNT", text_color=("#244A75", "#BFD7F2"),
            font=ctk.CTkFont(size=10, weight="bold")
        ).pack(anchor="w", padx=13, pady=(10, 2))
        ctk.CTkLabel(
            note, text="Username: admin    Password: admin",
            text_color=("gray25", "gray85"), font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=13, pady=(0, 10))
        ctk.CTkLabel(
            panel, text="Student accounts are created by the administrator.",
            wraplength=340, justify="left", text_color=("gray45", "gray65"),
            font=ctk.CTkFont(size=11)
        ).pack(anchor="w", padx=38, pady=(16, 0))

    def login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()
        if not username or not password:
            messagebox.showwarning("Missing details", "Enter both username and password.")
            return
        account = self.db.authenticate(username, password)
        if not account:
            messagebox.showerror("Login failed", "Invalid username or password.")
            return
        if account["role"] == "admin":
            self.current_user = Admin(account["user_id"], account["username"], "admin", self.db)
            self.show_admin_dashboard()
        else:
            student = Student(account["user_id"], account["username"], self.db)
            if not student._student_record:
                messagebox.showerror("Account error", "No student profile is linked to this login.")
                return
            self.current_user = student
            self.current_student_id = student._student_record["student_id"]
            self.show_student_dashboard()

    def make_header(self, title, subtitle=""):
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=("#FFFFFF", "#172438"),
                              border_width=1, border_color=("#DCE4EF", "#2B3B52"))
        header.pack(fill="x", padx=0, pady=0)
        title_row = ctk.CTkFrame(header, fg_color="transparent")
        title_row.pack(fill="x", padx=24, pady=(16, 12))
        ctk.CTkLabel(title_row, text=title, font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
                     text_color=("#17365D", "#EAF2FC")).pack(side="left")
        if subtitle:
            ctk.CTkLabel(title_row, text=subtitle, text_color=("gray35", "gray70")).pack(side="left", padx=16)
        ctk.CTkButton(title_row, text="Toggle Theme", width=115, command=self.toggle_theme,
                      fg_color="#7D3C98", hover_color="#633974").pack(side="right", padx=(8, 0))
        ctk.CTkButton(title_row, text="Logout", width=100, command=self.logout).pack(side="right")

    def toggle_theme(self):
        current = ctk.get_appearance_mode().lower()
        ctk.set_appearance_mode("Light" if current == "dark" else "Dark")

    def actor_name(self):
        return self.current_user.username if self.current_user else "system"

    def logout(self):
        self.current_user = None
        self.current_student_id = None
        self.selected_student_id = None
        self.selected_subject_id = None
        self.show_login()

    def show_admin_dashboard(self):
        self.clear_window()
        self.make_header("Admin Dashboard", "Manage students, subjects, marks and reports")
        self.tabs = ctk.CTkTabview(
            self, corner_radius=14, segmented_button_fg_color=("#E8EFF8", "#24354C"),
            segmented_button_selected_color=("#2367A8", "#2367A8"),
            segmented_button_selected_hover_color=("#174A7A", "#174A7A"),
            segmented_button_unselected_color=("#E8EFF8", "#24354C"),
            segmented_button_unselected_hover_color=("#D7E5F5", "#304762")
        )
        self.tabs.pack(fill="both", expand=True, padx=20, pady=18)
        for name in ("Overview", "Students", "Subjects", "Enter Marks", "Attendance", "Analytics", "Subject Analytics", "Activity Log"):
            self.tabs.add(name)
        self.build_overview_tab()
        self.build_students_tab()
        self.build_subjects_tab()
        self.build_marks_tab()
        self.build_attendance_tab()
        self.build_analytics_tab()
        self.build_subject_analytics_tab()
        self.build_activity_tab()

    def build_overview_tab(self):
        tab = self.tabs.tab("Overview")
        ctk.CTkLabel(tab, text="Welcome to the result management dashboard",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", padx=18, pady=(18, 6))
        ctk.CTkLabel(tab, text="Use the tabs to manage student records, subjects, marks and class performance.",
                     wraplength=850, justify="left").pack(anchor="w", padx=18, pady=4)
        cards = ctk.CTkFrame(tab, fg_color="transparent")
        cards.pack(fill="x", padx=12, pady=24)
        student_count = len(self.db.list_students())
        subject_count = len(self.db.list_subjects())
        analytics = self.db.class_analytics()
        self.stat_card(cards, "Students", str(student_count), 0)
        self.stat_card(cards, "Subjects", str(subject_count), 1)
        total_with_results = len(analytics["summaries"])
        pass_pct = (analytics["passed"] / total_with_results * 100) if total_with_results else 0
        self.stat_card(cards, "Class Average", f'{analytics["average"]:.1f}%', 2)
        self.stat_card(cards, "Pass Percentage", f'{pass_pct:.1f}%', 3)
        self.stat_card(cards, "Passed / Failed", f'{analytics["passed"]} / {analytics["failed"]}', 4)
        ctk.CTkLabel(tab, text="Student login: username is the student ID (e.g. STU0001); initial password is root.",
                     wraplength=900, justify="left", text_color=("gray35", "gray70")).pack(anchor="w", padx=18, pady=15)

    def stat_card(self, parent, label, value, column):
        card = ctk.CTkFrame(parent, corner_radius=12)
        card.grid(row=0, column=column, padx=8, pady=8, sticky="nsew")
        parent.grid_columnconfigure(column, weight=1)
        ctk.CTkLabel(card, text=label, text_color=("gray30", "gray75")).pack(padx=18, pady=(18, 6))
        ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=25, weight="bold")).pack(padx=18, pady=(0, 18))

    def build_students_tab(self):
        tab = self.tabs.tab("Students")
        search_bar = ctk.CTkFrame(tab, fg_color="transparent")
        search_bar.pack(fill="x", padx=12, pady=(12, 0))
        ctk.CTkLabel(search_bar, text="Search students", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(4, 8))
        self.student_search = ctk.CTkEntry(search_bar, placeholder_text="Search by name, ID, department or email", width=360)
        self.student_search.pack(side="left", padx=4)
        self.student_search.bind("<KeyRelease>", lambda _event: self.refresh_students())
        self.department_filter = ctk.CTkOptionMenu(search_bar, values=["All Departments"], command=lambda _value: self.refresh_students(), width=155)
        self.department_filter.pack(side="left", padx=6)
        self.sort_menu = ctk.CTkOptionMenu(search_bar, values=["Newest first", "Name A-Z", "Department"], command=lambda _value: self.refresh_students(), width=135)
        self.sort_menu.pack(side="left", padx=6)
        ctk.CTkButton(search_bar, text="Clear Search", width=105,
                      command=self.clear_student_search).pack(side="left", padx=8)

        form = ctk.CTkFrame(tab)
        form.pack(fill="x", padx=12, pady=12)
        self.student_name = ctk.CTkEntry(form, placeholder_text="Full name", width=220)
        self.student_name.grid(row=0, column=0, padx=7, pady=10)
        self.student_department = ctk.CTkEntry(form, placeholder_text="Department / Branch", width=200)
        self.student_department.grid(row=0, column=1, padx=7, pady=10)
        self.student_email = ctk.CTkEntry(form, placeholder_text="Email (optional)", width=220)
        self.student_email.grid(row=0, column=2, padx=7, pady=10)
        ctk.CTkButton(form, text="Add Student", command=self.add_student_ui).grid(row=0, column=3, padx=7, pady=10)
        ctk.CTkButton(form, text="Update Selected", command=self.update_student_ui, fg_color="#4977a8").grid(row=0, column=4, padx=7, pady=10)
        ctk.CTkButton(form, text="Delete Selected", command=self.delete_student_ui, fg_color="#C0392B", hover_color="#922B21").grid(row=0, column=5, padx=7, pady=10)
        ctk.CTkButton(form, text="Reset Password", command=self.reset_selected_student_password,
                      fg_color="#8E44AD", hover_color="#6C3483").grid(row=0, column=6, padx=7, pady=10)
        ctk.CTkButton(form, text="Clear", command=self.clear_student_form, width=70).grid(row=0, column=7, padx=7, pady=10)
        self.student_tree = self.make_tree(tab, ("ID", "Name", "Department", "Email", "Login", "Grade"), (55, 180, 145, 200, 100, 70))
        self.student_tree.bind("<<TreeviewSelect>>", self.on_student_select)
        self.student_tree.bind("<Double-1>", self.on_student_select)
        self.refresh_students()

    def make_tree(self, parent, columns, widths):
        frame = ctk.CTkFrame(parent)
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        for column, width in zip(columns, widths):
            tree.heading(column, text=column)
            tree.column(column, width=width, anchor="center")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scroll.pack(side="right", fill="y", padx=(0, 8), pady=8)
        return tree

    def clear_student_search(self):
        self.student_search.delete(0, "end")
        self.refresh_students()

    def refresh_students(self):
        if not hasattr(self, "student_tree"):
            return
        for item in self.student_tree.get_children():
            self.student_tree.delete(item)
        rows = list(self.db.list_students())
        if hasattr(self, "department_filter"):
            departments = ["All Departments"] + sorted({r["department"] for r in rows})
            current_dept = self.department_filter.get()
            self.department_filter.configure(values=departments)
            if current_dept not in departments:
                current_dept = "All Departments"
                self.department_filter.set(current_dept)
            if current_dept != "All Departments":
                rows = [r for r in rows if r["department"] == current_dept]
        sort_mode = self.sort_menu.get() if hasattr(self, "sort_menu") else "Newest first"
        if sort_mode == "Name A-Z":
            rows.sort(key=lambda r: r["name"].casefold())
        elif sort_mode == "Department":
            rows.sort(key=lambda r: (r["department"].casefold(), r["name"].casefold()))
        query = self.student_search.get().strip().casefold() if hasattr(self, "student_search") else ""
        for index, row in enumerate(rows):
            result = self.db.result_for_student(row["student_id"])
            values = (row["student_id"], row["name"], row["department"], row["email"] or "", row["login_username"] or "", result["grade"])
            if query and not any(query in str(value).casefold() for value in values):
                continue
            self.student_tree.insert("", "end", values=values, tags=("evenrow" if index % 2 == 0 else "oddrow",))
        self.student_tree.tag_configure("evenrow", background="#F4F7FB")
        self.student_tree.tag_configure("oddrow", background="#EAF1FB")

    def reset_selected_student_password(self):
        if not self.selected_student_id:
            messagebox.showwarning("Select student", "Select a student row first.")
            return
        if not messagebox.askyesno(
            "Reset password",
            "Reset this student's password to root? The student should change it after logging in."
        ):
            return
        try:
            self.db.reset_student_password(self.selected_student_id)
            messagebox.showinfo(
                "Password reset",
                "The student's initial password is now root."
            )
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Reset failed", str(exc))

    def on_student_select(self, _event=None):
        selected = self.student_tree.selection()
        if not selected:
            return
        values = self.student_tree.item(selected[0], "values")
        self.selected_student_id = int(values[0])
        row = self.db.get_student(self.selected_student_id)
        if row:
            self.student_name.delete(0, "end")
            self.student_name.insert(0, row["name"])
            self.student_department.delete(0, "end")
            self.student_department.insert(0, row["department"])
            self.student_email.delete(0, "end")
            self.student_email.insert(0, row["email"] or "")

    def clear_student_form(self):
        self.selected_student_id = None
        for entry in (self.student_name, self.student_department, self.student_email):
            entry.delete(0, "end")
        for item in self.student_tree.selection():
            self.student_tree.selection_remove(item)

    def add_student_ui(self):
        try:
            student_id, username = self.db.add_student(
                self.student_name.get(), self.student_department.get(), self.student_email.get()
            )
            self.refresh_students()
            self.refresh_marks_student_options()
            self.refresh_attendance()
            self.refresh_subject_analytics()
            self.clear_student_form()
            self.refresh_overview_if_present()
            self.refresh_analytics_if_present()
            messagebox.showinfo("Student added", f"Student ID: STU{student_id:04d}\nLogin username: {username}\nInitial password: root")
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Could not add student", str(exc))

    def update_student_ui(self):
        if not self.selected_student_id:
            messagebox.showwarning("Select student", "Select a student row first.")
            return
        try:
            self.db.update_student(
                self.selected_student_id, self.student_name.get(),
                self.student_department.get(), self.student_email.get()
            )
            self.refresh_students()
            self.refresh_overview_if_present()
            self.refresh_analytics_if_present()
            messagebox.showinfo("Updated", "Student details updated.")
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Update failed", str(exc))

    def delete_student_ui(self):
        if not self.selected_student_id:
            messagebox.showwarning("Select student", "Select a student row first.")
            return
        if messagebox.askyesno("Confirm deletion", "Delete this student and all their results?"):
            try:
                self.db.delete_student(self.selected_student_id)
                self.clear_student_form()
                self.refresh_students()
                self.refresh_marks_student_options()
                self.refresh_attendance()
                self.refresh_subject_analytics()
                self.refresh_overview_if_present()
                self.refresh_analytics_if_present()
            except sqlite3.Error as exc:
                messagebox.showerror("Delete failed", str(exc))

    def build_subjects_tab(self):
        tab = self.tabs.tab("Subjects")
        form = ctk.CTkFrame(tab)
        form.pack(fill="x", padx=12, pady=12)
        self.subject_name = ctk.CTkEntry(form, placeholder_text="Subject name", width=300)
        self.subject_name.pack(side="left", padx=10, pady=12)
        ctk.CTkButton(form, text="Add Subject (max 100)", command=self.add_subject_ui).pack(side="left", padx=8)
        ctk.CTkButton(form, text="Delete Selected", command=self.delete_subject_ui,
                      fg_color="#b64040", hover_color="#8e2c2c").pack(side="left", padx=8)
        self.subject_tree = self.make_tree(tab, ("ID", "Subject", "Maximum Marks"), (100, 500, 180))
        self.refresh_subjects()

    def refresh_subjects(self):
        for item in self.subject_tree.get_children():
            self.subject_tree.delete(item)
        for row in self.db.list_subjects():
            self.subject_tree.insert("", "end", values=(row["subject_id"], row["subject_name"], row["max_marks"]))
        if hasattr(self, "marks_subject_menu"):
            self.refresh_marks_subject_options()

    def add_subject_ui(self):
        try:
            self.db.add_subject(self.subject_name.get())
            self.subject_name.delete(0, "end")
            self.refresh_subjects()
            self.refresh_overview_if_present()
            self.refresh_marks_table()
            self.refresh_analytics_if_present()
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Could not add subject", str(exc))

    def delete_subject_ui(self):
        selected = self.subject_tree.selection()
        if not selected:
            messagebox.showwarning("Select subject", "Select a subject row first.")
            return
        subject_id = int(self.subject_tree.item(selected[0], "values")[0])
        if messagebox.askyesno("Confirm deletion", "Delete this subject and its marks for all students?"):
            try:
                self.db.delete_subject(subject_id)
                self.refresh_subjects()
                self.refresh_marks_subject_options()
                self.refresh_marks_table()
                self.refresh_overview_if_present()
                self.refresh_analytics_if_present()
            except sqlite3.Error as exc:
                messagebox.showerror("Delete failed", str(exc))

    def build_marks_tab(self):
        tab = self.tabs.tab("Enter Marks")
        form = ctk.CTkFrame(tab)
        form.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(form, text="Student").grid(row=0, column=0, padx=8, pady=(12, 4), sticky="w")
        self.marks_student_menu = ctk.CTkOptionMenu(form, values=["No students"], command=self.on_marks_student_change, width=250)
        self.marks_student_menu.grid(row=1, column=0, padx=8, pady=(0, 12))
        ctk.CTkLabel(form, text="Subject").grid(row=0, column=1, padx=8, pady=(12, 4), sticky="w")
        self.marks_subject_menu = ctk.CTkOptionMenu(form, values=["No subjects"], command=self.on_marks_subject_change, width=250)
        self.marks_subject_menu.grid(row=1, column=1, padx=8, pady=(0, 12))
        ctk.CTkLabel(form, text="Marks (0–100)").grid(row=0, column=2, padx=8, pady=(12, 4), sticky="w")
        self.marks_entry = ctk.CTkEntry(form, placeholder_text="e.g. 85", width=130)
        self.marks_entry.grid(row=1, column=2, padx=8, pady=(0, 12))
        ctk.CTkButton(form, text="Save / Update Marks", command=self.save_marks_ui).grid(row=1, column=3, padx=8, pady=(0, 12))
        ctk.CTkButton(form, text="View Selected Result", command=self.view_selected_result).grid(row=1, column=4, padx=8, pady=(0, 12))
        self.marks_tree = self.make_tree(tab, ("Subject", "Marks", "Max", "Last Updated"), (300, 100, 100, 250))
        self.refresh_marks_student_options()
        self.refresh_marks_subject_options()

    def refresh_marks_student_options(self):
        if not hasattr(self, "marks_student_menu"):
            return
        students = self.db.list_students()
        self.student_map = {f'STU{row["student_id"]:04d} - {row["name"]}': row["student_id"] for row in students}
        values = list(self.student_map) or ["No students"]
        self.marks_student_menu.configure(values=values)
        self.marks_student_menu.set(values[0])
        self.on_marks_student_change(values[0])

    def refresh_marks_subject_options(self):
        if not hasattr(self, "marks_subject_menu"):
            return
        subjects = self.db.list_subjects()
        self.subject_map = {row["subject_name"]: row["subject_id"] for row in subjects}
        values = list(self.subject_map) or ["No subjects"]
        self.marks_subject_menu.configure(values=values)
        self.marks_subject_menu.set(values[0])
        self.on_marks_subject_change(values[0])

    def on_marks_student_change(self, value):
        self.selected_marks_student_id = self.student_map.get(value) if hasattr(self, "student_map") else None
        self.refresh_marks_table()

    def on_marks_subject_change(self, value):
        self.selected_subject_id = self.subject_map.get(value) if hasattr(self, "subject_map") else None

    def refresh_marks_table(self):
        if not hasattr(self, "marks_tree"):
            return
        for item in self.marks_tree.get_children():
            self.marks_tree.delete(item)
        student_id = getattr(self, "selected_marks_student_id", None)
        if not student_id:
            return
        result = self.db.result_for_student(student_id)
        for row in result["rows"]:
            self.marks_tree.insert("", "end", values=(
                row["subject_name"],
                row["marks"] if row["marks"] is not None else "Not entered",
                row["max_marks"],
                row["updated_at"] or "-"
            ))

    def save_marks_ui(self):
        student_id = getattr(self, "selected_marks_student_id", None)
        subject_id = self.subject_map.get(self.marks_subject_menu.get())
        if not student_id or not subject_id:
            messagebox.showwarning("Missing selection", "Add at least one student and one subject first.")
            return
        try:
            self.db.save_marks(student_id, subject_id, self.marks_entry.get().strip())
            self.marks_entry.delete(0, "end")
            self.refresh_marks_table()
            self.refresh_overview_if_present()
            self.refresh_analytics_if_present()
            self.refresh_subject_analytics()
            self.refresh_activity()
            messagebox.showinfo("Saved", "Marks saved successfully.")
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Invalid marks", str(exc))

    def view_selected_result(self):
        student_id = getattr(self, "selected_marks_student_id", None)
        if not student_id:
            messagebox.showwarning("Select student", "Select a student first.")
            return
        self.show_result_dialog(student_id)

    def show_result_dialog(self, student_id, student_name=None):
        student = self.db.get_student(student_id)
        if not student:
            return
        result = self.db.result_for_student(student_id)
        dialog = ctk.CTkToplevel(self)
        dialog.title(f'Result - {student["name"]}')
        dialog.geometry("650x520")
        dialog.transient(self)
        ctk.CTkLabel(dialog, text=student["name"], font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(18, 4))
        ctk.CTkLabel(dialog, text=f'{student["department"]}  |  ID: STU{student_id:04d}').pack(pady=(0, 10))
        tree = ttk.Treeview(dialog, columns=("Subject", "Marks", "Maximum", "Status"), show="headings", height=10)
        for col, width in zip(("Subject", "Marks", "Maximum", "Status"), (270, 90, 100, 100)):
            tree.heading(col, text=col)
            tree.column(col, width=width, anchor="center")
        tree.pack(fill="both", expand=True, padx=16, pady=8)
        for row in result["rows"]:
            marks = row["marks"]
            status = "Not entered" if marks is None else ("Pass" if marks >= PASS_MARK else "Fail")
            tree.insert("", "end", values=(row["subject_name"], marks if marks is not None else "-", row["max_marks"], status))
        summary = f'Total: {result["total"]}/{result["maximum"]}    Percentage: {result["percentage"]:.2f}%    Grade: {result["grade"]}    Status: {result["status"]}'
        ctk.CTkLabel(dialog, text=summary, font=ctk.CTkFont(size=13, weight="bold"), wraplength=600).pack(pady=8)
        ctk.CTkButton(dialog, text="Generate PDF Report Card", command=lambda: self.generate_pdf(student_id)).pack(pady=(2, 16))

    def build_attendance_tab(self):
        tab = self.tabs.tab("Attendance")
        form = ctk.CTkFrame(tab)
        form.pack(fill="x", padx=12, pady=12)
        ctk.CTkLabel(form, text="Student").grid(row=0, column=0, padx=8, pady=(10, 4), sticky="w")
        self.attendance_student_menu = ctk.CTkOptionMenu(form, values=["No students"], width=300)
        self.attendance_student_menu.grid(row=1, column=0, padx=8, pady=(0, 12))
        ctk.CTkLabel(form, text="Attendance % (0–100)").grid(row=0, column=1, padx=8, pady=(10, 4), sticky="w")
        self.attendance_entry = ctk.CTkEntry(form, placeholder_text="e.g. 92.5", width=160)
        self.attendance_entry.grid(row=1, column=1, padx=8, pady=(0, 12))
        ctk.CTkButton(form, text="Save Attendance", command=self.save_attendance_ui,
                      fg_color="#148F77", hover_color="#117864").grid(row=1, column=2, padx=8, pady=(0, 12))
        self.attendance_tree = self.make_tree(tab, ("Student ID", "Name", "Department", "Attendance %"), (120, 260, 220, 150))
        self.refresh_attendance()

    def refresh_attendance(self):
        if not hasattr(self, "attendance_tree"):
            return
        students = self.db.list_students()
        labels = {f'STU{r["student_id"]:04d} - {r["name"]}': r["student_id"] for r in students}
        self.attendance_map = labels
        options = list(labels) or ["No students"]
        self.attendance_student_menu.configure(values=options)
        if self.attendance_student_menu.get() not in options:
            self.attendance_student_menu.set(options[0])
        for item in self.attendance_tree.get_children():
            self.attendance_tree.delete(item)
        for row in students:
            full = self.db.get_student(row["student_id"])
            self.attendance_tree.insert("", "end", values=(f'STU{row["student_id"]:04d}', row["name"], row["department"], f'{full["attendance_pct"]:.1f}%'))

    def save_attendance_ui(self):
        student_id = self.attendance_map.get(self.attendance_student_menu.get())
        if not student_id:
            messagebox.showwarning("Select student", "Add a student first.")
            return
        try:
            self.db.set_attendance(student_id, self.attendance_entry.get().strip())
            self.attendance_entry.delete(0, "end")
            self.refresh_attendance()
            self.refresh_overview_if_present()
            messagebox.showinfo("Saved", "Attendance updated successfully.")
        except (ValueError, sqlite3.Error) as exc:
            messagebox.showerror("Invalid attendance", str(exc))

    def build_subject_analytics_tab(self):
        tab = self.tabs.tab("Subject Analytics")
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=10)
        ctk.CTkButton(top, text="Refresh Subject Analytics", command=self.refresh_subject_analytics).pack(side="left", padx=4)
        self.subject_analytics_tree = self.make_tree(tab, ("Subject", "Completed", "Pending", "Average %", "Highest", "Pass Rate %"), (240, 100, 100, 120, 100, 130))
        self.refresh_subject_analytics()

    def refresh_subject_analytics(self):
        if not hasattr(self, "subject_analytics_tree"):
            return
        for item in self.subject_analytics_tree.get_children():
            self.subject_analytics_tree.delete(item)
        student_count = len(self.db.list_students())
        for row in self.db.subject_analytics():
            pending = max(student_count - row["completed"], 0)
            self.subject_analytics_tree.insert("", "end", values=(row["subject_name"], row["completed"], pending, f'{row["average"]:.2f}', row["highest"], f'{row["pass_rate"]:.1f}'))

    def build_activity_tab(self):
        tab = self.tabs.tab("Activity Log")
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=10)
        ctk.CTkButton(top, text="Refresh Log", command=self.refresh_activity).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Export Class Result PDF", command=self.generate_class_pdf,
                      fg_color="#148F77", hover_color="#117864").pack(side="left", padx=4)
        self.activity_tree = self.make_tree(tab, ("Time", "User", "Action", "Details"), (170, 130, 180, 520))
        self.refresh_activity()

    def refresh_activity(self):
        if not hasattr(self, "activity_tree"):
            return
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        for row in self.db.list_activity():
            self.activity_tree.insert("", "end", values=(row["created_at"], row["actor"], row["action"], row["details"]))

    def generate_class_pdf(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(title="Save class result sheet", defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")], initialfile="Class_Result_Sheet.pdf")
        if not path:
            return
        try:
            pdf = FPDF(orientation="L", unit="mm", format="A4")
            pdf.set_auto_page_break(auto=True, margin=12)
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, "CLASS RESULT SHEET", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%d-%m-%Y %H:%M")}', new_x="LMARGIN", new_y="NEXT")
            widths=[22, 55, 40, 25, 25, 25, 25, 25]
            headers=["ID", "Student", "Department", "Attendance", "Total", "Percent", "Grade", "Status"]
            pdf.set_font("Helvetica", "B", 9)
            for h,w in zip(headers,widths): pdf.cell(w,8,h,border=1,align="C")
            pdf.ln()
            pdf.set_font("Helvetica", "", 8)
            for student in self.db.list_students():
                result=self.db.result_for_student(student["student_id"])
                rec=self.db.get_student(student["student_id"])
                vals=[f'STU{student["student_id"]:04d}', student["name"], student["department"],
                      f'{rec["attendance_pct"]:.1f}%', f'{result["total"]}/{result["maximum"]}',
                      f'{result["percentage"]:.1f}%', result["grade"], result["status"]]
                for value,w in zip(vals,widths):
                    safe=str(value).encode("latin-1","replace").decode("latin-1")
                    pdf.cell(w,7,safe[:30],border=1,align="C")
                pdf.ln()
            pdf.output(path)
            messagebox.showinfo("Export complete", f"Class result PDF saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("PDF error", str(exc))

    def build_analytics_tab(self):
        tab = self.tabs.tab("Analytics")
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", padx=12, pady=10)
        ctk.CTkButton(top, text="Refresh Analytics", command=self.refresh_analytics).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Export Student Results to CSV", command=self.export_csv).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Export Class PDF", command=self.generate_class_pdf).pack(side="left", padx=4)
        self.analytics_summary = ctk.CTkLabel(tab, text="", font=ctk.CTkFont(size=15, weight="bold"))
        self.analytics_summary.pack(pady=5)
        self.insights_label = ctk.CTkLabel(tab, text="", justify="left", anchor="w", wraplength=900)
        self.insights_label.pack(fill="x", padx=16, pady=4)
        self.chart_frame = ctk.CTkFrame(tab)
        self.chart_frame.pack(fill="both", expand=True, padx=12, pady=10)
        self.refresh_analytics()

    def refresh_analytics(self):
        if not hasattr(self, "chart_frame"):
            return
        for child in self.chart_frame.winfo_children():
            child.destroy()
        data = self.db.class_analytics()
        self.analytics_summary.configure(
            text=f'Class average: {data["average"]:.2f}%    Passed: {data["passed"]}    Failed: {data["failed"]}'
        )
        ranked = sorted(data["summaries"], key=lambda item: item["percentage"], reverse=True)
        top_text = f'Top performer: {ranked[0]["name"]} ({ranked[0]["percentage"]:.1f}%)' if ranked else 'Top performer: No results yet'
        support = [item for item in ranked if item["percentage"] < 50 or item["status"] == "FAIL"]
        support_text = ', '.join(f'{item["name"]} ({item["percentage"]:.1f}%)' for item in support[:5]) or 'None currently identified'
        if hasattr(self, "insights_label"):
            self.insights_label.configure(text=f'{top_text}    |    Students needing support: {support_text}')
        fig = Figure(figsize=(8.2, 4.2), dpi=100)
        ax = fig.add_subplot(111)
        if data["summaries"]:
            labels = [s["name"][:14] for s in data["summaries"]]
            values = [s["percentage"] for s in data["summaries"]]
            ax.bar(labels, values)
            ax.set_ylim(0, 100)
            ax.set_ylabel("Percentage")
            ax.set_title("Student Performance")
            ax.tick_params(axis="x", rotation=25)
            fig.tight_layout()
        else:
            ax.text(0.5, 0.5, "Enter marks to display class analytics", ha="center", va="center")
            ax.set_axis_off()
        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def refresh_overview_if_present(self):
        if hasattr(self, "tabs") and "Overview" in self.tabs._tab_dict:
            current = self.tabs.get()
            self.tabs.delete("Overview")
            self.tabs.add("Overview")
            self.build_overview_tab()
            if current in self.tabs._tab_dict:
                self.tabs.set(current)

    def refresh_analytics_if_present(self):
        if hasattr(self, "chart_frame"):
            self.refresh_analytics()

    def export_csv(self):
        import csv
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            title="Export results", defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")], initialfile="student_results.csv"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as file:
                writer = csv.writer(file)
                writer.writerow(["Student ID", "Name", "Department", "Email", "Attendance %", "Subject", "Marks", "Maximum", "Subject Status", "Percentage", "Grade", "Overall Status"])
                for student in self.db.list_students():
                    result = self.db.result_for_student(student["student_id"])
                    profile = self.db.get_student(student["student_id"])
                    for row in result["rows"]:
                        marks = row["marks"]
                        subject_status = "Pending" if marks is None else ("Pass" if marks >= PASS_MARK else "Fail")
                        writer.writerow([
                            f'STU{student["student_id"]:04d}', student["name"], student["department"],
                            student["email"] or "", f'{profile["attendance_pct"]:.1f}', row["subject_name"],
                            marks if marks is not None else "", row["max_marks"], subject_status,
                            f'{result["percentage"]:.2f}', result["grade"], result["status"]
                        ])
            messagebox.showinfo("Export complete", f"CSV saved to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def generate_pdf(self, student_id):
        from tkinter import filedialog
        student = self.db.get_student(student_id)
        if not student:
            messagebox.showerror("Not found", "Student record no longer exists.")
            return
        result = self.db.result_for_student(student_id)
        safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", student["name"]).strip("_") or "student"
        path = filedialog.asksaveasfilename(
            title="Save report card", defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"Report_Card_STU{student_id:04d}_{safe_name}.pdf"
        )
        if not path:
            return
        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 18)
            pdf.cell(0, 12, "STUDENT REPORT CARD", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.ln(4)
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 8, f'Student ID: STU{student_id:04d}', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Name: {student["name"]}', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Department: {student["department"]}', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Email: {student["email"] or "-"}', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Attendance: {student["attendance_pct"]:.1f}%', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%d-%m-%Y %H:%M")}', new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            widths = [82, 32, 35, 35]
            pdf.set_font("Helvetica", "B", 10)
            for label, width in zip(["Subject", "Marks", "Maximum", "Status"], widths):
                pdf.cell(width, 9, label, border=1, align="C")
            pdf.ln()
            pdf.set_font("Helvetica", "", 10)
            for row in result["rows"]:
                marks = row["marks"]
                status = "Not entered" if marks is None else ("Pass" if marks >= PASS_MARK else "Fail")
                subject_name = row["subject_name"].encode("latin-1", "replace").decode("latin-1")
                pdf.cell(widths[0], 9, subject_name[:38], border=1)
                pdf.cell(widths[1], 9, str(marks) if marks is not None else "-", border=1, align="C")
                pdf.cell(widths[2], 9, str(row["max_marks"]), border=1, align="C")
                pdf.cell(widths[3], 9, status, border=1, align="C")
                pdf.ln()
            pdf.ln(7)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, f'Total: {result["total"]}/{result["maximum"]}', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Percentage: {result["percentage"]:.2f}%', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Grade: {result["grade"]}', new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f'Overall Status: {result["status"]}', new_x="LMARGIN", new_y="NEXT")
            pdf.output(path)
            messagebox.showinfo("PDF generated", f"Report card saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("PDF error", f"Could not generate PDF:\n{exc}")

    def show_student_dashboard(self):
        self.clear_window()
        student = self.db.get_student(self.current_student_id)
        self.make_header("Student Dashboard", f'Welcome, {student["name"]}')
        content = ctk.CTkFrame(self)
        content.pack(fill="both", expand=True, padx=22, pady=20)
        ctk.CTkLabel(content, text="My Academic Result", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", padx=16, pady=(16, 8))
        ctk.CTkLabel(content, text=f'Student ID: STU{self.current_student_id:04d}   |   Department: {student["department"]}   |   Email: {student["email"] or "-"}   |   Attendance: {student["attendance_pct"]:.1f}%', wraplength=900, justify="left").pack(anchor="w", padx=16, pady=(0, 12))
        self.student_result_tree = self.make_tree(content, ("Subject", "Marks", "Maximum", "Subject Status", "Last Updated"), (300, 100, 100, 140, 230))
        self.refresh_student_result()
        self.student_summary = ctk.CTkLabel(content, text="", font=ctk.CTkFont(size=16, weight="bold"))
        self.student_summary.pack(pady=12)
        actions = ctk.CTkFrame(content, fg_color="transparent")
        actions.pack(pady=8)
        ctk.CTkButton(actions, text="Refresh Result", command=self.refresh_student_result).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Download PDF Report", command=lambda: self.generate_pdf(self.current_student_id)).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Change Password", command=self.open_change_password_dialog,
                      fg_color="#8E44AD", hover_color="#6C3483").pack(side="left", padx=8)

    def open_change_password_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Change Password")
        dialog.geometry("420x330")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Change Your Password",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(22, 12))
        current_entry = ctk.CTkEntry(dialog, placeholder_text="Current password", show="*", width=300)
        current_entry.pack(pady=8)
        new_entry = ctk.CTkEntry(dialog, placeholder_text="New password (8+ characters)", show="*", width=300)
        new_entry.pack(pady=8)
        confirm_entry = ctk.CTkEntry(dialog, placeholder_text="Confirm new password", show="*", width=300)
        confirm_entry.pack(pady=8)

        def save_password():
            current = current_entry.get()
            new = new_entry.get()
            confirm = confirm_entry.get()
            if new != confirm:
                messagebox.showerror("Password mismatch", "The new passwords do not match.", parent=dialog)
                return
            try:
                self.db.change_password(self.current_user._user_id, current, new)
                messagebox.showinfo("Success", "Your password has been changed.", parent=dialog)
                dialog.destroy()
            except ValueError as exc:
                messagebox.showerror("Could not change password", str(exc), parent=dialog)

        ctk.CTkButton(dialog, text="Save New Password", command=save_password,
                      fg_color="#2471A3", hover_color="#1A5276").pack(pady=16)

    def refresh_student_result(self):
        if not hasattr(self, "student_result_tree"):
            return
        for item in self.student_result_tree.get_children():
            self.student_result_tree.delete(item)
        result = self.db.result_for_student(self.current_student_id)
        for row in result["rows"]:
            marks = row["marks"]
            status = "Not entered" if marks is None else ("Pass" if marks >= PASS_MARK else "Fail")
            self.student_result_tree.insert("", "end", values=(
                row["subject_name"], marks if marks is not None else "-",
                row["max_marks"], status, row["updated_at"] or "-"
            ))
        self.student_summary.configure(
            text=f'Total: {result["total"]}/{result["maximum"]}    Percentage: {result["percentage"]:.2f}%    Grade: {result["grade"]}    Status: {result["status"]}'
        )

    def on_close(self):
        try:
            self.db.close()
        finally:
            self.destroy()


if __name__ == "__main__":
    app = StudentResultApp()
    app.mainloop()
