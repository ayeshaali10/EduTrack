# EduTrack — Student Result Management System

A clean, professional college ERP-style desktop application built with Python, CustomTkinter and SQLite. It is intentionally designed to remain easy to explain in a project viva.

## Main features
- Role-based Admin and Student login
- Student management (add, view, update, delete, search)
- Subject management and marks entry/update
- Automatic total, percentage, grade and pass/fail calculation
- Attendance percentage management
- Dashboard statistics and class performance charts
- Subject-wise analytics and pending-mark visibility
- Student performance insights based on transparent rules
- Individual PDF report cards and consolidated class result sheet
- CSV export (opens in Excel)
- Password change and Admin password reset
- Activity log for important Admin actions
- Dark/light theme toggle
- SQLite persistence with a migration for the attendance column

## Requirements
- Python 3.10+
- Windows/macOS/Linux
- Internet only for installing dependencies

## Setup on Windows
1. Extract this ZIP.
2. Open the extracted folder in VS Code.
3. Open the terminal in the project folder.
4. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
5. Run the app:
   ```powershell
   python app.py
   ```

## Default Admin login
- Username: `admin`
- Password: `admin`

These short credentials are for a college demonstration only, not for a real deployment.

## Student login
When Admin creates a student:
- Username: generated student code such as `STU0001`
- Initial password: `root`

Students can change their password from their dashboard. Admin can reset a student's password from the student-management screen.

## Existing database and migration
The app uses `student_results.db` in the same folder as `app.py`. It creates the database if it does not exist and adds the `attendance_pct` column to an older `students` table if needed. It does not intentionally delete existing student, subject or result records. On the first launch after this update, it sets the Admin password to `admin` and all existing student account passwords to `root` once; it will not repeat this reset on later launches.

**Before first launch of this redesigned copy:** close the old app and make a backup copy of your existing `student_results.db`. Place that database beside this `app.py` if you want to continue using the existing records. If your old database lives in another folder, copy it into this folder before launching.

## Simple grading rules
- Pass mark per subject: 35/100
- Overall result: Pass only when all entered subjects are at least 35
- Grade scale: A+ (90+), A (80+), B (70+), C (60+), D (50+), E (35+), F (below 35)
- All subjects use a maximum of 100 marks

These grade boundaries are project assumptions; confirm them with your teacher if your college uses different rules.

## Notes
- CSV export is Excel-compatible; it does not require the `openpyxl` package.
- Performance insights are rule-based summaries, not AI predictions.
- This is a local academic demo, not a production-ready ERP.
