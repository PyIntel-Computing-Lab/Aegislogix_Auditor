from django.shortcuts import render, redirect
from datetime import date
from .models import User, LogFile, Threat, Report


# ===========================
# HOME
# ===========================
def home(request):
    return render(request, "home.html")


# ===========================
# REGISTER
# ===========================
def register(request):

    if request.method == "POST":

        print("===== REGISTER =====")
        print(request.POST)

        full_name = request.POST.get("full_name")
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        print("Full Name:", full_name)
        print("Username:", username)
        print("Email:", email)
        print("Phone:", phone)
        print("Password:", password)
        print("Confirm Password:", confirm_password)

        if password != confirm_password:
            return render(request, "register.html", {
                "error": "Passwords do not match."
            })

        if User.objects.filter(email=email).exists():
            return render(request, "register.html", {
                "error": "Email already exists."
            })

        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {
                "error": "Username already exists."
            })

        User.objects.create(
            full_name=full_name,
            username=username,
            email=email,
            phone=phone,
            password=password
        )

        return redirect("login")

    return render(request, "register.html")


# ===========================
# LOGIN
# ===========================
def login(request):

    if request.method == "POST":

        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            user = User.objects.get(email=email, password=password)

            request.session["user_id"] = user.id
            request.session["username"] = user.username

            return redirect("dashboard")

        except User.DoesNotExist:
            return render(request, "login.html", {
                "error": "Invalid Email or Password"
            })

    return render(request, "login.html")


# ===========================
# DASHBOARD
# ===========================
def dashboard(request):

    # Check login
    if "user_id" not in request.session:
        return redirect("login")

    # Get currently logged-in user
    user_id = request.session["user_id"]

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        request.session.flush()
        return redirect("login")

    # --------------------------------
    # USER-SPECIFIC LOGS
    # --------------------------------

    user_logs = LogFile.objects.filter(
        user=user
    ).order_by("-uploaded_at")

    # --------------------------------
    # USER'S THREATS
    # --------------------------------

    user_threats = Threat.objects.filter(
        log__user=user
    ).order_by("-detected_on")

    # --------------------------------
    # REPORTS
    # --------------------------------

    # Your current Report model does not
    # have a direct user field.
    # Therefore reports are counted globally.
    total_reports = Report.objects.count()

    # --------------------------------
    # DASHBOARD COUNTS
    # --------------------------------

    total_logs = user_logs.count()

    total_threats = user_threats.count()

    # --------------------------------
    # RECENT LOGS
    # --------------------------------

    recent_logs = user_logs[:5]

    # --------------------------------
    # RECENT THREATS
    # --------------------------------

    recent_threats = user_threats[:5]

    # --------------------------------
    # SECURITY STATUS
    # --------------------------------

    if total_threats == 0:

        security_status = "Secure"
        security_message = "No threats detected."

    elif total_threats <= 3:

        security_status = "Warning"
        security_message = "Some suspicious activity detected."

    else:

        security_status = "Critical"
        security_message = "Multiple security threats detected."

    # --------------------------------
    # CONTEXT
    # --------------------------------

    context = {

        "username": user.username,

        "user": user,

        "total_logs": total_logs,

        "total_users": User.objects.count(),

        "total_threats": total_threats,

        "total_reports": total_reports,

        "recent_logs": recent_logs,

        "recent_threats": recent_threats,

        "security_status": security_status,

        "security_message": security_message,
    }

    return render(
        request,
        "dashboard.html",
        context
    )
# ===========================
# UPLOAD LOGS
# ===========================
def upload_logs(request):

    # User must be logged in
    if "user_id" not in request.session:
        return redirect("login")

    # Get logged-in user
    try:
        user = User.objects.get(id=request.session["user_id"])
    except User.DoesNotExist:
        request.session.flush()
        return redirect("login")

    # ===========================
    # POST - UPLOAD FILE
    # ===========================
    if request.method == "POST":

        log_file = request.FILES.get("log_file")
        log_type = request.POST.get("log_type")
        description = request.POST.get("description", "").strip()

        # ---------------------------
        # Validate file
        # ---------------------------
        if not log_file:
            return render(request, "upload_logs.html", {
                "logs": LogFile.objects.filter(
                    user=user
                ).order_by("-uploaded_at"),
                "error": "Please select a log file."
            })

        # ---------------------------
        # Validate log type
        # ---------------------------
        allowed_types = [
            "Apache",
            "Nginx",
            "System",
            "Application"
        ]

        if log_type not in allowed_types:
            return render(request, "upload_logs.html", {
                "logs": LogFile.objects.filter(
                    user=user
                ).order_by("-uploaded_at"),
                "error": "Please select a valid log type."
            })

        # ---------------------------
        # Validate description
        # ---------------------------
        if not description:
            return render(request, "upload_logs.html", {
                "logs": LogFile.objects.filter(
                    user=user
                ).order_by("-uploaded_at"),
                "error": "Please enter a description."
            })

        # ===========================
        # READ FILE CONTENT
        # ===========================

        try:

            file_content = log_file.read()

            log_text = file_content.decode(
                "utf-8",
                errors="ignore"
            ).lower()

        except Exception:

            log_text = ""

        # Also include description in analysis
        analysis_text = (
            log_text + " " + description.lower()
        )

        # ===========================
        # CREATE LOG RECORD
        # ===========================

        uploaded_log = LogFile.objects.create(
            user=user,
            log_file=log_file,
            log_type=log_type,
            description=description
        )

        # ===========================
        # THREAT RULES
        # ===========================

        threat_rules = [

            {
                "keywords": ["sql injection", "sql-injection"],
                "name": "SQL Injection",
                "severity": "High"
            },

            {
                "keywords": ["unauthorized access"],
                "name": "Unauthorized Access",
                "severity": "High"
            },

            {
                "keywords": ["unauthorized"],
                "name": "Unauthorized Access",
                "severity": "High"
            },

            {
                "keywords": ["malware"],
                "name": "Malware Detected",
                "severity": "High"
            },

            {
                "keywords": ["virus"],
                "name": "Virus Found",
                "severity": "High"
            },

            {
                "keywords": ["cyber attack", "attack detected"],
                "name": "Cyber Attack",
                "severity": "High"
            },

            {
                "keywords": ["failed login"],
                "name": "Failed Login Attempt",
                "severity": "Medium"
            },

            {
                "keywords": ["xss", "cross site scripting"],
                "name": "Cross Site Scripting",
                "severity": "Medium"
            }
        ]

        # ===========================
        # DETECT MULTIPLE THREATS
        # ===========================

        detected_threats = []

        for rule in threat_rules:

            found = False

            for keyword in rule["keywords"]:

                if keyword in analysis_text:
                    found = True
                    break

            if found:

                # Avoid duplicate threat names
                if rule["name"] not in detected_threats:

                    detected_threats.append(
                        rule["name"]
                    )

                    # Create Threat
                    Threat.objects.create(
                        log=uploaded_log,
                        threat_name=rule["name"],
                        severity=rule["severity"],
                        status="Detected",
                        detected_on=date.today()
                    )

                    # Create Report
                    Report.objects.create(
                        report_name=f"{rule['name']} Report",
                        description=(
                            f"AegisLogix detected "
                            f"{rule['name']} in the uploaded "
                            f"log file '{uploaded_log.log_file.name}'. "
                            f"Severity: {rule['severity']}. "
                            f"Log type: {log_type}. "
                            f"Description: {description}"
                        )
                    )

        # ===========================
        # SUCCESS MESSAGE
        # ===========================

        if detected_threats:

            threat_message = (
                f"{len(detected_threats)} threat(s) detected: "
                + ", ".join(detected_threats)
            )

        else:

            threat_message = (
                "Log uploaded successfully. "
                "No known threats were detected."
            )

        # ===========================
        # SHOW UPDATED LOG LIST
        # ===========================

        logs = LogFile.objects.filter(
            user=user
        ).order_by("-uploaded_at")

        return render(request, "upload_logs.html", {
            "logs": logs,
            "success": threat_message
        })

    # ===========================
    # GET - UPLOAD PAGE
    # ===========================

    logs = LogFile.objects.filter(
        user=user
    ).order_by("-uploaded_at")

    return render(request, "upload_logs.html", {
        "logs": logs
    })


# ===========================
# THREAT DETECTION
# ===========================

def threat(request):

    if "user_id" not in request.session:
        return redirect("login")

    threats = Threat.objects.select_related(
        "log"
    ).order_by("-detected_on", "-id")

    total_threats = threats.count()

    high_threats = threats.filter(
        severity="High"
    ).count()

    medium_threats = threats.filter(
        severity="Medium"
    ).count()

    low_threats = threats.filter(
        severity="Low"
    ).count()

    detected_threats = threats.filter(
        status="Detected"
    ).count()

    resolved_threats = threats.filter(
        status="Resolved"
    ).count()

    context = {
        "threats": threats,
        "total_threats": total_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "detected_threats": detected_threats,
        "resolved_threats": resolved_threats,
    }

    return render(request, "threat.html", context)

# ===========================
# REPORTS
# ===========================
def reports(request):

    if "user_id" not in request.session:
        return redirect("login")

    report_list = Report.objects.all().order_by("created_at")

    return render(request, "reports.html", {
        "reports": report_list
    })
# ===========================
# PROFILE
# ===========================
def profile(request):

    # Check login
    if "user_id" not in request.session:
        return redirect("login")

    try:
        user = User.objects.get(
            id=request.session["user_id"]
        )
    except User.DoesNotExist:
        request.session.flush()
        return redirect("login")

    return render(request, "profile.html", {
        "user": user
    })


# ===========================
# SETTINGS / EDIT PROFILE
# ===========================
def settings(request):

    # Check login
    if "user_id" not in request.session:
        return redirect("login")

    try:
        user = User.objects.get(
            id=request.session["user_id"]
        )
    except User.DoesNotExist:
        request.session.flush()
        return redirect("login")

    # ===========================
    # UPDATE PROFILE
    # ===========================
    if request.method == "POST":

        full_name = request.POST.get("full_name", "").strip()
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        phone = request.POST.get("phone", "").strip()
        new_password = request.POST.get("password", "").strip()
        confirm_password = request.POST.get("confirm_password", "").strip()

        # ---------------------------
        # Basic validation
        # ---------------------------

        if not full_name:
            return render(request, "settings.html", {
                "user": user,
                "error": "Full Name cannot be empty."
            })

        if not username:
            return render(request, "settings.html", {
                "user": user,
                "error": "Username cannot be empty."
            })

        if not email:
            return render(request, "settings.html", {
                "user": user,
                "error": "Email cannot be empty."
            })

        if not phone:
            return render(request, "settings.html", {
                "user": user,
                "error": "Phone Number cannot be empty."
            })

        # ---------------------------
        # Check duplicate username
        # ---------------------------

        if User.objects.filter(
            username=username
        ).exclude(id=user.id).exists():

            return render(request, "settings.html", {
                "user": user,
                "error": "Username already exists."
            })

        # ---------------------------
        # Check duplicate email
        # ---------------------------

        if User.objects.filter(
            email=email
        ).exclude(id=user.id).exists():

            return render(request, "settings.html", {
                "user": user,
                "error": "Email already exists."
            })

        # ---------------------------
        # Password validation
        # ---------------------------

        if new_password:

            if new_password != confirm_password:

                return render(request, "settings.html", {
                    "user": user,
                    "error": "New password and confirm password do not match."
                })

            if len(new_password) < 6:

                return render(request, "settings.html", {
                    "user": user,
                    "error": "Password must contain at least 6 characters."
                })

        # ---------------------------
        # Save updated information
        # ---------------------------

        user.full_name = full_name
        user.username = username
        user.email = email
        user.phone = phone

        if new_password:
            user.password = new_password

        user.save()

        # Update session username
        request.session["username"] = user.username

        return render(request, "settings.html", {
            "user": user,
            "success": "Profile updated successfully!"
        })

    # GET request
    return render(request, "settings.html", {
        "user": user
    })


# ===========================
# FORGOT PASSWORD
# ===========================
def forgot_password(request):

    if request.method == "POST":

        email = request.POST.get("email", "").strip()
        new_password = request.POST.get("password", "").strip()
        confirm_password = request.POST.get(
            "confirm_password", ""
        ).strip()

        # ---------------------------
        # Check email
        # ---------------------------

        if not email:

            return render(request, "forgot_password.html", {
                "error": "Please enter your email address."
            })

        # ---------------------------
        # Check whether email exists
        # ---------------------------

        try:

            user = User.objects.get(email=email)

        except User.DoesNotExist:

            return render(request, "forgot_password.html", {
                "error": "No account found with this email address."
            })

        # ---------------------------
        # Check password
        # ---------------------------

        if not new_password:

            return render(request, "forgot_password.html", {
                "error": "Please enter a new password.",
                "email": email
            })

        # ---------------------------
        # Check password length
        # ---------------------------

        if len(new_password) < 6:

            return render(request, "forgot_password.html", {
                "error": "Password must contain at least 6 characters.",
                "email": email
            })

        # ---------------------------
        # Confirm password
        # ---------------------------

        if new_password != confirm_password:

            return render(request, "forgot_password.html", {
                "error": "New password and confirm password do not match.",
                "email": email
            })

        # ---------------------------
        # Update password
        # ---------------------------

        user.password = new_password
        user.save()

        return render(request, "forgot_password.html", {
            "success": "Password updated successfully! You can now login.",
        })

    return render(request, "forgot_password.html")


# ===========================
# LOGOUT
# ===========================
def logout(request):
    request.session.flush()
    return redirect("login")