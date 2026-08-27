from django.shortcuts import render, redirect
from datetime import date
from .models import User, LogFile, Threat, Report


# ============================================================
# HOME
# ============================================================
def home(request):
    return render(request, "home.html")


# ============================================================
# REGISTER
# ============================================================
def register(request):

    if request.method == "POST":

        full_name = request.POST.get("full_name")
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # Password confirmation
        if password != confirm_password:
            return render(request, "register.html", {
                "error": "Passwords do not match."
            })

        # Email validation
        if User.objects.filter(email=email).exists():
            return render(request, "register.html", {
                "error": "Email already exists."
            })

        # Username validation
        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {
                "error": "Username already exists."
            })

        # Create user
        User.objects.create(
            full_name=full_name,
            username=username,
            email=email,
            phone=phone,
            password=password
        )

        return redirect("login")

    return render(request, "register.html")


# ============================================================
# LOGIN
# ============================================================
def login(request):

    if request.method == "POST":

        email = request.POST.get("email")
        password = request.POST.get("password")

        try:

            user = User.objects.get(
                email=email,
                password=password
            )

            request.session["user_id"] = user.id
            request.session["username"] = user.username

            return redirect("dashboard")

        except User.DoesNotExist:

            return render(request, "login.html", {
                "error": "Invalid Email or Password"
            })

    return render(request, "login.html")


# ============================================================
# DASHBOARD
# ============================================================
def dashboard(request):

    if "user_id" not in request.session:
        return redirect("login")

    context = {

        "total_logs":
            LogFile.objects.count(),

        "total_users":
            User.objects.count(),

        "total_threats":
            Threat.objects.count(),

        "total_reports":
            Report.objects.count(),

        "recent_logs":
            LogFile.objects.order_by(
                "-uploaded_at"
            )[:5],

        "username":
            request.session.get("username"),
    }

    return render(
        request,
        "dashboard.html",
        context
    )


# ============================================================
# UPLOAD LOGS + ADVANCED THREAT DETECTION
# ============================================================
def upload_logs(request):

    # --------------------------------------------------------
    # LOGIN CHECK
    # --------------------------------------------------------
    if "user_id" not in request.session:
        return redirect("login")

    try:

        user = User.objects.get(
            id=request.session["user_id"]
        )

    except User.DoesNotExist:

        request.session.flush()

        return redirect("login")

    # ========================================================
    # POST REQUEST
    # ========================================================
    if request.method == "POST":

        # ----------------------------------------------------
        # GET FORM DATA
        # ----------------------------------------------------
        log_file = request.FILES.get("log_file")

        log_type = request.POST.get(
            "log_type"
        )

        description = request.POST.get(
            "description",
            ""
        ).strip()

        # ----------------------------------------------------
        # VALIDATE FILE
        # ----------------------------------------------------
        if not log_file:

            logs = LogFile.objects.filter(
                user=user
            ).order_by("-uploaded_at")

            return render(
                request,
                "upload_logs.html",
                {
                    "logs": logs,
                    "error":
                        "Please select a log file."
                }
            )

        # ----------------------------------------------------
        # VALIDATE LOG TYPE
        # ----------------------------------------------------
        allowed_types = [
            "Apache",
            "Nginx",
            "System",
            "Application"
        ]

        if log_type not in allowed_types:

            logs = LogFile.objects.filter(
                user=user
            ).order_by("-uploaded_at")

            return render(
                request,
                "upload_logs.html",
                {
                    "logs": logs,
                    "error":
                        "Please select a valid log type."
                }
            )

        # ----------------------------------------------------
        # VALIDATE DESCRIPTION
        # ----------------------------------------------------
        if not description:

            logs = LogFile.objects.filter(
                user=user
            ).order_by("-uploaded_at")

            return render(
                request,
                "upload_logs.html",
                {
                    "logs": logs,
                    "error":
                        "Please enter a description."
                }
            )

        # ====================================================
        # READ LOG FILE
        # ====================================================

        try:

            file_content = log_file.read()

            log_text = file_content.decode(
                "utf-8",
                errors="ignore"
            ).lower()

        except Exception:

            log_text = ""

        # ----------------------------------------------------
        # COMBINE LOG CONTENT + DESCRIPTION
        # ----------------------------------------------------
        analysis_text = (
            log_text
            + " "
            + description.lower()
        )

        # ====================================================
        # SAVE LOG FILE
        # ====================================================

        uploaded_log = LogFile.objects.create(
            user=user,
            log_file=log_file,
            log_type=log_type,
            description=description
        )

        # ====================================================
        # ADVANCED THREAT DETECTION RULES
        # ====================================================

        threat_rules = [

            # ------------------------------------------------
            # SQL INJECTION
            # ------------------------------------------------
            {
                "keywords": [
                    "sql injection",
                    "sql-injection",
                    "union select",
                    "' or 1=1",
                    "or 1=1",
                    "drop table",
                    "select * from"
                ],
                "name": "SQL Injection",
                "severity": "High"
            },

            # ------------------------------------------------
            # UNAUTHORIZED ACCESS
            # ------------------------------------------------
            {
                "keywords": [
                    "unauthorized access",
                    "unauthorized user",
                    "unauthorized",
                    "access denied",
                    "permission denied"
                ],
                "name": "Unauthorized Access",
                "severity": "High"
            },

            # ------------------------------------------------
            # MALWARE
            # ------------------------------------------------
            {
                "keywords": [
                    "malware",
                    "malicious software",
                    "malicious program"
                ],
                "name": "Malware Detected",
                "severity": "High"
            },

            # ------------------------------------------------
            # VIRUS
            # ------------------------------------------------
            {
                "keywords": [
                    "virus",
                    "virus detected",
                    "infected file",
                    "infected system"
                ],
                "name": "Virus Detected",
                "severity": "High"
            },

            # ------------------------------------------------
            # CYBER ATTACK
            # ------------------------------------------------
            {
                "keywords": [
                    "cyber attack",
                    "attack detected",
                    "security attack"
                ],
                "name": "Cyber Attack",
                "severity": "High"
            },

            # ------------------------------------------------
            # FAILED LOGIN
            # ------------------------------------------------
            {
                "keywords": [
                    "failed login",
                    "login failed",
                    "authentication failed",
                    "invalid login",
                    "login failure",
                    "authentication error"
                ],
                "name": "Failed Login Attempt",
                "severity": "Medium"
            },

            # ------------------------------------------------
            # BRUTE FORCE
            # ------------------------------------------------
            {
                "keywords": [
                    "brute force",
                    "multiple failed login",
                    "multiple login failures",
                    "too many login attempts",
                    "repeated login failure",
                    "repeated failed login"
                ],
                "name": "Brute Force Attack",
                "severity": "High"
            },

            # ------------------------------------------------
            # CROSS SITE SCRIPTING
            # ------------------------------------------------
            {
                "keywords": [
                    "<script>",
                    "xss",
                    "cross site scripting",
                    "javascript injection"
                ],
                "name": "Cross-Site Scripting (XSS)",
                "severity": "Medium"
            },

            # ------------------------------------------------
            # COMMAND INJECTION
            # ------------------------------------------------
            {
                "keywords": [
                    "command injection",
                    "cmd injection",
                    "shell injection",
                    ";whoami",
                    ";cat /etc/passwd",
                    "|whoami"
                ],
                "name": "Command Injection",
                "severity": "High"
            },

            # ------------------------------------------------
            # PATH TRAVERSAL
            # ------------------------------------------------
            {
                "keywords": [
                    "../",
                    "..\\",
                    "directory traversal",
                    "path traversal"
                ],
                "name": "Path Traversal",
                "severity": "High"
            },

            # ------------------------------------------------
            # SUSPICIOUS HTTP REQUEST
            # ------------------------------------------------
            {
                "keywords": [
                    "suspicious request",
                    "malicious request",
                    "invalid http request",
                    "suspicious http"
                ],
                "name": "Suspicious HTTP Request",
                "severity": "Medium"
            },

            # ------------------------------------------------
            # PORT SCANNING
            # ------------------------------------------------
            {
                "keywords": [
                    "port scan",
                    "port scanning",
                    "network scan",
                    "nmap scan"
                ],
                "name": "Port Scanning Activity",
                "severity": "Medium"
            },

            # ------------------------------------------------
            # PRIVILEGE ESCALATION
            # ------------------------------------------------
            {
                "keywords": [
                    "privilege escalation",
                    "root access",
                    "administrator privilege",
                    "admin privilege"
                ],
                "name": "Privilege Escalation",
                "severity": "High"
            }
        ]

        # ====================================================
        # DETECT THREATS
        # ====================================================

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

                    # ----------------------------------------
                    # SAVE THREAT
                    # ----------------------------------------

                    Threat.objects.create(

                        log=uploaded_log,

                        threat_name=
                            rule["name"],

                        severity=
                            rule["severity"],

                        status=
                            "Detected",

                        detected_on=
                            date.today()
                    )

        # ====================================================
        # CREATE SECURITY REPORT
        # ====================================================

        if detected_threats:

            threat_names = ", ".join(
                detected_threats
            )

            Report.objects.create(

                report_name=(
                    "Security Report - "
                    f"{uploaded_log.log_file.name}"
                ),

                description=(

                    "AegisLogix detected "
                    f"{len(detected_threats)} "
                    "security threat(s) "
                    "in the uploaded log. "

                    f"Threats detected: "
                    f"{threat_names}. "

                    f"Log file: "
                    f"{uploaded_log.log_file.name}. "

                    f"Log type: "
                    f"{log_type}. "

                    f"Uploaded by: "
                    f"{user.username}. "

                    f"Description: "
                    f"{description}"
                )
            )

        # ====================================================
        # SUCCESS MESSAGE
        # ====================================================

        if detected_threats:

            threat_message = (

                "Security analysis completed. "

                f"{len(detected_threats)} "
                "threat(s) detected: "

                + ", ".join(
                    detected_threats
                )
            )

        else:

            threat_message = (

                "Log uploaded and analyzed "
                "successfully. "

                "No known security threats "
                "were detected."
            )

        # ====================================================
        # GET UPDATED LOGS
        # ====================================================

        logs = LogFile.objects.filter(
            user=user
        ).order_by("-uploaded_at")

        return render(
            request,
            "upload_logs.html",
            {
                "logs": logs,
                "success":
                    threat_message
            }
        )

    # ========================================================
    # GET REQUEST
    # ========================================================

    logs = LogFile.objects.filter(
        user=user
    ).order_by("-uploaded_at")

    return render(
        request,
        "upload_logs.html",
        {
            "logs": logs
        }
    )


# ============================================================
# THREAT DETECTION
# ============================================================
def threat(request):

    if "user_id" not in request.session:
        return redirect("login")

    # -----------------------------------------
    # GET FILTER VALUES
    # -----------------------------------------
    search = request.GET.get(
        "search",
        ""
    ).strip()

    severity = request.GET.get(
        "severity",
        ""
    ).strip()

    log_type = request.GET.get(
        "log_type",
        ""
    ).strip()

    status = request.GET.get(
        "status",
        ""
    ).strip()

    # -----------------------------------------
    # GET ALL THREATS
    # -----------------------------------------
    threats = Threat.objects.select_related(
        "log"
    ).all().order_by(
        "-detected_on",
        "-id"
    )

    # -----------------------------------------
    # SEARCH
    # -----------------------------------------
    if search:

        threats = threats.filter(
            threat_name__icontains=search
        )

    # -----------------------------------------
    # SEVERITY FILTER
    # -----------------------------------------
    if severity:

        threats = threats.filter(
            severity=severity
        )

    # -----------------------------------------
    # LOG TYPE FILTER
    # -----------------------------------------
    if log_type:

        threats = threats.filter(
            log__log_type=log_type
        )

    # -----------------------------------------
    # STATUS FILTER
    # -----------------------------------------
    if status:

        threats = threats.filter(
            status=status
        )

    # -----------------------------------------
    # STATISTICS
    # -----------------------------------------
    total_threats = threats.count()

    high_count = threats.filter(
        severity="High"
    ).count()

    medium_count = threats.filter(
        severity="Medium"
    ).count()

    low_count = threats.filter(
        severity="Low"
    ).count()

    detected_count = threats.filter(
        status="Detected"
    ).count()

    resolved_count = threats.filter(
        status="Resolved"
    ).count()

    # -----------------------------------------
    # RENDER PAGE
    # -----------------------------------------
    return render(
        request,
        "threat.html",
        {
            "threats": threats,

            "search": search,
            "severity": severity,
            "log_type": log_type,
            "status": status,

            "total_threats": total_threats,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,

            "detected_count": detected_count,
            "resolved_count": resolved_count,
        }
    )

# ============================================================
# REPORTS
# ============================================================
def reports(request):

    if "user_id" not in request.session:
        return redirect("login")

    # Ascending ID order
    # Report 1 → Report 2 → Report 3
    reports = Report.objects.all().order_by("id")

    return render(
        request,
        "reports.html",
        {
            "reports": reports
        }
    )


# ============================================================
# PROFILE
# ============================================================
def profile(request):

    if "user_id" not in request.session:
        return redirect("login")

    user = User.objects.get(
        id=request.session["user_id"]
    )

    return render(
        request,
        "profile.html",
        {
            "user": user
        }
    )


# ============================================================
# SETTINGS
# ============================================================
def settings(request):

    if "user_id" not in request.session:
        return redirect("login")

    user = User.objects.get(
        id=request.session["user_id"]
    )

    if request.method == "POST":

        user.full_name = request.POST.get(
            "full_name"
        )

        user.username = request.POST.get(
            "username"
        )

        user.email = request.POST.get(
            "email"
        )

        user.phone = request.POST.get(
            "phone"
        )

        new_password = request.POST.get(
            "password"
        )

        if new_password:

            user.password = new_password

        user.save()

        return render(
            request,
            "settings.html",
            {
                "user": user,
                "success":
                    "Profile Updated Successfully!"
            }
        )

    return render(
        request,
        "settings.html",
        {
            "user": user
        }
    )


# ============================================================
# FORGOT PASSWORD
# ============================================================
def forgot_password(request):

    return render(
        request,
        "forgot_password.html"
    )


# ============================================================
# LOGOUT
# ============================================================
def logout(request):

    request.session.flush()

    return redirect("login")