from django.urls import path
from . import views


urlpatterns = [

    # ========================================================
    # HOME
    # ========================================================
    path(
        "",
        views.home,
        name="home"
    ),


    # ========================================================
    # AUTHENTICATION
    # ========================================================
    path(
        "register/",
        views.register,
        name="register"
    ),

    path(
        "login/",
        views.login,
        name="login"
    ),

    path(
        "logout/",
        views.logout,
        name="logout"
    ),

    path(
        "forgot-password/",
        views.forgot_password,
        name="forgot_password"
    ),


    # ========================================================
    # DASHBOARD
    # ========================================================
    path(
        "dashboard/",
        views.dashboard,
        name="dashboard"
    ),


    # ========================================================
    # LOG UPLOAD
    # ========================================================
    path(
        "upload-logs/",
        views.upload_logs,
        name="upload_logs"
    ),


    # ========================================================
    # THREAT DETECTION
    # ========================================================
    path(
        "threat/",
        views.threat,
        name="threat"
    ),


    # ========================================================
    # THREAT DETAILS
    # ========================================================
    path(
        "threat/<int:threat_id>/",
        views.threat_details,
        name="threat_details"
    ),


    # ========================================================
    # SECURITY REPORTS
    # ========================================================
    path(
        "reports/",
        views.reports,
        name="reports"
    ),


    # ========================================================
    # PROFILE
    # ========================================================
    path(
        "profile/",
        views.profile,
        name="profile"
    ),


    # ========================================================
    # SETTINGS
    # ========================================================
    path(
        "settings/",
        views.settings,
        name="settings"
    ),
]