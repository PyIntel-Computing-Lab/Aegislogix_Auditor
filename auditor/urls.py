from django.urls import path
from . import views

urlpatterns = [

    path("", views.home, name="home"),

    path("register/",
         views.register,
         name="register"),

    path("login/",
         views.login,
         name="login"),

    path("forgot-password/",
         views.forgot_password,
         name="forgot_password"),

    path("dashboard/",
         views.dashboard,
         name="dashboard"),

    path("upload_logs/",
         views.upload_logs,
         name="upload_logs"),

    path("threat/",
         views.threat,
         name="threat"),

    path("reports/",
         views.reports,
         name="reports"),

    path("profile/",
         views.profile,
         name="profile"),

    path("settings/",
         views.settings,
         name="settings"),

    path("logout/",
         views.logout,
         name="logout"),
]