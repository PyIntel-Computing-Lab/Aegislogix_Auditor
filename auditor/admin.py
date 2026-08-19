from django.contrib import admin
from .models import User, LogFile, Threat, Report

admin.site.register(User)
admin.site.register(LogFile)
admin.site.register(Threat)
admin.site.register(Report)