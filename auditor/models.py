from django.db import models


# User Registration Model
class User(models.Model):
    full_name = models.CharField(max_length=100)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=10)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username


# Uploaded Log File Model
class LogFile(models.Model):
    LOG_TYPES = [
        ('Apache', 'Apache Log'),
        ('Nginx', 'Nginx Log'),
        ('System', 'System Log'),
        ('Application', 'Application Log'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    log_file = models.FileField(upload_to='logs/')
    log_type = models.CharField(max_length=20, choices=LOG_TYPES)
    description = models.TextField(default="")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.log_file.name


# Threat Detection Model
class Threat(models.Model):
    SEVERITY = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    STATUS = [
        ('Detected', 'Detected'),
        ('Resolved', 'Resolved'),
    ]

    log = models.ForeignKey(LogFile, on_delete=models.CASCADE)
    threat_name = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY)
    status = models.CharField(max_length=20, choices=STATUS)
    detected_on = models.DateField()

    def __str__(self):
        return self.threat_name


# Report Model
class Report(models.Model):

    log = models.ForeignKey(
        LogFile,
        on_delete=models.CASCADE,
        related_name="reports"
    )

    report_name = models.CharField(max_length=200)

    description = models.TextField()

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        return self.report_name