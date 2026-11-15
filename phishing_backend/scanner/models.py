



from django.db import models
from django.contrib.auth.models import User


# Create your models here.

class ScanRecord(models.Model):

    SCAN_TYPES = [
        ('email', 'Email Scan'),
        ('url', 'URL Scan'),
        ('combined', 'Combined Scan'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='scan_records'
    )

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPES
    )

    email_content = models.TextField(
        blank=True,
        default=''
    )

    scanned_url = models.URLField(
        max_length=2048,
        blank=True,
        default=''
    )

    email_result = models.JSONField(
        null=True,
        blank=True
    )

    url_result = models.JSONField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.scan_type} - {self.created_at}"
