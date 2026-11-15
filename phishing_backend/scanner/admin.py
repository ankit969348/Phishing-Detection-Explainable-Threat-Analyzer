
from django.contrib import admin
from .models import ScanRecord


# Register your models here.

@admin.register(ScanRecord)
class ScanRecordAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'scan_type',
        'created_at',
    )

    list_filter = (
        'scan_type',
        'created_at',
    )

    search_fields = (
        'email_content',
        'scanned_url',
        'user__username',
    )

    readonly_fields = ('created_at',)
