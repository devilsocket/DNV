from django.contrib import admin
from .models import DnvSession, DnvDns, DnvUploadHistory, DnvScanHistory
# Register your models here.
admin.site.register(DnvSession)
admin.site.register(DnvDns)
admin.site.register(DnvUploadHistory)
admin.site.register(DnvScanHistory)