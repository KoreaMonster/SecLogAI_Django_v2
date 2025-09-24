from django.contrib import admin

from logs.models import LogFile, LogEntry

# Register your models here.
#관리자 페이지에서 데이터 확인할 수 있도록

admin.site.register(LogFile)
admin.site.register(LogEntry)