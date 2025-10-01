from django.contrib import admin
from .models import AnalysisResult


@admin.register(AnalysisResult)
class AnalysisResultAdmin(admin.ModelAdmin):
    list_display = ['log_file', 'analysis_type', 'created_at']
    list_filter = ['analysis_type', 'created_at']
    search_fields = ['log_file__name']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        ('기본 정보', {
            'fields': ('log_file', 'analysis_type')
        }),
        ('분석 결과', {
            'fields': ('result_data',)
        }),
        ('시간 정보', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )