# logs/models.py
from django.db import models


class LogFile(models.Model):
    """업로드된 로그 파일 정보"""
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to='log_files/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    total_entries = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.name


class LogEntry(models.Model):
    """기존 SQLite logs 테이블과 동일한 구조"""
    log_file = models.ForeignKey(LogFile, on_delete=models.CASCADE)

    # 기존 분석 코드와 정확히 동일한 필드들
    timestamp = models.DateTimeField()
    log_type = models.CharField(max_length=50)
    source_ip = models.CharField(max_length=45, null=True, blank=True)
    message = models.TextField()
    severity = models.CharField(max_length=20)
    raw_log = models.TextField()
    metadata = models.TextField()  # JSON 문자열로 저장 (기존과 동일)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"{self.timestamp} - {self.log_type}"