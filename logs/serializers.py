# logs/serializers.py
from rest_framework import serializers
from .models import LogFile, LogEntry


class LogFileSerializer(serializers.ModelSerializer):
    """로그 파일 업로드 및 조회용 Serializer"""

    class Meta:
        model = LogFile
        fields = ['id', 'name', 'file', 'uploaded_at', 'total_entries']
        read_only_fields = ['uploaded_at', 'total_entries']  # 자동 생성되는 필드들


class LogEntrySerializer(serializers.ModelSerializer):
    """로그 엔트리 조회용 Serializer"""

    class Meta:
        model = LogEntry
        fields = ['id', 'timestamp', 'log_type', 'source_ip', 'message',
                  'severity', 'raw_log', 'metadata']
        # log_file은 제외 (관계 필드는 나중에 필요시 추가)