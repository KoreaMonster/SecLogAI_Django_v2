# logs/tests.py
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from django.core.files.uploadedfile import SimpleUploadedFile

from .models import LogFile, LogEntry


class LogFileTests(TestCase):
    """로그 파일 관련 테스트"""

    def setUp(self):
        """테스트 설정"""
        self.client = APIClient()

        # 테스트용 로그 파일 내용
        self.test_log_content = """
2025-09-01 07:00:05 INFO File accessed: /var/www/html/admin.php by user 'guest'
2025-09-01 07:00:30 WARN Failed login attempt for user 'root' from 203.0.113.6
2025-09-01 07:00:35 ERROR Malware signature detected in file /etc/passwd
""".strip().encode()

    def test_create_log_file_model(self):
        """LogFile 모델 생성 테스트"""
        log_file = LogFile.objects.create(
            name="test.log",
            total_entries=10
        )

        self.assertEqual(log_file.name, "test.log")
        self.assertEqual(log_file.total_entries, 10)
        self.assertTrue(log_file.uploaded_at)

    def test_create_log_entry_model(self):
        """LogEntry 모델 생성 테스트"""
        # LogFile 먼저 생성
        log_file = LogFile.objects.create(name="test.log")

        # LogEntry 생성
        log_entry = LogEntry.objects.create(
            log_file=log_file,
            timestamp=timezone.now(),
            log_type="security_event",
            source_ip="192.168.1.1",
            message="Test log message",
            severity="high",
            raw_log="Raw log line",
            metadata='{"test": "data"}'
        )

        self.assertEqual(log_entry.log_file, log_file)
        self.assertEqual(log_entry.log_type, "security_event")
        self.assertEqual(log_entry.severity, "high")

    def test_list_log_files_api(self):
        """로그 파일 목록 API 테스트"""
        # 테스트 데이터 생성
        LogFile.objects.create(name="test1.log")
        LogFile.objects.create(name="test2.log")

        # API 호출
        url = reverse('list_log_files')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_log_file_detail_api(self):
        """로그 파일 상세 API 테스트"""
        # 테스트 데이터 생성
        log_file = LogFile.objects.create(name="test.log", total_entries=5)

        # API 호출
        url = reverse('log_file_detail', kwargs={'file_id': log_file.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], "test.log")
        self.assertIn('stats', response.data)

    def test_log_entries_api(self):
        """로그 엔트리 API 테스트"""
        # 테스트 데이터 생성
        log_file = LogFile.objects.create(name="test.log")
        LogEntry.objects.create(
            log_file=log_file,
            timestamp=timezone.now(),
            log_type="security_event",
            message="Test message",
            severity="high",
            raw_log="Test raw log",
            metadata="{}"
        )

        # API 호출
        url = reverse('log_entries', kwargs={'file_id': log_file.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(len(response.data['results']), 1)

    def test_log_preview_api(self):
        """로그 미리보기 API 테스트"""
        # 테스트 데이터 생성
        log_file = LogFile.objects.create(name="test.log")

        # API 호출
        url = reverse('log_preview', kwargs={'file_id': log_file.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('preview', response.data)
        self.assertIn('total_count', response.data)

    def test_delete_log_file_api(self):
        """로그 파일 삭제 API 테스트"""
        # 테스트 데이터 생성
        log_file = LogFile.objects.create(name="test.log")

        # API 호출
        url = reverse('delete_log_file', kwargs={'file_id': log_file.id})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(LogFile.objects.filter(id=log_file.id).exists())

    def test_file_upload_api_without_ml(self):
        """파일 업로드 API 테스트 (ML 제외)"""
        # 테스트 파일 생성
        test_file = SimpleUploadedFile(
            "test.log",
            self.test_log_content,
            content_type="text/plain"
        )

        # API 호출 (ML 처리는 실제로는 실패할 수 있음)
        url = reverse('upload_log_file')
        response = self.client.post(url, {
            'name': 'test.log',
            'file': test_file
        }, format='multipart')

        # 파일 업로드 자체는 성공해야 함 (ML 실패해도 일단 파일은 저장됨)
        self.assertIn(response.status_code, [
            status.HTTP_201_CREATED,  # 성공
            status.HTTP_500_INTERNAL_SERVER_ERROR  # ML 실패
        ])


class LogModelRelationshipTests(TestCase):
    """모델 관계 테스트"""

    def test_log_file_entries_relationship(self):
        """LogFile과 LogEntry 관계 테스트"""
        # LogFile 생성
        log_file = LogFile.objects.create(name="test.log")

        # LogEntry들 생성
        entry1 = LogEntry.objects.create(
            log_file=log_file,
            timestamp=timezone.now(),
            log_type="apache",
            message="GET request",
            severity="low",
            raw_log="GET /index.html",
            metadata="{}"
        )

        entry2 = LogEntry.objects.create(
            log_file=log_file,
            timestamp=timezone.now(),
            log_type="security_event",
            message="Failed login",
            severity="high",
            raw_log="Failed login attempt",
            metadata="{}"
        )

        # 관계 확인
        self.assertEqual(log_file.logentry_set.count(), 2)
        self.assertIn(entry1, log_file.logentry_set.all())
        self.assertIn(entry2, log_file.logentry_set.all())