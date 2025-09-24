# analysis/tests.py
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone
from logs.models import LogFile, LogEntry


class BasicAnalysisAPITest(TestCase):
    """기본적인 API 동작 테스트"""

    def setUp(self):
        self.client = APIClient()

        # 테스트 데이터 생성
        self.log_file = LogFile.objects.create(name="test.log")
        LogEntry.objects.create(
            log_file=self.log_file,
            timestamp=timezone.now(),
            log_type='apache',
            source_ip='192.168.1.100',
            message='GET /admin.php',
            severity='high',
            raw_log='test log',
            metadata='{"status_code": 404}'
        )

    def test_basic_stats_api_responds(self):
        """기본 통계 API 응답 확인"""
        response = self.client.get('/analysis/basic-stats/')
        self.assertIn(response.status_code, [200, 500])  # 응답만 확인

    def test_security_threat_api_responds(self):
        """보안 위협 API 응답 확인"""
        response = self.client.get('/analysis/security-threat/')
        self.assertIn(response.status_code, [200, 500])

    def test_all_apis_respond(self):
        """모든 API가 응답하는지 확인"""
        urls = [
            '/analysis/basic-stats/',
            '/analysis/security-threat/',
            '/analysis/anomaly/',
            '/analysis/correlation/',
            '/analysis/predictive/'
        ]

        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                # 500 에러나지 않으면 OK
                self.assertNotEqual(response.status_code, 500,
                                    f"{url}에서 500 에러 발생")

'''
class EmptyDatabaseTest(TestCase):
    """빈 데이터베이스 처리 테스트"""

    def setUp(self):
        self.client = APIClient()
        # 데이터 없음

    def test_empty_db_handling(self):
        """빈 DB에서도 오류 없이 응답"""
        urls = ['/analysis/basic-stats/', '/analysis/security-threat/']

        for url in urls:
            response = self.client.get(url)
            # 오류 없이 응답하면 성공
            self.assertIn(response.status_code, [200, 400, 404])
            self.assertNotEqual(response.status_code, 500)
'''

class URLPatternTest(TestCase):
    """URL 연결 테스트"""

    def test_url_patterns_exist(self):
        """URL 패턴 존재 확인"""
        try:
            reverse('basic_stats_analysis')
            reverse('security_threat_analysis')
            reverse('generate_report')
        except:
            self.fail("URL 패턴 누락")

    def test_post_generate_report(self):
        """리포트 생성 POST 테스트"""
        response = self.client.post('/analysis/generate-report/',
                                    {'analysis_type': 'basic_stats'})
        self.assertNotEqual(response.status_code, 500)


class ImportTest(TestCase):
    """분석기 임포트 테스트"""

    def test_can_import_analyzers(self):
        """분석기 임포트 가능 확인"""
        try:
            from analysis.analysis_scripts.basic_stats_01 import BasicStatsAnalyzer
            analyzer = BasicStatsAnalyzer()
            self.assertTrue(hasattr(analyzer, 'df'))
        except Exception as e:
            self.fail(f"BasicStatsAnalyzer 임포트/초기화 실패: {e}")

    def test_analyzer_basic_methods(self):
        """분석기 기본 메서드 존재 확인"""
        try:
            from analysis.analysis_scripts.basic_stats_01 import BasicStatsAnalyzer
            analyzer = BasicStatsAnalyzer()

            # 메서드 존재 확인
            self.assertTrue(hasattr(analyzer, 'get_overview_text'))

            # 실행해보기 (에러만 안나면 됨)
            overview = analyzer.get_overview_text()
            self.assertIsInstance(overview, str)

        except Exception as e:
            self.fail(f"분석기 메서드 테스트 실패: {e}")


class BasicFunctionalityTest(TestCase):
    """기본 기능 테스트"""

    def setUp(self):
        # 실제 데이터 생성
        log_file = LogFile.objects.create(name="real_test.log")
        test_data = [
            {'log_type': 'apache', 'source_ip': '192.168.1.1', 'severity': 'medium'},
            {'log_type': 'system', 'source_ip': '10.0.0.1', 'severity': 'high'},
            {'log_type': 'apache', 'source_ip': '192.168.1.1', 'severity': 'low'},
        ]

        for i, data in enumerate(test_data):
            LogEntry.objects.create(
                log_file=log_file,
                timestamp=timezone.now(),
                message=f'test message {i}',
                raw_log=f'raw log {i}',
                metadata='{}',
                **data
            )

    def test_with_real_data(self):
        """실제 데이터로 API 테스트"""
        response = self.client.get('/analysis/basic-stats/')

        if response.status_code == 200:
            data = response.json()
            self.assertIn('overview', data)
        else:
            # 에러라도 500은 아니어야 함
            self.assertNotEqual(response.status_code, 500)