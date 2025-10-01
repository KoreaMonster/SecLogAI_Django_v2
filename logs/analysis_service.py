"""
로그 업로드 시 자동 분석 실행 서비스
"""
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class AutoAnalysisService:
    """
    로그 파일이 업로드되면 5가지 분석을 자동으로 실행하고 DB에 저장
    """

    def __init__(self):
        self.results = {
            'basic_stats': False,
            'security_threat': False,
            'anomaly': False,
            'correlation': False,
            'predictive': False
        }

    def run_all_analyses(self, log_file) -> Dict:
        """
        5가지 분석을 순차적으로 실행하고 DB에 저장

        Args:
            log_file: LogFile 모델 인스턴스

        Returns:
            실행 결과 딕셔너리
        """
        logger.info(f"📊 자동 분석 시작: {log_file.name}")

        # 1. 기본 통계 분석
        try:
            from analysis.analysis_scripts.basic_stats_01 import BasicStatsAnalyzer
            analyzer = BasicStatsAnalyzer()
            analyzer.save_to_db(log_file)
            self.results['basic_stats'] = True
            logger.info("✅ 기본 통계 분석 완료")
        except Exception as e:
            logger.error(f"❌ 기본 통계 분석 실패: {e}")

        # 2. 보안 위협 분석
        try:
            from analysis.analysis_scripts.security_threat_02 import SecurityThreatAnalyzer
            analyzer = SecurityThreatAnalyzer()
            analyzer.save_to_db(log_file)
            self.results['security_threat'] = True
            logger.info("✅ 보안 위협 분석 완료")
        except Exception as e:
            logger.error(f"❌ 보안 위협 분석 실패: {e}")

        # 3. 이상 행위 분석
        try:
            from analysis.analysis_scripts.anomaly_03 import AnomalyAnalyzer
            analyzer = AnomalyAnalyzer()
            analyzer.save_to_db(log_file)
            self.results['anomaly'] = True
            logger.info("✅ 이상 행위 분석 완료")
        except Exception as e:
            logger.error(f"❌ 이상 행위 분석 실패: {e}")

        # 4. 상관관계 분석
        try:
            from analysis.analysis_scripts.correlation_04 import CorrelationAnalyzer
            analyzer = CorrelationAnalyzer()
            analyzer.save_to_db(log_file)
            self.results['correlation'] = True
            logger.info("✅ 상관관계 분석 완료")
        except Exception as e:
            logger.error(f"❌ 상관관계 분석 실패: {e}")

        # 5. 예측 분석
        try:
            from analysis.analysis_scripts.predictive_05 import PredictiveAnalyzer
            analyzer = PredictiveAnalyzer()
            analyzer.save_to_db(log_file)
            self.results['predictive'] = True
            logger.info("✅ 예측 분석 완료")
        except Exception as e:
            logger.error(f"❌ 예측 분석 실패: {e}")

        # 결과 요약
        success_count = sum(self.results.values())
        logger.info(f"📊 자동 분석 완료: {success_count}/5 성공")

        return {
            'total': 5,
            'success': success_count,
            'failed': 5 - success_count,
            'details': self.results
        }