# analysis/views.py
from rest_framework.decorators import api_view
from rest_framework.response import Response
from datetime import datetime

from .analysis_scripts.basic_stats_01 import BasicStatsAnalyzer
from .analysis_scripts.security_threat_02 import SecurityThreatAnalyzer
from .analysis_scripts.anomaly_03 import AnomalyAnalyzer
from .analysis_scripts.correlation_04 import CorrelationAnalyzer
from .analysis_scripts.predictive_05 import PredictiveAnalyzer


@api_view(['GET'])
def basic_stats_analysis(request):
    """기본 통계 분석"""
    analyzer = BasicStatsAnalyzer()
    return Response({
        'overview': analyzer.get_overview_text(),
        'time_analysis': analyzer.get_time_analysis_text(),
    })


@api_view(['GET'])
def security_threat_analysis(request):
    """보안 위협 분석"""
    analyzer = SecurityThreatAnalyzer()
    threats = analyzer.detect_threat_patterns()
    return Response({
        'overview': analyzer.get_security_overview_text(),
        'threat_patterns': {k: len(v) for k, v in threats.items()},
        'suspicious_ips': analyzer.detect_suspicious_ips()[:5],
    })


@api_view(['GET'])
def anomaly_analysis(request):
    """이상 행위 분석"""
    analyzer = AnomalyAnalyzer()
    volume_anomalies, volume_summary = analyzer.detect_volume_anomalies()
    behavioral_anomalies, behavioral_summary = analyzer.detect_behavioral_anomalies()

    return Response({
        'overview': analyzer.get_anomaly_overview_text(),
        'volume_summary': volume_summary,
        'behavioral_summary': behavioral_summary,
        'total_anomalies': len(volume_anomalies) + len(behavioral_anomalies),
    })


@api_view(['GET'])
def correlation_analysis(request):
    """상관관계 분석"""
    analyzer = CorrelationAnalyzer()
    temporal_data, temporal_summary = analyzer.analyze_temporal_correlation()

    return Response({
        'overview': analyzer.get_correlation_overview_text(),
        'temporal_summary': temporal_summary,
        'strong_correlations': temporal_data.get('strong_correlations', [])[:3],
    })


@api_view(['GET'])
def predictive_analysis(request):
    """예측 분석"""
    analyzer = PredictiveAnalyzer()
    traffic_data, traffic_summary = analyzer.predict_traffic_volume()
    threat_data, threat_summary = analyzer.predict_security_threats()

    return Response({
        'overview': analyzer.get_prediction_overview_text(),
        'traffic_summary': traffic_summary,
        'threat_summary': threat_summary,
        'traffic_prediction': traffic_data,
    })


@api_view(['POST'])
def generate_report(request):
    """리포트 생성"""
    analysis_type = request.data.get('analysis_type', 'basic_stats')

    if analysis_type == 'basic_stats':
        analyzer = BasicStatsAnalyzer()
        report = analyzer.generate_basic_report()
    elif analysis_type == 'security_threat':
        analyzer = SecurityThreatAnalyzer()
        report = analyzer.generate_security_report()
    else:
        analyzer = BasicStatsAnalyzer()  # 기본값
        report = analyzer.generate_basic_report()

    return Response({
        'report': report,
        'generated_at': datetime.now().isoformat()
    })