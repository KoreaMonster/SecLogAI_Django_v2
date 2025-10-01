from django.db import models


class AnalysisResult(models.Model):
    """
    분석 결과 통합 저장 모델
    5가지 분석 결과를 JSON 형태로 저장
    """
    ANALYSIS_TYPES = [
        ('basic_stats', '기본 통계 분석'),
        ('security_threat', '보안 위협 분석'),
        ('anomaly', '이상 행위 분석'),
        ('correlation', '상관관계 분석'),
        ('predictive', '예측 분석'),
    ]

    log_file = models.ForeignKey(
        'logs.LogFile',
        on_delete=models.CASCADE,
        related_name='analysis_results'
    )
    analysis_type = models.CharField(
        max_length=50,
        choices=ANALYSIS_TYPES
    )
    result_data = models.JSONField(
        help_text="분석 결과를 JSON 형태로 저장"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['log_file', 'analysis_type']
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.log_file.name} - {self.get_analysis_type_display()}"