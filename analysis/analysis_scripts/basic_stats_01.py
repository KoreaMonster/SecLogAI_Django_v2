#!/usr/bin/env python3
"""
Django 기반 기본 통계 분석기
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
from datetime import datetime
from collections import Counter
from typing import Dict, List, Optional
from django.apps import apps

plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.unicode_minus'] = False
sns.set_style("whitegrid")


class BasicStatsAnalyzer:
    def __init__(self):
        # Django ORM 사용
        LogEntry = apps.get_model('logs', 'LogEntry')
        self.LogEntry = LogEntry
        self.df = None
        self._load_data()

    def _load_data(self):
        """Django ORM으로 데이터 로드"""
        entries = self.LogEntry.objects.all().values(
            'timestamp', 'log_type', 'source_ip', 'message', 'severity', 'metadata'
        )
        self.df = pd.DataFrame(entries)

        if len(self.df) > 0:
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'], errors='coerce')
            self.df = self.df.dropna(subset=['timestamp'])
            self.df['hour'] = self.df['timestamp'].dt.hour
            self.df['date'] = self.df['timestamp'].dt.date

    def get_metadata_field(self, field_name):
        """메타데이터에서 필드 추출"""

        def extract_field(metadata_str):
            try:
                if pd.isna(metadata_str):
                    return None
                metadata = json.loads(metadata_str)
                return metadata.get(field_name)
            except:
                return None

        return self.df['metadata'].apply(extract_field)

    def get_overview_text(self) -> str:
        """전체 개요"""
        if len(self.df) == 0:
            return "📊 분석할 데이터가 없습니다."

        total_logs = len(self.df)
        unique_ips = self.df['source_ip'].dropna().nunique()
        log_types = self.df['log_type'].nunique()
        severity_dist = self.df['severity'].value_counts()

        overview = f"""
📊 기본 통계 분석 (Django ORM)
{'=' * 30}
• 총 로그 수: {total_logs:,}개
• 고유 IP 수: {unique_ips}개
• 로그 타입: {log_types}개
• 심각도별 분포:
"""
        for severity, count in severity_dist.items():
            percentage = (count / total_logs) * 100
            overview += f"  - {severity}: {count:,}개 ({percentage:.1f}%)\n"

        # 시간대별 분석
        if 'hour' in self.df.columns:
            peak_hour = self.df['hour'].value_counts().index[0]
            overview += f"\n• 최다 활동 시간: {peak_hour}시"

        return overview

    def get_time_analysis_text(self) -> str:
        """시간대별 분석"""
        if len(self.df) == 0:
            return "시간대별 분석 데이터가 없습니다."

        hourly_counts = self.df['hour'].value_counts().sort_index()
        peak_hour = hourly_counts.index[0]
        peak_count = hourly_counts.iloc[0]

        # 일별 트렌드
        daily_counts = self.df.groupby('date').size()
        avg_daily = daily_counts.mean()

        analysis = f"""
⏰ 시간대별 분석
{'=' * 30}
• 최다 활동 시간: {peak_hour}시 ({peak_count}개)
• 일평균 로그: {avg_daily:.1f}개
• 분석 기간: {daily_counts.index.min()} ~ {daily_counts.index.max()}
"""

        # 시간대별 상위 3개
        analysis += "\n• 활동량 상위 3시간:\n"
        for hour, count in hourly_counts.head(3).items():
            analysis += f"  - {hour}시: {count}개\n"

        return analysis

    def analyze_log_types(self) -> Dict:
        """로그 타입별 분석"""
        if len(self.df) == 0:
            return {}

        type_analysis = {}
        for log_type in self.df['log_type'].unique():
            type_data = self.df[self.df['log_type'] == log_type]

            type_analysis[log_type] = {
                'count': len(type_data),
                'percentage': len(type_data) / len(self.df) * 100,
                'severity_dist': type_data['severity'].value_counts().to_dict(),
                'unique_ips': type_data['source_ip'].nunique(),
                'peak_hour': type_data['hour'].value_counts().index[0] if len(type_data) > 0 else None
            }

        return type_analysis

    def analyze_source_ips(self) -> Dict:
        """IP별 분석"""
        if len(self.df) == 0:
            return {}

        ip_stats = {}
        ip_counts = self.df['source_ip'].value_counts()

        for ip, count in ip_counts.head(10).items():
            ip_data = self.df[self.df['source_ip'] == ip]

            ip_stats[ip] = {
                'total_requests': count,
                'log_types': ip_data['log_type'].value_counts().to_dict(),
                'severity_dist': ip_data['severity'].value_counts().to_dict(),
                'time_pattern': ip_data['hour'].value_counts().head(3).to_dict()
            }

        return ip_stats

    def plot_basic_stats(self, save_path: Optional[str] = None):
        """기본 통계 시각화"""
        if len(self.df) == 0:
            print("시각화할 데이터가 없습니다.")
            return

        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # 1. 시간대별 로그 분포
        hourly_counts = self.df['hour'].value_counts().sort_index()
        axes[0, 0].bar(hourly_counts.index, hourly_counts.values, color='skyblue')
        axes[0, 0].set_title('시간대별 로그 분포', fontweight='bold')
        axes[0, 0].set_xlabel('시간')
        axes[0, 0].set_ylabel('로그 수')

        # 2. 로그 타입별 분포
        type_counts = self.df['log_type'].value_counts()
        axes[0, 1].pie(type_counts.values, labels=type_counts.index, autopct='%1.1f%%')
        axes[0, 1].set_title('로그 타입별 분포', fontweight='bold')

        # 3. 심각도별 분포
        severity_counts = self.df['severity'].value_counts()
        axes[1, 0].bar(severity_counts.index, severity_counts.values,
                       color=['red', 'orange', 'yellow', 'green'])
        axes[1, 0].set_title('심각도별 분포', fontweight='bold')
        axes[1, 0].set_xlabel('심각도')
        axes[1, 0].set_ylabel('로그 수')

        # 4. 상위 IP 분포
        ip_counts = self.df['source_ip'].value_counts().head(10)
        axes[1, 1].barh(range(len(ip_counts)), ip_counts.values)
        axes[1, 1].set_yticks(range(len(ip_counts)))
        axes[1, 1].set_yticklabels(ip_counts.index)
        axes[1, 1].set_title('상위 10개 IP', fontweight='bold')
        axes[1, 1].set_xlabel('요청 수')

        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def generate_basic_report(self) -> str:
        """기본 통계 리포트 생성"""
        type_analysis = self.analyze_log_types()
        ip_analysis = self.analyze_source_ips()

        report = f"""
{'=' * 60}
📊 기본 통계 분석 리포트 (Django ORM)
{'=' * 60}

{self.get_overview_text()}

{'=' * 60}

{self.get_time_analysis_text()}

{'=' * 60}
📊 로그 타입별 상세 분석
{'=' * 60}
"""

        for log_type, analysis in type_analysis.items():
            report += f"\n[{log_type}]\n"
            report += f"• 개수: {analysis['count']:,}개 ({analysis['percentage']:.1f}%)\n"
            report += f"• 고유 IP: {analysis['unique_ips']}개\n"
            if analysis['peak_hour']:
                report += f"• 최다 활동 시간: {analysis['peak_hour']}시\n"

        report += f"""

{'=' * 60}
🌐 상위 IP 분석
{'=' * 60}
"""

        for ip, stats in list(ip_analysis.items())[:5]:
            report += f"\n[{ip}]\n"
            report += f"• 총 요청: {stats['total_requests']}개\n"
            main_type = max(stats['log_types'], key=stats['log_types'].get)
            report += f"• 주요 로그 타입: {main_type}\n"

        report += f"""

{'=' * 60}
생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Django ORM 기반 분석
"""
        return report