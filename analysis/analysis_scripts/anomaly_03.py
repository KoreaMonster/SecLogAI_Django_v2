#!/usr/bin/env python3
"""
Django 기반 이상 행위 분석기
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from django.apps import apps

plt.rcParams['font.family'] = 'DejaVu Sans'
sns.set_style("whitegrid")


class AnomalyAnalyzer:
    def __init__(self):
        # Django ORM 사용
        LogEntry = apps.get_model('logs', 'LogEntry')
        self.LogEntry = LogEntry
        self.df = None
        self._load_data()

        self.thresholds = {
            'volume_zscore_threshold': 2.0,
            'behavior_contamination': 0.1,
            'time_window_hours': 1
        }

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

    def get_anomaly_overview_text(self) -> str:
        """이상 행위 분석 개요"""
        if len(self.df) == 0:
            return "🔍 분석할 이상 행위 데이터가 없습니다."

        total_logs = len(self.df)
        unique_ips = self.df['source_ip'].dropna().nunique()
        time_span = (self.df['timestamp'].max() - self.df['timestamp'].min()).days

        # 기본 이상 탐지
        volume_anomalies, _ = self.detect_volume_anomalies()
        behavioral_anomalies, _ = self.detect_behavioral_anomalies()
        time_anomalies, _ = self.detect_time_anomalies()

        overview = f"""
🔍 이상 행위 분석 (Django ORM)
{'=' * 30}
• 총 로그 수: {total_logs:,}개
• 분석 IP 수: {unique_ips}개
• 분석 기간: {time_span}일
• 볼륨 이상: {len(volume_anomalies)}건
• 행위 이상: {len(behavioral_anomalies)}건
• 시간 이상: {len(time_anomalies)}건
"""
        return overview

    def detect_volume_anomalies(self) -> Tuple[List[Dict], str]:
        """볼륨 기반 이상 탐지"""
        if len(self.df) == 0:
            return [], "볼륨 이상 탐지 데이터가 없습니다."

        # 시간별 볼륨 분석
        hourly_volumes = self.df.groupby('hour').size()
        volume_mean = hourly_volumes.mean()
        volume_std = hourly_volumes.std()

        anomalies = []
        for hour, count in hourly_volumes.items():
            z_score = abs((count - volume_mean) / volume_std) if volume_std > 0 else 0

            if z_score > self.thresholds['volume_zscore_threshold']:
                anomalies.append({
                    'hour': hour,
                    'volume': count,
                    'z_score': z_score,
                    'type': 'high_volume' if count > volume_mean else 'low_volume'
                })

        # IP별 볼륨 이상
        ip_volumes = self.df['source_ip'].value_counts()
        ip_mean = ip_volumes.mean()
        ip_std = ip_volumes.std()

        for ip, count in ip_volumes.head(20).items():
            z_score = abs((count - ip_mean) / ip_std) if ip_std > 0 else 0

            if z_score > self.thresholds['volume_zscore_threshold']:
                anomalies.append({
                    'source_ip': ip,
                    'volume': count,
                    'z_score': z_score,
                    'type': 'high_volume_ip'
                })

        summary = f"""
📊 볼륨 이상 탐지
{'=' * 30}
• 탐지된 이상: {len(anomalies)}건
• 시간별 평균: {volume_mean:.1f}개
• IP별 평균: {ip_mean:.1f}개
"""
        return anomalies, summary

    def detect_behavioral_anomalies(self) -> Tuple[List[Dict], str]:
        """행위 패턴 기반 이상 탐지"""
        if len(self.df) == 0:
            return [], "행위 이상 탐지 데이터가 없습니다."

        anomalies = []

        # IP별 행위 패턴 분석
        for ip in self.df['source_ip'].dropna().unique():
            ip_data = self.df[self.df['source_ip'] == ip]

            if len(ip_data) < 5:  # 최소 데이터 요구
                continue

            # 특성 벡터 생성
            features = []

            # 로그 타입 다양성
            log_type_diversity = len(ip_data['log_type'].unique())
            features.append(log_type_diversity)

            # 심각도 분포
            high_severity_ratio = len(ip_data[ip_data['severity'] == 'high']) / len(ip_data)
            features.append(high_severity_ratio)

            # 시간 패턴 (활동 시간대 수)
            active_hours = len(ip_data['hour'].unique())
            features.append(active_hours)

            # 요청 간격 분석
            if len(ip_data) > 1:
                time_diffs = ip_data['timestamp'].diff().dt.total_seconds()
                avg_interval = time_diffs.mean()
                features.append(avg_interval if not pd.isna(avg_interval) else 0)
            else:
                features.append(0)

            # 이상 점수 계산 (간단한 휴리스틱)
            anomaly_score = 0

            # 다양한 로그 타입 접근 (5개 이상이면 의심)
            if log_type_diversity >= 5:
                anomaly_score += 2

            # 높은 심각도 비율 (50% 이상이면 의심)
            if high_severity_ratio >= 0.5:
                anomaly_score += 3

            # 24시간 내내 활동 (의심스러운 패턴)
            if active_hours >= 20:
                anomaly_score += 2

            # 너무 빠른 요청 간격 (10초 이하)
            if len(ip_data) > 1 and avg_interval < 10:
                anomaly_score += 2

            if anomaly_score >= 3:  # 임계값
                anomalies.append({
                    'source_ip': ip,
                    'anomaly_score': anomaly_score,
                    'log_type_diversity': log_type_diversity,
                    'high_severity_ratio': high_severity_ratio,
                    'active_hours': active_hours,
                    'request_count': len(ip_data),
                    'avg_interval': avg_interval if len(ip_data) > 1 else 0
                })

        # 점수 기준으로 정렬
        anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)

        summary = f"""
🤖 행위 이상 탐지
{'=' * 30}
• 탐지된 이상: {len(anomalies)}건
• 분석 IP 수: {self.df['source_ip'].nunique()}개
• 탐지 기준: 다양성, 심각도, 시간패턴
"""
        return anomalies, summary

    def detect_time_anomalies(self) -> Tuple[List[Dict], str]:
        """시간 패턴 기반 이상 탐지"""
        if len(self.df) == 0:
            return [], "시간 이상 탐지 데이터가 없습니다."

        anomalies = []

        # 비정상적인 시간대 활동 탐지
        hourly_activity = self.df.groupby('hour').size()

        # 새벽 시간대 (0-5시) 고활동 탐지
        night_hours = [0, 1, 2, 3, 4, 5]
        night_activity = sum(hourly_activity.get(hour, 0) for hour in night_hours)
        total_activity = hourly_activity.sum()
        night_ratio = night_activity / total_activity if total_activity > 0 else 0

        if night_ratio > 0.3:  # 30% 이상이면 이상
            anomalies.append({
                'type': 'night_activity',
                'ratio': night_ratio,
                'night_logs': night_activity,
                'description': '새벽 시간대 과다 활동'
            })

        # IP별 시간 패턴 분석
        for ip in self.df['source_ip'].dropna().unique():
            ip_data = self.df[self.df['source_ip'] == ip]

            if len(ip_data) < 10:  # 최소 데이터 요구
                continue

            ip_hours = ip_data['hour'].unique()

            # 24시간 내내 활동하는 IP
            if len(ip_hours) >= 20:
                anomalies.append({
                    'type': 'continuous_activity',
                    'source_ip': ip,
                    'active_hours': len(ip_hours),
                    'request_count': len(ip_data),
                    'description': '지속적 활동 패턴'
                })

            # 특정 시간대 집중 활동
            hour_counts = ip_data['hour'].value_counts()
            max_hour_count = hour_counts.max()
            max_hour_ratio = max_hour_count / len(ip_data)

            if max_hour_ratio > 0.8 and len(ip_data) > 20:  # 80% 이상 특정 시간대
                peak_hour = hour_counts.idxmax()
                anomalies.append({
                    'type': 'concentrated_activity',
                    'source_ip': ip,
                    'peak_hour': peak_hour,
                    'concentration_ratio': max_hour_ratio,
                    'request_count': len(ip_data),
                    'description': f'{peak_hour}시 집중 활동'
                })

        summary = f"""
⏰ 시간 이상 탐지
{'=' * 30}
• 탐지된 이상: {len(anomalies)}건
• 새벽 활동 비율: {night_ratio:.1%}
• 분석 기간: {self.df['timestamp'].dt.date.nunique()}일
"""
        return anomalies, summary

    def plot_anomaly_detection(self, save_path: Optional[str] = None):
        """이상 탐지 시각화"""
        if len(self.df) == 0:
            print("시각화할 데이터가 없습니다.")
            return

        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # 1. 시간별 볼륨과 이상점 표시
        hourly_volumes = self.df.groupby('hour').size()
        volume_mean = hourly_volumes.mean()
        volume_std = hourly_volumes.std()

        axes[0, 0].bar(hourly_volumes.index, hourly_volumes.values, alpha=0.7)
        axes[0, 0].axhline(y=volume_mean + 2 * volume_std, color='red', linestyle='--',
                           label='이상 임계값')
        axes[0, 0].axhline(y=volume_mean, color='green', linestyle='-', label='평균')
        axes[0, 0].set_title('시간별 로그 볼륨 및 이상점', fontweight='bold')
        axes[0, 0].set_xlabel('시간')
        axes[0, 0].set_ylabel('로그 수')
        axes[0, 0].legend()

        # 2. IP별 요청 수 분포
        ip_counts = self.df['source_ip'].value_counts().head(20)
        axes[0, 1].barh(range(len(ip_counts)), ip_counts.values)
        axes[0, 1].set_yticks(range(len(ip_counts)))
        axes[0, 1].set_yticklabels(ip_counts.index)
        axes[0, 1].set_title('상위 20개 IP 요청 수', fontweight='bold')
        axes[0, 1].set_xlabel('요청 수')

        # 3. 심각도별 시간 분포
        severity_time = self.df.groupby(['hour', 'severity']).size().unstack(fill_value=0)
        severity_time.plot(kind='area', stacked=True, ax=axes[1, 0], alpha=0.7)
        axes[1, 0].set_title('시간별 심각도 분포', fontweight='bold')
        axes[1, 0].set_xlabel('시간')
        axes[1, 0].set_ylabel('로그 수')
        axes[1, 0].legend(title='심각도', loc='upper right')

        # 4. 이상 점수 분포
        behavioral_anomalies, _ = self.detect_behavioral_anomalies()
        if behavioral_anomalies:
            anomaly_scores = [a['anomaly_score'] for a in behavioral_anomalies]
            axes[1, 1].hist(anomaly_scores, bins=10, alpha=0.7, color='orange')
            axes[1, 1].set_title('행위 이상 점수 분포', fontweight='bold')
            axes[1, 1].set_xlabel('이상 점수')
            axes[1, 1].set_ylabel('IP 수')
        else:
            axes[1, 1].text(0.5, 0.5, '행위 이상 없음', transform=axes[1, 1].transAxes,
                            ha='center', va='center')
            axes[1, 1].set_title('행위 이상 점수 분포', fontweight='bold')

        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def generate_anomaly_report(self) -> str:
        """이상 행위 분석 리포트 생성"""
        volume_anomalies, volume_summary = self.detect_volume_anomalies()
        behavioral_anomalies, behavioral_summary = self.detect_behavioral_anomalies()
        time_anomalies, time_summary = self.detect_time_anomalies()

        report = f"""
{'=' * 60}
🔍 이상 행위 분석 리포트 (Django ORM)
{'=' * 60}

{self.get_anomaly_overview_text()}

{'=' * 60}
{volume_summary}
{'=' * 60}
"""

        if volume_anomalies:
            report += "상세 볼륨 이상:\n"
            for anomaly in volume_anomalies[:10]:
                if 'hour' in anomaly:
                    report += f"• {anomaly['hour']}시: {anomaly['volume']}개 (Z-점수: {anomaly['z_score']:.2f})\n"
                elif 'source_ip' in anomaly:
                    report += f"• IP {anomaly['source_ip']}: {anomaly['volume']}개 (Z-점수: {anomaly['z_score']:.2f})\n"

        report += f"""

{'=' * 60}
{behavioral_summary}
{'=' * 60}
"""

        for i, anomaly in enumerate(behavioral_anomalies[:10], 1):
            report += f"\n{i}. {anomaly['source_ip']}\n"
            report += f"   • 이상 점수: {anomaly['anomaly_score']}\n"
            report += f"   • 로그 타입: {anomaly['log_type_diversity']}개\n"
            report += f"   • 고위험 비율: {anomaly['high_severity_ratio']:.1%}\n"
            report += f"   • 활동 시간: {anomaly['active_hours']}시간대\n"

        report += f"""

{'=' * 60}
{time_summary}
{'=' * 60}
"""

        for anomaly in time_anomalies:
            if anomaly['type'] == 'night_activity':
                report += f"• 새벽 활동 비율: {anomaly['ratio']:.1%}\n"
            elif anomaly['type'] == 'continuous_activity':
                report += f"• 지속 활동 IP: {anomaly['source_ip']} ({anomaly['active_hours']}시간대)\n"
            elif anomaly['type'] == 'concentrated_activity':
                report += f"• 집중 활동 IP: {anomaly['source_ip']} ({anomaly['peak_hour']}시 집중)\n"

        report += f"""

{'=' * 60}
생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Django ORM 기반 이상 탐지
"""
        return report