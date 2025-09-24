#!/usr/bin/env python3
"""
Django 기반 상관관계 분석기
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
from django.apps import apps

plt.rcParams['font.family'] = 'DejaVu Sans'
sns.set_style("whitegrid")


class CorrelationAnalyzer:
    def __init__(self):
        # Django ORM 사용
        LogEntry = apps.get_model('logs', 'LogEntry')
        self.LogEntry = LogEntry
        self.df = None
        self._load_data()

        self.thresholds = {
            'correlation_threshold': 0.7,
            'sequence_gap_minutes': 30,
            'clustering_min_events': 5
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

    def get_correlation_overview_text(self) -> str:
        """상관관계 분석 개요"""
        if len(self.df) == 0:
            return "🔗 분석할 상관관계 데이터가 없습니다."

        total_logs = len(self.df)
        unique_ips = self.df['source_ip'].dropna().nunique()
        unique_log_types = self.df['log_type'].nunique()
        time_span = (self.df['timestamp'].max() - self.df['timestamp'].min()).days

        overview = f"""
🔗 상관관계 분석 (Django ORM)
{'=' * 30}
• 총 로그 수: {total_logs:,}개
• 고유 IP 수: {unique_ips}개
• 로그 타입: {unique_log_types}개
• 분석 기간: {time_span}일
"""
        return overview

    def analyze_temporal_correlation(self) -> Tuple[Dict, str]:
        """시간적 상관관계 분석"""
        if len(self.df) == 0:
            return {}, "시간적 상관관계 분석 데이터가 없습니다."

        # 시간별 로그 타입 분포
        time_log_type = self.df.groupby(['hour', 'log_type']).size().unstack(fill_value=0)

        # 상관관계 계산
        correlation_matrix = time_log_type.corr()

        # 강한 상관관계 찾기
        strong_correlations = []
        for i in range(len(correlation_matrix.columns)):
            for j in range(i + 1, len(correlation_matrix.columns)):
                corr_value = correlation_matrix.iloc[i, j]
                if abs(corr_value) >= self.thresholds['correlation_threshold']:
                    strong_correlations.append({
                        'log_type_1': correlation_matrix.columns[i],
                        'log_type_2': correlation_matrix.columns[j],
                        'correlation': corr_value
                    })

        # 시간대별 패턴 분석
        peak_hours = {}
        for log_type in self.df['log_type'].unique():
            type_data = self.df[self.df['log_type'] == log_type]
            hourly_counts = type_data['hour'].value_counts()
            if len(hourly_counts) > 0:
                peak_hours[log_type] = {
                    'peak_hour': hourly_counts.index[0],
                    'peak_count': hourly_counts.iloc[0],
                    'total_count': len(type_data)
                }

        summary = f"""
⏰ 시간적 상관관계 분석
{'=' * 30}
• 분석 로그 타입: {len(time_log_type.columns)}개
• 강한 상관관계: {len(strong_correlations)}쌍
• 상관관계 임계값: {self.thresholds['correlation_threshold']}
"""

        if strong_correlations:
            summary += "\n• 주요 상관관계:\n"
            for corr in strong_correlations[:3]:
                summary += f"  - {corr['log_type_1']} ↔ {corr['log_type_2']}: {corr['correlation']:.3f}\n"

        return {
            'correlation_matrix': correlation_matrix.to_dict(),
            'strong_correlations': strong_correlations,
            'peak_hours': peak_hours,
            'time_log_type_distribution': time_log_type.to_dict()
        }, summary

    def analyze_ip_clustering(self) -> Tuple[Dict, str]:
        """IP 클러스터링 분석"""
        if len(self.df) == 0:
            return {}, "IP 클러스터링 분석 데이터가 없습니다."

        # IP별 행위 패턴 분석
        ip_patterns = {}

        for ip in self.df['source_ip'].dropna().unique():
            ip_data = self.df[self.df['source_ip'] == ip]

            if len(ip_data) < self.thresholds['clustering_min_events']:
                continue

            pattern = {
                'total_requests': len(ip_data),
                'log_types': ip_data['log_type'].value_counts().to_dict(),
                'severity_dist': ip_data['severity'].value_counts().to_dict(),
                'hourly_pattern': ip_data['hour'].value_counts().to_dict(),
                'active_hours': len(ip_data['hour'].unique()),
                'time_span_hours': (ip_data['timestamp'].max() - ip_data['timestamp'].min()).total_seconds() / 3600
            }

            ip_patterns[ip] = pattern

        # 유사한 패턴을 가진 IP 그룹 찾기
        ip_clusters = defaultdict(list)

        for ip1, pattern1 in ip_patterns.items():
            cluster_key = (
                len(pattern1['log_types']),  # 로그 타입 다양성
                pattern1['active_hours'] // 4,  # 활동 시간대 (4시간 단위)
                'high' in pattern1['severity_dist']  # 고위험 이벤트 존재
            )
            ip_clusters[cluster_key].append((ip1, pattern1))

        # 의미있는 클러스터만 필터링 (2개 이상 IP)
        significant_clusters = {k: v for k, v in ip_clusters.items() if len(v) >= 2}

        summary = f"""
🌐 IP 클러스터링 분석
{'=' * 30}
• 분석 IP 수: {len(ip_patterns)}개
• 발견된 클러스터: {len(significant_clusters)}개
• 최소 이벤트 수: {self.thresholds['clustering_min_events']}개
"""

        if significant_clusters:
            largest_cluster = max(significant_clusters.values(), key=len)
            summary += f"\n• 최대 클러스터 크기: {len(largest_cluster)}개 IP"

        return {
            'ip_patterns': ip_patterns,
            'clusters': dict(significant_clusters),
            'cluster_stats': {k: len(v) for k, v in significant_clusters.items()}
        }, summary

    def analyze_attack_sequences(self) -> Tuple[Dict, str]:
        """공격 시퀀스 분석"""
        if len(self.df) == 0:
            return {}, "공격 시퀀스 분석 데이터가 없습니다."

        # 공격 관련 로그 필터링
        attack_keywords = ['failed', 'error', 'unauthorized', 'blocked', 'malware', 'suspicious']
        attack_logs = self.df[
            self.df['message'].str.lower().str.contains('|'.join(attack_keywords), na=False) |
            self.df['severity'].isin(['high', 'critical'])
            ].copy()

        if len(attack_logs) == 0:
            return {}, "공격 관련 로그가 없습니다."

        # IP별 공격 시퀀스 분석
        attack_sequences = []
        gap_threshold = timedelta(minutes=self.thresholds['sequence_gap_minutes'])

        for ip in attack_logs['source_ip'].dropna().unique():
            ip_attacks = attack_logs[attack_logs['source_ip'] == ip].sort_values('timestamp')

            if len(ip_attacks) < 2:
                continue

            # 시퀀스 탐지
            current_sequence = [ip_attacks.iloc[0]]

            for i in range(1, len(ip_attacks)):
                time_diff = ip_attacks.iloc[i]['timestamp'] - current_sequence[-1]['timestamp']

                if time_diff <= gap_threshold:
                    current_sequence.append(ip_attacks.iloc[i])
                else:
                    if len(current_sequence) >= 2:
                        sequence_info = {
                            'ip': ip,
                            'sequence_length': len(current_sequence),
                            'start_time': current_sequence[0]['timestamp'],
                            'end_time': current_sequence[-1]['timestamp'],
                            'duration': current_sequence[-1]['timestamp'] - current_sequence[0]['timestamp'],
                            'log_types': [event['log_type'] for event in current_sequence],
                            'severity_levels': [event['severity'] for event in current_sequence]
                        }
                        attack_sequences.append(sequence_info)
                    current_sequence = [ip_attacks.iloc[i]]

            # 마지막 시퀀스 처리
            if len(current_sequence) >= 2:
                sequence_info = {
                    'ip': ip,
                    'sequence_length': len(current_sequence),
                    'start_time': current_sequence[0]['timestamp'],
                    'end_time': current_sequence[-1]['timestamp'],
                    'duration': current_sequence[-1]['timestamp'] - current_sequence[0]['timestamp'],
                    'log_types': [event['log_type'] for event in current_sequence],
                    'severity_levels': [event['severity'] for event in current_sequence]
                }
                attack_sequences.append(sequence_info)

        # 상위 시퀀스
        top_sequences = sorted(attack_sequences, key=lambda x: x['sequence_length'], reverse=True)[:5]

        summary = f"""
🔍 공격 시퀀스 분석
{'=' * 30}
• 탐지된 시퀀스: {len(attack_sequences)}개
• 공격 관련 로그: {len(attack_logs)}개
"""

        if top_sequences:
            summary += "\n• 주요 공격 시퀀스:\n"
            for i, seq in enumerate(top_sequences[:3], 1):
                duration_min = seq['duration'].total_seconds() / 60
                summary += f"  {i}. {seq['ip']}: {seq['sequence_length']}개 이벤트 ({duration_min:.1f}분)\n"

        return {'sequences': top_sequences, 'all_sequences': attack_sequences}, summary

    def plot_correlation_matrix(self, save_path: Optional[str] = None):
        """상관관계 매트릭스 시각화"""
        if len(self.df) == 0:
            print("시각화할 데이터가 없습니다.")
            return

        fig, axes = plt.subplots(2, 2, figsize=(15, 12))

        # 1. 로그 타입간 시간적 상관관계
        time_log_type = self.df.groupby(['hour', 'log_type']).size().unstack(fill_value=0)

        if len(time_log_type.columns) > 1:
            correlation_matrix = time_log_type.corr()
            sns.heatmap(correlation_matrix, annot=True, cmap='RdYlBu', center=0,
                        ax=axes[0, 0], fmt='.2f')
            axes[0, 0].set_title('로그 타입간 시간적 상관관계', fontweight='bold')
        else:
            axes[0, 0].text(0.5, 0.5, '상관관계 분석 불가\n(로그 타입 부족)',
                            transform=axes[0, 0].transAxes, ha='center', va='center')
            axes[0, 0].set_title('로그 타입간 시간적 상관관계', fontweight='bold')

        # 2. 시간대별 로그 타입 분포
        log_type_counts = self.df['log_type'].value_counts()
        for log_type in log_type_counts.head(5).index:
            type_data = self.df[self.df['log_type'] == log_type]
            hourly = type_data['hour'].value_counts().sort_index()
            axes[0, 1].plot(hourly.index, hourly.values, marker='o', label=log_type, alpha=0.7)

        axes[0, 1].set_title('시간대별 주요 로그 타입 분포', fontweight='bold')
        axes[0, 1].set_xlabel('시간')
        axes[0, 1].set_ylabel('로그 수')
        axes[0, 1].legend(bbox_to_anchor=(1.05, 1), loc='upper left')

        # 3. IP별 활동 패턴 클러스터링
        ip_analysis, _ = self.analyze_ip_clustering()
        ip_patterns = ip_analysis.get('ip_patterns', {})

        if ip_patterns:
            # IP별 활동 시간대와 요청 수 시각화
            ips = list(ip_patterns.keys())[:10]  # 상위 10개 IP만
            request_counts = [ip_patterns[ip]['total_requests'] for ip in ips]
            active_hours = [ip_patterns[ip]['active_hours'] for ip in ips]

            scatter = axes[1, 0].scatter(active_hours, request_counts, alpha=0.6, s=60)
            axes[1, 0].set_xlabel('활동 시간대 수')
            axes[1, 0].set_ylabel('총 요청 수')
            axes[1, 0].set_title('IP별 활동 패턴', fontweight='bold')

            # 주요 IP 라벨링
            for i, ip in enumerate(ips[:5]):
                axes[1, 0].annotate(ip, (active_hours[i], request_counts[i]),
                                    xytext=(5, 5), textcoords='offset points', fontsize=8)
        else:
            axes[1, 0].text(0.5, 0.5, 'IP 클러스터링 데이터 부족',
                            transform=axes[1, 0].transAxes, ha='center', va='center')
            axes[1, 0].set_title('IP별 활동 패턴', fontweight='bold')

        # 4. 공격 시퀀스 시간 분포
        attack_analysis, _ = self.analyze_attack_sequences()
        sequences = attack_analysis.get('all_sequences', [])

        if sequences:
            durations = [(seq['duration'].total_seconds() / 60) for seq in sequences]
            lengths = [seq['sequence_length'] for seq in sequences]

            axes[1, 1].scatter(durations, lengths, alpha=0.6, color='red')
            axes[1, 1].set_xlabel('지속 시간 (분)')
            axes[1, 1].set_ylabel('시퀀스 길이')
            axes[1, 1].set_title('공격 시퀀스 분석', fontweight='bold')
        else:
            axes[1, 1].text(0.5, 0.5, '탐지된 공격 시퀀스 없음',
                            transform=axes[1, 1].transAxes, ha='center', va='center')
            axes[1, 1].set_title('공격 시퀀스 분석', fontweight='bold')

        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def generate_correlation_report(self) -> str:
        """상관관계 분석 리포트 생성"""
        temporal_analysis, temporal_summary = self.analyze_temporal_correlation()
        ip_analysis, ip_summary = self.analyze_ip_clustering()
        attack_analysis, attack_summary = self.analyze_attack_sequences()

        report = f"""
{'=' * 60}
🔗 상관관계 분석 리포트 (Django ORM)
{'=' * 60}

{self.get_correlation_overview_text()}

{'=' * 60}
{temporal_summary}
{'=' * 60}
"""

        # 강한 상관관계 상세 정보
        strong_correlations = temporal_analysis.get('strong_correlations', [])
        if strong_correlations:
            report += "주요 상관관계:\n"
            for corr in strong_correlations:
                report += f"• {corr['log_type_1']} ↔ {corr['log_type_2']}: {corr['correlation']:.3f}\n"

        # 시간대별 피크 정보
        peak_hours = temporal_analysis.get('peak_hours', {})
        if peak_hours:
            report += "\n로그 타입별 피크 시간:\n"
            for log_type, info in list(peak_hours.items())[:5]:
                report += f"• {log_type}: {info['peak_hour']}시 ({info['peak_count']}개)\n"

        report += f"""

{'=' * 60}
{ip_summary}
{'=' * 60}
"""

        clusters = ip_analysis.get('clusters', {})
        if clusters:
            report += "IP 클러스터 정보:\n"
            for i, (cluster_key, ips) in enumerate(clusters.items(), 1):
                if i <= 3:  # 상위 3개 클러스터만
                    report += f"• 클러스터 {i}: {len(ips)}개 IP\n"
                    report += f"  - 특성: {cluster_key}\n"

        report += f"""

{'=' * 60}
{attack_summary}
{'=' * 60}
"""

        sequences = attack_analysis.get('sequences', [])
        for i, seq in enumerate(sequences[:5], 1):
            duration_min = seq['duration'].total_seconds() / 60
            report += f"\n{i}. {seq['ip']}\n"
            report += f"   • 시퀀스 길이: {seq['sequence_length']}개\n"
            report += f"   • 지속 시간: {duration_min:.1f}분\n"
            report += f"   • 로그 타입: {', '.join(set(seq['log_types']))}\n"

        report += f"""

{'=' * 60}
생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Django ORM 기반 상관관계 분석
"""
        return report