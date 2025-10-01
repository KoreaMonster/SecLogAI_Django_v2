#!/usr/bin/env python3
"""
Django 기반 보안 위협 분석기
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple
from django.apps import apps

plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.unicode_minus'] = False
sns.set_style("whitegrid")


class SecurityThreatAnalyzer:
    def __init__(self):
        # Django ORM 사용
        LogEntry = apps.get_model('logs', 'LogEntry')
        self.LogEntry = LogEntry
        self.df = None
        self._load_data()

        # 위협 탐지 패턴
        self.threat_patterns = {
            'sql_injection': ['union', 'select', 'drop', 'insert', 'delete', 'script', ';--', "' or"],
            'xss': ['<script>', 'javascript:', 'alert(', 'onerror=', 'onload='],
            'lfi': ['../../../', '/etc/passwd', '/etc/shadow', '..\\..\\..\\'],
            'brute_force': ['failed login', 'authentication failed', 'login failed'],
            'malware': ['malware', 'virus', 'trojan', 'suspicious', 'blocked']
        }

        self.thresholds = {
            'failed_login_threshold': 5,
            'request_rate_threshold': 100,
            'suspicious_pattern_threshold': 3,
            'time_window_minutes': 10
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

    def get_security_overview_text(self) -> str:
        """보안 위협 개요"""
        if len(self.df) == 0:
            return "🔒 분석할 보안 데이터가 없습니다."

        # 기본 통계
        total_logs = len(self.df)
        high_severity = len(self.df[self.df['severity'] == 'high'])
        unique_ips = self.df['source_ip'].dropna().nunique()

        # 위협 탐지
        threats_detected = self.detect_threat_patterns()
        failed_logins = self.analyze_failed_logins()
        suspicious_ips = self.detect_suspicious_ips()

        overview = f"""
🔒 보안 위협 분석 (Django ORM)
{'=' * 30}
• 총 로그 수: {total_logs:,}개
• 고위험 이벤트: {high_severity}개
• 분석 IP 수: {unique_ips}개
• 탐지된 위협 패턴: {len(threats_detected)}개
• 실패한 로그인: {len(failed_logins)}건
• 의심스러운 IP: {len(suspicious_ips)}개
"""
        return overview

    def detect_threat_patterns(self) -> Dict:
        """위협 패턴 탐지"""
        threat_results = {}

        for threat_type, patterns in self.threat_patterns.items():
            detected_logs = []

            for _, log in self.df.iterrows():
                message_lower = str(log['message']).lower()

                for pattern in patterns:
                    if pattern.lower() in message_lower:
                        detected_logs.append({
                            'timestamp': log['timestamp'],
                            'source_ip': log['source_ip'],
                            'message': log['message'],
                            'pattern': pattern,
                            'log_type': log['log_type']
                        })
                        break

            threat_results[threat_type] = detected_logs

        return threat_results

    def analyze_failed_logins(self) -> List[Dict]:
        """실패한 로그인 분석"""
        failed_login_logs = []

        # 실패 로그인 관련 로그 필터링
        for _, log in self.df.iterrows():
            message = str(log['message']).lower()
            if any(pattern in message for pattern in self.threat_patterns['brute_force']):
                failed_login_logs.append({
                    'timestamp': log['timestamp'],
                    'source_ip': log['source_ip'],
                    'message': log['message'],
                    'log_type': log['log_type']
                })

        return failed_login_logs

    def detect_suspicious_ips(self) -> List[Dict]:
        """의심스러운 IP 탐지"""
        ip_analysis = []

        for ip in self.df['source_ip'].dropna().unique():
            ip_logs = self.df[self.df['source_ip'] == ip]

            # 위협 지표 계산
            high_severity_count = len(ip_logs[ip_logs['severity'] == 'high'])
            request_rate = len(ip_logs) / max(1, len(ip_logs.groupby(ip_logs['timestamp'].dt.date)))

            # 패턴 매칭
            pattern_matches = 0
            for _, log in ip_logs.iterrows():
                message = str(log['message']).lower()
                for patterns in self.threat_patterns.values():
                    if any(pattern.lower() in message for pattern in patterns):
                        pattern_matches += 1
                        break

            # 의심스러운 IP 판단
            is_suspicious = (
                    high_severity_count >= 2 or
                    request_rate > self.thresholds['request_rate_threshold'] or
                    pattern_matches >= self.thresholds['suspicious_pattern_threshold']
            )

            if is_suspicious:
                ip_analysis.append({
                    'ip': ip,
                    'total_requests': len(ip_logs),
                    'high_severity_events': high_severity_count,
                    'pattern_matches': pattern_matches,
                    'request_rate': request_rate,
                    'main_log_types': ip_logs['log_type'].value_counts().to_dict(),
                    'time_pattern': ip_logs['hour'].value_counts().head(3).to_dict()
                })

        return sorted(ip_analysis, key=lambda x: x['pattern_matches'], reverse=True)

    def analyze_attack_timeline(self) -> Tuple[Dict, str]:
        """공격 타임라인 분석"""
        if len(self.df) == 0:
            return {}, "공격 타임라인 분석 데이터가 없습니다."

        # 시간별 고위험 이벤트
        high_risk_logs = self.df[self.df['severity'] == 'high']
        hourly_attacks = high_risk_logs.groupby('hour').size()

        # 일별 공격 트렌드
        daily_attacks = high_risk_logs.groupby(high_risk_logs['timestamp'].dt.date).size()

        peak_hour = hourly_attacks.idxmax() if len(hourly_attacks) > 0 else None
        peak_day = daily_attacks.idxmax() if len(daily_attacks) > 0 else None

        summary = f"""
📅 공격 타임라인 분석
{'=' * 30}
• 고위험 이벤트: {len(high_risk_logs)}개
• 최다 공격 시간: {peak_hour}시
• 최다 공격일: {peak_day}
• 분석 기간: {len(daily_attacks)}일
"""

        return {
            'hourly_attacks': hourly_attacks.to_dict(),
            'daily_attacks': daily_attacks.to_dict(),
            'peak_hour': peak_hour,
            'peak_day': str(peak_day) if peak_day else None
        }, summary

    def plot_security_threats(self, save_path: Optional[str] = None):
        """보안 위협 시각화"""
        if len(self.df) == 0:
            print("시각화할 데이터가 없습니다.")
            return

        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # 1. 위협 패턴별 탐지 수
        threats = self.detect_threat_patterns()
        threat_counts = {k: len(v) for k, v in threats.items()}

        if sum(threat_counts.values()) > 0:
            axes[0, 0].bar(threat_counts.keys(), threat_counts.values(), color='red')
            axes[0, 0].set_title('위협 패턴별 탐지 수', fontweight='bold')
            axes[0, 0].set_ylabel('탐지 수')
            axes[0, 0].tick_params(axis='x', rotation=45)
        else:
            axes[0, 0].text(0.5, 0.5, '탐지된 위협 없음', transform=axes[0, 0].transAxes,
                            ha='center', va='center')
            axes[0, 0].set_title('위협 패턴별 탐지 수', fontweight='bold')

        # 2. 심각도별 시간 분포
        severity_time = self.df.groupby(['hour', 'severity']).size().unstack(fill_value=0)
        severity_time.plot(kind='bar', stacked=True, ax=axes[0, 1],
                           color=['green', 'yellow', 'orange', 'red'])
        axes[0, 1].set_title('시간별 심각도 분포', fontweight='bold')
        axes[0, 1].set_xlabel('시간')
        axes[0, 1].set_ylabel('로그 수')
        axes[0, 1].legend(title='심각도')

        # 3. 의심스러운 IP TOP 10
        suspicious_ips = self.detect_suspicious_ips()
        if suspicious_ips:
            top_ips = suspicious_ips[:10]
            ip_names = [ip_info['ip'] for ip_info in top_ips]
            ip_scores = [ip_info['pattern_matches'] for ip_info in top_ips]

            axes[1, 0].barh(ip_names, ip_scores, color='orange')
            axes[1, 0].set_title('의심스러운 IP TOP 10', fontweight='bold')
            axes[1, 0].set_xlabel('패턴 매칭 수')
        else:
            axes[1, 0].text(0.5, 0.5, '의심스러운 IP 없음', transform=axes[1, 0].transAxes,
                            ha='center', va='center')
            axes[1, 0].set_title('의심스러운 IP TOP 10', fontweight='bold')

        # 4. 일별 공격 트렌드
        high_risk_logs = self.df[self.df['severity'] == 'high']
        daily_attacks = high_risk_logs.groupby(high_risk_logs['timestamp'].dt.date).size()

        if len(daily_attacks) > 0:
            axes[1, 1].plot(daily_attacks.index, daily_attacks.values, marker='o', color='red')
            axes[1, 1].set_title('일별 고위험 이벤트 트렌드', fontweight='bold')
            axes[1, 1].set_ylabel('이벤트 수')
            axes[1, 1].tick_params(axis='x', rotation=45)
        else:
            axes[1, 1].text(0.5, 0.5, '고위험 이벤트 없음', transform=axes[1, 1].transAxes,
                            ha='center', va='center')
            axes[1, 1].set_title('일별 고위험 이벤트 트렌드', fontweight='bold')

        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def generate_security_report(self) -> str:
        """보안 위협 리포트 생성"""
        threats = self.detect_threat_patterns()
        failed_logins = self.analyze_failed_logins()
        suspicious_ips = self.detect_suspicious_ips()
        _, timeline_summary = self.analyze_attack_timeline()

        report = f"""
{'=' * 60}
🔒 보안 위협 분석 리포트 (Django ORM)
{'=' * 60}

{self.get_security_overview_text()}

{'=' * 60}
🚨 탐지된 위협 패턴
{'=' * 60}
"""

        for threat_type, detected_logs in threats.items():
            report += f"\n[{threat_type.upper()}]\n"
            report += f"• 탐지 건수: {len(detected_logs)}건\n"

            if detected_logs:
                unique_ips = len(set(log['source_ip'] for log in detected_logs if log['source_ip']))
                report += f"• 관련 IP: {unique_ips}개\n"

                # 최근 탐지 사례
                recent_case = max(detected_logs, key=lambda x: x['timestamp'])
                report += f"• 최근 탐지: {recent_case['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n"

        report += f"""

{'=' * 60}
🔐 실패한 로그인 분석
{'=' * 60}
• 총 실패 건수: {len(failed_logins)}건
"""

        if failed_logins:
            failed_ips = Counter([log['source_ip'] for log in failed_logins if log['source_ip']])
            report += f"• 관련 IP: {len(failed_ips)}개\n"
            report += "• 상위 5개 IP:\n"
            for ip, count in failed_ips.most_common(5):
                report += f"  - {ip}: {count}회\n"

        report += f"""

{'=' * 60}
⚠️ 의심스러운 IP 분석
{'=' * 60}
"""

        for i, ip_info in enumerate(suspicious_ips[:10], 1):
            report += f"\n{i}. {ip_info['ip']}\n"
            report += f"   • 총 요청: {ip_info['total_requests']}개\n"
            report += f"   • 고위험 이벤트: {ip_info['high_severity_events']}개\n"
            report += f"   • 패턴 매칭: {ip_info['pattern_matches']}개\n"

        report += f"""

{'=' * 60}
{timeline_summary}
{'=' * 60}
생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Django ORM 기반 보안 분석
"""
        return report

    def save_to_db(self, log_file):
        """보안 위협 분석 결과를 DB에 저장"""
        from analysis.models import AnalysisResult

        if len(self.df) == 0:
            return

        # 위협 패턴 탐지
        threats = self.detect_threat_patterns()
        suspicious_ips = self.detect_suspicious_ips()

        result_dict = {
            'total_logs': len(self.df),
            'high_severity_count': len(self.df[self.df['severity'] == 'high']),
            'unique_ips': int(self.df['source_ip'].dropna().nunique()),
            'threat_patterns': {k: len(v) for k, v in threats.items()},
            'suspicious_ip_count': len(suspicious_ips),
            'top_suspicious_ips': [
                {
                    'ip': ip_info['ip'],
                    'total_requests': ip_info['total_requests'],
                    'high_severity_events': ip_info['high_severity_events'],
                    'pattern_matches': ip_info['pattern_matches']
                }
                for ip_info in suspicious_ips[:5]
            ]
        }

        AnalysisResult.objects.update_or_create(
            log_file=log_file,
            analysis_type='security_threat',
            defaults={'result_data': result_dict}
        )