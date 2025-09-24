#!/usr/bin/env python3
"""
Django 기반 예측 분석기
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LinearRegression
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from django.apps import apps
import json

plt.rcParams['font.family'] = 'DejaVu Sans'
sns.set_style("whitegrid")


class PredictiveAnalyzer:
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

    def get_numeric_metadata(self, data, field_name):
        """메타데이터에서 숫자 필드 추출"""

        def extract_numeric(metadata_str):
            try:
                if pd.isna(metadata_str):
                    return None
                metadata = json.loads(metadata_str)
                value = metadata.get(field_name)
                return float(value) if value is not None else None
            except:
                return None

        numeric_values = data['metadata'].apply(extract_numeric)
        return pd.to_numeric(numeric_values, errors='coerce').dropna()

    def get_prediction_overview_text(self) -> str:
        """예측 분석 개요"""
        if len(self.df) == 0:
            return "🔮 분석할 예측 데이터가 없습니다."

        total_logs = len(self.df)
        unique_ips = self.df['source_ip'].dropna().nunique()
        time_span = (self.df['timestamp'].max() - self.df['timestamp'].min()).days
        daily_avg = total_logs / max(time_span, 1)

        overview = f"""
🔮 예측 분석 (Django ORM)
{'=' * 30}
• 총 로그 수: {total_logs:,}개
• 분석 IP 수: {unique_ips}개
• 분석 기간: {time_span}일
• 일평균 로그: {daily_avg:.1f}개
"""
        return overview

    def predict_traffic_volume(self) -> Tuple[Dict, str]:
        """트래픽 볼륨 예측"""
        if len(self.df) == 0:
            return {}, "트래픽 예측 데이터가 없습니다."

        # 일별 트래픽 패턴
        daily_volume = self.df.groupby('date').size()

        if len(daily_volume) < 3:
            return {}, "예측에 충분한 일별 데이터가 없습니다."

        # 단순 선형 회귀로 트렌드 예측
        days = np.arange(len(daily_volume)).reshape(-1, 1)
        volumes = daily_volume.values

        model = LinearRegression()
        model.fit(days, volumes)

        # 다음 7일 예측
        future_days = np.arange(len(daily_volume), len(daily_volume) + 7).reshape(-1, 1)
        predicted_volumes = model.predict(future_days)

        # 통계 계산
        current_avg = daily_volume.mean()
        predicted_avg = predicted_volumes.mean()
        trend = "증가" if predicted_avg > current_avg else "감소"
        change_percent = ((predicted_avg - current_avg) / current_avg) * 100

        summary = f"""
📈 트래픽 볼륨 예측
{'=' * 30}
• 현재 일평균: {current_avg:.1f}개
• 예측 일평균: {predicted_avg:.1f}개
• 트렌드: {trend} ({change_percent:+.1f}%)
• 예측 기간: 7일
"""

        return {
            'current_average': current_avg,
            'predicted_average': predicted_avg,
            'trend': trend,
            'change_percent': change_percent,
            'daily_volumes': daily_volume.to_dict(),
            'predictions': predicted_volumes.tolist()
        }, summary

    def extract_threat_features(self, ip_data):
        """IP별 위협 특성 추출"""
        features = []

        # 기본 통계
        features.append(len(ip_data))  # 총 요청 수
        features.append(len(ip_data['log_type'].unique()))  # 로그 타입 다양성
        features.append(len(ip_data[ip_data['severity'] == 'high']))  # 고위험 이벤트 수

        # 시간 패턴
        features.append(len(ip_data['hour'].unique()))  # 활동 시간대 수

        # 웹 관련 특성 (apache 로그가 있는 경우)
        apache_data = ip_data[ip_data['log_type'] == 'apache']
        if len(apache_data) > 0:
            status_codes = self.get_numeric_metadata(apache_data, 'status_code')
            if len(status_codes) > 0:
                features.append(len(status_codes[status_codes >= 400]))  # 4xx, 5xx 에러
                features.append(status_codes.mean())  # 평균 상태 코드
            else:
                features.extend([0, 200])  # 기본값
        else:
            features.extend([0, 200])  # apache 로그 없음

        return features

    def predict_security_threats(self) -> Tuple[Dict, str]:
        """보안 위협 예측"""
        if len(self.df) == 0:
            return {}, "보안 위협 예측 데이터가 없습니다."

        # 보안 관련 특성 추출
        threat_features = []
        threat_ips = []

        for ip in self.df['source_ip'].dropna().unique():
            ip_data = self.df[self.df['source_ip'] == ip]
            features = self.extract_threat_features(ip_data)
            threat_features.append(features)
            threat_ips.append(ip)

        if len(threat_features) < 5:
            return {}, "위협 예측에 충분한 데이터가 없습니다."

        # 특성 길이 통일
        max_features = max(len(features) for features in threat_features)
        normalized_features = []
        for features in threat_features:
            while len(features) < max_features:
                features.append(0)
            normalized_features.append(features)

        # Isolation Forest로 이상 IP 탐지
        try:
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(normalized_features)

            isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_scores = isolation_forest.fit_predict(features_scaled)

            threat_ips_list = [threat_ips[i] for i, score in enumerate(anomaly_scores) if score == -1]

            # 위협 IP들의 상세 분석
            threat_analysis = {}
            for ip in threat_ips_list:
                ip_data = self.df[self.df['source_ip'] == ip]

                analysis = {
                    'total_requests': len(ip_data),
                    'high_severity_events': len(ip_data[ip_data['severity'] == 'high']),
                    'main_log_types': ip_data['log_type'].value_counts().to_dict(),
                    'time_pattern': ip_data['hour'].value_counts().head(3).to_dict()
                }

                # 웹 공격 패턴
                apache_data = ip_data[ip_data['log_type'] == 'apache']
                if len(apache_data) > 0:
                    status_codes = self.get_numeric_metadata(apache_data, 'status_code')
                    if len(status_codes) > 0:
                        analysis['web_errors'] = len(status_codes[status_codes >= 400])

                threat_analysis[ip] = analysis

        except Exception as e:
            return {}, f"위협 예측 중 오류 발생: {str(e)}"

        summary = f"""
🚨 보안 위협 예측
{'=' * 30}
• 분석된 IP 수: {len(threat_ips)}개
• 위험 IP 수: {len(threat_ips_list)}개
• 위험도 임계값: 10%
"""

        if threat_ips_list:
            summary += f"\n• 주요 위험 IP: {', '.join(threat_ips_list[:5])}"

        return {
            'threat_ips': threat_ips_list,
            'total_analyzed': len(threat_ips),
            'threat_analysis': threat_analysis
        }, summary

    def predict_system_load(self) -> Tuple[Dict, str]:
        """시스템 부하 예측"""
        if len(self.df) == 0:
            return {}, "시스템 부하 예측 데이터가 없습니다."

        # 일별 로그 볼륨
        daily_volume = self.df.groupby('date').size()

        if len(daily_volume) < 3:
            return {}, "부하 예측에 충분한 일별 데이터가 없습니다."

        # 통계적 분석
        volume_mean = daily_volume.mean()
        volume_std = daily_volume.std()

        # 부하 수준 분류
        high_load_days = len(daily_volume[daily_volume > volume_mean + volume_std])
        normal_load_days = len(daily_volume[abs(daily_volume - volume_mean) <= volume_std])
        low_load_days = len(daily_volume[daily_volume < volume_mean - volume_std])

        # 최근 트렌드 (최근 3일)
        recent_volumes = daily_volume.tail(3)
        recent_avg = recent_volumes.mean()

        if recent_avg > volume_mean + volume_std:
            load_prediction = "높은 부하"
        elif recent_avg < volume_mean - volume_std:
            load_prediction = "낮은 부하"
        else:
            load_prediction = "정상 부하"

        summary = f"""
⚡ 시스템 부하 예측
{'=' * 30}
• 평균 일일 부하: {volume_mean:.1f}개
• 최근 3일 평균: {recent_avg:.1f}개
• 예상 부하 수준: {load_prediction}
• 고부하 발생일: {high_load_days}일
"""

        return {
            'average_load': volume_mean,
            'recent_average': recent_avg,
            'load_prediction': load_prediction,
            'high_load_days': high_load_days,
            'normal_load_days': normal_load_days,
            'low_load_days': low_load_days
        }, summary

    def predict_peak_times(self) -> Tuple[Dict, str]:
        """피크 시간 예측"""
        if len(self.df) == 0:
            return {}, "피크 시간 예측 데이터가 없습니다."

        # 시간별 활동 패턴
        hourly_activity = self.df.groupby('hour').size()

        # 피크 시간 식별
        activity_mean = hourly_activity.mean()
        peak_hours = hourly_activity[hourly_activity > activity_mean * 1.5].index.tolist()

        # 요일별 패턴 (가능한 경우)
        self.df['weekday'] = self.df['timestamp'].dt.dayofweek
        weekday_activity = self.df.groupby('weekday').size()
        busiest_weekday = weekday_activity.idxmax()
        weekday_names = ['월', '화', '수', '목', '금', '토', '일']

        summary = f"""
⏰ 피크 시간 예측
{'=' * 30}
• 피크 시간대: {', '.join(map(str, peak_hours))}시
• 시간당 평균: {activity_mean:.1f}개
• 최다 활동 요일: {weekday_names[busiest_weekday]}요일
"""

        return {
            'peak_hours': peak_hours,
            'hourly_average': activity_mean,
            'busiest_weekday': busiest_weekday,
            'hourly_distribution': hourly_activity.to_dict()
        }, summary

    def plot_predictions(self, save_path: Optional[str] = None):
        """예측 결과 시각화"""
        if len(self.df) == 0:
            print("시각화할 데이터가 없습니다.")
            return

        fig, axes = plt.subplots(2, 2, figsize=(15, 10))

        # 1. 트래픽 볼륨 트렌드와 예측
        daily_volume = self.df.groupby('date').size()
        if len(daily_volume) >= 3:
            axes[0, 0].plot(daily_volume.index, daily_volume.values, marker='o', label='실제 데이터')

            # 트렌드 라인
            days = np.arange(len(daily_volume))
            z = np.polyfit(days, daily_volume.values, 1)
            p = np.poly1d(z)
            axes[0, 0].plot(daily_volume.index, p(days), "--", alpha=0.8, label='트렌드')

            axes[0, 0].set_title('일별 트래픽 볼륨 트렌드', fontweight='bold')
            axes[0, 0].set_xlabel('날짜')
            axes[0, 0].set_ylabel('로그 수')
            axes[0, 0].legend()
            axes[0, 0].tick_params(axis='x', rotation=45)
        else:
            axes[0, 0].text(0.5, 0.5, '트렌드 데이터 부족', transform=axes[0, 0].transAxes,
                            ha='center', va='center', fontsize=12)
            axes[0, 0].set_title('일별 트래픽 볼륨 트렌드', fontweight='bold')

        # 2. 시스템 부하 레벨 분포
        daily_volume = self.df.groupby('date').size()
        if len(daily_volume) >= 3:
            volume_mean = daily_volume.mean()
            volume_std = daily_volume.std()

            high_load = len(daily_volume[daily_volume > volume_mean + volume_std])
            normal_load = len(daily_volume[abs(daily_volume - volume_mean) <= volume_std])
            low_load = len(daily_volume[daily_volume < volume_mean - volume_std])

            axes[0, 1].bar(['낮은 부하', '정상 부하', '높은 부하'],
                           [low_load, normal_load, high_load],
                           color=['green', 'yellow', 'red'])
            axes[0, 1].set_title('시스템 부하 수준 분포', fontweight='bold')
            axes[0, 1].set_ylabel('일수')
        else:
            axes[0, 1].text(0.5, 0.5, '부하 데이터 부족', transform=axes[0, 1].transAxes,
                            ha='center', va='center', fontsize=12)
            axes[0, 1].set_title('시스템 부하 수준 분포', fontweight='bold')

        # 3. 시간별 활동 패턴과 피크 예측
        hourly_activity = self.df.groupby('hour').size()
        activity_mean = hourly_activity.mean()

        bars = axes[1, 0].bar(hourly_activity.index, hourly_activity.values, alpha=0.7)
        axes[1, 0].axhline(y=activity_mean * 1.5, color='red', linestyle='--',
                           label='피크 임계값')

        # 피크 시간 강조
        peak_hours = hourly_activity[hourly_activity > activity_mean * 1.5].index
        for hour in peak_hours:
            if hour in hourly_activity.index:
                idx = list(hourly_activity.index).index(hour)
                bars[idx].set_color('red')

        axes[1, 0].set_title('시간별 활동 패턴 및 피크 예측', fontweight='bold')
        axes[1, 0].set_xlabel('시간')
        axes[1, 0].set_ylabel('로그 수')
        axes[1, 0].legend()

        # 4. 위험 IP 예측 결과
        threat_pred, _ = self.predict_security_threats()
        if threat_pred and threat_pred.get('total_analyzed', 0) > 0:
            threat_count = len(threat_pred.get('threat_ips', []))
            safe_count = threat_pred.get('total_analyzed', 0) - threat_count

            axes[1, 1].pie([safe_count, threat_count],
                           labels=['안전 IP', '위험 IP'],
                           colors=['lightgreen', 'red'],
                           autopct='%1.1f%%')
            axes[1, 1].set_title('IP 위험도 예측', fontweight='bold')
        else:
            axes[1, 1].text(0.5, 0.5, '위험도 예측 데이터 부족',
                            transform=axes[1, 1].transAxes, ha='center', va='center')
            axes[1, 1].set_title('IP 위험도 예측', fontweight='bold')

        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()

    def generate_prediction_report(self) -> str:
        """예측 분석 리포트 생성"""
        traffic_analysis, traffic_summary = self.predict_traffic_volume()
        threat_analysis, threat_summary = self.predict_security_threats()
        load_analysis, load_summary = self.predict_system_load()
        peak_analysis, peak_summary = self.predict_peak_times()

        report = f"""
{'=' * 60}
🔮 예측 분석 리포트 (Django ORM)
{'=' * 60}

{self.get_prediction_overview_text()}

{'=' * 60}
{traffic_summary}
{'=' * 60}
"""

        if traffic_analysis:
            report += f"상세 트래픽 예측:\n"
            report += f"• 현재 평균: {traffic_analysis['current_average']:.1f}개/일\n"
            report += f"• 예측 평균: {traffic_analysis['predicted_average']:.1f}개/일\n"
            report += f"• 변화율: {traffic_analysis['change_percent']:+.1f}%\n"

        report += f"""

{'=' * 60}
{threat_summary}
{'=' * 60}
"""

        threat_ips = threat_analysis.get('threat_ips', [])
        for i, ip in enumerate(threat_ips[:5], 1):
            threat_info = threat_analysis.get('threat_analysis', {}).get(ip, {})
            report += f"\n{i}. {ip}\n"
            report += f"   • 총 요청: {threat_info.get('total_requests', 0)}개\n"
            report += f"   • 고위험 이벤트: {threat_info.get('high_severity_events', 0)}개\n"

        report += f"""

{'=' * 60}
{load_summary}
{'=' * 60}
{peak_summary}
{'=' * 60}
생성 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Django ORM 기반 예측 분석
"""
        return report