#!/usr/bin/env python3
"""
Django 연동 ML 기반 로그 정보 추출 시스템
기존 ml_log_classifier.py를 Django ORM과 연동하도록 최소 수정
"""

import json
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple, List
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import joblib
import numpy as np
import re
from collections import Counter

# Django imports
from .models import LogFile, LogEntry
from django.db import models

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ImprovedMLLogExtractor:
    """기존 ML 기반 로그 정보 추출기 (Django 연동)"""

    def __init__(self):
        self.log_classifier = None
        self.tfidf_vectorizer = None
        self.trained = False

    def extract_enhanced_features(self, text):
        """향상된 특성 추출 (기존 코드 유지)"""
        features = []

        # 기본 텍스트 특성
        features.append(len(text))
        features.append(len(text.split()))
        features.append(text.count(' '))
        features.append(text.count(':'))
        features.append(text.count('['))
        features.append(text.count(']'))
        features.append(text.count('"'))
        features.append(text.count('-'))
        features.append(text.count('='))
        features.append(text.count('/'))

        # 구조적 특성 (가중치 강화)
        digit_count = sum(c.isdigit() for c in text)
        alpha_count = sum(c.isalpha() for c in text)
        features.append(digit_count / len(text) if text else 0)
        features.append(alpha_count / len(text) if text else 0)

        # 보안 관련 키워드 (가중치 증가)
        security_keywords = ['ERROR', 'WARN', 'INFO', 'failed', 'denied', 'login',
                             'access', 'file', 'user', 'attempt', 'blocked']
        for keyword in security_keywords:
            features.append(2 if keyword.lower() in text.lower() else 0)

        # 웹 로그 특성
        web_keywords = ['GET', 'POST', 'HTTP', 'html', 'php', 'css', 'js']
        for keyword in web_keywords:
            features.append(1 if keyword in text.upper() else 0)

        # 시스템 로그 특성
        system_keywords = ['kernel', 'systemd', 'sshd', 'mysqld']
        for keyword in system_keywords:
            features.append(1 if keyword.lower() in text.lower() else 0)

        # 방화벽 특성
        firewall_keywords = ['TRAFFIC', 'THREAT', 'ALLOW', 'DENY', 'firewall', 'IPTABLES']
        for keyword in firewall_keywords:
            features.append(1 if keyword.upper() in text.upper() else 0)

        # 구조 패턴
        features.append(1 if text and text[0].isdigit() else 0)
        features.append(1 if text.startswith('{') else 0)
        features.append(1 if text.startswith('[') else 0)
        features.append(1 if 'HTTP' in text and any(m in text for m in ['GET', 'POST']) else 0)

        return features

    def load_and_analyze_training_data(self, file_path):
        """기존 학습 데이터 분석 로직 유지"""
        print("📚 학습 데이터 로드 중...")

        logs = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    logs.append(line)

        print(f"📊 총 {len(logs)}개 로그 로드됨")

        # 향상된 특성 추출
        features = [self.extract_enhanced_features(log) for log in logs]

        # TF-IDF 벡터화
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=300,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.8
        )
        tfidf_features = self.tfidf_vectorizer.fit_transform(logs).toarray()

        # 특성 결합
        combined_features = np.hstack([features, tfidf_features])

        # K-means 클러스터링
        n_clusters = 4
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        cluster_labels = kmeans.fit_predict(combined_features)

        # 클러스터 라벨링
        cluster_to_type = {}
        for i in range(n_clusters):
            cluster_logs = [logs[j] for j in range(len(logs)) if cluster_labels[j] == i]
            log_type = self.improved_log_type_detection(cluster_logs)
            cluster_to_type[i] = log_type

            print(f"클러스터 {i} -> {log_type}: {len(cluster_logs)}개")
            for sample in cluster_logs[:2]:
                print(f"  예시: {sample[:80]}...")

        # 최종 라벨링
        log_types = [cluster_to_type[label] for label in cluster_labels]

        # 분류 모델 학습
        self.log_classifier = RandomForestClassifier(n_estimators=150, random_state=42, max_depth=10)
        self.log_classifier.fit(combined_features, log_types)

        print("🤖 ML 모델 학습 완료")
        self.trained = True

        return logs, log_types

    def improved_log_type_detection(self, samples):
        """기존 로그 타입 결정 로직 유지"""
        combined_text = ' '.join(samples).upper()

        scores = {
            'security_event': 0,
            'apache': 0,
            'nginx': 0,
            'syslog': 0,
            'firewall': 0,
            'application': 0
        }

        # 보안 이벤트 점수
        security_terms = ['ERROR', 'WARN', 'FAILED', 'DENIED', 'LOGIN', 'FILE', 'USER', 'MALWARE', 'SQL', 'ATTEMPT']
        for term in security_terms:
            if term in combined_text:
                scores['security_event'] += 2

        # 웹 로그 점수
        if 'HTTP' in combined_text:
            if any(method in combined_text for method in ['GET', 'POST', 'PUT', 'DELETE']):
                if '- -' in combined_text or 'HTTPD' in combined_text:
                    scores['apache'] += 3
                else:
                    scores['nginx'] += 3

        # 시스템 로그 점수
        system_terms = ['KERNEL', 'SYSTEMD', 'SSHD', 'CRON']
        for term in system_terms:
            if term in combined_text:
                scores['syslog'] += 3

        # 방화벽 점수
        fw_terms = ['TRAFFIC', 'THREAT', 'FIREWALL', 'IPTABLES', 'ALLOW', 'DENY']
        for term in fw_terms:
            if term in combined_text:
                scores['firewall'] += 3

        # 애플리케이션 로그 점수
        if any(term in combined_text for term in ['EXEC', 'CONTROLLER', 'SPRING']):
            scores['application'] += 2

        best_type = max(scores, key=scores.get)
        if scores[best_type] < 2:
            return 'unknown'

        return best_type

    def classify_log(self, log_text):
        """기존 로그 분류 로직 유지"""
        if not self.trained:
            return 'unknown'

        try:
            enhanced_features = self.extract_enhanced_features(log_text)
            tfidf_features = self.tfidf_vectorizer.transform([log_text]).toarray()[0]
            combined_features = np.hstack([enhanced_features, tfidf_features]).reshape(1, -1)

            prediction = self.log_classifier.predict(combined_features)[0]
            probabilities = self.log_classifier.predict_proba(combined_features)[0]
            confidence = max(probabilities)

            if confidence < 0.6:
                return 'unknown'

            return prediction
        except:
            return 'unknown'

    def extract_ip_from_log(self, log_text):
        """기존 IP 추출 로직 유지"""
        words = log_text.replace(',', ' ').replace(':', ' ').replace(';', ' ').split()

        for word in words:
            clean_word = word.strip('[]()"\',')
            parts = clean_word.split('.')

            if len(parts) == 4:
                try:
                    nums = [int(part) for part in parts]
                    if all(0 <= num <= 255 for num in nums):
                        ip = '.'.join(parts)
                        if not ip.startswith(('0.0.0', '255.255.255')):
                            return ip
                except (ValueError, IndexError):
                    continue

        return None

    def extract_timestamp_from_log(self, log_text):
        """기존 타임스탬프 추출 로직 유지"""
        timestamp_patterns = [
            (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', "%Y-%m-%d %H:%M:%S"),
            (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', "%Y-%m-%dT%H:%M:%S"),
            (r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', "%d/%b/%Y:%H:%M:%S"),
            (r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})', "%b %d %H:%M:%S")
        ]

        for pattern, format_str in timestamp_patterns:
            match = re.search(pattern, log_text)
            if match:
                try:
                    time_str = match.group(1)
                    if format_str == "%b %d %H:%M:%S":
                        current_year = datetime.now().year
                        time_str = f"{current_year} {time_str}"
                        format_str = f"%Y {format_str}"
                    return datetime.strptime(time_str, format_str)
                except:
                    continue

        return datetime.now()

    def extract_severity_from_log(self, log_text, log_type):
        """기존 심각도 추출 로직 유지"""
        text_upper = log_text.upper()

        high_risk = ['ERROR', 'CRITICAL', 'FATAL', 'FAILED', 'DENIED', 'MALWARE', 'SQL', 'INJECTION', 'EXPLOIT',
                     'ATTACK']
        medium_risk = ['WARN', 'WARNING', 'TIMEOUT', 'ANOMALOUS', 'SUSPICIOUS', 'BLOCKED']
        low_risk = ['INFO', 'DEBUG', 'TRACE', 'COMPLETED', 'SUCCESS']

        score = 0
        for keyword in high_risk:
            if keyword in text_upper:
                score += 3
        for keyword in medium_risk:
            if keyword in text_upper:
                score += 2
        for keyword in low_risk:
            if keyword in text_upper:
                score += 1

        if score >= 5:
            return 'high'
        elif score >= 3:
            return 'medium'
        elif score >= 1:
            return 'low'
        else:
            return 'info'

    def build_message_from_log(self, log_text, log_type):
        """기존 메시지 구성 로직 유지"""
        if log_type in ['apache', 'nginx']:
            method = None
            path = None
            status = None

            parts = log_text.split()
            for i, part in enumerate(parts):
                if part in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']:
                    method = part
                    if i + 1 < len(parts):
                        path = parts[i + 1].strip('"').split()[0] if parts[i + 1] else '/'
                elif part.isdigit() and len(part) == 3 and 100 <= int(part) <= 599:
                    status = part

            return f"{method or 'GET'} {path or '/'} → {status or '200'}"

        elif log_type == 'security_event':
            key_parts = []
            if 'ERROR' in log_text:
                key_parts.append('ERROR')
            if 'failed' in log_text.lower():
                key_parts.append('Login Failed')
            if 'file' in log_text.lower():
                key_parts.append('File Access')
            if 'sql' in log_text.lower():
                key_parts.append('SQL Injection')
            if 'malware' in log_text.lower():
                key_parts.append('Malware Detected')

            if key_parts:
                return ' | '.join(key_parts)
            return log_text[:100] + '...' if len(log_text) > 100 else log_text

        return log_text[:100] + '...' if len(log_text) > 100 else log_text

    def build_metadata_from_log(self, log_text, log_type):
        """기존 메타데이터 구성 로직 유지"""
        metadata = {'log_format': log_type}

        if log_type in ['apache', 'nginx']:
            parts = log_text.split()
            for part in parts:
                if part in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']:
                    metadata['method'] = part
                elif part.isdigit() and len(part) == 3:
                    try:
                        metadata['status_code'] = int(part)
                    except:
                        pass

        return metadata

    def extract_all_info(self, log_line):
        """기존 정보 추출 로직 유지"""
        log_type = self.classify_log(log_line)
        timestamp = self.extract_timestamp_from_log(log_line)
        source_ip = self.extract_ip_from_log(log_line)
        severity = self.extract_severity_from_log(log_line, log_type)
        message = self.build_message_from_log(log_line, log_type)
        metadata = self.build_metadata_from_log(log_line, log_type)

        return {
            'timestamp': timestamp,
            'log_type': log_type,
            'source_ip': source_ip,
            'message': message,
            'severity': severity,
            'raw_log': log_line,
            'metadata': json.dumps(metadata)
        }


class LogMLService:
    """Django 연동 ML 로그 처리 서비스"""

    def __init__(self):
        self.extractor = ImprovedMLLogExtractor()

    def process_uploaded_file(self, log_file_instance: LogFile) -> Tuple[int, int]:
        """
        업로드된 LogFile을 ML로 처리하여 LogEntry들 생성
        기존 process_file 로직을 Django ORM으로 수정
        """
        file_path = log_file_instance.file.path
        processed = 0
        failed = 0

        print(f"📁 파일 처리 시작: {file_path}")

        # ML 모델 학습 (기존 로직)
        try:
            self.extractor.load_and_analyze_training_data(file_path)
        except Exception as e:
            logger.error(f"ML 학습 실패: {e}")
            return 0, 1

        # 로그 처리 및 Django 모델 저장 (핵심 수정 부분)
        log_entries_to_create = []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                try:
                    # 기존 ML 처리 로직
                    extracted_info = self.extractor.extract_all_info(line)

                    # Django LogEntry 객체 생성 (SQLite 대신)
                    log_entry = LogEntry(
                        log_file=log_file_instance,
                        timestamp=extracted_info['timestamp'],
                        log_type=extracted_info['log_type'],
                        source_ip=extracted_info['source_ip'],
                        message=extracted_info['message'],
                        severity=extracted_info['severity'],
                        raw_log=extracted_info['raw_log'],
                        metadata=extracted_info['metadata']
                    )
                    log_entries_to_create.append(log_entry)
                    processed += 1

                except Exception as e:
                    logger.error(f"로그 처리 오류 (라인 {line_num}): {e}")
                    failed += 1

                # 배치 처리 (메모리 효율성)
                if len(log_entries_to_create) >= 1000:
                    LogEntry.objects.bulk_create(log_entries_to_create)
                    log_entries_to_create = []
                    print(f"⏳ 처리중: {line_num} 라인...")

        # 남은 로그 엔트리들 저장
        if log_entries_to_create:
            LogEntry.objects.bulk_create(log_entries_to_create)

        # LogFile 정보 업데이트
        log_file_instance.total_entries = processed
        log_file_instance.save()

        print(f"✅ 파일 처리 완료: {processed}개 성공, {failed}개 실패")
        return processed, failed

    def get_processing_stats(self, log_file_instance: LogFile) -> Dict:
        """처리 통계 조회"""
        entries = LogEntry.objects.filter(log_file=log_file_instance)

        # log_type별 카운트 집계
        log_type_counts = entries.values('log_type').annotate(count=models.Count('id'))
        log_type_distribution = {item['log_type']: item['count'] for item in log_type_counts}

        # severity별 카운트 집계
        severity_counts = entries.values('severity').annotate(count=models.Count('id'))
        severity_distribution = {item['severity']: item['count'] for item in severity_counts}

        return {
            'total_entries': entries.count(),
            'log_type_distribution': log_type_distribution,
            'severity_distribution': severity_distribution,
            'unique_ips': entries.values('source_ip').distinct().count()
        }