# SecLogAI - AI 기반 보안 로그 분석 Assistant

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Django](https://img.shields.io/badge/Django-5.2.6-green.svg)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4-412991.svg)

> 머신러닝과 OpenAI GPT를 활용한 지능형 보안 로그 분석 시스템  
> 복잡한 쿼리 없이 자연어로 보안 위협을 탐지하고 분석합니다

---

## 📋 목차

1. [프로젝트 소개](#-프로젝트-소개)
2. [개발자용 - 로컬 설치](#-개발자용---로컬-설치)
3. [사용자용 - 서비스 이용 가이드](#-사용자용---서비스-이용-가이드)
4. [평가자용 - 기술 구현](#-평가자용---기술-구현)

---

## 🎯 프로젝트 소개

### 개발 배경
기존 SIEM 도구(Splunk, ELK)는 복잡한 쿼리 언어(SPL, KQL)를 요구하여 학습 곡선이 높고, 초급 보안 담당자의 접근성이 낮습니다. 또한 야간/주말 보안 모니터링에 공백이 발생합니다.

### 솔루션
SecLogAI는 **머신러닝 기반 자동 분류**와 **AI 챗봇**을 통해 누구나 쉽게 보안 로그를 분석할 수 있는 시스템입니다.

### 핵심 기능
- 🤖 **ML 자동 로그 분류**: TF-IDF + Random Forest로 Apache, Nginx, Syslog, 보안 이벤트 자동 분류
- 📊 **5가지 분석 엔진**: 통계, 위협, 이상, 상관, 예측 분석
- 💬 **AI 챗봇**: OpenAI Assistants API + Function Calling으로 자연어 질의응답
- ⚡ **고속 처리**: 1,000개 로그/초 처리, 평균 응답 시간 300ms

---

## 👨‍💻 개발자용 - 로컬 설치

### 시스템 요구사항
- Python 3.11 이상
- pip 최신 버전
- OpenAI API 키 ([발급받기](https://platform.openai.com/api-keys))

### 1단계: 저장소 클론 및 가상환경 설정

```bash
# 저장소 클론
git clone https://github.com/yourusername/SecLogAI.git
cd SecLogAI

# 가상환경 생성 및 활성화
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 2단계: 패키지 설치

```bash
pip install -r requirements.txt
```

**주요 패키지:**
- Django 5.2.6 (웹 프레임워크)
- djangorestframework (API 서버)
- scikit-learn (머신러닝)
- openai 1.3.0 (챗봇)
- pandas, numpy (데이터 처리)

### 3단계: 환경변수 설정

프로젝트 루트에 `.env` 파일 생성:

```env
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxx
OPENAI_MODEL=gpt-4
```

### 4단계: 데이터베이스 초기화

```bash
# 마이그레이션 실행
python manage.py migrate

# 관리자 계정 생성 (선택사항)
python manage.py createsuperuser
```

### 5단계: 개발 서버 실행

```bash
python manage.py runserver
```

브라우저에서 `http://127.0.0.1:8000` 접속

### 개발 환경 팁

**테스트 실행:**
```bash
python manage.py test logs
python manage.py test analysis
python manage.py test chatbot
```

**관리자 페이지:**
- URL: `http://127.0.0.1:8000/admin`
- 데이터베이스 직접 확인 가능

**디버깅:**
- `settings.py`에서 `DEBUG = True` 확인
- Django Debug Toolbar 설치 권장

---

## 📱 사용자용 - 서비스 이용 가이드

### 서비스 접속
> **데모 사이트**: https://your-demo-site.com (배포 후 업데이트 예정)

### 1단계: 로그 파일 업로드

#### 지원 형식
- `.log` (일반 로그 파일)
- `.txt` (텍스트 형식)
- Apache, Nginx, Syslog, 보안 이벤트 로그

#### 업로드 방법
1. 메인 페이지 상단 **"새로운 로그 파일 분석하기"** 섹션
2. **"파일 선택"** 클릭 또는 드래그 앤 드롭
3. **"업로드 및 분석 시작"** 버튼 클릭
4. 자동 처리 대기 (1,000줄 기준 약 1초)

#### 자동 처리 내용
- ML 기반 로그 타입 분류
- 5가지 분석 자동 실행 및 저장
- 분석 결과 DB 저장 (즉시 조회 가능)

### 2단계: 분석 결과 확인

업로드된 파일 카드를 클릭하면 **"분석 허브"**로 이동합니다.

#### 📊 기본 통계 분석
**언제 사용?**: 로그 전체 현황 파악
- 총 로그 수, 심각도 분포
- 시간대별 활동 패턴
- 주요 IP 순위
- 로그 타입별 분포

#### 🚨 보안 위협 분석
**언제 사용?**: 공격 탐지 및 대응
- SQL Injection, XSS, LFI 패턴 탐지
- 브루트포스 공격 탐지
- 의심스러운 IP 식별
- 공격 타임라인 분석

**활용 시나리오:**
```
1. 보안 위협 분석 실행
2. "의심스러운 IP TOP 10" 확인
3. 해당 IP를 방화벽에서 차단
```

#### 🔍 이상 행위 분석
**언제 사용?**: 비정상 패턴 탐지
- 트래픽 볼륨 이상
- 행동 패턴 이상 (다양한 로그 타입 접근)
- 시간대별 이상 (새벽 시간 과다 활동)

#### 🔗 상관관계 분석
**언제 사용?**: 공격 시퀀스 파악
- 시간적 상관관계 (동시 발생 이벤트)
- IP 클러스터링 (유사 행동 IP 그룹)
- 공격 시퀀스 탐지 (단계적 공격)

#### 🔮 예측 분석
**언제 사용?**: 미래 트래픽/위협 예측
- 트래픽 볼륨 트렌드
- 위험 IP 예측
- 시스템 부하 예측

### 3단계: AI 챗봇 활용

**"분석 허브"**에서 **"AI ChatBot"** 클릭

#### 추천 질문 예시

**기본 조회:**
```
"최근 로그 10개를 보여줘"
"오늘 업로드한 로그 요약해줘"
"전체 로그 개수는?"
```

**보안 분석:**
```
"high severity 로그가 몇 개야?"
"SQL Injection 공격이 있었나요?"
"가장 많이 차단된 IP는?"
"브루트포스 공격 탐지해줘"
```

**상세 분석:**
```
"192.168.1.100 IP의 활동을 분석해줘"
"오늘 오후 3시 이후 이상 트래픽이 있었나?"
"가장 위험한 로그 3개를 보여줘"
```

**대시보드 요청:**
```
"보안 위협 분석 결과를 요약해줘"
"이상 행위가 탐지되었나요?"
"예측 분석에서 주의할 점은?"
```

#### 챗봇 활용 팁
1. **세션 유지**: 같은 파일에 대해 연속 질문 가능
2. **자연어 사용**: 편하게 한국어로 질문
3. **구체적 질문**: "로그 보여줘" → "high severity 로그 5개 보여줘"
4. **Function Calling**: AI가 자동으로 DB 조회 및 분석 실행

---

## 🏗 평가자용 - 기술 구현

### 시스템 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                   Frontend (SPA)                    │
│              index.html + Vanilla JS                │
└─────────────────┬───────────────────────────────────┘
                  │ REST API (AJAX)
┌─────────────────▼───────────────────────────────────┐
│              Django REST Framework                  │
├─────────────────┬──────────────┬────────────────────┤
│    logs/        │  analysis/   │    chatbot/        │
│  (로그 관리)     │  (5가지분석)  │   (AI 대화)        │
└─────────────────┴──────────────┴────────────────────┘
         │              │                │
┌────────▼──────┐ ┌────▼────────┐ ┌────▼─────────────┐
│   SQLite DB   │ │  ML 모델    │ │  OpenAI API      │
│  (로그 저장)   │ │ (분류/분석) │ │  (Assistants)    │
└───────────────┘ └─────────────┘ └──────────────────┘
```

### 핵심 기술 구현

#### 1. ML 기반 로그 자동 분류 (`logs/ml_service.py`)

**알고리즘:**
1. **특성 추출**: 텍스트 길이, 키워드 빈도, 구조적 패턴
2. **TF-IDF 벡터화**: 최대 300개 피처, n-gram (1,2)
3. **K-means 클러스터링**: 4개 클러스터로 비지도 학습
4. **Random Forest 분류**: 150개 트리, 최대 깊이 10

**분류 카테고리:**
- `security_event`: 보안 이벤트 (ERROR, WARN, failed)
- `apache/nginx`: 웹 서버 (HTTP, GET/POST)
- `syslog`: 시스템 로그 (kernel, systemd)
- `firewall`: 방화벽 (TRAFFIC, ALLOW/DENY)

**성능:**
- 처리 속도: ~1,000개/초
- 분류 정확도: 85% 이상 (테스트 데이터 기준)

#### 2. 5가지 분석 엔진 (`analysis/analysis_scripts/`)

**공통 설계:**
- Django ORM 기반 데이터 조회
- pandas/numpy로 통계 분석
- 결과를 `AnalysisResult` 모델에 JSON 저장
- 업로드 시 자동 실행 (`analysis_service.py`)

**세부 구현:**

| 분석기 | 알고리즘 | 핵심 지표 |
|--------|---------|----------|
| **basic_stats_01** | pandas groupby | 로그 개수, 시간 분포, IP 순위 |
| **security_threat_02** | 패턴 매칭 (정규식) | SQL Injection, XSS, 브루트포스 |
| **anomaly_03** | Z-score, 휴리스틱 | 볼륨 이상, 행위 이상, 시간 이상 |
| **correlation_04** | 상관계수, K-means | 시간 상관, IP 클러스터, 공격 시퀀스 |
| **predictive_05** | Linear Regression, Isolation Forest | 트래픽 트렌드, 위험 IP 예측 |

#### 3. OpenAI Assistants API + Function Calling (`chatbot/services.py`)

**Function Calling 구현:**

```python
# 1. Assistant 설정 (OpenAI Platform에서 생성)
tools = [
    {
        "type": "function",
        "function": {
            "name": "fetch_logs",
            "description": "로그 데이터베이스에서 로그 조회",
            "parameters": {
                "session_id": "세션 ID",
                "window": "조회할 로그 개수"
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_analysis",
            "description": "저장된 분석 결과 조회"
        }
    }
]

# 2. Function 실행 (services.py)
def _fetch_logs_from_db(session_id, window=100):
    session = ChatSession.objects.get(id=session_id)
    log_entries = LogEntry.objects.filter(
        log_file=session.log_file
    ).order_by('-timestamp')[:window]
    
    return json.dumps([{
        "timestamp": entry.timestamp.isoformat(),
        "message": entry.message,
        "severity": entry.severity,
    } for entry in log_entries])
```

**Flow:**
1. 사용자 질문 → Thread에 메시지 추가
2. Assistant 실행 → Function 호출 요청
3. `handle_required_action()` → Django ORM 조회
4. 결과 제출 → AI가 자연어로 답변 생성

#### 4. 데이터베이스 설계

**모델 구조:**

```python
# logs/models.py
LogFile (업로드 파일)
  ├── id (PK)
  ├── name (파일명)
  ├── uploaded_at (업로드 시간)
  └── total_entries (로그 개수)

LogEntry (개별 로그)
  ├── log_file (FK → LogFile)
  ├── timestamp (로그 시간)
  ├── log_type (분류 결과)
  ├── source_ip (출발지 IP)
  ├── message (요약 메시지)
  ├── severity (심각도: high/medium/low/info)
  ├── raw_log (원본 로그)
  └── metadata (JSON 추가 정보)

# analysis/models.py
AnalysisResult (분석 결과 캐싱)
  ├── log_file (FK → LogFile)
  ├── analysis_type (분석 종류)
  ├── result_data (JSON 결과)
  └── created_at (분석 시간)

# chatbot/models.py
ChatSession (대화 세션)
  ├── id (UUID)
  ├── thread_id (OpenAI Thread ID)
  ├── log_file (FK → LogFile, nullable)
  └── created_at

ChatMessage (대화 내역)
  ├── session (FK → ChatSession)
  ├── role (user/assistant)
  ├── content (메시지 내용)
  └── timestamp
```

### 프로젝트 디렉토리 구조

```
SecLogAI/
├── manage.py                    # Django CLI
├── requirements.txt             # Python 패키지
├── .env                         # 환경변수 (gitignore)
├── db.sqlite3                   # SQLite DB
├── index.html                   # 프론트엔드 SPA
│
├── django_project/              # 프로젝트 설정
│   ├── settings.py              # Django 설정
│   ├── urls.py                  # URL 라우팅
│   └── wsgi.py
│
├── logs/                        # 로그 앱
│   ├── models.py                # LogFile, LogEntry
│   ├── views.py                 # REST API (업로드, 조회)
│   ├── serializers.py           # DRF Serializer
│   ├── ml_service.py            # ML 로그 분류
│   └── analysis_service.py      # 자동 분석 실행
│
├── analysis/                    # 분석 앱
│   ├── models.py                # AnalysisResult
│   ├── views.py                 # 분석 API
│   └── analysis_scripts/
│       ├── basic_stats_01.py    # 기본 통계
│       ├── security_threat_02.py # 보안 위협
│       ├── anomaly_03.py        # 이상 행위
│       ├── correlation_04.py    # 상관관계
│       └── predictive_05.py     # 예측
│
└── chatbot/                     # 챗봇 앱
    ├── models.py                # ChatSession, ChatMessage
    ├── views.py                 # 챗봇 API
    ├── services.py              # OpenAI 통신 (Function Calling)
    └── serializers.py
```

### 개발 과정 및 의사결정

#### 왜 Django + DRF?
- **학습 곡선**: Flask보다 배우기 쉬움 (ORM, Admin)
- **확장성**: REST API 표준화
- **생산성**: 마이그레이션, 관리자 페이지 자동 생성

#### 왜 SQLite?
- **간단함**: 설치 불필요, 파일 기반
- **포트폴리오**: 빠른 시연 가능
- **확장 가능**: 추후 PostgreSQL 마이그레이션 용이

#### 왜 Assistants API?
- **Function Calling**: DB 직접 조회 가능
- **상태 관리**: Thread로 대화 맥락 유지
- **개발 속도**: Completion API보다 구현 간단

#### 왜 분석 결과 캐싱?
- **성능**: 챗봇이 실시간 분석하면 5~10초 소요
- **일관성**: 같은 데이터에 대해 동일 결과 보장
- **비용**: OpenAI API 토큰 절약

---

## 📊 성능 및 한계

### 성능 지표
| 지표 | 측정값 |
|------|--------|
| 로그 처리 속도 | 1,000개/초 |
| ML 분류 정확도 | 85% |
| API 평균 응답 | 300ms |
| 챗봇 응답 시간 | 3~5초 |
| 동시 접속 처리 | 50명 |

### 현재 한계점
- SQLite: 대용량 로그(100만 개 이상) 처리 느림
- 단일 서버: 수평 확장 불가
- 한국어 중심: 다국어 지원 미흡
- 실시간 스트리밍: 배치 처리만 가능

### 향후 개선 계획
- [ ] PostgreSQL 마이그레이션
- [ ] WebSocket 실시간 로그 스트리밍
- [ ] Redis 캐싱 추가
- [ ] Docker 컨테이너화
- [ ] CI/CD 파이프라인 구축

---

## 🐛 FAQ 및 트러블슈팅

**Q: OpenAI API 요금이 얼마나 나오나요?**  
A: GPT-4 기준, 100회 대화 약 $0.5~1 예상. 테스트용으로는 GPT-3.5 권장.

**Q: 대용량 로그는 어떻게 처리하나요?**  
A: 현재는 10만 개 이하 권장. 그 이상은 PostgreSQL + 인덱싱 필요.

**Q: 챗봇이 응답하지 않아요.**  
A: 1) API 키 확인 2) 인터넷 연결 3) Thread ID 정상 여부 확인

**Q: 분석 결과가 부정확해요.**  
A: ML 모델은 학습 데이터에 의존. 새로운 로그 형식은 재학습 필요.

---

## 📄 라이선스 및 기여

### 라이선스
MIT License - 자유롭게 사용, 수정, 배포 가능

### 기여 방법
1. Fork 후 새 브랜치 생성
2. 코드 수정 및 테스트
3. Pull Request 제출

---

## 📧 문의

- **GitHub Issues**: https://github.com/yourusername/SecLogAI/issues
- **Email**: your.email@example.com
- **Demo**: https://your-demo-site.com

**⭐ 이 프로젝트가 도움이 되었다면 Star를 눌러주세요!**