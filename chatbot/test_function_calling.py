"""
Function Calling 통합 테스트
"""
import os
import sys
import django

# Django 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from rest_framework.test import APIClient
from chatbot.models import ChatSession
from logs.models import LogFile, LogEntry
from datetime import datetime
import uuid


def setup_test_data():
    """테스트용 로그 데이터 생성"""
    print("\n📦 테스트 데이터 생성 중...")

    # 로그 파일 생성
    log_file = LogFile.objects.create(
        name="test_security.log",
        total_entries=5
    )

    # 로그 엔트리 생성
    test_logs = [
        {
            "timestamp": datetime.now(),
            "log_type": "security_event",
            "source_ip": "192.168.1.100",
            "message": "Failed login attempt",
            "severity": "high",
            "raw_log": "2025-10-01 10:00:00 Failed login",
            "metadata": "{}"
        },
        {
            "timestamp": datetime.now(),
            "log_type": "access_log",
            "source_ip": "192.168.1.101",
            "message": "Access granted to /admin",
            "severity": "medium",
            "raw_log": "2025-10-01 10:01:00 Access granted",
            "metadata": "{}"
        },
        {
            "timestamp": datetime.now(),
            "log_type": "security_event",
            "source_ip": "192.168.1.102",
            "message": "SQL injection attempt detected",
            "severity": "high",
            "raw_log": "2025-10-01 10:02:00 SQL injection",
            "metadata": "{}"
        },
        {
            "timestamp": datetime.now(),
            "log_type": "error_log",
            "source_ip": "192.168.1.103",
            "message": "Database connection failed",
            "severity": "high",
            "raw_log": "2025-10-01 10:03:00 DB error",
            "metadata": "{}"
        },
        {
            "timestamp": datetime.now(),
            "log_type": "access_log",
            "source_ip": "192.168.1.100",
            "message": "Normal page access",
            "severity": "low",
            "raw_log": "2025-10-01 10:04:00 Page access",
            "metadata": "{}"
        }
    ]

    for log_data in test_logs:
        LogEntry.objects.create(log_file=log_file, **log_data)

    print(f"✅ 로그 파일 생성: {log_file.id}")
    print(f"✅ 로그 엔트리 생성: {len(test_logs)}개")

    return log_file


def cleanup_test_data():
    """테스트 데이터 정리"""
    print("\n🧹 테스트 데이터 정리 중...")
    LogFile.objects.filter(name="test_security.log").delete()
    ChatSession.objects.filter(thread_id__startswith="thread_").delete()
    print("✅ 정리 완료")


def test_1_general_question():
    """테스트 1: 일반 질문 (Function 호출 불필요)"""
    print("\n" + "=" * 60)
    print("테스트 1: 일반 질문 (Function 호출 없음)")
    print("=" * 60)

    client = APIClient()

    data = {
        "message": "보안 로그 분석이 뭔가요?",
        "session_id": None
    }

    print(f"\n📤 요청: {data['message']}")
    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"Session ID: {response.data['session_id']}")
        print(f"\nAI 응답:\n{response.data['assistant_message'][:200]}...")
        return response.data['session_id']
    else:
        print(f"❌ 실패: {response.data}")
        return None


def test_2_fetch_logs(session_id, log_file_id):
    """테스트 2: 로그 조회 (fetch_logs 호출)"""
    print("\n" + "=" * 60)
    print("테스트 2: 로그 조회 (fetch_logs Function 호출)")
    print("=" * 60)

    # 세션에 log_file 연결
    session = ChatSession.objects.get(id=session_id)
    session.log_file_id = log_file_id
    session.save()
    print(f"✅ 세션에 로그 파일 연결: {log_file_id}")

    client = APIClient()

    data = {
        "message": "최근 로그를 보여주세요",
        "session_id": str(session_id)
    }

    print(f"\n📤 요청: {data['message']}")
    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\nAI 응답:\n{response.data['assistant_message'][:500]}...")

        # Function 호출 확인
        if "로그" in response.data['assistant_message'] or "log" in response.data['assistant_message'].lower():
            print("\n✅ Function 호출 성공 (로그 데이터 기반 답변)")
        else:
            print("\n⚠️ Function 호출 안 됨 (일반 답변)")
    else:
        print(f"❌ 실패: {response.data}")


def test_3_fetch_analysis(session_id):
    """테스트 3: 분석 결과 조회 (fetch_analysis 호출)"""
    print("\n" + "=" * 60)
    print("테스트 3: 분석 결과 조회 (fetch_analysis Function 호출)")
    print("=" * 60)

    client = APIClient()

    data = {
        "message": "보안 위협이 탐지되었나요?",
        "session_id": str(session_id)
    }

    print(f"\n📤 요청: {data['message']}")
    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\nAI 응답:\n{response.data['assistant_message'][:500]}...")

        # Function 호출 확인
        if "high" in response.data['assistant_message'].lower() or "위협" in response.data['assistant_message']:
            print("\n✅ Function 호출 성공 (분석 데이터 기반 답변)")
        else:
            print("\n⚠️ Function 호출 안 됨 (일반 답변)")
    else:
        print(f"❌ 실패: {response.data}")


def test_4_specific_query(session_id):
    """테스트 4: 구체적인 로그 질문"""
    print("\n" + "=" * 60)
    print("테스트 4: 구체적인 로그 질문")
    print("=" * 60)

    client = APIClient()

    data = {
        "message": "high severity 로그가 몇 개인가요?",
        "session_id": str(session_id)
    }

    print(f"\n📤 요청: {data['message']}")
    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\nAI 응답:\n{response.data['assistant_message']}")

        # 정확한 숫자 확인 (테스트 데이터에는 3개의 high severity)
        if "3" in response.data['assistant_message']:
            print("\n✅ 정확한 데이터 기반 답변!")
        else:
            print("\n⚠️ 답변 확인 필요")
    else:
        print(f"❌ 실패: {response.data}")


def test_5_no_log_file(session_id):
    """테스트 5: 로그 파일이 없는 세션"""
    print("\n" + "=" * 60)
    print("테스트 5: 로그 파일이 없는 세션 (에러 처리)")
    print("=" * 60)

    # 새 세션 생성 (log_file 없음)
    client = APIClient()

    data = {
        "message": "로그를 분석해주세요",
        "session_id": None  # 새 세션
    }

    print(f"\n📤 요청: {data['message']}")
    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ API 성공")
        print(f"\nAI 응답:\n{response.data['assistant_message'][:300]}...")

        # 에러 메시지 확인
        if "로그 파일" in response.data['assistant_message'] or "업로드" in response.data['assistant_message']:
            print("\n✅ 에러 처리 성공 (적절한 안내 메시지)")
        else:
            print("\n⚠️ 에러 메시지 확인 필요")
    else:
        print(f"❌ API 실패: {response.data}")


if __name__ == "__main__":
    print("\n🤖 Function Calling 통합 테스트 시작")
    print("=" * 60)

    try:
        # 테스트 데이터 생성
        log_file = setup_test_data()

        # 테스트 1: 일반 질문
        session_id = test_1_general_question()

        if session_id:
            # 테스트 2: 로그 조회
            test_2_fetch_logs(session_id, log_file.id)

            # 테스트 3: 분석 결과 조회
            test_3_fetch_analysis(session_id)

            # 테스트 4: 구체적인 질문
            test_4_specific_query(session_id)

        # 테스트 5: 에러 처리
        test_5_no_log_file(None)

        print("\n" + "=" * 60)
        print("✅ 모든 테스트 완료!")
        print("=" * 60)

        # 테스트 데이터 정리
        cleanup_test_data()

    except Exception as e:
        print(f"\n❌ 테스트 실패: {e}")
        import traceback

        traceback.print_exc()
        cleanup_test_data()