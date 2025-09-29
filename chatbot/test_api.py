"""
Chatbot API 테스트 (간단 버전)
"""
import os
import sys
import django

# Django 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from rest_framework.test import APIClient
from chatbot.models import ChatSession, ChatMessage


def test_send_message():
    """메시지 보내기 테스트"""
    print("=" * 60)
    print("테스트 1: 첫 메시지 보내기")
    print("=" * 60)

    client = APIClient()

    # 요청 데이터
    data = {
        "message": "안녕하세요! 보안 로그 분석이 뭔가요?",
        "session_id": None
    }

    print(f"\n📤 요청: POST /api/chatbot/message/")
    print(f"데이터: {data}")

    # API 호출
    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"\n📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\n응답 데이터:")
        print(f"  - Session ID: {response.data['session_id']}")
        print(f"  - Thread ID: {response.data['thread_id']}")
        print(f"  - 사용자 메시지: {response.data['user_message']}")
        print(f"  - AI 응답: {response.data['assistant_message'][:100]}...")

        return response.data['session_id']
    else:
        print(f"❌ 실패: {response.data}")
        return None


def test_continue_conversation(session_id):
    """이어서 대화하기 테스트"""
    print("\n" + "=" * 60)
    print("테스트 2: 같은 세션에서 이어서 대화")
    print("=" * 60)

    client = APIClient()

    data = {
        "message": "SQL Injection은 어떻게 방어하나요?",
        "session_id": str(session_id)
    }

    print(f"\n📤 요청: POST /api/chatbot/message/")
    print(f"데이터: {data}")

    response = client.post('/api/chatbot/message/', data, format='json')

    print(f"\n📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\n응답 데이터:")
        print(f"  - Session ID: {response.data['session_id']} (동일한지 확인)")
        print(f"  - AI 응답: {response.data['assistant_message'][:100]}...")
    else:
        print(f"❌ 실패: {response.data}")


def test_session_list():
    """세션 목록 조회 테스트"""
    print("\n" + "=" * 60)
    print("테스트 3: 세션 목록 조회")
    print("=" * 60)

    client = APIClient()

    print(f"\n📤 요청: GET /api/chatbot/sessions/")

    response = client.get('/api/chatbot/sessions/')

    print(f"\n📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\n총 세션 수: {len(response.data)}개")
        for session in response.data:
            print(f"  - {session['id'][:8]}... (메시지 {session['message_count']}개)")
    else:
        print(f"❌ 실패: {response.data}")


def test_session_detail(session_id):
    """세션 상세 조회 테스트"""
    print("\n" + "=" * 60)
    print("테스트 4: 세션 상세 조회")
    print("=" * 60)

    client = APIClient()

    print(f"\n📤 요청: GET /api/chatbot/sessions/{session_id}/")

    response = client.get(f'/api/chatbot/sessions/{session_id}/')

    print(f"\n📥 응답 상태: {response.status_code}")

    if response.status_code == 200:
        print(f"✅ 성공!")
        print(f"\n세션 정보:")
        print(f"  - ID: {response.data['id']}")
        print(f"  - Thread ID: {response.data['thread_id']}")
        print(f"\n메시지 내역:")
        for msg in response.data['messages']:
            print(f"  [{msg['role']}] {msg['content'][:50]}...")
    else:
        print(f"❌ 실패: {response.data}")


if __name__ == "__main__":
    print("\n🤖 Chatbot API 테스트 시작\n")

    try:
        # 테스트 1: 첫 메시지
        session_id = test_send_message()

        if session_id:
            # 테스트 2: 이어서 대화
            test_continue_conversation(session_id)

            # 테스트 3: 세션 목록
            test_session_list()

            # 테스트 4: 세션 상세
            test_session_detail(session_id)

        print("\n" + "=" * 60)
        print("✅ 모든 테스트 완료!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 테스트 실패: {e}")
        import traceback

        traceback.print_exc()