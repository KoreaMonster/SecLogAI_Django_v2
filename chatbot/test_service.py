"""
Assistants API 간단 테스트
"""
import os
import sys
import django

# Django 설정
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from chatbot.services import ChatbotService


def test_basic_chat():
    """기본 대화 테스트"""
    print("=" * 60)
    print("Assistants API 테스트 시작")
    print("=" * 60)

    service = ChatbotService()

    # 테스트 메시지 1
    print("\n[테스트 1] 첫 번째 메시지")
    print("-" * 60)
    user_msg = "안녕하세요! 보안 로그 분석에 대해 간단히 설명해주세요."
    print(f"사용자: {user_msg}")

    response, thread_id = service.chat(user_msg)
    print(f"\nAI: {response}")
    print(f"\nThread ID: {thread_id}")

    # 테스트 메시지 2 (같은 Thread에서)
    print("\n" + "=" * 60)
    print("[테스트 2] 이어서 대화하기 (같은 Thread)")
    print("-" * 60)
    user_msg2 = "그럼 어떤 종류의 위협이 있나요?"
    print(f"사용자: {user_msg2}")

    response2, thread_id = service.chat(user_msg2, thread_id=thread_id)
    print(f"\nAI: {response2}")

    print("\n" + "=" * 60)
    print("✅ 테스트 완료!")
    print("=" * 60)


def test_new_thread():
    """새 Thread 생성 테스트"""
    print("\n" + "=" * 60)
    print("[테스트 3] 새로운 대화 시작")
    print("-" * 60)

    service = ChatbotService()

    user_msg = "SQL Injection 공격이 뭔가요?"
    print(f"사용자: {user_msg}")

    response, thread_id = service.chat(user_msg)
    print(f"\nAI: {response}")
    print(f"\nThread ID: {thread_id}")

    print("\n✅ 새 Thread 테스트 완료")


if __name__ == "__main__":
    print("\n🤖 Assistants API 테스트\n")

    try:
        # 기본 대화 테스트
        test_basic_chat()

        # 새 Thread 테스트
        test_new_thread()

    except Exception as e:
        print(f"\n❌ 테스트 실패: {e}")
        import traceback

        traceback.print_exc()