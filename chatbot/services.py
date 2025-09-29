"""
OpenAI Assistants API 통신 서비스 (간단 버전)
"""
from openai import OpenAI
from django.conf import settings
import time


class ChatbotService:
    """
    Assistants API를 사용하는 챗봇 서비스
    """

    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        # OpenAI에서 생성한 Assistant ID
        self.assistant_id = "asst_Uu0iFAj2uWAWj3dbISkiEqLM"

    def create_thread(self):
        """
        새로운 대화 Thread 생성

        Returns:
            thread_id: 생성된 Thread의 ID
        """
        thread = self.client.beta.threads.create()
        return thread.id

    def send_message(self, thread_id, user_message):
        """
        Thread에 사용자 메시지 추가

        Args:
            thread_id: 대화 Thread ID
            user_message: 사용자가 보낸 메시지
        """
        self.client.beta.threads.messages.create(
            thread_id=thread_id,
            role="user",
            content=user_message
        )

    def run_assistant(self, thread_id):
        """
        Assistant를 실행하고 응답 생성

        Args:
            thread_id: 대화 Thread ID

        Returns:
            run_id: 실행 ID
        """
        run = self.client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=self.assistant_id
        )
        return run.id

    def wait_for_completion(self, thread_id, run_id, max_wait=30):
        """
        Assistant 실행이 완료될 때까지 대기

        Args:
            thread_id: Thread ID
            run_id: Run ID
            max_wait: 최대 대기 시간 (초)

        Returns:
            status: 실행 상태 ('completed', 'failed', etc.)
        """
        elapsed = 0
        while elapsed < max_wait:
            run = self.client.beta.threads.runs.retrieve(
                thread_id=thread_id,
                run_id=run_id
            )

            # 완료되면 상태 반환
            if run.status in ['completed', 'failed', 'cancelled', 'expired']:
                return run.status

            # 1초 대기
            time.sleep(1)
            elapsed += 1

        return 'timeout'

    def get_latest_message(self, thread_id):
        """
        Thread에서 가장 최근 AI 응답 가져오기

        Args:
            thread_id: Thread ID

        Returns:
            AI의 응답 텍스트
        """
        messages = self.client.beta.threads.messages.list(
            thread_id=thread_id,
            order='desc',
            limit=1
        )

        # 가장 최근 메시지의 텍스트 추출
        if messages.data:
            return messages.data[0].content[0].text.value
        return "응답을 가져올 수 없습니다."

    def chat(self, user_message, thread_id=None):
        """
        전체 대화 프로세스 (간단 버전)

        Args:
            user_message: 사용자 메시지
            thread_id: 기존 Thread ID (없으면 새로 생성)

        Returns:
            (응답 텍스트, thread_id)
        """
        try:
            # 1. Thread 생성 또는 재사용
            if not thread_id:
                thread_id = self.create_thread()
                print(f"✅ 새 Thread 생성: {thread_id}")

            # 2. 메시지 추가
            self.send_message(thread_id, user_message)
            print(f"✅ 메시지 추가 완료")

            # 3. Assistant 실행
            run_id = self.run_assistant(thread_id)
            print(f"✅ Assistant 실행 시작: {run_id}")

            # 4. 완료 대기
            status = self.wait_for_completion(thread_id, run_id)
            print(f"✅ 실행 상태: {status}")

            if status != 'completed':
                return f"오류: Assistant 실행 실패 ({status})", thread_id

            # 5. 응답 가져오기
            response = self.get_latest_message(thread_id)
            print(f"✅ 응답 받음")

            return response, thread_id

        except Exception as e:
            return f"오류 발생: {str(e)}", thread_id