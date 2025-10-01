"""
세션 생성 문제 진단 테스트 (15가지 체크포인트)
"""
import os
import sys
import django
import time
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from chatbot.services import ChatbotService
from chatbot.models import ChatSession, ChatMessage
from logs.models import LogFile, LogEntry
from analysis.models import AnalysisResult


class DebugTester:
    def __init__(self):
        self.service = ChatbotService()
        self.results = []

    def log(self, msg, level="INFO"):
        symbols = {"INFO": "ℹ️", "PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}
        print(f"{symbols.get(level, 'ℹ️')} {msg}")

    def test(self, name, func):
        """테스트 실행 및 결과 기록"""
        try:
            result = func()
            self.results.append((name, result))
            return result
        except Exception as e:
            self.log(f"오류: {e}", "FAIL")
            self.results.append((name, False))
            return False

    # ============================================================
    # 1. Thread 생성 시 metadata 저장
    # ============================================================
    def test_01_thread_metadata(self):
        self.log("\n[1/15] Thread metadata 저장 테스트")

        test_id = "test-session-001"
        thread_id = self.service.create_thread(session_id=test_id)
        self.log(f"Thread 생성: {thread_id}")

        thread = self.service.client.beta.threads.retrieve(thread_id)
        metadata = thread.metadata

        self.log(f"저장된 metadata: {metadata}")

        if metadata.get("session_id") == test_id:
            self.log("metadata 저장 정상", "PASS")
            return True
        else:
            self.log("metadata 저장 실패", "FAIL")
            return False

    # ============================================================
    # 2. Session DB 즉시 조회
    # ============================================================
    def test_02_session_immediate_query(self):
        self.log("\n[2/15] Session DB 즉시 조회 테스트")

        session = ChatSession.objects.create(thread_id="test_thread_002")
        self.log(f"Session 생성: {session.id}")

        try:
            found = ChatSession.objects.get(id=session.id)
            self.log(f"즉시 조회 성공: {found.id}", "PASS")
            session.delete()
            return True
        except:
            self.log("즉시 조회 실패", "FAIL")
            return False

    # ============================================================
    # 3. Thread metadata 업데이트 가능 여부
    # ============================================================
    def test_03_metadata_update(self):
        self.log("\n[3/15] Thread metadata 업데이트 테스트")

        thread_id = self.service.create_thread()
        self.log(f"Thread 생성: {thread_id}")

        # 업데이트
        new_id = "updated-session-003"
        self.service.client.beta.threads.update(
            thread_id,
            metadata={"session_id": new_id}
        )

        # 재조회
        thread = self.service.client.beta.threads.retrieve(thread_id)

        if thread.metadata.get("session_id") == new_id:
            self.log("metadata 업데이트 성공", "PASS")
            return True
        else:
            self.log("metadata 업데이트 실패", "FAIL")
            return False

    # ============================================================
    # 4. 현재 views.py 로직 시뮬레이션
    # ============================================================
    def test_04_current_flow_simulation(self):
        self.log("\n[4/15] 현재 views.py 로직 시뮬레이션")

        # 현재 방식: Session 먼저 생성 (thread_id="temp")
        session = ChatSession.objects.create(thread_id="temp")
        self.log(f"1. Session 생성 (thread_id=temp): {session.id}")

        # Thread 생성
        thread_id = self.service.create_thread(session_id=str(session.id))
        self.log(f"2. Thread 생성: {thread_id}")

        # Session 업데이트
        session.thread_id = thread_id
        session.save()
        self.log(f"3. Session 업데이트: thread_id={thread_id}")

        # Thread metadata 확인
        thread = self.service.client.beta.threads.retrieve(thread_id)
        saved_session_id = thread.metadata.get("session_id")
        self.log(f"4. Thread metadata session_id: {saved_session_id}")

        # DB에서 조회
        try:
            found = ChatSession.objects.get(id=saved_session_id)
            self.log(f"5. DB 조회 성공: {found.id}", "PASS")
            session.delete()
            return True
        except:
            self.log(f"5. DB 조회 실패: {saved_session_id}", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 5. 제안된 새 로직 시뮬레이션
    # ============================================================
    def test_05_new_flow_simulation(self):
        self.log("\n[5/15] 제안된 새 로직 시뮬레이션")

        # 1. Thread 먼저 생성
        thread_id = self.service.create_thread()
        self.log(f"1. Thread 생성: {thread_id}")

        # 2. Session 생성 (실제 thread_id)
        session = ChatSession.objects.create(thread_id=thread_id)
        self.log(f"2. Session 생성: {session.id}")

        # 3. Thread metadata 업데이트
        self.service.client.beta.threads.update(
            thread_id,
            metadata={"session_id": str(session.id)}
        )
        self.log(f"3. Thread metadata 업데이트 완료")

        # 4. metadata 조회
        thread = self.service.client.beta.threads.retrieve(thread_id)
        saved_session_id = thread.metadata.get("session_id")
        self.log(f"4. Thread metadata session_id: {saved_session_id}")

        # 5. DB 조회
        try:
            found = ChatSession.objects.get(id=saved_session_id)
            self.log(f"5. DB 조회 성공: {found.id}", "PASS")
            session.delete()
            return True
        except:
            self.log(f"5. DB 조회 실패", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 6. LogFile 존재 여부
    # ============================================================
    def test_06_logfile_exists(self):
        self.log("\n[6/15] LogFile 데이터 존재 확인")

        count = LogFile.objects.count()
        self.log(f"LogFile 개수: {count}")

        if count > 0:
            latest = LogFile.objects.latest('uploaded_at')
            self.log(f"최신 파일: {latest.name} (ID: {latest.id})")
            self.log(f"로그 엔트리: {latest.total_entries}개")
            self.log("LogFile 존재", "PASS")
            return True
        else:
            self.log("LogFile 없음", "WARN")
            return False

    # ============================================================
    # 7. LogEntry 존재 여부
    # ============================================================
    def test_07_logentry_exists(self):
        self.log("\n[7/15] LogEntry 데이터 존재 확인")

        count = LogEntry.objects.count()
        self.log(f"LogEntry 개수: {count}")

        if count > 0:
            sample = LogEntry.objects.first()
            self.log(f"샘플: {sample.log_type} | {sample.severity} | {sample.source_ip}")
            self.log("LogEntry 존재", "PASS")
            return True
        else:
            self.log("LogEntry 없음", "WARN")
            return False

    # ============================================================
    # 8. AnalysisResult 존재 여부
    # ============================================================
    def test_08_analysis_exists(self):
        self.log("\n[8/15] AnalysisResult 데이터 존재 확인")

        count = AnalysisResult.objects.count()
        self.log(f"AnalysisResult 개수: {count}")

        if count > 0:
            types = AnalysisResult.objects.values_list('analysis_type', flat=True).distinct()
            self.log(f"분석 타입: {list(types)}")
            self.log("AnalysisResult 존재", "PASS")
            return True
        else:
            self.log("AnalysisResult 없음", "WARN")
            return False

    # ============================================================
    # 9. Session에 LogFile 연결 테스트
    # ============================================================
    def test_09_session_logfile_link(self):
        self.log("\n[9/15] Session-LogFile 연결 테스트")

        log_files = LogFile.objects.all()
        if not log_files.exists():
            self.log("LogFile 없음 - 테스트 스킵", "WARN")
            return False

        log_file = log_files.first()
        session = ChatSession.objects.create(
            thread_id="test_thread_009",
            log_file=log_file
        )
        self.log(f"Session 생성: {session.id}")
        self.log(f"연결된 LogFile: {session.log_file.name}")

        # 조회 테스트
        found = ChatSession.objects.get(id=session.id)
        if found.log_file == log_file:
            self.log("LogFile 연결 정상", "PASS")
            session.delete()
            return True
        else:
            self.log("LogFile 연결 실패", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 10. fetch_logs Function 시뮬레이션
    # ============================================================
    def test_10_fetch_logs_function(self):
        self.log("\n[10/15] fetch_logs Function 시뮬레이션")

        # Session 생성 (LogFile 연결)
        log_files = LogFile.objects.all()
        if not log_files.exists():
            self.log("LogFile 없음 - 테스트 스킵", "WARN")
            return False

        session = ChatSession.objects.create(
            thread_id="test_thread_010",
            log_file=log_files.first()
        )
        self.log(f"Session 생성: {session.id}")

        # fetch_logs 실행
        result = self.service._fetch_logs_from_db(str(session.id), window=10)
        self.log(f"Function 결과 타입: {type(result)}")

        try:
            data = json.loads(result)
            if 'logs' in data:
                self.log(f"조회된 로그: {data['total_count']}개")
                self.log("fetch_logs 정상", "PASS")
                session.delete()
                return True
            elif 'error' in data:
                self.log(f"에러: {data['error']}", "FAIL")
                session.delete()
                return False
        except:
            self.log("JSON 파싱 실패", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 11. fetch_analysis Function 시뮬레이션
    # ============================================================
    def test_11_fetch_analysis_function(self):
        self.log("\n[11/15] fetch_analysis Function 시뮬레이션")

        # Session 생성 (LogFile 연결)
        log_files = LogFile.objects.all()
        if not log_files.exists():
            self.log("LogFile 없음 - 테스트 스킵", "WARN")
            return False

        session = ChatSession.objects.create(
            thread_id="test_thread_011",
            log_file=log_files.first()
        )
        self.log(f"Session 생성: {session.id}")

        # fetch_analysis 실행
        result = self.service._fetch_analysis_from_db(str(session.id))
        self.log(f"Function 결과 타입: {type(result)}")

        try:
            data = json.loads(result)
            if 'summary' in data or 'severity_distribution' in data:
                self.log("분석 결과 조회 성공")
                self.log("fetch_analysis 정상", "PASS")
                session.delete()
                return True
            elif 'error' in data:
                self.log(f"에러: {data['error']}", "FAIL")
                session.delete()
                return False
        except:
            self.log("JSON 파싱 실패", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 12. Assistant Function 정의 확인
    # ============================================================
    def test_12_assistant_functions(self):
        self.log("\n[12/15] Assistant Function 정의 확인")

        assistant = self.service.client.beta.assistants.retrieve(
            self.service.assistant_id
        )

        functions = [t for t in assistant.tools if t.type == 'function']
        self.log(f"등록된 Function: {len(functions)}개")

        for func_tool in functions:
            func = func_tool.function
            self.log(f"  - {func.name}")

            params = func.parameters.get('properties', {})
            required = func.parameters.get('required', [])

            if 'session_id' in params:
                is_required = 'session_id' in required
                self.log(f"    session_id 필수: {is_required}")

        if len(functions) >= 2:
            self.log("Function 정의 정상", "PASS")
            return True
        else:
            self.log("Function 정의 부족", "FAIL")
            return False

    # ============================================================
    # 13. 실제 API 호출 타이밍 테스트
    # ============================================================
    def test_13_api_timing(self):
        self.log("\n[13/15] 실제 API 호출 타이밍 테스트")

        log_files = LogFile.objects.all()
        if not log_files.exists():
            self.log("LogFile 없음 - 테스트 스킵", "WARN")
            return False

        # 1. Thread 생성
        thread_id = self.service.create_thread()
        self.log(f"1. Thread 생성: {thread_id}")

        # 2. Session 생성
        session = ChatSession.objects.create(
            thread_id=thread_id,
            log_file=log_files.first()
        )
        self.log(f"2. Session 생성: {session.id}")

        # 3. Metadata 업데이트
        self.service.client.beta.threads.update(
            thread_id,
            metadata={"session_id": str(session.id)}
        )
        self.log(f"3. Metadata 업데이트")

        # 4. 메시지 전송
        self.service.send_message(thread_id, "최근 로그를 보여주세요")
        self.log(f"4. 메시지 전송")

        # 5. Assistant 실행
        run_id = self.service.run_assistant(thread_id)
        self.log(f"5. Assistant 실행: {run_id}")

        # 6. 완료 대기
        status = self.service.wait_for_completion(thread_id, run_id, max_wait=30)
        self.log(f"6. 실행 완료: {status}")

        if status == 'completed':
            response = self.service.get_latest_message(thread_id)
            self.log(f"7. 응답 받음: {response[:50]}...")
            self.log("API 호출 타이밍 정상", "PASS")
            session.delete()
            return True
        else:
            self.log(f"API 호출 실패: {status}", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 14. ChatMessage 저장 테스트
    # ============================================================
    def test_14_chatmessage_save(self):
        self.log("\n[14/15] ChatMessage 저장 테스트")

        session = ChatSession.objects.create(thread_id="test_thread_014")
        self.log(f"Session 생성: {session.id}")

        # 메시지 저장
        msg = ChatMessage.objects.create(
            session=session,
            role='user',
            content='테스트 메시지'
        )
        self.log(f"메시지 저장: {msg.id}")

        # 조회
        found = ChatMessage.objects.filter(session=session).first()
        if found and found.content == '테스트 메시지':
            self.log("ChatMessage 저장 정상", "PASS")
            session.delete()
            return True
        else:
            self.log("ChatMessage 저장 실패", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 15. 전체 통합 테스트
    # ============================================================
    def test_15_full_integration(self):
        self.log("\n[15/15] 전체 통합 테스트 (실제 대화)")

        log_files = LogFile.objects.all()
        if not log_files.exists():
            self.log("LogFile 없음 - 테스트 스킵", "WARN")
            return False

        # 1. Thread 생성
        thread_id = self.service.create_thread()

        # 2. Session 생성
        session = ChatSession.objects.create(
            thread_id=thread_id,
            log_file=log_files.first()
        )

        # 3. Metadata 업데이트
        self.service.client.beta.threads.update(
            thread_id,
            metadata={"session_id": str(session.id)}
        )

        self.log(f"Session: {session.id}")
        self.log(f"Thread: {thread_id}")

        # 4. 대화 실행
        try:
            response, _ = self.service.chat(
                user_message="보안 위협이 있나요?",
                thread_id=thread_id,
                session_id=str(session.id)
            )

            self.log(f"응답: {response[:100]}...")

            # 5. 메시지 저장 확인
            msg_count = ChatMessage.objects.filter(session=session).count()
            self.log(f"저장된 메시지: {msg_count}개")

            if msg_count >= 2:
                self.log("전체 통합 테스트 성공", "PASS")
                session.delete()
                return True
            else:
                self.log("메시지 저장 부족", "FAIL")
                session.delete()
                return False

        except Exception as e:
            self.log(f"통합 테스트 실패: {e}", "FAIL")
            session.delete()
            return False

    # ============================================================
    # 실행
    # ============================================================
    def run_all(self):
        print("\n" + "=" * 60)
        print("  🧪 세션 문제 진단 테스트 (15개)")
        print("=" * 60)

        tests = [
            ("Thread metadata 저장", self.test_01_thread_metadata),
            ("Session DB 즉시 조회", self.test_02_session_immediate_query),
            ("Metadata 업데이트", self.test_03_metadata_update),
            ("현재 로직 시뮬레이션", self.test_04_current_flow_simulation),
            ("제안 로직 시뮬레이션", self.test_05_new_flow_simulation),
            ("LogFile 존재", self.test_06_logfile_exists),
            ("LogEntry 존재", self.test_07_logentry_exists),
            ("AnalysisResult 존재", self.test_08_analysis_exists),
            ("Session-LogFile 연결", self.test_09_session_logfile_link),
            ("fetch_logs Function", self.test_10_fetch_logs_function),
            ("fetch_analysis Function", self.test_11_fetch_analysis_function),
            ("Assistant Function 정의", self.test_12_assistant_functions),
            ("API 호출 타이밍", self.test_13_api_timing),
            ("ChatMessage 저장", self.test_14_chatmessage_save),
            ("전체 통합", self.test_15_full_integration),
        ]

        for name, func in tests:
            self.test(name, func)
            time.sleep(0.5)

        # 결과 출력
        print("\n" + "=" * 60)
        print("  📊 테스트 결과")
        print("=" * 60)

        for name, passed in self.results:
            status = "✅" if passed else "❌"
            print(f"{status} {name}")

        passed = sum(1 for _, p in self.results if p)
        total = len(self.results)

        print("\n" + "=" * 60)
        print(f"  결과: {passed}/{total} 통과 ({passed / total * 100:.0f}%)")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    tester = DebugTester()
    tester.run_all()