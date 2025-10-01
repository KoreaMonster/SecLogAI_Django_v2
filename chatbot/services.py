"""
OpenAI Assistants API 통신 서비스 (Function Calling 지원)
"""
from openai import OpenAI
from django.conf import settings
import time
import json
import logging

# Django 모델 임포트
from .models import ChatSession
from logs.models import LogEntry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ChatbotService:
    """
    Assistants API를 사용하는 챗봇 서비스 (Function Calling 포함)
    """

    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self.assistant_id = "asst_Uu0iFAj2uWAWj3dbISkiEqLM"

    def create_thread(self, session_id=None):
        """
        새로운 대화 Thread 생성

        Args:
            session_id: 세션 ID (metadata에 저장)

        Returns:
            thread_id: 생성된 Thread의 ID
        """
        metadata = {}
        if session_id:
            metadata["session_id"] = str(session_id)

        thread = self.client.beta.threads.create(metadata=metadata)
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
        Assistant 실행이 완료될 때까지 대기 (Function Calling 처리 포함)

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

            # Function 호출 요청 처리
            if run.status == 'requires_action':
                logger.info("🔧 Function 호출 요청 감지")
                tool_outputs = self.handle_required_action(run, thread_id)
                self.submit_tool_outputs(thread_id, run_id, tool_outputs)
                logger.info("✅ Function 결과 제출 완료")
                # 다시 대기 계속

            # 완료
            elif run.status == 'completed':
                logger.info("✅ Assistant 실행 완료")
                return 'completed'

            # 실패/취소/만료
            elif run.status in ['failed', 'cancelled', 'expired']:
                logger.error(f"❌ Assistant 실행 실패: {run.status}")
                return run.status

            # 1초 대기
            time.sleep(1)
            elapsed += 1

        logger.error("⏱️ 타임아웃")
        return 'timeout'

    def handle_required_action(self, run, thread_id):
        """
        Function 호출 요청 처리

        Args:
            run: Run 객체 (required_action 포함)
            thread_id: Thread ID (metadata에서 session_id 추출용)

        Returns:
            tool_outputs: Function 실행 결과 리스트
        """
        tool_outputs = []
        tool_calls = run.required_action.submit_tool_outputs.tool_calls

        # Thread metadata에서 session_id 가져오기
        thread = self.client.beta.threads.retrieve(thread_id)
        session_id = thread.metadata.get("session_id")

        if not session_id:
            logger.warning("⚠️ Thread metadata에 session_id가 없습니다")

        for tool_call in tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)

            # session_id를 자동으로 주입
            if session_id and "session_id" not in function_args:
                function_args["session_id"] = session_id
                logger.info(f"📌 session_id 자동 주입: {session_id[:8]}...")

            logger.info(f"🔧 Function 호출: {function_name}, 파라미터: {function_args}")

            # Function 실행
            try:
                output = self._route_function_call(function_name, function_args)
            except Exception as e:
                logger.error(f"❌ Function 실행 오류: {e}")
                output = json.dumps({"error": str(e)})

            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output": output
            })

        return tool_outputs

    def submit_tool_outputs(self, thread_id, run_id, tool_outputs):
        """
        Function 실행 결과를 OpenAI에 제출

        Args:
            thread_id: Thread ID
            run_id: Run ID
            tool_outputs: Function 실행 결과 리스트
        """
        self.client.beta.threads.runs.submit_tool_outputs(
            thread_id=thread_id,
            run_id=run_id,
            tool_outputs=tool_outputs
        )

    def _route_function_call(self, function_name, arguments):
        """
        Function 이름에 따라 적절한 조회 함수 호출

        Args:
            function_name: 호출할 Function 이름
            arguments: Function 파라미터 딕셔너리

        Returns:
            JSON 문자열 형태의 실행 결과
        """
        if function_name == "fetch_logs":
            session_id = arguments.get("session_id")
            window = arguments.get("window", 100)
            return self._fetch_logs_from_db(session_id, window)

        elif function_name == "fetch_analysis":
            session_id = arguments.get("session_id")
            return self._fetch_analysis_from_db(session_id)

        else:
            return json.dumps({
                "error": f"알 수 없는 Function: {function_name}"
            })

    def _fetch_logs_from_db(self, session_id, window=100):
        """
        Django ORM으로 로그 데이터 조회

        Args:
            session_id: 조회할 세션 UUID (문자열)
            window: 최근 N개만 가져오기

        Returns:
            JSON 문자열
        """
        try:
            # 세션 조회
            session = ChatSession.objects.get(id=session_id)
            logger.info(f"📊 세션 조회 성공: {session_id[:8]}...")

            # 로그 파일 확인
            if not session.log_file:
                return json.dumps({
                    "error": "로그 파일이 업로드되지 않은 세션입니다."
                })

            # 로그 엔트리 조회
            log_entries = LogEntry.objects.filter(
                log_file=session.log_file
            ).order_by('-timestamp')[:window]

            # 딕셔너리 리스트로 변환
            logs_data = []
            for entry in log_entries:
                logs_data.append({
                    "timestamp": entry.timestamp.isoformat(),
                    "log_type": entry.log_type,
                    "source_ip": entry.source_ip,
                    "message": entry.message,
                    "severity": entry.severity,
                })

            result = {
                "total_count": len(logs_data),
                "logs": logs_data
            }

            logger.info(f"✅ 로그 조회 완료: {len(logs_data)}개")
            return json.dumps(result, ensure_ascii=False)

        except ChatSession.DoesNotExist:
            logger.error(f"❌ 세션을 찾을 수 없음: {session_id}")
            return json.dumps({
                "error": "해당 세션을 찾을 수 없습니다."
            })

        except Exception as e:
            logger.error(f"❌ DB 조회 오류: {e}")
            return json.dumps({
                "error": f"데이터베이스 조회 중 오류가 발생했습니다: {str(e)}"
            })

    def _fetch_analysis_from_db(self, session_id):
        """
        Django ORM으로 분석 결과 조회 (저장된 결과 사용)

        Args:
            session_id: 조회할 세션 UUID (문자열)

        Returns:
            JSON 문자열
        """
        try:
            # Django 모델 import
            from analysis.models import AnalysisResult

            # 세션 조회
            session = ChatSession.objects.get(id=session_id)
            logger.info(f"📊 세션 조회 성공: {session_id[:8]}...")

            # 로그 파일 확인
            if not session.log_file:
                return json.dumps({
                    "error": "로그 파일이 업로드되지 않은 세션입니다."
                })

            # 저장된 분석 결과 조회
            try:
                basic_stats = AnalysisResult.objects.get(
                    log_file=session.log_file,
                    analysis_type='basic_stats'
                )
                security_threat = AnalysisResult.objects.get(
                    log_file=session.log_file,
                    analysis_type='security_threat'
                )
                anomaly = AnalysisResult.objects.get(
                    log_file=session.log_file,
                    analysis_type='anomaly'
                )
            except AnalysisResult.DoesNotExist:
                return json.dumps({
                    "error": "분석이 아직 완료되지 않았습니다. 잠시 후 다시 시도해주세요."
                })

            # 저장된 데이터에서 정보 추출
            basic_data = basic_stats.result_data
            security_data = security_threat.result_data
            anomaly_data = anomaly.result_data

            # 통합 결과 생성
            result = {
                "summary": f"총 {basic_data.get('total_logs', 0)}개의 로그가 분석되었습니다.",
                "severity_distribution": basic_data.get('severity_distribution', {}),
                "log_types": basic_data.get('log_type_distribution', {}),
                "top_ips": basic_data.get('top_ips', {}),
                "security_analysis": {
                    "high_severity_count": security_data.get('high_severity_count', 0),
                    "threat_patterns": security_data.get('threat_patterns', {}),
                    "suspicious_ip_count": security_data.get('suspicious_ip_count', 0)
                },
                "anomaly_analysis": {
                    "total_anomalies": anomaly_data.get('total_anomalies', 0),
                    "volume_anomalies": anomaly_data.get('volume_anomaly_count', 0),
                    "behavioral_anomalies": anomaly_data.get('behavioral_anomaly_count', 0)
                },
                "recommendations": []
            }

            # 위협 판단 및 권고사항
            high_count = security_data.get('high_severity_count', 0)
            if high_count > 0:
                result["recommendations"].append(
                    f"⚠️ {high_count}개의 high severity 로그가 발견되었습니다. 즉시 확인이 필요합니다."
                )

            suspicious_count = security_data.get('suspicious_ip_count', 0)
            if suspicious_count > 0:
                result["recommendations"].append(
                    f"🚨 {suspicious_count}개의 의심스러운 IP가 탐지되었습니다."
                )

            anomaly_count = anomaly_data.get('total_anomalies', 0)
            if anomaly_count > 0:
                result["recommendations"].append(
                    f"🔍 {anomaly_count}개의 이상 행위가 감지되었습니다."
                )

            logger.info(f"✅ 분석 결과 조회 완료 (저장된 데이터)")
            return json.dumps(result, ensure_ascii=False)

        except ChatSession.DoesNotExist:
            logger.error(f"❌ 세션을 찾을 수 없음: {session_id}")
            return json.dumps({
                "error": "해당 세션을 찾을 수 없습니다."
            })

        except Exception as e:
            logger.error(f"❌ 분석 조회 오류: {e}")
            return json.dumps({
                "error": f"분석 결과 조회 중 오류가 발생했습니다: {str(e)}"
            })

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

        if messages.data:
            return messages.data[0].content[0].text.value
        return "응답을 가져올 수 없습니다."

    def chat(self, user_message, thread_id=None, session_id=None):
        """
        전체 대화 프로세스 (Function Calling 지원)

        Args:
            user_message: 사용자 메시지
            thread_id: 기존 Thread ID (없으면 새로 생성)
            session_id: 세션 ID (Thread metadata에 저장)

        Returns:
            (응답 텍스트, thread_id)
        """
        try:
            # 1. Thread 생성 또는 재사용
            if not thread_id:
                thread_id = self.create_thread(session_id)
                logger.info(f"✅ 새 Thread 생성: {thread_id}")

            # 2. 메시지 추가
            self.send_message(thread_id, user_message)
            logger.info(f"✅ 메시지 추가 완료")

            # 3. Assistant 실행
            run_id = self.run_assistant(thread_id)
            logger.info(f"✅ Assistant 실행 시작: {run_id}")

            # 4. 완료 대기 (Function Calling 자동 처리)
            status = self.wait_for_completion(thread_id, run_id)
            logger.info(f"✅ 실행 상태: {status}")

            if status != 'completed':
                return f"오류: Assistant 실행 실패 ({status})", thread_id

            # 5. 응답 가져오기
            response = self.get_latest_message(thread_id)
            logger.info(f"✅ 응답 받음")

            return response, thread_id

        except Exception as e:
            logger.error(f"❌ 챗봇 오류: {e}")
            return f"오류 발생: {str(e)}", thread_id