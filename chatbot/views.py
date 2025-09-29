"""
Chatbot API Views
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .models import ChatSession, ChatMessage
from .serializers import (
    ChatRequestSerializer,
    ChatResponseSerializer,
    ChatSessionSerializer,
    ChatSessionDetailSerializer
)
from .services import ChatbotService


class ChatMessageView(APIView):
    """
    채팅 메시지 API
    POST: 메시지 보내고 응답 받기
    """

    def post(self, request):
        """
        사용자 메시지를 받아서 GPT 응답 반환
        """
        # 1. 입력 데이터 검증
        serializer = ChatRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        # 2. 데이터 추출
        user_message = serializer.validated_data['message']
        session_id = serializer.validated_data.get('session_id')
        log_file_id = serializer.validated_data.get('log_file_id')

        # 3. ChatbotService 초기화
        chatbot_service = ChatbotService()

        # 4. 세션 확인 또는 생성
        if session_id:
            # 기존 세션 가져오기
            session = get_object_or_404(ChatSession, id=session_id)
            thread_id = session.thread_id
        else:
            # 새 세션 생성
            thread_id = None
            session = None

        # 5. GPT에게 메시지 보내고 응답 받기
        try:
            assistant_response, thread_id = chatbot_service.chat(
                user_message=user_message,
                thread_id=thread_id
            )
        except Exception as e:
            return Response(
                {"error": f"챗봇 오류: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 6. 새 세션이면 DB에 저장
        if not session:
            session = ChatSession.objects.create(
                thread_id=thread_id,
                log_file_id=log_file_id
            )

        # 7. 메시지 저장 (사용자 + AI)
        ChatMessage.objects.create(
            session=session,
            role='user',
            content=user_message
        )

        assistant_msg = ChatMessage.objects.create(
            session=session,
            role='assistant',
            content=assistant_response
        )

        # 8. 응답 반환
        response_data = {
            'session_id': session.id,
            'thread_id': session.thread_id,
            'user_message': user_message,
            'assistant_message': assistant_response,
            'timestamp': assistant_msg.timestamp
        }

        response_serializer = ChatResponseSerializer(response_data)
        return Response(
            response_serializer.data,
            status=status.HTTP_200_OK
        )


class ChatSessionListView(APIView):
    """
    채팅 세션 목록 API
    GET: 전체 세션 목록 조회
    """

    def get(self, request):
        """세션 목록 반환"""
        sessions = ChatSession.objects.all()
        serializer = ChatSessionSerializer(sessions, many=True)
        return Response(serializer.data)


class ChatSessionDetailView(APIView):
    """
    채팅 세션 상세 API
    GET: 특정 세션의 전체 메시지 조회
    """

    def get(self, request, session_id):
        """세션 상세 정보 반환 (메시지 포함)"""
        session = get_object_or_404(ChatSession, id=session_id)
        serializer = ChatSessionDetailSerializer(session)
        return Response(serializer.data)