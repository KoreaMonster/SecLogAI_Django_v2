"""
Chatbot API Serializers
"""
from rest_framework import serializers
from .models import ChatSession, ChatMessage


class ChatMessageSerializer(serializers.ModelSerializer):
    """
    채팅 메시지 Serializer
    """

    class Meta:
        model = ChatMessage
        fields = ['role', 'content', 'timestamp']
        read_only_fields = ['timestamp']


class ChatSessionSerializer(serializers.ModelSerializer):
    """
    채팅 세션 Serializer (목록용)
    """
    message_count = serializers.SerializerMethodField()

    class Meta:
        model = ChatSession
        fields = ['id', 'thread_id', 'created_at', 'updated_at', 'message_count']
        read_only_fields = ['id', 'thread_id', 'created_at', 'updated_at']

    def get_message_count(self, obj):
        """메시지 개수 반환"""
        return obj.messages.count()


class ChatSessionDetailSerializer(serializers.ModelSerializer):
    """
    채팅 세션 상세 Serializer (메시지 포함)
    """
    messages = ChatMessageSerializer(many=True, read_only=True)

    class Meta:
        model = ChatSession
        fields = ['id', 'thread_id', 'log_file', 'created_at', 'updated_at', 'messages']
        read_only_fields = ['id', 'thread_id', 'created_at', 'updated_at']


class ChatRequestSerializer(serializers.Serializer):
    """
    채팅 요청 Serializer (입력 검증)
    """
    message = serializers.CharField(
        max_length=2000,
        help_text="사용자 메시지"
    )
    session_id = serializers.UUIDField(
        required=False,
        allow_null=True,
        help_text="기존 세션 ID (없으면 새로 생성)"
    )
    log_file_id = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text="참조할 로그 파일 ID (선택)"
    )

    def validate_message(self, value):
        """메시지 검증"""
        if not value.strip():
            raise serializers.ValidationError("메시지가 비어있습니다.")
        return value.strip()


class ChatResponseSerializer(serializers.Serializer):
    """
    채팅 응답 Serializer (출력 포맷)
    """
    session_id = serializers.UUIDField(help_text="세션 ID")
    thread_id = serializers.CharField(help_text="OpenAI Thread ID")
    user_message = serializers.CharField(help_text="사용자 메시지")
    assistant_message = serializers.CharField(help_text="AI 응답")
    timestamp = serializers.DateTimeField(help_text="응답 시간")