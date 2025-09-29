from django.db import models
import uuid


class ChatSession(models.Model):
    """
    대화 세션 - OpenAI Thread와 1:1 매핑
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    thread_id = models.CharField(
        max_length=255,
        unique=True,
        help_text="OpenAI Thread ID"
    )
    log_file = models.ForeignKey(
        'logs.LogFile',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='chat_sessions'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Session {self.id[:8]} (Thread: {self.thread_id[:15]}...)"


class ChatMessage(models.Model):
    """
    개별 채팅 메시지
    """
    ROLE_CHOICES = [
        ('user', '사용자'),
        ('assistant', 'AI 어시스턴트'),
    ]

    session = models.ForeignKey(
        ChatSession,
        on_delete=models.CASCADE,
        related_name='messages'
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"{self.role}: {self.content[:50]}..."