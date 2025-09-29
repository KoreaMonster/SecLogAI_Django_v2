from django.urls import path
from . import views

app_name = 'chatbot'

urlpatterns = [
    # 메시지 보내기
    path('message/', views.ChatMessageView.as_view(), name='chat-message'),

    # 세션 목록
    path('sessions/', views.ChatSessionListView.as_view(), name='session-list'),

    # 세션 상세 (UUID 파라미터)
    path('sessions/<uuid:session_id>/', views.ChatSessionDetailView.as_view(), name='session-detail'),
]