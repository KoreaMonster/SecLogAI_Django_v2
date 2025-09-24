# logs/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # 파일 업로드
    path('upload/', views.upload_log_file, name='upload_log_file'),

    # 파일 목록 및 상세
    path('files/', views.list_log_files, name='list_log_files'),
    path('files/<int:file_id>/', views.get_log_file_detail, name='log_file_detail'),

    # 로그 엔트리 조회
    path('files/<int:file_id>/entries/', views.get_log_entries, name='log_entries'),
    path('files/<int:file_id>/preview/', views.preview_log_entries, name='log_preview'),

    # 파일 삭제
    path('files/<int:file_id>/delete/', views.delete_log_file, name='delete_log_file'),
]