from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # API 엔드포인트
    path('api/logs/', include('logs.urls')),
    path('api/analysis/', include('analysis.urls')),
    path('api/chatbot/', include('chatbot.urls')),

    # 루트 경로에서 index.html 서빙
    path('', TemplateView.as_view(template_name='index.html'), name='home'),
]

# 미디어 파일 서빙 (업로드된 로그 파일)
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)