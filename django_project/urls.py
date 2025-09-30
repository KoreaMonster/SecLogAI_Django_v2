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

    # 단일 페이지 라우팅 (index.html만 사용)
    path('', TemplateView.as_view(template_name='index.html'), name='home'),
]

if settings.DEBUG:
    urlpatterns += static('/', document_root=settings.BASE_DIR)