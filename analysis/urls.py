# analysis/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('basic-stats/', views.basic_stats_analysis, name='basic_stats_analysis'),
    path('security-threat/', views.security_threat_analysis, name='security_threat_analysis'),
    path('anomaly/', views.anomaly_analysis, name='anomaly_analysis'),
    path('correlation/', views.correlation_analysis, name='correlation_analysis'),
    path('predictive/', views.predictive_analysis, name='predictive_analysis'),
    path('generate-report/', views.generate_report, name='generate_report'),
]