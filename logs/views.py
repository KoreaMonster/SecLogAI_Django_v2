from django.shortcuts import render

# Create your views here.
# logs/views.py
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
# ⭐️ 1. csrf_exempt를 import 합니다.
from django.views.decorators.csrf import csrf_exempt

from .models import LogFile, LogEntry
from .serializers import LogFileSerializer, LogEntrySerializer
from .ml_service import LogMLService


# ⭐️ 2. @csrf_exempt 데코레이터를 @api_view 바로 위에 추가합니다.
@csrf_exempt
@api_view(['POST'])
def upload_log_file(request):
    """로그 파일 업로드 및 ML 처리"""
    serializer = LogFileSerializer(data=request.data)

    if serializer.is_valid():
        # 파일 저장
        log_file = serializer.save()

        # ML 처리 시작
        try:
            ml_service = LogMLService()
            processed, failed = ml_service.process_uploaded_file(log_file)

            return Response({
                'message': 'File uploaded and processed successfully',
                'log_file_id': log_file.id,
                'processed_entries': processed,
                'failed_entries': failed
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'error': f'ML processing failed: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def list_log_files(request):
    """업로드된 로그 파일 목록 조회"""
    log_files = LogFile.objects.all()
    serializer = LogFileSerializer(log_files, many=True)
    return Response(serializer.data)


@api_view(['GET'])
def get_log_file_detail(request, file_id):
    """특정 로그 파일 정보 조회"""
    log_file = get_object_or_404(LogFile, id=file_id)
    serializer = LogFileSerializer(log_file)

    # 추가 통계 정보
    ml_service = LogMLService()
    stats = ml_service.get_processing_stats(log_file)

    response_data = serializer.data
    response_data['stats'] = stats

    return Response(response_data)


@api_view(['GET'])
def get_log_entries(request, file_id):
    """특정 파일의 로그 엔트리 목록 조회 (페이지네이션)"""
    log_file = get_object_or_404(LogFile, id=file_id)

    # 쿼리 파라미터
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 50))
    log_type = request.GET.get('log_type')
    severity = request.GET.get('severity')

    # 필터링
    entries = LogEntry.objects.filter(log_file=log_file)
    if log_type:
        entries = entries.filter(log_type=log_type)
    if severity:
        entries = entries.filter(severity=severity)

    # 페이지네이션
    start = (page - 1) * page_size
    end = start + page_size
    paginated_entries = entries[start:end]

    serializer = LogEntrySerializer(paginated_entries, many=True)

    return Response({
        'results': serializer.data,
        'count': entries.count(),
        'page': page,
        'page_size': page_size
    })


@api_view(['GET'])
def preview_log_entries(request, file_id):
    """로그 엔트리 미리보기 (처음 100개)"""
    log_file = get_object_or_404(LogFile, id=file_id)
    entries = LogEntry.objects.filter(log_file=log_file)[:100]
    serializer = LogEntrySerializer(entries, many=True)

    return Response({
        'preview': serializer.data,
        'total_count': LogEntry.objects.filter(log_file=log_file).count()
    })


@api_view(['DELETE'])
def delete_log_file(request, file_id):
    """로그 파일 및 관련 엔트리 삭제"""
    log_file = get_object_or_404(LogFile, id=file_id)

    # 파일 삭제 (관련 LogEntry들은 CASCADE로 자동 삭제)
    log_file.delete()

    return Response({
        'message': 'Log file deleted successfully'
    }, status=status.HTTP_204_NO_CONTENT)
