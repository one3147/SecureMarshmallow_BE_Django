from datetime import timedelta
from django.http import JsonResponse
from django.utils import timezone
from Marshmallow.models import RequestLog
from config import settings


class BlockForeignIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        if is_local_ip(ip):
            return JsonResponse({'error': 'Blocked Ip.'})
        response = self.get_response(request)
        return response

def is_local_ip(ip):
    korean_ip_ranges = [
        '127.0.0.1',
        '58.120.0.0/14',  # KT Corp
        '58.121.0.0/16',  # KT Corp
        '58.122.0.0/16',  # KT Corp
        '58.123.0.0/16',  # KT Corp
        '58.124.0.0/14',  # KT Corp
        '58.125.0.0/16',  # KT Corp
        '58.126.0.0/16',  # KT Corp
        '58.127.0.0/16',  # KT Corp
        '61.32.0.0/12',  # SK Broadband
        '112.160.0.0/11',  # LG Uplus Corp
        '118.32.0.0/12',  # LG Uplus Corp
        '211.224.0.0/11',  # SK Telecom
        '222.98.0.0/17',  # LG DACOM Corporation
        '222.99.0.0/16',  # LG DACOM Corporation
        '222.100.0.0/14',  # LG DACOM Corporation
        '222.104.0.0/13',  # LG DACOM Corporation
        '222.112.0.0/13',  # LG DACOM Corporation
        '222.120.0.0/13',  # LG DACOM Corporation
        '222.224.0.0/11',  # LG DACOM Corporation
        '218.144.0.0/12',  # LG Uplus Corp
        '221.128.0.0/11',  # SK Broadband
        '211.192.0.0/11',  # SK Telecom
    ]
    for i in korean_ip_ranges:
        if i == ip:
            return False
    return True

class RequestRateThrottleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self.should_be_throttled(request):
            return JsonResponse({'error': 'Too many Request.'})
        return self.get_response(request)

    def should_be_throttled(self, request):
        current_time = timezone.now()
        time_window = current_time - settings.REQUEST_THROTTLE_TIME_WINDOW
        user_ip = request.META.get('REMOTE_ADDR')
        request_count = RequestLog.objects.filter(
            user_ip=user_ip,
            timestamp__gte=time_window,
        ).count()
        if request_count >= settings.REQUEST_THROTTLE_MAX_REQUESTS:
            return True

        RequestLog.objects.create(user_ip=user_ip, timestamp=current_time)

        time_threshold = current_time - timedelta(seconds=1)
        RequestLog.objects.filter(timestamp__lt=time_threshold).delete()

        return False


class RequestSizeLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if self.is_request_too_large(request):
            return JsonResponse({'error': 'Invalid Request.'})
        return self.get_response(request)

    def is_request_too_large(self, request):
        content_length = request.META.get('CONTENT_LENGTH')
        if content_length is None or content_length == '':
            return False

        try:
            content_length = int(content_length)
        except ValueError:
            return False

        exception_urls = ['/api/file/upload']
        if (request.body is None or content_length > 10000) and request.path not in exception_urls:
            return True
        return False


