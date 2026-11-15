
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated


from . import ml
from .models import ScanRecord


class ScanView(APIView):
    """POST /api/scan/ with email text and/or URL."""

    def post(self, request):
        text = (request.data.get("text") or "").strip()
        url = (request.data.get("url") or "").strip()

        if not text and not url:
            return Response(
                {"error": "Send 'text' (email content) and/or 'url'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        result = {}

        email_result = None
        url_result = None

        if text:
            email_result = ml.scan_email(text)
            result["email"] = email_result

        if url:
            url_result = ml.scan_url(url)
            result["url"] = url_result

        if text and url:
            scan_type = "combined"
        elif text:
            scan_type = "email"
        else:
            scan_type = "url"

        if request.user.is_authenticated:
            ScanRecord.objects.create(
                user=request.user,
                scan_type=scan_type,
                email_content=text,
                scanned_url=url,
                email_result=email_result,
                url_result=url_result
            )

        return Response(result)








class HistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        records = ScanRecord.objects.filter(user=request.user)[:100]
        data = []
        for rec in records:
            res = {}
            if rec.email_result:
                res['email'] = rec.email_result
            if rec.url_result:
                res['url'] = rec.url_result
            data.append({
                'id': str(rec.id),
                'timestamp': rec.created_at.isoformat(),
                'type': 'both' if rec.scan_type == 'combined' else rec.scan_type,
                'result': res,
                'emailPreview': rec.email_content or '',
                'urlPreview': rec.scanned_url or '',
            })
        return Response(data)

    def delete(self, request):
        ScanRecord.objects.filter(user=request.user).delete()
        return Response({'message': 'Scan history cleared.'})
