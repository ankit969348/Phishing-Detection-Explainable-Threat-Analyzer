

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from . import ml


class ScanView(APIView):
    """POST /api/scan/  with JSON: {"text": "...email..."} and/or {"url": "..."}"""

    def post(self, request):
        text = (request.data.get("text") or "").strip()
        url = (request.data.get("url") or "").strip()

        if not text and not url:
            return Response({"error": "Send 'text' (email content) and/or 'url'."},
                            status=status.HTTP_400_BAD_REQUEST)

        result = {}
        if text:
            result["email"] = ml.scan_email(text)
        if url:
            result["url"] = ml.scan_url(url)
        return Response(result)
