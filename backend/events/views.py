from rest_framework.generics import ListAPIView, RetrieveAPIView

from .models import SecurityEvent
from .serializers import SecurityEventSerializer


class SecurityEventListView(ListAPIView):
    queryset = SecurityEvent.objects.order_by('-event_time', '-id')
    serializer_class = SecurityEventSerializer


class SecurityEventDetailView(RetrieveAPIView):
    queryset = SecurityEvent.objects.all()
    serializer_class = SecurityEventSerializer
