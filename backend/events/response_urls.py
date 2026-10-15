from django.urls import path

from .views import ResponseDetailView, ResponseListView, WebAutoStatusView

urlpatterns = [
    path('', ResponseListView.as_view(), name='response-list'),
    path('web-auto/', WebAutoStatusView.as_view(), name='response-web-auto'),
    path('<int:pk>/', ResponseDetailView.as_view(), name='response-detail'),
]
