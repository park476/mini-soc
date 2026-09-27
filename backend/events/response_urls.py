from django.urls import path

from .views import ResponseDetailView, ResponseListView

urlpatterns = [
    path('', ResponseListView.as_view(), name='response-list'),
    path('<int:pk>/', ResponseDetailView.as_view(), name='response-detail'),
]
