from django.urls import path

from .views import SecurityEventDetailView, SecurityEventListView

urlpatterns = [
    path('', SecurityEventListView.as_view(), name='event-list'),
    path('<int:pk>/', SecurityEventDetailView.as_view(), name='event-detail'),
]
