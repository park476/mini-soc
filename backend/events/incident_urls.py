from django.urls import path

from .views import IncidentDetailView, IncidentListView

urlpatterns = [
    path('', IncidentListView.as_view(), name='incident-list'),
    path('<int:pk>/', IncidentDetailView.as_view(), name='incident-detail'),
]
