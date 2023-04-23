from django.urls import path
from . import views

urlpatterns = [
    path('send/', views.send_email, name='send_email'),
    path('check/', views.check_email, name='check_email'),
]
