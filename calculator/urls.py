from django.urls import path
from . import views

urlpatterns = [
	path('', views.home, name= 'home'),
	path('str_to_hash/', views.StringToHash, name= 'str_to_hash'),
]
