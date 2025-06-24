from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path ('home/', views.home, name='home'),
    path('', views.index, name="index"),
    path('verify-email/<str:token>/', views.verify_email, name='verify_email'),     
    path('two-factor-verification/', views.two_factor_verification, name='two_factor_verification'),
    path('forgetpassword.html/', views.forgetpassword, name='forgetpassword'),
    path('reset-password/<str:token>/', views.reset_password, name='reset-password'),
    path('logout/', views.signout, name='logout'),  
]

