"""myfirst URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from . import views


urlpatterns = [
    path('v1/auth/registration', views.registration),
    path('v1/auth/login', views.login),
    path('v1/locks/<int:id>/add_user', views.add_user),
    path('v1/locks/<int:id>/remove_user', views.remove_user),
    path('v1/locks', views.get_locks),
    path('v1/locks/<int:id>', views.get_lock_token),
    path('v1/users', views.get_users),
    path('v1/users/info', views.get_user)
]