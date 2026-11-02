from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # Ensure 'api/v1/' prefix is explicitly here:
    path('api/v1/', include('api.urls')), 
   
]