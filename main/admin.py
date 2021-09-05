from django.contrib import admin
from .models import Users, Locks, Access

admin.site.register(Users)
admin.site.register(Locks)
admin.site.register(Access)