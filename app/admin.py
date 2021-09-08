from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext, gettext_lazy as _

from .models import User


class CustomUserAdmin(UserAdmin):
    model = User
    ordering = ('email', )

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'role', 'country')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'country'),
        }),
    )
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'country')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups', 'country')
    search_fields = ('username', 'first_name', 'last_name', 'email', 'country')


admin.site.register(User, CustomUserAdmin)
