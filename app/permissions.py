from rest_framework.permissions import BasePermission
from .models import User


class IsAdminRoleUser(BasePermission):
    """
    Allows access only to admin role users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.role == User.ADMIN)


class IsModeratorRoleUser(BasePermission):
    """
    Allows access only to admin role users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.role == User.MODERATOR)


class IsAdminOrModeratorRoleUser(BasePermission):
    """
    Allows access only to admin role users.
    """

    def has_permission(self, request, view):
        return bool(request.user and (request.user.role == User.ADMIN or request.user.role == User.MODERATOR))


class IsAdminOrRegularRoleUser(BasePermission):
    """
    Allows access only to admin role users.
    """

    def has_permission(self, request, view):
        return bool(request.user and (request.user.role == User.ADMIN or request.user.role == User.REGULAR_USER))
