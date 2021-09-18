from rest_framework.permissions import BasePermission
from .models import User


class IsAdminOrModeratorUser(BasePermission):
    """
    Allows access only to admin or moderator users.
    """

    def has_permission(self, request, view):
        return bool(request.user and (request.user.role == User.ADMIN or request.user.role == User.MODERATOR))


class IsAdminOrRegularUser(BasePermission):
    """
    Allows access only to admin or regular users.
    """

    def has_permission(self, request, view):
        return bool(request.user and (request.user.role == User.ADMIN or request.user.role == User.REGULAR_USER))
