from rest_framework import permissions
from .models import Role


class IsAdmin(permissions.BasePermission):
    """
    only allow admins.
    """

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == Role.Roles.ADMIN
        )


class IsEmployee(permissions.BasePermission):
    """
    only allow employees.
    """

    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role == Role.Roles.EMPLOYEE
        )
