from rest_framework import permissions

class MyUserObjectPermission(permissions.BasePermission):
    """
    If authenticated user is object owner (creator)
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_staff:
            return True
        return obj == request.user
