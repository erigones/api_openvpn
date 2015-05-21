from rest_framework.exceptions import APIException
from django.core.exceptions import ValidationError
from django.utils.encoding import force_text


def validate_only_one_instance(obj):
    model = obj.__class__
    if (model.objects.count() > 0 and
            obj.id != model.objects.get().id):
        raise ValidationError("Can only create 1 %s instance" % model.__name__)


class FatalKeyException(APIException):
    status_code = 404
    default_detail = "You must identify user by his username"


class TypeOfKeyDoesNotExist(APIException):
    status_code = 404
    default_detail = "This type of key is not supported"


class UserNotFoundException(APIException):
    status_code = 404
    default_detail = "User has not been found"


class InstanceHaveNoVarsAttributesException(APIException):
    status_code = 500
    default_detail = "Object can't be parsed into dictionary, because it hasn't" \
                     "vars attributes"


class NoContentException(APIException):
    status_code = 204
    default_detail = "No content"


class ServerIsNotCreatedException(APIException):
    status_code = 404
    default_detail = "Server keys hasn't been generated yet"


class InvalidSectionException(APIException):
    status_code = 404
    default_detail = 'Section "{section}" is invalid.'

    def __init__(self, section, detail=None):
        if detail is not None:
            self.detail = force_text(detail)
        else:
            self.detail = force_text(self.default_detail).format(section=section)


class EmptyValueException(APIException):
    status_code = 404
    default_detail = "Configuration '{name}' can't be blank."

    def __init__(self, name, detail=None):
        if detail is not None:
            self.detail = force_text(detail)
        else:
            self.detail = force_text(self.default_detail).format(name=name)


class InvalidValueException(APIException):
    status_code = 404
    default_detail = "Value '{value}' in '{name}' is invalid. Try '{correct}'."

    def __init__(self, name, value, correct, detail=None):
        if detail is not None:
            self.detail = force_text(detail)
        else:
            self.detail = force_text(self.default_detail).format(name=name, value=value, correct=correct)