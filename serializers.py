from django.contrib.auth.models import User
from rest_framework import serializers
from api_openvpn.models import UserProfile, OpenVPNKeys, ServerKeys, OpenVPNConfig, OpenVPNConfigOtherChoices, \
    OpenVPNConfigRoutes, OpenVPNConfigPush

class ServerKeysSerializer(serializers.ModelSerializer):
    server_id = serializers.IntegerField(source='pk', read_only=True)
    secred_key = serializers.CharField(source='server.secred_key', read_only=True)
    class Meta:
        model = ServerKeys
        fields = (
            'server_id', 'created'
        )


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user class
    """
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 'password'
        )
        write_only_fields = ('password', )

    def restore_object(self, attrs, instance=None):
        user = super(UserSerializer, self).restore_object(attrs, instance)
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for extended user class
    """
    id = serializers.IntegerField(source='pk', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', required=True)
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)

    class Meta:
        model = UserProfile
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name'
        )
        read_only_fields = ('secred_key', )

    def restore_object(self, attrs, instance=None):
        profile = super(UserProfileSerializer, self).restore_object(
            attrs, instance
        )
        if profile:
            user = profile.user
            user.email = attrs.get('user.email', user.email)
            user.first_name = attrs.get('user.first_name', user.first_name)
            user.last_name = attrs.get('user.last_name', user.last_name)
            user.save()
        return profile

'''
class VarsSerializer(serializers.ModelSerializer):
    """
    Serializer for VARS
    """
    KEY_SIZE = serializers.CharField(required=False)
    KEY_EXPIRE = serializers.CharField(required=False)
    CA_EXPIRE = serializers.CharField(required=False)
    KEY_COUNTRY = serializers.CharField(required=False)
    KEY_PROVINCE = serializers.CharField(required=False)
    KEY_CITY = serializers.CharField(required=False)
    KEY_ORG = serializers.CharField(required=False)
    KEY_EMAIL = serializers.CharField(required=False)
    user_id = serializers.IntegerField(source='user.id', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = Vars
        fields = (
            'KEY_SIZE', 'CA_EXPIRE', 'KEY_EXPIRE', 'KEY_COUNTRY', 'KEY_PROVINCE', 'KEY_CITY', 'KEY_ORG',
            'KEY_EMAIL',
        )
'''

class OpenVPNKeysSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenVPNKeys
        fields = (
            'created',
        )
        read_only_fields = ('created', )


class RetrieveUserSerializer(serializers.ModelSerializer):
    #vars = VarsSerializer()
    openvpnkeys = OpenVPNKeysSerializer()

    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 'openvpnkeys'
        )
        write_only_fields = ('password', )


class CreateUpdateSerializer(serializers.ModelSerializer):
    vars = serializers.PrimaryKeyRelatedField()
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 'vars'
        )
        write_only_fields = ('password', )


class OpenVPNConfigOtherChoicesSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenVPNConfigOtherChoices
        fields = (
            'opt_choice',
        )


class OpenVPNConfigRoutesSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenVPNConfigRoutes
        fields = (
            'route',
        )


class OpenVPNConfigPushSerializer(serializers.ModelSerializer):
    class Meta:
        model = OpenVPNConfigPush
        fields = (
            'push',
        )


class OpenVPNConfigSerializer(serializers.ModelSerializer):
    id = serializers.PrimaryKeyRelatedField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    deployed = serializers.BooleanField(read_only=True)
    push = OpenVPNConfigPushSerializer(required=False, many=True)
    route = OpenVPNConfigRoutesSerializer(required=False, many=True)
    optional = OpenVPNConfigOtherChoicesSerializer(required=False, many=True)

    class Meta:
        model = OpenVPNConfig
        ordering = ('id', 'created', 'deployed', 'push', 'route', 'optional', )



