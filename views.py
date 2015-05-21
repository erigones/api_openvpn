from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from serializers import UserSerializer, ServerKeysSerializer, RetrieveUserSerializer, \
    OpenVPNConfigSerializer, OpenVPNKeysSerializer
from models import Server, ServerKeys, OpenVPNConfig, OpenVPNConfigPush, OpenVPNConfigRoutes, \
    OpenVPNConfigOtherChoices, OpenVPNKeys
from rest_framework import status
from api_openvpn.permissions import MyUserObjectPermission
from django.contrib.auth.models import User
from rest_framework import generics
from api_openvpn.functions import ConfigFunctions, EasyRSAFuncions, ServerControl
from django.http import Http404
from api_openvpn.exceptions import *
from django.core.servers.basehttp import FileWrapper
from django.http import HttpResponse
from cStringIO import StringIO
from django.views.generic import View



class ListCreateUsers(APIView):
    """
    Admin can retrieve all users with their vars and key data. Also, new users can be created, but
    keys and vars are auto generated.
    """
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, format=None):
        """
        List of all users data.
        """
        users = User.objects.all()
        serializer = RetrieveUserSerializer(users, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        """
        Creation of new user, username, email and password are required.
        """
        serializer = UserSerializer(data=request.DATA)
        if serializer.is_valid():
            User.objects.create_user(
                email=serializer.init_data['email'],
                username=serializer.init_data['username'],
                password=serializer.init_data['password']
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RetrieveUpdateDestroyUser(APIView):
    """
    Admin or account owner can get detail information about account. Also account can be updated
    and destroyed.
    """
    permission_classes = (MyUserObjectPermission, )

    def get_object(self, pk):
        try:
            obj = User.objects.get(pk=pk)
            self.check_object_permissions(self.request, obj)
            return obj
        except:
            raise APIException("User doesn't exist")

    def get(self, request, pk, format=None):
        user = self.get_object(pk=pk)
        serializer = RetrieveUserSerializer(user)
        return Response(serializer.data)

    def put(self, request, pk, format=None):
        user = self.get_object(pk)
        serializer = UserSerializer(user, data=request.DATA)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        user = self.get_object(pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class GenerateClientConfig(APIView):
    """
    This class uses get method to retrieve configuration file for user. Only authorized users can
    retrieve their config files, which also contains public/private key pair and server public ca
    file.
    """
    def get(self, request, format=None):
        server_keys = ServerKeys.objects.all()
        if not server_keys:
            return Response("Server is not created", status.HTTP_204_NO_CONTENT)
        keys = OpenVPNKeys.objects.filter(user=request.user)
        if not keys:
            return Response("You have no keys", status.HTTP_204_NO_CONTENT)
        # lumberjack style checking permission
        elif keys[0].user != request.user:
            return Response("You do not have permission to perform this action.", status.HTTP_403_FORBIDDEN)
        config = OpenVPNConfig.objects.filter(deployed=True)
        if not config:
            return Response("There is no config file deployed on server side", status.HTTP_204_NO_CONTENT)
        ca = server_keys[0].decode('public_ca')
        key = keys[0].decode('private_key')
        cert = keys[0].decode('public_key')
        key_part = ConfigFunctions().create_user_keys(ca=ca, key=key, cert=cert)
        client_config = config[0].create_client_config(keys=key_part)
        return Response(client_config, status=status.HTTP_200_OK)


class GenerateClientConfigFile(View):
    """
    This class uses get method to retrieve configuration file for user. Only authorized users can
    retrieve their config files, which also contains public/private key pair and server public ca
    file.
    """
    def get(self, request, format=None):
        server_keys = ServerKeys.objects.all()
        if not server_keys:
            return HttpResponse("Server is not created", status.HTTP_204_NO_CONTENT)
        keys = OpenVPNKeys.objects.filter(user=request.user)
        if not keys:
            return HttpResponse("You have no keys", status.HTTP_204_NO_CONTENT)
        # lumberjack style checking permission
        elif keys[0].user != request.user:
            return HttpResponse("You do not have permission to perform this action.", status.HTTP_403_FORBIDDEN)
        config = OpenVPNConfig.objects.filter(deployed=True)
        if not config:
            return HttpResponse("There is no config file deployed on server side", status.HTTP_204_NO_CONTENT)
        ca = server_keys[0].decode('public_ca')
        key = keys[0].decode('private_key')
        cert = keys[0].decode('public_key')
        key_part = ConfigFunctions().create_user_keys(ca=ca, key=key, cert=cert)
        client_config = config[0].create_client_config(keys=key_part)
        file = StringIO()
        file.write(client_config)
        file.flush()
        file.seek(0)
        response = HttpResponse(FileWrapper(file))
        response['Content-Disposition'] = 'attachment; filename=client.conf'
        return response


class GenerateUserKey(APIView):
    permission_classes = (permissions.IsAdminUser,)

    def get_object(self, user):
        try:
            return OpenVPNKeys.objects.get(user=user)
        except OpenVPNKeys.DoesNotExist:
            raise APIException("User has no key")

    def get_user(self, pk):
        try:
            return User.objects.get(pk=pk)
        except OpenVPNKeys.DoesNotExist:
            raise APIException("User doesn't exist")

    def get(self, request, pk, format=None):
        user = self.get_user(pk)
        key = self.get_object(user)
        serializer = OpenVPNKeysSerializer(key)
        return Response(serializer.data)

    def post(self, request, pk,  format=None):
        try:
            user = self.get_user(pk)
            key = self.get_object(user)
            key.delete()
            key = OpenVPNKeys.objects.create(user=user)
            key.save()
            return Response(status=status.HTTP_201_CREATED)
        except APIException:
            key = OpenVPNKeys.objects.create(user=user)
            key.save()
            return Response(status=status.HTTP_201_CREATED)

    def delete(self, request, pk, format=None):
        user = self.get_user(pk)
        key = self.get_object(user)
        key.delete()
        functions = EasyRSAFuncions()
        functions.source_vars()
        functions.revoke_client(user.username)
        return Response(status=status.HTTP_204_NO_CONTENT)


class ServerRetrieveCreate(APIView):
    """
    Server can have only one instance, so we don't need pk. After creating new server instance, the old
    one is automatically deleted.
    """
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, format=None):
        server = ServerKeys.objects.all()
        serialzier = ServerKeysSerializer(server, many=True)
        status = ServerControl().do()
        if status:
            serialzier.data[0].update({'status': status})
        else:
            serialzier.data[0].update({'status': "Configuration file isn't deployed yet."})
        return Response(serialzier.data)

    def post(self, request, format=None):
        server = ServerKeys.objects.all()
        if server:
            server.delete()
        server = Server.objects.create()
        server.save()
        return Response(status=status.HTTP_201_CREATED)


class CreateUser(generics.CreateAPIView):
    permission_classes = (permissions.IsAdminUser,)
    queryset = User.objects.all()
    serializer_class = UserSerializer


class CreateConfig(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def post(self, request, format=None):
        funcions = ConfigFunctions()
        choices, routes, pushes = funcions.parse_config_data(request.DATA)
        choices_object = []
        routes_object = []
        pushes_object = []
        config = OpenVPNConfig.objects.create(**request.DATA)
        config.validate()
        for choice in choices:
            choice_obj = OpenVPNConfigOtherChoices.objects.create(opt_choice=choice, config=config)
            choice_obj.validate()
            choices_object.append(choice_obj)
        for route in routes:
            routes_object.append(OpenVPNConfigRoutes.objects.create(route=route, config=config))
        for push in pushes:
            pushes_object.append(OpenVPNConfigPush.objects.create(push=push, config=config))
        for choice in choices_object:
            choice.save()
        for route in routes_object:
            route.save()
        for push in pushes_object:
            push.save()
        config.save()
        return Response(status=status.HTTP_200_OK)

    def get(self, request, format=None):
        conf = OpenVPNConfig.objects.all()
        serializer = OpenVPNConfigSerializer(conf, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ConfigDetail(generics.RetrieveDestroyAPIView):
    permission_classes = (permissions.IsAdminUser, )
    queryset = OpenVPNConfig.objects.all()
    serializer_class = OpenVPNConfigSerializer


class TestConfig(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get_object(self, pk):
        try:
            return OpenVPNConfig.objects.get(pk=pk)
        except OpenVPNConfig.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        config = self.get_object(pk=pk)
        server = Server.objects.all()
        if not server:
            raise ServerIsNotCreatedException
        functions = EasyRSAFuncions()
        config_file = config.create_config(keys=functions.get_key_server_header())
        response = ConfigFunctions().config_test(config=config_file, pk=pk)
        return Response(response)


class DeployConfig(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get_object(self, pk):
        try:
            return OpenVPNConfig.objects.get(pk=pk)
        except OpenVPNConfig.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        config = self.get_object(pk=pk)
        server = Server.objects.all()
        if not server:
            raise ServerIsNotCreatedException
        functions = EasyRSAFuncions()
        config_file = config.create_config(keys=functions.get_key_server_header())
        if ConfigFunctions().config_deploy(config=config_file, pk=pk):
            old_config = OpenVPNConfig.objects.filter(deployed=True)
            if old_config:
                for cnf in old_config:
                    #old config is delpoyed, we must undeploy it
                    if cnf.deployed == True and cnf != config:
                        cnf.deployed = False
                        ConfigFunctions().config_undeploy(str(cnf.pk))
                        cnf.save()
            config.deployed = True
            config.save()
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UndeployConfigView(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get_object(self, pk):
        try:
            return OpenVPNConfig.objects.get(pk=pk)
        except OpenVPNConfig.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        config = self.get_object(pk)
        if config and ConfigFunctions().config_undeploy(pk):
            config.deployed = False
            config.save()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)



class StartServer(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, format=None):
        functions = ServerControl()
        result = functions.do()
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, requst, format=None):
        functions = ServerControl()
        result = functions.do('start')
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StopServer(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, format=None):
        functions = ServerControl()
        result = functions.do()
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, requst, format=None):
        functions = ServerControl()
        result = functions.do('stop')
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RestartServer(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, format=None):
        functions = ServerControl()
        result = functions.do()
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, requst, format=None):
        functions = ServerControl()
        result = functions.do('restart')
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReloadServer(APIView):
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, format=None):
        functions = ServerControl()
        result = functions.do()
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, requst, format=None):
        functions = ServerControl()
        result = functions.do('reload')
        if result:
            return Response(result, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetStatusView(APIView):
    """
    Method returns content of status file selected by his ID
    """
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, pk, format=None):
        response = ConfigFunctions().read_stat_file(pk=pk)
        return Response(response, status=status.HTTP_200_OK)


class GetLogView(APIView):
    """
    Method returns content of status file selected by his ID
    """
    permission_classes = (permissions.IsAdminUser, )

    def get(self, request, pk, format=None):
        response = ConfigFunctions().read_log_file(pk=pk)
        return Response(response, status=status.HTTP_200_OK)




