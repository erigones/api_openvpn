from django.contrib.auth.models import User
from api_openvpn.models import UserProfile, Server
from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from functions import EasyRSAFuncions
from rest_framework import exceptions
import time


class ApiTest(APITestCase):
    """
    It tests base operations with user acc
    """
    config = {
        "local": "192.168.1.4",
        "comp_lzo": "True",
        "proto": "udp",
        "port": "1194",
        "dev": "tun",
        "server": "10.10.10.0 255.255.255.0",
        "route": ["10.10.20.0 255.255.255.0"]
        }

    def setUp(self):
        # create two users, admin and regular user and then both will be logged in
        self.my_user = User.objects.create_user("josef", "user@user.com", "josef")
        self.my_admin = User.objects.create_superuser("root", "admin@admin.com", "root")
        self.user_client = APIClient()
        self.admin_client = APIClient()
        self.user_client.login(username='josef', password='josef')
        self.admin_client.login(username='root', password='root')

    def testServerInstanceAutoCreation(self):
        # test if after setup was server automatcally deployed
        server = Server.objects.all()
        if not server:
            raise exceptions.APIException("Server wasn't created")

    def testServerRecreation(self):
        # test if after server recreation, keys will be removed and after then again created
        response = self.admin_client.post("/server/")
        self.assertEqual(response.status_code, 201)
        response = self.admin_client.get("/users/1/")
        self.assertEqual(response.data['openvpnkeys'], None)
        response = self.admin_client.get("/users/2/")
        self.assertEqual(response.data['openvpnkeys'], None)
        response = self.admin_client.post("/users/key/1/")
        self.assertEqual(response.status_code, 201)
        response = self.admin_client.post("/users/key/2/")
        self.assertEqual(response.status_code, 201)

    def testCreateNewUserKeys(self):
        # test of creation new keys
        response = self.admin_client.post("/users/key/1/")
        self.assertEqual(response.status_code, 201)
        response = self.admin_client.post("/users/key/2/")
        self.assertEqual(response.status_code, 201)

    def testUserListPermisionPermission(self):
        # test some permissions
        response = self.user_client.get('/users/')
        self.assertEqual(response.data, {
            'detail': 'You do not have permission to perform this action.'
        })
        response = self.admin_client.get('/users/')
        self.assertEqual(response.status_code, 200)

    def testDelUsers(self):
        # test of deletion users
        response = self.user_client.delete('/users/1/')
        self.assertEqual(response.status_code, 204)
        response = self.admin_client.delete('/users/2/')
        self.assertEqual(response.status_code, 204)

    def testGetConfigForUserFail(self):
        # try get user config, but no one is deployed
        response = self.admin_client.get("/users/config/")
        self.assertEqual(response.data, "There is no config file deployed on server side")

    def testUploadConfigFile(self):
        # try get user config, but no one is deployed
        response = self.admin_client.post("/config/", self.config)
        self.assertEqual(response.status_code, 200)

    def testGetConfigAfterDeploy(self):
        # upload config file
        response = self.admin_client.post("/config/", self.config)
        self.assertEqual(response.status_code, 200)
        # deploy config file
        response = self.admin_client.get("/config/deploy/1/")
        self.assertEqual(response.status_code, 200)
        # try to get client config file
        response = self.admin_client.get("/users/config/")
        self.assertEqual(response.status_code, 200)

    def testGetConfigAfterUndeploy(self):
        self.testGetConfigAfterDeploy()
        response = self.admin_client.get("/config/undeploy/1/")
        self.assertEqual(response.status_code, 200)
        response = self.admin_client.get("/users/config/")
        self.assertEqual(response.data, "There is no config file deployed on server side")

    def testServerStatus(self):
        self.testGetConfigAfterDeploy()
        response = self.admin_client.get("/server/start/")
        self.assertRegexpMatches(response.data, r"VPN 'server1' is not running")

    def testRunServer(self):
        self.testGetConfigAfterDeploy()
        response = self.admin_client.post("/server/start/")
        self.assertRegexpMatches(response.data, r"Autostarting VPN 'server1'")
        # deploy config file

    def testStopServer(self):
        self.testGetConfigAfterDeploy()
        response = self.admin_client.post("/server/stop/")
        self.assertRegexpMatches(response.data, r"Stopping virtual private network daemon")
        # deploy config file

    def testReloadServer(self):
        self.testGetConfigAfterDeploy()
        response = self.admin_client.post("/server/reload/")
        self.assertRegexpMatches(response.data, r"Reloading virtual private network daemon")
        # deploy config file

    def testRestartServer(self):
        self.testGetConfigAfterDeploy()
        response = self.admin_client.post("/server/restart/")
        self.assertRegexpMatches(response.data, r".Autostarting VPN 'server1'")
        # deploy config file