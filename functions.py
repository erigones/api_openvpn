from eszone_openvpn.settings import VPN_DEFAULT_VARS, VPN_PATHS, VPN_VARS, OPENVPN_COMMANDS, HELP_VARS
from rest_framework.exceptions import APIException
import os, subprocess
from exceptions import InstanceHaveNoVarsAttributesException
import os.path
from exceptions import *
import re
import time


logFileName = "openvpn"    # example openvpn1.log  number is pk of config file
statFileName = "openvpn_status"  # openvpn_status1.log number is pk of config file


class EasyRSAFuncions():
    """
    Functions are equivalent like bash scripts, which are used by easy-rsa to generate keys.
    """
    def source_vars(self, *args, **kwargs):
        for key in VPN_VARS:
            os.environ[key] = VPN_VARS[key]
        for key in VPN_DEFAULT_VARS:
            os.environ[key] = VPN_DEFAULT_VARS[key]
        os.environ['KEY_CONFIG'] = subprocess.check_output([VPN_PATHS['easy-rsa_path'] + "/whichopensslcnf",
                                                            VPN_PATHS['easy-rsa_path']])[:-1]

    def clean_all(self, *args, **kwargs):
        return subprocess.call([VPN_PATHS['easy-rsa_path'] + "/clean-all"])

    def create_ca(self, *args, **kwargs):
        subprocess.call([VPN_PATHS['easy-rsa_path'] + "/pkitool", "--initca"])
        crt = open(VPN_VARS['KEY_DIR'] + "/ca.crt", "r")
        crt_str = crt.read()
        crt.close()
        key = open(VPN_VARS['KEY_DIR'] + "/ca.key", "r")
        key_str = key.read()
        key.close()
        return crt_str, key_str

    def rm_klient_keys(self, name):
        crt = VPN_VARS['KEY_DIR'] + "/" + name + ".crt"
        csr = VPN_VARS['KEY_DIR'] + "/" + name + ".csr"
        key = VPN_VARS['KEY_DIR'] + "/" + name + ".key"
        try:
            os.remove(crt)
            os.remove(csr)
            os.remove(key)
        except:
            APIException("Some files was missing")

    def revoke_client(self, name):
        process = subprocess.Popen([VPN_PATHS['easy-rsa_path'] + "/revoke-full", name], stdout=subprocess.PIPE)
        result = process.stdout.read()
        subprocess.call(["kill", str(process.pid)])
        self.rm_klient_keys(name)
        return result


    def create_server(self):
        server = "server"
        subprocess.call([VPN_PATHS['easy-rsa_path'] + "/pkitool", "--server", server])
        crt = open(VPN_VARS['KEY_DIR'] + "/" + server + ".crt", "r")
        crt_str = crt.read()
        crt.close()
        key = open(VPN_VARS['KEY_DIR'] + "/" + server + ".key", "r")
        key_str = key.read()
        key.close()
        return crt_str, key_str

    def build_dh_params(self, *args, **kwargs):
        key_size = VPN_DEFAULT_VARS['KEY_SIZE']
        subprocess.call([VPN_VARS['OPENSSL'], "dhparam", "-out",
                         VPN_VARS['KEY_DIR'] + "/dh" + key_size + ".pem", key_size])
        dh = open(VPN_VARS['KEY_DIR'] + "/dh" + key_size + ".pem", "r")
        dh_str = dh.read()
        dh.close()
        return dh_str

    def source_client_vars(self, dict=None):
        for key in VPN_VARS:
            os.environ[key] = VPN_VARS[key]
        for key in dict:
            os.environ[key] = dict[key]
        os.environ['KEY_CONFIG'] = subprocess.check_output([VPN_PATHS['easy-rsa_path'] + "/whichopensslcnf",
                                                            VPN_PATHS['easy-rsa_path']])[:-1]

    def create_client(self, name="client"):
        """
        At first, subprocess call script /path/to/rsa/pkitool with name parameter. Then keys files are readed and
        returned.
        :param name: Name of client certificate.
        :return: It return two strings, first is public key and second is private key.
        """
        process = subprocess.Popen([VPN_PATHS['easy-rsa_path'] + "/pkitool", name])
        process.wait()
        crt = open(VPN_VARS['KEY_DIR'] + "/" + name + ".crt", "r")
        crt_str = crt.read()
        crt.close()
        key = open(VPN_VARS['KEY_DIR'] + "/" + name + ".key", "r")
        key_str = key.read()
        key.close()

        return crt_str, key_str

    def get_key_server_header(self):
        server = "server"
        keys = "ca " + VPN_VARS['KEY_DIR'] + "/ca.crt\n" \
               "cert " + VPN_VARS['KEY_DIR'] + "/" + server + ".crt\n" \
               "key " + VPN_VARS['KEY_DIR'] + "/" + server + ".key\n" \
               "dh " + VPN_VARS['KEY_DIR'] + "/dh" + VPN_DEFAULT_VARS['KEY_SIZE'] + ".pem\n"
        return keys



class ConvertingFuncions():
    """
    It allows to
    """
    def get_vars_as_dict(self, object):
        try:
            dict = {
                'KEY_SIZE': object.KEY_SIZE,
                'KEY_EXPIRE': object.KEY_EXPIRE,
                'CA_EXPIRE': object.CA_EXPIRE,
                'KEY_COUNTRY': object.KEY_COUNTRY,
                'KEY_PROVINCE': object.KEY_PROVINCE,
                'KEY_CITY': object.KEY_CITY,
                'KEY_ORG': object.KEY_ORG,
                'KEY_EMAIL': object.KEY_EMAIL,
            }
            return dict
        except Exception:
            raise InstanceHaveNoVarsAttributesException()


class ConfigFunctions():

    def parse_config_data(self, object):
        choices = []
        routes = []
        pushes = []
        for value in object.keys():
            if 'optional' == value:
                for choice in object[value]:
                    choices.append(choice)
                del object[value]
            elif 'route' == value:
                for choice in object[value]:
                    routes.append(choice)
                del object[value]
            elif 'push' == value:
                for choice in object[value]:
                    pushes.append(choice)
                del object[value]
        return choices, routes, pushes

    def config_test(self, config, pk=None):
        try:
            server = "server"
            file_path = VPN_PATHS['openVPN-path'] + "/" + server + pk + "_test.conf"
            file = open(file_path, 'w+')
            file.write(re.sub(r'local.*\n', 'local '+HELP_VARS['testing_ip']+"\n", config))
            file.close()
            cmd = OPENVPN_COMMANDS['run-server'].format(file=file_path).split(" ")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.remove(file_path)
            time.sleep(1)   # wait one second, we want to see some output
            subprocess.call(["kill", str(process.pid)])
        except Exception as ex:
            raise APIException(ex)
        return {"errors": process.stderr.read(), "output": process.stdout.read()}

    def config_deploy(self, config, pk=None):
        #add to config file status file and log file and save config to path from settings
        server = "server"
        config += "log " + VPN_PATHS['log-path'] + "/" + logFileName + str(pk) + ".log\n"
        config += "status " + VPN_PATHS['log-path'] + "/" + statFileName + str(pk) + ".log\n"
        file_path = VPN_PATHS['openVPN-path'] + "/" + server + pk + ".conf"
        file = open(file_path, 'w+')
        file.write(config)
        file.close()
        return True

    def config_undeploy(self, pk=None):
        server = "server"
        try:
            os.remove(VPN_PATHS['openVPN-path'] + "/" + server + pk + ".conf")
            return True
        except:
            return False

    def read_log_file(self, pk):
        #if log file exists, return its contents
        file_path = VPN_PATHS['log-path'] + "/" + logFileName + str(pk) + ".log"
        if os.path.isfile(file_path):
            file = open(file_path, "r")
            file_content = file.read()
            file.close()
            return file_content
        else:
            raise NoContentException()

    def read_stat_file(self, pk):
        #if log file exists, return its contents
        file_path = VPN_PATHS['log-path'] + "/" + statFileName + str(pk) + ".log"
        if os.path.isfile(file_path):
            file = open(file_path, "r")
            file_content = file.read()
            file.close()
            return file_content
        else:
            raise NoContentException()

    def create_user_keys(self, ca=None, key=None, cert=None):
        if ca and key and cert:
            config = "<ca>\n" + ca + "</ca>\n"
            config += "<key>\n" + key + "</key>\n"
            config += "<cert>\n" + cert + "</cert>\n"
            return config
        else:
            raise APIException("One key is missing")


class ServerControl():
    """
    This class provides control about basic server operations like a start/stop/reload/restart/status
    """
    def __init__(self):
        self.operations = ['start', 'stop', 'reload', 'restart', 'status']

    def do(self, operation='status'):
        if operation in self.operations:
            process = subprocess.Popen(OPENVPN_COMMANDS[operation].split(" "), stdout=subprocess.PIPE)
            result = process.stdout.read()
            subprocess.call(["kill", str(process.pid)])
            return result
        else:
            return False






