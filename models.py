from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
import random
import string
from eszone_openvpn.settings import VPN_DEFAULT_VARS, SECRET_KEY
from Crypto.Cipher import AES
import base64
from api_openvpn.exceptions import *
from api_openvpn.functions import EasyRSAFuncions, ConvertingFuncions

"""
Lambda expressions for encryption and decryption keys in database, Chars is for generating random secret key
"""
BLOCK_SIZE = 32
CHARS = string.ascii_letters + string.digits
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)


class Server(models.Model):
    """
    This model can have only one instance. It is used to keep server files like dh, ca, private/public key. Before
    saving, secred_key is automatically generated.
    """
    secred_key = models.CharField(max_length=128)

    def save(self, *args, **kwargs):  #added generating secret key
        if not self.secred_key:    #be carefull with this
            self.secred_key = ''.join(random.choice(string.digits + string.ascii_letters) for _ in range(BLOCK_SIZE))
        return super(Server, self).save(*args, **kwargs)


class ServerKeys(models.Model):
    """
    This model contains servers private/public key, dh params and private/public cert, they are encrypted by
    secret key, which is stored in Server model instance. It is automatically created after Server instance
    is created.
    :param public_key: public part of the server key
    :param private_key: private part of the server key
    :param private_ca: private part of server ca
    :param public_ca: public part of server ca
    :param dh_params: diffie-hellman params
    """
    private_key = models.CharField(max_length=4200)
    public_key = models.CharField(max_length=4200)
    private_ca = models.CharField(max_length=4200)
    public_ca = models.CharField(max_length=4200)
    dh_params = models.CharField(max_length=4200)
    created = models.DateTimeField(auto_now_add=True)
    server = models.OneToOneField(Server, unique=True)

    @receiver(post_save, sender=Server)
    def create_server_keys(sender, instance=None, created=False, **kwargs):
        if created:
            ServerKeys.objects.create(server=instance)

    @receiver(pre_delete, sender=Server)
    def delete_server_keys(sender, instance=None, **kwargs):
        if instance:
            server_keys = ServerKeys.objects.get(server=instance)
            server_keys.delete()

    def save(self, *args, **kwargs):
        cipher = AES.new(self.server.secred_key)
        functions = EasyRSAFuncions()
        functions.source_vars()
        functions.clean_all()
        public_ca, private_ca = functions.create_ca()
        public_key, private_key = functions.create_server()
        User_keys = OpenVPNKeys.objects.all()
        for key in User_keys:
            key.delete()
        dh = functions.build_dh_params()
        self.private_key = EncodeAES(cipher, private_key)
        self.public_key = EncodeAES(cipher, public_key)
        self.private_ca = EncodeAES(cipher, private_ca)
        self.public_ca = EncodeAES(cipher, public_ca)
        self.dh_params = EncodeAES(cipher, dh)

        return super(ServerKeys, self).save(*args, **kwargs)

    def decode(self, key_type=None):
        types = {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "private_ca": self.private_ca,
            "public_ca": self.public_ca,
            "dh_params": self.dh_params,
        }
        if key_type in types:
            cipher = AES.new(self.server.secred_key)
            res = DecodeAES(cipher, types[key_type])
            return res
        else:
            raise TypeOfKeyDoesNotExist

class UserProfile(models.Model):
    """
    Overiding user model with extra components
    """
    user = models.OneToOneField(User, unique=True,related_name="user_reliationship")
    secred_key = models.CharField(max_length=64)

    def __unicode__(self):
        return self.user.username

    @receiver(post_save, sender=User)
    def create_profile_for_user(sender, instance=None, created=False, **kwargs):
        if created:
            UserProfile.objects.get_or_create(user=instance)

    @receiver(pre_delete, sender=User)
    def delete_profile_for_user(sender, instance=None, **kwargs):
        if instance:
            user_profile = UserProfile.objects.get(user=instance)
            user_profile.delete()

    def save(self, *args, **kwargs):
        if not self.secred_key:    #be carefull with this
            self.secred_key = ''.join(random.choice(string.digits + string.ascii_letters) for _ in range(BLOCK_SIZE))
        return super(UserProfile, self).save(*args, **kwargs)


class OpenVPNKeys(models.Model):
    """
    This model contans pair - public/pivate key which is mapped to CA
    """
    private = models.CharField(max_length=4200)
    public = models.CharField(max_length=4200)
    created = models.DateTimeField(auto_now_add=True)
    user = models.OneToOneField(User, unique=True, blank=True, related_name="openvpnkeys")
    #active = models.BooleanField(default=False)  #if key is active

    @receiver(post_save, sender=User)
    def create_key_for_user(sender, instance=None, created=False, **kwargs):
        if created:
            OpenVPNKeys.objects.get_or_create(user=instance)

    @receiver(pre_delete, sender=User)
    def delete_key_for_user(sender, instance=None, **kwargs):
        if instance:
            key = OpenVPNKeys.objects.get(user=instance)
            key.delete()

    def save(self, id=None, *args, **kwargs):
        """
        Encrypts and saves pair public/private key into database only, if object is actually created.
        :param public: public part of the key
        :param private: private part of the key
        :return:
        """
        if not self.private and not self.public and not self.created:
            server = ServerKeys.objects.all()
            if not server:
                server = Server.objects.create()
                server.save()
            #vars = Vars.objects.get(id=self.user.id)
            functions = EasyRSAFuncions()
            #vars_dict = ConvertingFuncions().get_vars_as_dict(object=vars)
            #functions.source_client_vars(dict=vars_dict)
            functions.source_vars()
            public, private = functions.create_client(name=self.user.username)
            public = public
            private = private
            user_profile = UserProfile.objects.get(id=self.user.id)
            cipher = AES.new(user_profile.secred_key)
            self.private = EncodeAES(cipher, private)
            self.public = EncodeAES(cipher, public)
            self.signed = True
        return super(OpenVPNKeys, self).save(*args, **kwargs)

    def decode(self, key_type=None):
        types = {
            "private_key": self.private,
            "public_key": self.public,
        }
        if key_type in types:
            cipher = AES.new(self.user.user_reliationship.secred_key)
            res = DecodeAES(cipher, types[key_type])
            return res
        else:
            raise TypeOfKeyDoesNotExist


class OpenVPNConfig(models.Model):
    """
    This model stores configuration data for OpenVPN service. Section is used to separate
    some common config data. Next config_name is name for special config value. And finally
    config_value is value of config_name.
    """
    DEV_CHOICES = [('tun', 'tun'), ('tap', 'tap')]
    dev_choices = ['tun', 'tap']
    PROTO_CHOICES = [('udp', 'udp'), ('tcp', 'tcp')]
    proto_choices = ['udp', 'tcp']
    created = models.DateTimeField(auto_now_add=True)
    deployed = models.BooleanField(default=False)
    local = models.IPAddressField(blank=False)
    port = models.CharField(max_length=50, blank=False)
    dev = models.CharField(max_length=3, choices=DEV_CHOICES, blank=False)
    proto = models.CharField(max_length=3, choices=PROTO_CHOICES, blank=False)
    server = models.CharField(max_length=50, blank=False)
    management = models.CharField(max_length=50, blank=True)
    cipher = models.CharField(max_length=50, blank=True)
    auth = models.CharField(max_length=50, blank=True)
    topology = models.CharField(max_length=50, blank=True)
    keepalive = models.CharField(max_length=50, blank=True)
    user = models.CharField(max_length=50, blank=True)
    group = models.CharField(max_length=50, blank=True)
    verb = models.CharField(max_length=50, blank=True)
    mute = models.CharField(max_length=50, blank=True)
    tls_timeout = models.CharField(max_length=50, blank=True)
    replay_window = models.CharField(max_length=50, blank=True)
    max_clients = models.CharField(max_length=50, blank=True)   #this option will be translated to max-clients
    client_to_client = models.BooleanField(default=False)
    persist_key = models.BooleanField(default=False)
    persist_tun = models.BooleanField(default=False)
    comp_lzo = models.BooleanField(default=False)

    def validate(self):
        if not self.port or not self.dev or not self.proto or not self.server or not self.local:
            raise EmptyValueException(name="port, dev, server, local and proto")
        elif self.dev not in self.dev_choices:
            raise InvalidValueException(name="dev", value=self.dev, correct=self.dev_choices)
        elif self.proto not in self.proto_choices:
            raise InvalidValueException(name="proto", value=self.proto, correct=self.proto_choices)

    def create_config(self, keys=None):
        config = "#This is server site configuration file generated by OpenVPN Api\n"
        if keys:
            config += keys + "\n"
        fields = self._meta.get_all_field_names()
        fields.remove(u'id')
        fields.remove('created')
        fields.remove('deployed')
        for field in fields:
            value = getattr(self, field)
            if field == 'optional':
                choices = OpenVPNConfigOtherChoices.objects.filter(config=self)
                for choice in choices:
                    config += choice.create_config() + "\n"
            elif field == 'route':
                routes = OpenVPNConfigRoutes.objects.filter(config=self)
                for route in routes:
                    config += route.create_config() + "\n"
            elif field == 'push':
                pushes = OpenVPNConfigPush.objects.filter(config=self)
                for push in pushes:
                    config += push.create_config() + "\n"
            elif value:
                if isinstance(value, unicode):
                    config += field.encode().replace("_", "-") + " " + value + "\n"
                elif isinstance(value, bool):
                    config += field.encode().replace("_", "-") + "\n"
                else:
                    config += field + " " + value + "\n"
        return config

    def create_client_config(self, keys=None):
        config = "#This is client site configuration file generated by OpenVPN Api\n"
        config += "client\nremote " + self.local + " " + self.port + "\ndev " + self.dev + "\nproto " + self.proto + "\n"
        push = OpenVPNConfigPush.objects.filter(config=self)
        if self.cipher:
             config += "cipher" + self.cipher + "\n"
        if self.comp_lzo:
            config += "comp-lzo\n"
        if push:
            config += "pull\n"
        if keys:
            config += keys + "\n"
        return config


class OpenVPNConfigOtherChoices(models.Model):
    """
    It allows to add untested config option
    """
    opt_choice = models.CharField(max_length=100, blank=False)
    config = models.ForeignKey(OpenVPNConfig, blank=False, related_name='optional')

    def validate(self):
        return True

    def create_config(self):
        return self.opt_choice.encode()


class OpenVPNConfigRoutes(models.Model):
    route = models.CharField(max_length=40, blank=False)
    config = models.ForeignKey(OpenVPNConfig, blank=False, related_name='route')

    def create_config(self):
        return "route '" + self.route.encode() + "'"


class OpenVPNConfigPush(models.Model):
    push = models.CharField(max_length=40, blank=False)
    config = models.ForeignKey(OpenVPNConfig, blank=False, related_name='push')

    def create_config(self):
        return "push '" + self.push.encode() + "'"
