from django.conf.urls import patterns, url
from django.contrib import admin
import views

urlpatterns = patterns('',
    url(r'^users/$', views.ListCreateUsers.as_view()),
    url(r'^users/(?P<pk>\d+)/$', views.RetrieveUpdateDestroyUser.as_view()),
    url(r'^users/config/$', views.GenerateClientConfig.as_view()),
    url(r'^users/configfile/$', views.GenerateClientConfigFile.as_view()),
    url(r'^users/key/(?P<pk>\d+)/$', views.GenerateUserKey.as_view()),
    url(r'^server/$', views.ServerRetrieveCreate.as_view()),
    url(r'^server/start/$', views.StartServer.as_view()),
    url(r'^server/stop/$', views.StopServer.as_view()),
    url(r'^server/restart/$', views.RestartServer.as_view()),
    url(r'^server/reload/$', views.ReloadServer.as_view()),
    url(r'^config/$', views.CreateConfig.as_view()),
    url(r'^config/(?P<pk>\d+)/$', views.ConfigDetail.as_view()),
    url(r'^config/test/(?P<pk>\d+)/$', views.TestConfig.as_view()),
    url(r'^config/deploy/(?P<pk>\d+)/$', views.DeployConfig.as_view()),
    url(r'^config/undeploy/(?P<pk>\d+)/$', views.UndeployConfigView.as_view()),
    url(r'^config/status/(?P<pk>\d+)/$', views.GetStatusView.as_view()),
    url(r'^config/log/(?P<pk>\d+)/$', views.GetLogView.as_view()),
)
