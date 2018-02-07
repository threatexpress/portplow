from django.conf.urls import url, include, patterns
from django.shortcuts import HttpResponseRedirect, resolve_url
from rest_framework.authtoken.views import obtain_auth_token
import debug_toolbar

from api.urls import router
from api.views import checkin
from scanner import urls as scanner_urls
from utils import urls as util_urls

urlpatterns = [
    url(r'^$', lambda r: HttpResponseRedirect(resolve_url('portplow:scan-list'))),
    url(r'^api/token/', obtain_auth_token, name='api-token'),
    url(r'^api/', include(router.urls, namespace="api")),
    url(r'^portplow/', include(scanner_urls.urlpatterns, namespace="portplow")),
    url(r'^account/', include(util_urls.urlpatterns, namespace='utils')),
    url(r'^checkin/(?P<id>[0-9a-zA-Z-]+)/', checkin, name='checkin-scanner'),
    url(r'^__debug__/', include(debug_toolbar.urls)),
    url(r'session_security/', include('session_security.urls')),
]
