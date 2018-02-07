from django.conf.urls import url, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
# router.register(r'users', views.UserViewSet)
# router.register(r'groups', views.GroupViewSet)
# router.register(r'scans', views.ScanViewSet)
# router.register(r'scanners', views.ScannerViewSet)
# router.register(r'profiles', views.ProfileViewSet)
# router.register(r'reports', views.AttachmentViewSet)
router.register(r'queue', views.QueueViewSet)
router.register(r'results', views.JobLogViewSet)
