from django.conf.urls import url
from django.shortcuts import HttpResponseRedirect, resolve_url
from django.contrib.auth.views import login, logout, password_change

from scanner import views

urlpatterns = [
    url(r'^$', lambda r: HttpResponseRedirect(resolve_url('portplow:scan-list'))),

    url(r'^scan$', views.scan_list, name="scan-list"),
    url(r'^scan/create$', views.scan_create, name="scan-create"),
    url(r'^scanners$', views.scanner_list, name="scanner-list"),

    url(r'^profile$', views.profile_list, name="profile-list"),
    url(r'^profile/create$', views.profile_create, name="profile-create"),
    url(r'^detail/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.scan_details, name="scan-details"),

    url(r'^results/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.scan_results, name="scan-results"),
    url(r'^export/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.export_scan, name="scan-export"),
    url(r'^report/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.scan_report, name="scan-report"),
    url(r'^results/parse/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/$',
        views.scan_process_results, name="scan-process"),

    url(r'^hold/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/$',
        views.scan_hold, name="scan-hold"),
    url(r'^resume/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})/$',
        views.scan_resume, name="scan-resume"),

    # Scanner operations
    url(r'^scanner/add/(?P<scan_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.scanner_add, name="scanner-add"),
    url(r'^scanner/remove/(?P<scanner_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.scanner_remove, name="scanner-remove"),

    # User Administration
    url(r'^users$', views.user_list, name="user-list"),
    url(r'^user-logs$', views.user_logs, name="user-logs"),
    url(r'^groups$', views.group_list, name="group-list"),

    # Page for scanners to retrieve deconfliction notices.
    url(r'^deconfliction/(?P<scanner_id>[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12})$',
        views.deconfliction_message, name='deconfliction_message'),

    # Authentication
    url(r'^login$', login, name='login',
        kwargs={'template_name': 'scanner/login.html'}),
    url(r'^logout$', logout, name='logout',
        kwargs={'next_page': '/'}),
]
