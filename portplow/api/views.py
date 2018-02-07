import json
import logging
from uuid import UUID

# from json import JSONDecodeError

from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.cache import cache
from django.shortcuts import get_object_or_404

from rest_framework.decorators import authentication_classes, api_view
from rest_framework import viewsets, exceptions, authentication, permissions, filters
from scanner.models import (Scan,
                            Scanner,
                            ScannerLog,
                            Profile,
                            Attachment,
                            Job,
                            JobLog, get_client_ip)
from scanner.signals import outside_window, cleanup_scan
from scanner.tasks import add_scanner_log, add_scanner_ip, assign_job

# Internal libraries
from api.serializers import (UserSerializer,
                             GroupSerializer,
                             ScanSerializer,
                             ScannerSerializer,
                             ProfileSerializer,
                             QueueSerializer,
                             JobLogSerializer,
                             # LogSerializer,
                             AttachmentSerializer)
from portplow.settings import MAX_JOB_RETRIES


def safe_get(lst, key):
    '''Get a value from a list or return None.
    '''
    try:
        return lst['key']
    except ValueError:
        return None


User = get_user_model()


class ScannerAuthentication(authentication.BaseAuthentication):

    auth_failed_msg = "Invalid token."

    def authenticate(self, request):
        auth = authentication.get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'scannertoken':
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            raise exceptions.AuthenticationFailed(self.auth_failed_msg)

        try:
            scanner = Scanner.objects.get(token=token)
        except Scanner.DoesNotExist:
            raise exceptions.AuthenticationFailed(self.auth_failed_msg)

        return scanner, token

    def authenticate_header(self, request):
        return 'ScannerToken'


class DefaultsMixin(object):
    """Default settings for view authentication, permissions, filtering and pagination."""
    authentication_classes = (
        authentication.BasicAuthentication,
        authentication.TokenAuthentication,
        authentication.SessionAuthentication,
    )
    permission_classes = (
        permissions.IsAuthenticated,
    )
    paginate_by = 250
    paginate_by_param = "page_size"
    max_paginate_by = 250
    filter_backends = (
        filters.DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    )


class UserViewSet(DefaultsMixin, viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for listing users.
    """
    lookup_field = User.USERNAME_FIELD
    lookup_url_kwarg = User.USERNAME_FIELD
    queryset = User.objects.order_by(User.USERNAME_FIELD)
    serializer_class = UserSerializer
    search_fields = (User.USERNAME_FIELD, )


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.order_by('name')
    serializer_class = GroupSerializer


class ScanViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """
    API endpoint that allows scans to be viewed or edited.
    """
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer


class ScannerViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """
    API endpoint that allows scans to be viewed or edited.
    """
    serializer_class = ScannerSerializer
    queryset = Scanner.objects.all()


class ProfileViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """
    API endpoint that allows scans to be viewed or edited.
    """
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer


class QueueViewSet(DefaultsMixin, viewsets.ReadOnlyModelViewSet):
    """
    API endpoint to view job status.
    """
    def get_queryset(self):
        """
        Restrict user to viewing only records they have access to...
        """
        queryset = Job.objects.all()
        user = self.request.user
        scan_id = self.request.query_params.get('scan', False)
        if not scan_id and not user.is_superuser:
            raise exceptions.NotAcceptable

        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)

        if self.request.user.is_superuser:
            return queryset

        queryset = queryset.filter(scan__group__in=user.groups.all())
        return queryset

    queryset = Job.objects.all()
    serializer_class = QueueSerializer
    search_fields = ('target_hosts',)
    base_name = "queue"


class JobLogViewSet(DefaultsMixin, viewsets.ReadOnlyModelViewSet):
    """
    API endpoint to see results of jobs.
    """

    def get_queryset(self):
        """
        Restrict user to viewing only records they have access to...
        """
        queryset = JobLog.objects.all().order_by('-start_time')
        user = self.request.user
        scan_id = self.request.query_params.get('scan', False)
        if not scan_id and not user.is_superuser:
            raise exceptions.NotAcceptable

        if scan_id:
            queryset = queryset.filter(job__scan_id=scan_id)

        if self.request.user.is_superuser:
            return queryset

        queryset = queryset.filter(job__scan__group__in=user.groups.all())
        return queryset

    queryset = JobLog.objects.all()
    serializer_class = JobLogSerializer


# class LogViewSet(DefaultsMixin, viewsets.ModelViewSet):
#     """
#     API endpoint that allows logs to be viewed or added.
#     """
#     queryset = Log.objects.order_by('-when')
#     serializer_class = LogSerializer
#
#     def partial_update(self, request, *args, **kwargs):
#         raise exceptions.MethodNotAllowed
#
#     def destroy(self, request, *args, **kwargs):
#         raise exceptions.MethodNotAllowed
#
#     def update(self, request, *args, **kwargs):
#         raise exceptions.MethodNotAllowed


class AttachmentViewSet(DefaultsMixin, viewsets.ModelViewSet):
    """
    API endpoint that allows reports to be viewed or added.
    """
    queryset = Attachment.objects.all()
    serializer_class = AttachmentSerializer

    def partial_update(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed

    def destroy(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed

    def update(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed


@api_view(['POST'])
@authentication_classes((ScannerAuthentication,))
def checkin(request, id=None):
    """
    Allow clients to check-in to the server to obtain jobs and return results.
    """
    log = logging.getLogger(__name__)

    if id is None:
        raise exceptions.PermissionDenied
    # log.debug("Found our target function. {}".format(id))
    # scanner = request.scanner
    # print("CHECKIN: {} -- {}".format(scanner.id, scanner.ip))
    scanner = get_object_or_404(Scanner, id=UUID(id))
    remote_ip = get_client_ip(request)
    if scanner.ip != remote_ip:
        add_scanner_ip.delay(scanner_id=str(scanner.id), new_ip=remote_ip)
    # log.debug("Received connection from: {}".format(remote_ip))
    # scanner.ip = remote_ip
    # scanner.save()

    # Store any extra data as a log entry.
    log_entry = "{}, {}".format(scanner.ip, request.body)
    add_scanner_log.delay(scanner_id=str(scanner.id),
                          log_type=ScannerLog.CHECKIN,
                          scanner_ip=remote_ip,
                          content=log_entry)

    content = json.loads(request.body.decode('utf8'))
    scanner_cache_key = "__scanner.ex.{}".format(str(scanner.id))

    # Update job information if any is passed.
    if 'jobs' in content:
        # log.debug("Has job section.")
        if len(content['jobs']) > 0:
            log.debug("Has at least one job.")
            for job_update in content['jobs']:
                log.debug("checking job update")

                id = job_update.get('id')
                if id is None:
                    log.error("No ID given for job specified in posted JSON.")
                    continue

                # Check that job actually exists.
                job = cache.get(scanner_cache_key)
                if job is None:
                    log.debug("Scanner is not assigned any job.")
                    raise exceptions.PermissionDenied("Permission denied to selected scanner.")
                elif str(job.id) != id:
                    log.debug("Scanner is not assigned this job -- {}.".format(id))
                    raise exceptions.PermissionDenied("Permission denied to selected scanner.")

                stderr = job_update.get('stderr')
                stdout = job_update.get('stdout')
                status = job_update.get('status')
                return_code = job_update.get('return_code')
                attempt = job_update.get('attempt', 0)

                print("status: {}, return_code: {}, attempt: {}".format(status, return_code, attempt))

                record = JobLog.objects.filter(scanner=scanner, job=job, attempt=attempt)
                if record.count() > 0:
                    job_record = record.first()
                else:
                    job_record = JobLog(scanner=scanner, job=job, attempt=attempt)

                if stderr is not None:
                    job_record.stderr += stderr

                if stdout is not None:
                    job_record.stdout += stdout

                job_record.return_code = return_code
                job_record.status = status
                job_record.save()

                # Update the job record accordingly.
                if status == Job.COMPLETE:
                    log.debug("Reported status as complete.")
                    job.status = Job.COMPLETE
                    job.scanner_lock = None
                    cache.delete(scanner_cache_key)
                    job_key = "__scanner.job.{}".format(str(job.id))
                    cache.delete(job_key)
                    job.attempts += 1
                elif status == Job.ERROR:
                    log.debug("Reported status as Error.")
                    if attempt >= MAX_JOB_RETRIES:
                        job.status = Job.KILLED
                    else:
                        job.status = Job.RETRY

                    job.scanner_lock = None
                    cache.delete(scanner_cache_key)
                # add_or_update_job_record(scanner_id=scanner.id, job_id=str(job.id), attempt=attempt, )
                job.save()

    if outside_window(scanner.scan.id):
        # Remove all running jobs
        for job in scanner.executing_jobs.all():
            job_key = "__scanner.job.{}".format(str(job.id))
            cache.delete(job_key)
            job.status = Job.RETRY
            job.scanner_lock = None
            job.save()
            log.debug("Killed job {} on scanner at IP {} because it was outside the window.".format(job.id, scanner.ip))
            print("Killed job {} on scanner at IP {} because it was outside the window.".format(job.id, scanner.ip))
        return JsonResponse({"message": "kill_all"})

    if content['status'] == "ready":
        next_job = scanner.scan.get_next_job(scanner=scanner)
        # log.debug("Gave us a status as ready.")
        # log.debug("Scanner: {}".format(scanner))
        if next_job:
            # log.debug("We have a job.")
            content = "Assigned job `{}`".format(next_job.command)
            assign_job.delay(str(next_job.id), str(scanner.id))
            add_scanner_log.delay(scanner_id=str(scanner.id),
                                  log_type=ScannerLog.ASSIGNED,
                                  scanner_ip=remote_ip,
                                  content=content)
            cache.set(scanner_cache_key, next_job, timeout=None)
            resp = JsonResponse({
                 "jobs": [
                     {
                         "id": next_job.id,
                         "command": next_job.command,
                         "tool": next_job.profile.tool,
                         "attempt": next_job.attempts,
                      },
                 ]
                })
            # log.debug("returning. {}".format(resp))
            return resp

    return JsonResponse({"message": "ok"})
