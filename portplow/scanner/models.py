'''
License.....
'''

# Standard libraries
from __future__ import unicode_literals

import logging
import random
import re
import uuid
from base64 import b64encode
from datetime import datetime, timedelta

# External libraries
# from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError
from django.core.cache import cache
from django.core.validators import MinValueValidator, MaxValueValidator
from django_redis import get_redis_connection
from django.db import models, transaction
from django.db.models import Count, Sum, F
from django.db.models.signals import post_save
from django.contrib.auth.signals import user_logged_in, user_logged_out
# from django.utils import timezone
from memoize import memoize, delete_memoized, delete_memoized_verhash

# Internal libraries
from scanner.signals import setup_scan, outside_window, parse_results, update_last_seen
from scanner.tasks import assign_job
from portplow.settings import MAX_JOB_RETRIES


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
        if ip == "0.0.0.0":
            ip = request.META.get('HTTP_X_REAL_IP', "unknown")
    return ip


def generate_random_password(size=40):
        chrset = 'abcdefghijklmnopqrstuvwxyz' \
                 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' \
                 '0123456789~-_=+/.><,][}{'
        return b64encode(''.join(random.SystemRandom().choice(chrset) for _ in range(size)).encode('utf-8'))

# User = get_user_model()


class LogUser(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=50)
    ip = models.CharField(max_length=64)
    dt = models.DateTimeField(verbose_name="Date/Time", default=datetime.utcnow)
    action = models.CharField(max_length=15)

    def __unicode(self):
        return self.username


def login_user(sender, request, user, **kwargs):
    LogUser(username=user.username,
            ip=get_client_ip(request),
            action="login").save()


def logout_user(sender, request, user, **kwargs):
    LogUser(username=user.username,
            ip=get_client_ip(request),
            action="logout").save()

user_logged_in.connect(login_user)
# user_logged_out.connect(logout_user)


class Scan(models.Model):
    """Model representing scans created by the user.
    """
    # Scan status choices
    PENDING = 'P'
    SETTING_UP = 'S'
    RUNNING = 'R'
    COMPLETE = 'C'
    ON_HOLD = 'H'
    STOPPING = 'X'
    SCAN_STATUS_CHOICES = (
        (PENDING, "Pending"),
        (SETTING_UP, "Setting up"),
        (RUNNING, "Running"),
        (COMPLETE, "Complete"),
        (ON_HOLD, "On Hold"),
    )

    # Field definitions
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group = models.ForeignKey(Group, related_name="scans")
    name = models.CharField(max_length=150, default="")
    hosts = models.TextField(help_text="One range/IP per line")
    profile = models.ForeignKey("Profile", related_name="scans")
    user = models.ForeignKey(User, blank=False, null=False)
    status = models.CharField(max_length=1,
                              choices=SCAN_STATUS_CHOICES,
                              default=RUNNING)
    chunk_size = models.PositiveIntegerField(default=8,
                                             validators=[
                                                 MinValueValidator(1),
                                                 MaxValueValidator(256)])
    scanner_count = models.PositiveIntegerField(default=1,
                                                validators=[
                                                    MinValueValidator(1),
                                                    MaxValueValidator(100)])
    deconfliction_message = models.TextField(null=True, blank=True)
    htaccess = models.TextField(null=True, blank=True, verbose_name="Scanner Passwords")
    scan_hours = models.TextField(null=True, blank=True)
    start_date = models.DateTimeField(null=True)
    stop_date = models.DateTimeField(null=True)

    def __unicode__(self):
        return self.args

    def __str__(self):
        return self.name

    # def is_valid(self, el):
    #     el = el.rstrip()
    #     fqdn = re.findall("(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)", el)
    #     ips = re.findall("(?:[0-9]{1,3}\.){3}[0-9]{1,3}", el)
    #
    #     if len(ips) + len(fqdn) <= 0:
    #         raise ValidationError("Proper FQDN or IP not provided")
    #
    # def clean(self):
    #     for line in self.hosts.split("\n"):  # if your hosts field can have multiple lines, you can remove this
    #         elems = line.split(",")  # creates an array from comma separated values
    #         if line:
    #             for el in elems:
    #                 self.is_valid(el)

    def get_next_job(self, scanner=None):
        """Retrieve a job and mark it as executing for a scanner.
        """
        log = logging.getLogger(__name__)
        if type(scanner) != Scanner:
            return None

        raw_con = get_redis_connection("default")

        # Make sure the scanner isn't already executing a job.
        # current_jobs = self.jobs.filter(scanner_lock=scanner, status=Job.EXECUTING)
        log.debug("Got current jobs.")

        scanner_cache_key = "__scanner.ex.{}".format(str(scanner.id))
        exec_job = cache.get(scanner_cache_key)
        if exec_job is not None:
            log.debug("Already executing a job!!!")
            # return current_jobs.first()
            return exec_job

        # Ensure the scan is still in an active state
        if self.status != self.RUNNING:
            log.debug("Scan is not in an active state. {}".format(self.status))
            return None

        if outside_window(str(self.id)):
            log.debug("Not returning a job because we're outside the window.")
            return None

        log.debug("Getting next job.")

        scan_key = "__scanner.job_queue.{}".format(scanner.scan_id)
        next_job_id = raw_con.lpop(scan_key)
        # # next_job = self.jobs.select_for_update(). \
        # next_job_query = self.jobs. \
        #     filter(status__in=[Job.PENDING, Job.RETRY]).\
        #     only("id", "command", "profile__tool", "attempts")

        # if next_job_query.count() == 0:
        #    log.debug("No jobs to give.")
        #    if self.is_complete():
        #       from scanner.signals import cleanup_scan
        #        cleanup_scan(self)
        #    return None

        if next_job_id is None:
            log.debug("No jobs to give.")
            return None

        job_key = "__scanner.job.{}".format(next_job_id.decode('utf-8'))

        next_job = cache.get(job_key)

        if next_job is None:
            log.error("Unable to locate job for next_job {} / Scan {}".format(next_job_id, scanner.scan.name))
            return None

        log.debug("Giving scanner {} job {}.".format(scanner.id, next_job.id))
        return next_job

    def is_complete(self):
        return self.jobs.filter(status__in=[Job.PENDING,
                                            Job.RETRY,
                                            Job.EXECUTING,
                                            Job.HOLD]).count() == 0

    def progress(self):
        key_id = "_scanner.progress.{}".format(str(self.id))
        ctx = cache.get(key_id)
        if ctx is None:
            cache.set(key_id, self.latest_progress(), timeout=None)

        ctx = cache.get(key_id)
        return ctx

    # def estimate_remaining(self):
    #     """
    #     Estimate the time remaining on a job using the time window and runtime of the scans that have run.
    #     """
    #
    #     run_time = JobLog.objects.filter(job__scan=s).aggregate(total=Sum(F('end_time') - F('start_time')))['total']
    #     complete_jobs = JobLog.objects.filter(job__scan=self, start_time__isnull=False, end_time__isnull=False).count()
    #     total_jobs = Job.objects.filter(scan=self).count()
    #
    #     # Calculate total scan time per day.
    #     windows = self.scan_hours.split("\n")
    #     base_dt = datetime.utcnow()
    #     total_seconds = 0
    #     for window in windows:
    #         tmp_start, tmp_end = window.split("-")
    #         start_time = base_dt.replace(hour=tmp_start.split(":")[0],
    #                                      minute=tmp_start.split(":")[1])
    #         end_time = base_dt.replace(hour=tmp_end.split(":")[0],
    #                                    minute=tmp_end.split(":")[1])
    #         total_seconds += (end_time - start_time).total_seconds()

    def estimate_remaining(self):
        """
        Extremely simplistic time estimate for a scan.
        """
        days_elapsed = (datetime.utcnow() - self.start_date).days
        completed_jobs = JobLog.objects.filter(job__scan=self, start_time__isnull=False, end_time__isnull=False).count()
        total_jobs = Job.objects.filter(scan=self).count()
        if completed_jobs == 0 or total_jobs == 0:
            return None
        days_needed = days_elapsed / (completed_jobs / total_jobs)
        return self.start_date + timedelta(days=days_needed)

    @property
    def estimate(self):
        key_id = "__scanner.complete.{}".format(str(self.id))
        est = cache.get(key_id)
        if est is None:
            est = self.estimate_remaining()
            cache.set(key_id, est)
        return est

    def latest_progress(self):
        amounts = self.jobs.values('status').annotate(total=Count('id', distinct=True))
        ctx = {}
        total = 0
        for key, status in Job.JOB_STATUS_CHOICES:
            ctx.update({status.lower(): 0})
            for rec in amounts:
                if rec['status'] == key:
                    ctx.update({status.lower(): rec['total']})
                    total += rec['total']

        if total != 0:
            ctx.update({"percentage": "{0:.0f}%".format(ctx['complete'] / total * 100)})
        return ctx


# Make sure that scans are setup after a new one is added.
post_save.connect(setup_scan, sender=Scan)


class Profile(models.Model):
    """Profiles are the basic setup for how a scan is run.
    Add the command line and all scans using this profile
    will use it as a template.
    """
    # Tool options
    TOOL_CHOICES = (
        ('/usr/bin/nmap', 'nmap'),
        ('/opt/portplow/masscan/bin/masscan', 'masscan'),
    )

    # Field definitions
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, null=False, unique=True)
    command = models.TextField(default="", verbose_name="Command Line", help_text="Please use <ips> for target ranges.")
    tool = models.CharField(max_length=50, choices=TOOL_CHOICES)
    description = models.TextField(null=True)

    def __unicode__(self):
        return self.name

    def __str__(self):
        return self.name


class Scanner(models.Model):
    """Model representing external systems that perform
    the scans.
    """
    # Scanner status
    ACTIVE = 'A'
    DECOMISSIONED = 'D'
    ERROR = 'E'

    SCANNER_STATUS_CHOICES = (
        (ACTIVE, "Active"),
        (DECOMISSIONED, "Decommissioned"),
        (ERROR, "Error"),
    )

    # Field definitions
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, blank=True, null=True, on_delete=models.CASCADE, related_name="scanners")
    name = models.CharField(max_length=100)
    notes = models.TextField(null=True)
    status = models.CharField(max_length=1, choices=SCANNER_STATUS_CHOICES, default=ACTIVE)
    ip = models.GenericIPAddressField(null=True)
    key = models.TextField(editable=False, null=True)
    external_id = models.CharField(max_length=40, null=True)
    token = models.CharField(max_length=256, default=generate_random_password)

    def last_seen(self):
        """
        Retrieves the last time the scanner was seen. It trys to get
        it from cache if it exists. Otherwise, it'll look it up and save
        it there.
        """
        key_id = "_scanner.last_seen.{}".format(str(self.id))
        ts = cache.get(key_id)
        try:
            ts = datetime.fromtimestamp(int(ts))
        except ValueError:
            ts = None
        except TypeError:
            ts = None

        return ts

    def __str__(self):
        return "{0} ({1})".format(self.name, self.ip)


class ScannerLog(models.Model):
    """Model to track checkins and other events on the scanners.
    """
    # Types
    CHECKIN = 'C'
    ASSIGNED = 'A'
    ERROR = 'E'
    DATA_INCOMING = 'D'
    SCANNER_LOG_TYPES = (
        (CHECKIN, 'Checkin'),
        (ASSIGNED, 'Assigned job'),
        (ERROR, 'Error'),
        (DATA_INCOMING, 'Data Received'),
    )

    # Field definitions
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scanner = models.ForeignKey(Scanner, related_name="logs")
    ip = models.GenericIPAddressField(null=True)
    dt = models.DateTimeField(default=datetime.utcnow, editable=False)
    log_type = models.CharField(max_length=1, choices=SCANNER_LOG_TYPES)
    content = models.TextField()


post_save.connect(update_last_seen, sender=ScannerLog)


class Job(models.Model):
    """Model storing information about the individual jobs setup
    based on the parameters of a scan. Each job is tracked per scan & scanner.
    """

    # Job Status Types
    PENDING = 'P'
    EXECUTING = 'E'
    RETRY = 'R'
    KILLED = 'K'
    COMPLETE = 'C'
    HOLD = 'H'
    ERROR = 'X'
    JOB_STATUS_CHOICES = (
        (PENDING, 'Pending'),
        (EXECUTING, 'Executing'),
        (RETRY, 'Retry'),
        (KILLED, 'Killed'),
        (COMPLETE, 'Complete'),
        (HOLD, 'Hold'),
    )

    # Field definitions
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, blank=False, null=False, related_name="jobs", editable=False)
    profile = models.ForeignKey(Profile, related_name="jobs", on_delete=models.DO_NOTHING)
    status = models.CharField(max_length=1, choices=JOB_STATUS_CHOICES, editable=False, default=PENDING)
    scanner_lock = models.ForeignKey(Scanner, related_name="executing_jobs", null=True)
    attempts = models.PositiveSmallIntegerField(default=0,
                                                validators=[MinValueValidator(0), MaxValueValidator(MAX_JOB_RETRIES)])
    command = models.TextField(null=False)
    target_hosts = models.TextField(null=False)

    def __str__(self):
        return "{} ({})".format(self.scan.name, self.command)


class JobLog(models.Model):
    """Model to store output of jobs from scanners.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_date = models.DateTimeField(editable=False, auto_now_add=True)
    scanner = models.ForeignKey(Scanner, on_delete=models.CASCADE, editable=False)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    attempt = models.PositiveSmallIntegerField(default=0,
                                               validators=[MinValueValidator(0), MaxValueValidator(MAX_JOB_RETRIES)])
    job = models.ForeignKey(Job, related_name="raw_results", on_delete=models.DO_NOTHING)
    return_code = models.PositiveSmallIntegerField(null=True, blank=True, default=None)
    stdout = models.TextField(null=True, blank=True, default="")
    stderr = models.TextField(null=True, blank=True, default="")
    parsed = models.BooleanField(default=False)


post_save.connect(parse_results, sender=JobLog)


def attachment_path(instance, filename):
    return "{}/report_{}_".format(instance.scan.id, str(datetime.utcnow()).replace(" ", "_"), filename)


class Attachment(models.Model):
    """Model which stores the output files associated with a particular job.
    """
    scan = models.ForeignKey(Scan, related_name="attachments")
    scanner = models.ForeignKey(Scanner, related_name="attachments", on_delete=models.CASCADE)
    job = models.ForeignKey(Job, related_name="attachments", on_delete=models.DO_NOTHING)
    filename = models.FileField(upload_to=attachment_path)


class ScanResult(models.Model):
    """
    Model for tracking results of the scans.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    joblog = models.ForeignKey(JobLog, related_name="parsed_results", on_delete=models.CASCADE)
    scan = models.ForeignKey(Scan, related_name="parsed_results", on_delete=models.CASCADE)
    ip = models.CharField(max_length=15, null=True, blank=True)
    mac = models.CharField(max_length=20, null=True, blank=True)
    os = models.CharField(max_length=50, null=True, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    hostname = models.CharField(max_length=150)
    port = models.SmallIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, null=True, blank=True)
    state = models.CharField(max_length=20, null=True, blank=True)
    service = models.CharField(max_length=40, null=True, blank=True)
    reason = models.CharField(max_length=20, null=True, blank=True)

