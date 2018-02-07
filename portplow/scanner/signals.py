## Helper functions for managing scans

import logging
import os
import stat
from base64 import b64encode
from datetime import datetime, timedelta
from random import shuffle

from Crypto.PublicKey import RSA
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.template.loader import get_template
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider

# from libcloud.compute.deployment import MultiStepDeployment, ScriptDeployment, SSHKeyDeployment

from portplow import settings
from portplow.settings import CLIENT_DELAY, EXTERNAL_IP, EXTERNAL_PORT, DOMAIN
from ipaddress import ip_network
from libnmap.parser import NmapParser, NmapParserException
from django.core.cache import cache
from django_redis import get_redis_connection
from scanner.tasks import complete_scan_setup


class NodeNotRunningException(Exception):
    pass


class ExternalIDNotFoundException(Exception):
    pass


class MissingScanIDException(Exception):
    pass


def get_current_nodes():
    '''Get a list of nodes on the DigitalOcean account.
    '''
    cls = get_driver(Provider.DIGITAL_OCEAN)
    driver = cls(settings.DO_APIKEY, api_version="v2")
    return driver.list_nodes()


class ExternalScanner(object):

    def __init__(self, scan=None, scanner=None, count=0):

        print("Creating external scanner.")

        if scan is None:
            raise MissingScanIDException("Please pass the scan record.")

        self.scan_id = str(scan.id).replace("-", "")
        self.scan_uuid = scan.id
        self.scanner_id = str(scanner.id)
        self.count = count
        self.scanner = scanner

        self.external_id = scanner.external_id

        # Setup connection to DigitalOcean
        cls = get_driver(Provider.DIGITAL_OCEAN)
        self.driver = cls(settings.DO_APIKEY, api_version="v2")

        if scanner.external_id is not None:
            for remote_node in self.driver.list_nodes():
                if remote_node.get_uuid() == scanner.external_id:
                    self.node = remote_node
                    continue

        if scanner.external_id is not None and self.node is None:
            raise ExternalIDNotFoundException()

        self.key = None
        self.remote_key = None
        self.remote_key_name = "ssh-{}-{}".format(self.scan_id, self.count)

    def generate_key(self, bits=2048):
        '''
        Generate an OpenSSH keypair
        param: bits The key length in bits
        Return private key and public key in OpenSSH format
        '''
        new_key = RSA.generate(bits, os.urandom)
        # public_key = new_key.publickey().exportKey("PEM")
        # private_key = new_key.exportKey("PEM")
        return new_key

    def setup(self):

        self.create_key_pair()

        options = {
            'backups': False,
            'private_networking': True,
            'ssh_keys': [self.remote_key.fingerprint],
            # 'user_data': "#!/bin/bash\napt-get install python-pip",
        }
        name = '{}-{}-portplow'.format(self.scan_id, self.count)

        # Get information from DigitalOcean on available systems.
        # We want the cheapest possible.
        sizes = self.driver.list_sizes()
        size = sorted(sizes, key=lambda t: t.price)[0]

        # Target is "ubuntu-14-04-x64" in "nyc3"
        images = self.driver.list_images()
        image = [i for i in images if i.extra['slug'] == "ubuntu-14-04-x64"][0]
        locations = self.driver.list_locations()
        location = [i for i in locations if i.id == 'nyc3'][0]

        # Create the node with the bootstrap.sh function.
        self.node = self.driver.create_node(name,
                                            size,
                                            image,
                                            location,
                                            ex_create_attr=options,
                                            ex_user_data=self.client_env())

    def create_key_pair(self):
        '''Generate an OpenSSH compatible key for the external scanner.
        '''
        self.key = self.generate_key()

        # Write out key to temporary file.
        private_key_file = "/tmp/scan_{}-{}".format(self.scan_id, self.count)
        with open(private_key_file, "w", 0o600) as f:
            f.write(self.key.exportKey().decode('utf8'))
        os.chmod(private_key_file, stat.S_IRUSR | stat.S_IWUSR)

        # Write out public key to temporary file.
        with open("/tmp/scan_{}-{}.pub".format(self.scan_id, self.count), "w") as f:
            f.write(self.key.exportKey("OpenSSH").decode('utf8'))

        # Add it to the profile.
        self.remote_key = self.driver.\
            create_key_pair(self.remote_key_name,
                            self.key.exportKey("OpenSSH").decode('utf8'))

    def destroy(self):
        '''Remove the scanner node from the server and remove the SSH key.
        '''
        self.node.destroy()
        key_pair = [x for x in self.driver.list_key_pairs() if x.name == self.remote_key_name]
        if len(key_pair) > 0:
            self.driver.delete_key_pair(key_pair[0])
        self.node = None

    def client_env(self, service_url=None, scanner=None):

        if service_url is None:
            service_url = "https://{}:{}{}".format(
                DOMAIN,
                EXTERNAL_PORT,
                reverse('checkin-scanner', args=[self.scanner_id]))

        if scanner is None:
            scanner = self.scanner

        deconfliction_url = "https://{}:{}{}".format(
            DOMAIN,
            EXTERNAL_PORT,
            reverse('portplow:deconfliction_message', args=[self.scanner_id]))

        ctx = {
            "SERVICE_URL": service_url,
            "API_TOKEN": scanner.token,
            "DELAY": CLIENT_DELAY,
            "DIR": "/var/opt/portplow",
            "CLIENT_SCRIPT": b64encode(open("client/client.py", 'r').
                                       read().encode('utf-8')),
            "NETWORKS": " ".join([x.strip() for x in scanner.scan.hosts.split("\n")]),
            "SEC_MESSAGE": scanner.scan.deconfliction_message,
            "HT_PASSWORDS": scanner.scan.htaccess,
            "DECONFLICTION_URL": deconfliction_url,
            }

        template = get_template("bootstrap.sh")
        return template.render(context=ctx)


def setup_scan(sender, instance, created=False, **kwargs):
    """
    Function to parse out a scan into individual jobs and to setup
    the external scanners.
    """
    from scanner.models import Job, Scanner

    log = logging.getLogger(__name__)

    created = created
    if not created:
        return

    complete_scan_setup.delay(str(instance.id))


def hold_scan(scan=None):
    """
    Set a scan on hold.
    :param scan: Scan object
    :return: True/False
    """
    from scanner.models import Job

    scan.status = scan.ON_HOLD
    scan.save()

    return scan.jobs.select_for_update().\
        filter(status__in=[Job.EXECUTING,
                           Job.PENDING,
                           Job.RETRY]).update(status=Job.HOLD)


def resume_scan(scan=None):
    """
    Resume a paused scan.
    :param scan:
    :return:
    """
    from scanner.models import Job
    scan.status = scan.RUNNING
    scan.save()

    return scan.jobs.select_for_update().\
        filter(status=Job.HOLD).update(status=Job.PENDING)


def cleanup_scan(scan=None, force_stop=False):
    """
    Cleanup after a scan completes by shutting down remote scanners.
    :param scan: Scan object
    :param force_stop: True/False. Whether or not to force a scan to end.
    :return: True/False
    """
    from scanner.models import Job, Scan
    log = logging.getLogger(__name__)

    if scan is None:
        return False

    # Try and stop race conditions.
    scan.refresh_from_db()
    if scan.status == scan.STOPPING:
        return False
    else:
        scan.status = scan.STOPPING
        scan.save()

    if not scan.is_complete() and not force_stop:
        log.debug("There are outstanding jobs.  Not cleaning up now.")
        return False
    elif not scan.is_complete() and force_stop:
        log.debug("There are outstanding jobs.  Forcing stop.")
        for job in scan.jobs.filter(status__in=[Job.RETRY, Job.EXECUTING, Job.PENDING]).all():
            job.status = Job.KILLED
            job.scanner_lock = None
            cache.delete("__scanner.job.{}".format(str(job.id)))
            job.save()

    # Remove scanners.
    for scanner in scan.scanners.all():
        key = "_scanner.last_seen.{}.".format(str(scanner.id))
        cache.delete(key)
        remove_scanner(scanner)

    # Need to clear job queues
    raw_con = get_redis_connection("default")
    raw_con.delete("__scanner.job_queue.{}".format(str(scan.id)))

    # Mark scan as complete.
    scan.status = Scan.COMPLETE
    scan.save()

    return True


def add_scanner(scan):
    """
    Add a scanner to the selected scan.
    """
    from scanner.models import Scan, Scanner

    if scan.status in [Scan.COMPLETE, Scan.STOPPING]:
        return False

    scanner_record = Scanner(scan=scan)
    scanner = ExternalScanner(scan=scan, scanner=scanner_record, count=scan.scanner_count)
    scanner.setup()
    scanner_record.external_id = scanner.node.get_uuid()
    scanner_record.key = scanner.key.exportKey().decode('utf8')
    scanner_record.save()
    scan.scanner_count += 1
    scan.save()
    return True


def remove_scanner(scanner):
    """
    Destroy scanner instance and set as decommissioned.
    """
    # Check if scanner has any current jobs and mark them as killed.
    from scanner.models import Scanner, Job, JobLog
    outstanding_jobs = Job.objects.filter(scanner_lock=scanner)
    if outstanding_jobs.count() > 0:
        for job in outstanding_jobs.all():
            job_log = JobLog(scanner=scanner,
                             job=job,
                             attempt=job.attempts,
                             end_time=datetime.utcnow(),
                             stderr="Job killed via scanner decomissioning.")
            job_log.save()
            job.status = job.RETRY
            job.attempts += 1
            job.scanner_lock = None
            job.save()

    # Remove it from provider and mark it was decommissioned.
    external_scanner = ExternalScanner(scan=scanner.scan, scanner=scanner)
    log = logging.getLogger(__name__)
    if external_scanner.node is not None:
        try:
            external_scanner.destroy()
        except Exception as e:
            log.error("Error destroying scanner {}. Error returned was: {}".format(scanner.id, e))
        scanner.status = scanner.DECOMISSIONED
        scanner.save()
        return True
    else:
        log.error("Unable to attach to {}".format(scanner.id))
        return False


def parse_nmap_results(joblog=None, results=None):
    """
    Post-processor for parsing out nmap results in xml format.
    """
    from scanner.models import ScanResult
    log = logging.getLogger(__name__)
    log.debug("Called {}".format(__name__))

    if results is None and joblog is None:
        log.error("No results or joblog passed.")
        return False
    elif results is None:
        results = joblog.stdout

    try:
        report = NmapParser.parse_fromstring(results)
    except NmapParserException as e:
        log.error("Invalid nmap xml passed. JobLog ID: {}. {}".format(str(joblog.id), e))
        return False

    start_time = datetime.fromtimestamp(report.started)
    end_time = datetime.fromtimestamp(report.endtime)

    joblog.start_time = start_time
    joblog.end_time = end_time
    joblog.save()

    for host in report.hosts:
        host_data = {}
        host_data.update({"ip": host.address,
                          "mac": host.mac,
                          "hostname": host.hostnames,
                          "joblog": joblog,
                          "scan": joblog.job.scan,
                          "start_time": start_time,
                          "end_time": end_time})

        if host.os_fingerprinted:
            host_data.update({"os": host.os})

        all_results = []
        for service in host.services:
            if service.state != "filtered":
                result = ScanResult(**host_data)
                for field in [f.name for f in ScanResult._meta.get_fields() if f.name != "id"]:
                    if hasattr(service, field):
                        setattr(result, field, getattr(service, field))
                all_results.append(result)

        ScanResult.objects.bulk_create(all_results)

    return True


def outside_window(scan_id):
    """
    Determine if we are inside the scan window.
    """
    from scanner.models import Scan

    log = logging.getLogger(__name__)
    now = datetime.utcnow()

    # Check if scan hours are cached.
    key_id = "_scanner.scans.{}".format(str(scan_id))
    scan = cache.get(key_id)

    if scan is None:
        scan = Scan.objects.get(id=scan_id)
        cache.set(key_id, scan, timeout=60)

    if not (scan.start_date <= now <= scan.stop_date):
        log.debug("Outside scan window.")
        return True

    # Check if time within scan hours.
    if scan.scan_hours == "" or scan.scan_hours is None:
        return False

    hour_groups = scan.scan_hours.split("\n")

    ow = True
    for group in hour_groups:
        hrs = group.split("-")
        start_time = datetime.strptime("{} {}".format(datetime.now().strftime("%Y/%m/%d"), hrs[0].strip()),
                                       "%Y/%m/%d %H:%M")
        stop_time = datetime.strptime("{} {}".format(datetime.now().strftime("%Y/%m/%d"), hrs[1].strip()),
                                      "%Y/%m/%d %H:%M")
        if stop_time < start_time:
            stop_time = stop_time + timedelta(days=1)

        log.debug("Scan hour window: {} to {}".format(start_time.strftime("%Y-%m-%d %H:%M:%S"),
                                                      stop_time.strftime("%Y-%m-%d %H:%M:%S")))

        if start_time <= now <= stop_time:
            log.debug("Within the current scan window.")
            ow = False
            continue

    if ow:
        log.debug("Outside today's scan window.")
        return True


def parse_results(sender, instance, **kwargs):

    # created = kwargs.get("created", False)
    # if not created or instance.return_code != 0:
    #     return
    #
    # if instance.job.profile.tool == "/usr/bin/nmap":
    #     parse_nmap_results(joblog=instance)
    pass


def update_last_seen(sender, instance, **kwargs):
    from scanner.models import ScannerLog
    if instance.log_type == ScannerLog.CHECKIN:
        key_id = "_scanner.last_seen.{}".format(str(instance.scanner.id))
        cache.set(key_id, instance.dt.timestamp(), timeout=None)
