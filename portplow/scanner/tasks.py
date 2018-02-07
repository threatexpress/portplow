from __future__ import absolute_import
from datetime import datetime
from celery import shared_task
from ipaddress import ip_address, ip_network
import logging
from random import shuffle
from django.core.cache import cache
# from scanner.models import JobLog, Scan, Job, ScannerLog, Scanner
# from scanner.signals import cleanup_scan, ExternalScanner


@shared_task
def parse_results(scan_id):
    """
    Parse results of a scan.
    """
    from scanner.models import Scan, JobLog
    from scanner.signals import parse_nmap_results
    scan = Scan.objects.get(id=scan_id)
    not_parsed = JobLog.objects.filter(job__scan=scan,
                                       parsed=False,
                                       job__profile__tool="/usr/bin/nmap").all()
    if not_parsed.count() > 0:
        for rec in not_parsed:
            parse_nmap_results(joblog=rec)
            rec.parsed = True
            rec.save()
        return "Parsed results for {}".format(scan.name)
    else:
        return "No results to parse."


@shared_task
def update_progress_counts():
    from scanner.models import Scan
    scans = Scan.objects.all()
    for scan in scans:
        key_id = "_scanner.progress.{}".format(str(scan.id))
        cache.delete(key_id)
        print("Scan {}: {}".format(scan.id, scan.progress()))
    return "Counts have been updated."


@shared_task
def cleanup_completed_scans():
    from scanner.models import Scan
    from scanner.signals import cleanup_scan
    scans = Scan.objects.filter(status=Scan.RUNNING).all()
    for scan in scans:
        if scan.is_complete():
            print("Scan {} is complete. Issuing cleanup command.".format(scan.name))
            cleanup_scan(scan)
    return "Finished cleaning up completed scans."


@shared_task
def add_scanner_log(scanner_id=None, log_type=None, content=None, scanner_ip=None):
    '''
    Update the last seen in the cache if it's a checkin.
    Otherwise, add it to the database.
    '''
    from scanner.models import ScannerLog
    if log_type == ScannerLog.CHECKIN:
        key_id = "_scanner.last_seen.{}".format(str(scanner_id))
        cache.set(key_id, datetime.utcnow().timestamp(), timeout=None)
        return "Checkin from {}".format(scanner_id)
    else:
        log_entry = ScannerLog(scanner_id=scanner_id,
                               log_type=log_type,
                               ip=scanner_ip,
                               content=content)
        log_entry.save()
        return "Log from {} ({}) saved - {}.".format(scanner_id, scanner_ip, log_type)


@shared_task
def add_scanner_ip(scanner_id=None, new_ip=None):
    from scanner.models import Scanner
    scanner = Scanner.objects.filter(id=scanner_id).update(ip=new_ip)
    return "Updated IP for {} to {} -- {}".format(scanner_id, new_ip, scanner)


@shared_task
def complete_scan_setup(scan_id):
    from scanner.models import Scan, Job, Scanner
    from scanner.signals import ExternalScanner
    scan = Scan.objects.get(id=scan_id)
    log = logging.getLogger(__name__)
    # Create a list of IPs
    ips = []
    networks = scan.hosts.split("\n")
    for network in networks:
        try:
            ips.extend(list(map(str, ip_network(network.strip(), strict=False))))
        except ValueError as e:
            log.error("Error: {}".format(str(e)))
            pass

    if len(ips) == 0:
        return

    shuffle(ips)

    job_list = []
    for x in range(0, len(ips), scan.chunk_size):
        ip_list = ips[x:x + scan.chunk_size]
        command_line = scan.profile.command.replace("<ips>", " ".join(ip_list))
        job = Job(scan=scan, command=command_line, profile=scan.profile, target_hosts=",".join(ip_list))
        job_list.append(job)
        if len(job_list) == 1000:
            Job.objects.bulk_create(job_list)
            job_list = []

    if len(job_list) > 0:
        Job.objects.bulk_create(job_list)

    records = []
    # Create each of the scanners
    for x in range(0, scan.scanner_count):
        log.debug("Creating scanner.")
        scanner_record = Scanner(scan=scan)
        scanner = ExternalScanner(scan=scan, scanner=scanner_record, count=x)
        scanner.setup()
        scanner_record.external_id = scanner.node.get_uuid()
        scanner_record.key = scanner.key.exportKey().decode('utf8')
        scanner_record.save()
        records.append(scanner_record)

    scan.status = Scan.RUNNING
    scan.save()

    return "Scan setup for \"{}\" has been completed.".format(scan.name)


@shared_task
def load_job_queues():
    from scanner.models import Scan, Job
    from django_redis import get_redis_connection

    scans = Scan.objects.filter(status=Scan.RUNNING).all()
    raw_con = get_redis_connection("default")

    for scan in scans:
        key_id = "__scanner.job_queue.{}".format(scan.id)
        key_id_executing = "__scanner.executing.*"
        executing_jobs = [x.decode('utf-8').replace(":1:__scanner.job.", "") for x in raw_con.lrange(key_id_executing, 0, -1)]
        # Get the number of cached jobs
        num_cached = raw_con.llen(key_id)
        loaded_ids = [x.decode('utf-8') for x in raw_con.lrange(key_id, 0, -1)]
        max_cached = 100
        if num_cached < max_cached:
            jobs = scan.jobs.\
                filter(status__in=[Job.PENDING, Job.RETRY]).\
                exclude(id__in=loaded_ids).exclude(id__in=executing_jobs).\
                only("id", "command", "profile__tool", "attempts")[:max_cached - num_cached]
            job_count = jobs.count()
            for job in jobs:
                raw_con.rpush(key_id, str(job.id))
                job_key = "__scanner.job.{}".format(str(job.id))
                cache.set(job_key, job, timeout=None)
                print("Added job {} to cache.".format(job_key))
            print("Loaded {} jobs on the queue for {}".format(job_count, scan.name))
        else:
            print("Job queue for {} is already maxed out.".format(scan.name))

    return "Completed load_jobs_queues"


@shared_task
def assign_job(job_id, scanner_id):
    from scanner.models import Scanner, Job
    scanner = Scanner.objects.get(id=scanner_id)
    job = Job.objects.get(id=job_id)
    job.status = Job.EXECUTING
    job.scanner_lock = scanner
    job.save()
    return "Assigned job {} to scanner {}".format(str(job.id), scanner.ip)


@shared_task
def clear_job_queues():
    from scanner.models import Scan, Job
    from django_redis import get_redis_connection

    scans = Scan.objects.filter(status=Scan.RUNNING).all()
    raw_con = get_redis_connection("default")

    for scan in scans:
        key_id = "__scanner.job_queue.{}".format(str(scan.id))
        raw_con.ltrim(key_id, 1, 0)

@shared_task
def update_completion_dates():
    from scanner.models import Scan, Job

    scans = Scan.objects.filter(status=Scan.RUNNING).all()
    for scan in scans:
        key_id = "__scanner.complete.{}".format(str(scan.id))
        cache.set(key_id, scan.estimate_remaining(), timeout=None)

    return "Updated scan completion estimates."


@shared_task
def export_scan(scan_id):
    from scanner.models import JobLog, Job, Scan
    from datetime import datetime
    from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
    from django.core.paginator import Paginator

    import os

    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return "Unable to export scan {}. Scan was not found.".format(scan_id)

    zip_name = "/opt/portplow/backups/{} - Scan Export {}.zip". \
        format(datetime.now().strftime("%Y-%m-%d_%H.%M.%S"), scan.name)
    zip = ZipFile(zip_name, 'w', ZIP_DEFLATED, allowZip64=True)

    paginator = Paginator(
        JobLog.objects.filter(return_code=0,
                              job_id__in=Job.objects.filter(scan=scan)).only('start_time', 'id',
                                                                             'job__target_hosts',
                                                                             'stdout').order_by('id').all(), 5000)

    for page in range(1, paginator.num_pages + 1):
        for result in paginator.page(page).object_list:
            if result.start_time is not None:
                dt = result.start_time.timetuple()
                folder_dt = result.start_time.strftime("%Y-%m-%d")
            else:
                dt = datetime.utcnow().timetuple()
                folder_dt = "unparsed"
            # output_path = os.path.join("/", "tmp", "scans", folder_dt)
            # if not os.path.exists(output_path):
            #     print(output_path)
            #     os.makedirs(output_path, exist_ok=True)
            # with open(os.path.join(output_path, str(result.id)), "w") as ft:
            #     a = ft.write(result.stdout)
            info = ZipInfo("scans/{}/{}".format(folder_dt, str(result.id)),
                           date_time=dt)
            info.compress_type = ZIP_DEFLATED
            info.comment = bytes(result.job.target_hosts, 'utf-8')
            info.create_system = 0
            zip.writestr(info, result.stdout)  # 'utf-8'))

    zip.close()
    return "Created export for {} at {}".format(scan.name, zip_name)
