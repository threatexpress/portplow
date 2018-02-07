from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, get_object_or_404, redirect, resolve_url
from django.views.decorators.cache import cache_page
from django.contrib import messages
from django.db.models import Count

from scanner.models import Scan, Scanner, Profile, User, LogUser, Group, ScanResult, JobLog, Job
from scanner.forms import ScanForm, ProfileForm
from scanner.signals import hold_scan, resume_scan, add_scanner, remove_scanner
from datetime import datetime
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
from io import BytesIO, StringIO
from django.core.paginator import Paginator
import csv


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scan_create(request, template_name="scanner/scan-create.html"):
    scan_form = ScanForm(request.POST or None)
    if request.method == "POST":
        if scan_form.is_valid():
            print("Got a valid form.")
            scan = scan_form.save(commit=False)
            scan.user = request.user
            scan.status = Scan.SETTING_UP
            scan.save()
            messages.success(request, "Scan created successfully.  Setup will occur in the background "
                                      "and will be ready shortly.")
            return redirect('portplow:scan-list')
        else:
            print("Invalid form received.")
            for field in scan_form:
                print("{} -- {}".format(field, field.errors))

    return render(request, template_name, {'form': scan_form})


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scan_hold(request, scan_id=None):
    scan = get_object_or_404(Scan, id=scan_id)
    if scan.status != scan.RUNNING and scan.status != scan.PENDING:
        messages.error(request, "Scan is not currently running.")
    else:
        messages.success(request, "Scan is now on hold.")
        hold_scan(scan)

    return HttpResponseRedirect(resolve_url("portplow:scan-list"))


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scan_resume(request, scan_id=None):
    scan = get_object_or_404(Scan, id=scan_id)
    if scan.status != scan.ON_HOLD:
        messages.error(request, "Scan is not currently on hold.")
    else:
        messages.success(request, "Scan is now on running.")
        resume_scan(scan)

    return HttpResponseRedirect(resolve_url("portplow:scan-list"))


@login_required
@user_passes_test(lambda u: u.is_superuser)
def profile_create(request, template_name="scanner/profile-create.html"):
    profile_form = ProfileForm(request.POST or None)
    if request.method == "POST":
        if profile_form.is_valid():
            print("Got a valid form.")
            profile_form.save()
            return redirect('portplow:profile-list')
        else:
            print("Invalid form received.")
            for field in profile_form:
                print("{} -- {}".format(field, field.errors))

    return render(request, template_name, {'form': profile_form})


@login_required
def profile_list(request):
    profiles = Profile.objects.all()

    ctx = {
        "profiles": profiles
    }
    return render(request, template_name="scanner/profile-list.html", context=ctx)


@login_required
def scanner_list(request):
    if request.user.is_staff:
        scanners = Scanner.objects.all()
    else:
        scanners = Scanner.objects.filter(scan__group__in=request.user.groups.all()).all()
    ctx = {
        "scanners": scanners.order_by('scan__name', 'status', 'ip')
    }
    return render(request, template_name="scanner/scanner-list.html", context=ctx)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def user_list(request):
    users = User.objects.all().order_by('-is_superuser', 'last_name', 'first_name')

    ctx = {
        "users": users
    }
    return render(request, template_name="scanner/user-list.html", context=ctx)


@login_required
def group_list(request):
    groups = Group.objects.all()

    ctx = {
        "groups": groups
    }
    return render(request, template_name="scanner/group-list.html", context=ctx)



@login_required
def scan_list(request):
    if request.user.is_staff:
        scans = Scan.objects.all()
    else:
        scans = Scan.objects.filter(group__in=request.user.groups.all()).all()

    ctx = {
        "scans": scans.order_by('name')
    }
    return render(request, template_name="scanner/scan-list.html", context=ctx)


@login_required
# @cache_page(60)
def scan_details(request, scan_id=None):

    if request.user.is_staff:
        scan = get_object_or_404(Scan, id=scan_id)
    else:
        queryset = Scan.objects.filter(group__in=request.user.groups.all())
        scan = get_object_or_404(queryset, id=scan_id)

    port_counts = ScanResult.objects.filter(scan=scan, state="open").values('port').annotate(total=Count('id'))

    ctx = {
        "scan": scan,
        "port_counts": port_counts
    }

    return render(request, template_name="scanner/scan-detail-all-jobs.html", context=ctx)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scan_process_results(request, scan_id=None):
    print("Called scan_process_results")
    from scanner.models import JobLog
    from scanner.tasks import parse_results

    if request.user.is_staff:
        scan = get_object_or_404(Scan, id=scan_id)
    else:
        queryset = Scan.objects.filter(group__in=request.user.groups)
        scan = get_object_or_404(queryset, id=scan_id)

    print("Found scan.")
    unparsed = JobLog.objects.filter(job__scan=scan, parsed=False).all()
    if unparsed.count() > 0:
        parse_results.delay(scan_id=scan_id)
        messages.success(request, "Queued job to parse scan results.")
    else:
        messages.error(request, "No results to process at this time.")

    print("Checked for unparsed.")
    return HttpResponseRedirect(resolve_url("portplow:scan-details", scan_id=scan_id))


@login_required
@permission_required("scan.view_results")
def scan_results(request, scan_id=None):

    if request.user.is_staff:
        scan = get_object_or_404(Scan, id=scan_id)
    else:
        queryset = Scan.objects.filter(group__in=request.user.groups)
        scan = get_object_or_404(queryset, id=scan_id)

    ctx = {
        "scan": scan,
    }
    return render(request, template_name="scanner/scan-results.html", context=ctx)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def user_logs(request, template_name="scanner/user-logs.html"):
    logs = LogUser.objects.all()
    return render(request, template_name, context={"logs": logs})


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scanner_add(request, scan_id=None):
    scan = get_object_or_404(Scan, id=scan_id)
    if add_scanner(scan):
        messages.success(request, "Scanner added successfully.")
    else:
        messages.error(request, "Unable to add scanner.")

    return HttpResponseRedirect(resolve_url('portplow:scan-details', scan_id=scan_id))


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scanner_remove(request, scanner_id=None):
    scanner = get_object_or_404(Scanner, id=scanner_id)
    if remove_scanner(scanner):
        messages.success(request, "Scanner removed successfully.")
    else:
        messages.error(request, "Unable to remove scanner.")

    return HttpResponseRedirect(resolve_url('portplow:scan-details', scan_id=scanner.scan_id))


@login_required
@user_passes_test(lambda u: u.is_superuser)
def export_scan(request, scan_id=None):
    """
    Export all XML files associated with a scan.
    """
    scan = get_object_or_404(Scan, id=scan_id)

    in_memory = BytesIO()
    zip = ZipFile(in_memory, 'w', ZIP_DEFLATED, allowZip64=True)
    paginator = Paginator(JobLog.objects.filter(return_code=0,
                                                job__scan=scan).only('start_time', 'id',
                                                                     'job__target_hosts',
                                                                     'stdout').order_by('id').all(), 2500)
    for page in paginator.page_range:
        for result in paginator.page(page).object_list:
            if result.start_time is not None:
                dt = result.start_time.timetuple()
                folder_dt = result.start_time.strftime("%Y-%m-%d")
            else:
                dt = datetime.utcnow().timetuple()
                folder_dt = "unparsed"
            info = ZipInfo("scans/{}/{}".format(folder_dt, str(result.id)),
                            date_time=dt)
            info.compress_type= ZIP_DEFLATED
            info.comment = bytes(result.job.target_hosts, 'utf-8')
            info.create_system = 0
            zip.writestr(info, result.stdout) #  'utf-8'))

    zip.close()
    zip_name = "{} - Scan Export {}".\
        format(datetime.now().strftime("%Y-%m-%d_%H%M%S"), scan.name)

    response = HttpResponse(content_type="application/zip")
    response["Content-Disposition"] = "attachment; filename={}.zip".format(zip_name)
    response.write(in_memory.getvalue())
    return response


@login_required
@user_passes_test(lambda u: u.is_superuser)
def scan_report(request, scan_id=None):
    scan = get_object_or_404(Scan, id=scan_id)

    results = ScanResult.objects.filter(scan=scan).values('ip', 'state', 'reason', 'port').all()

    in_memory = StringIO()

    csv_name = "{} - Scan Export {}". \
        format(datetime.now().strftime("%Y-%m-%d_%H%M%S"), scan.name)

    fields = ['ip', 'port', 'state', 'reason']
    output = csv.DictWriter(in_memory, fieldnames=fields)
    output.writeheader()
    output.writerows(results)

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename={}.csv".format(csv_name)
    response.write(in_memory.getvalue())
    return response


def deconfliction_message(request, scanner_id=None):
    """
    Provides the deconfliction message used for any given scan.  This is
    used to update the individual scanners' deconfliction pages.
    """
    scanner = get_object_or_404(Scanner, id=scanner_id)
    message = scanner.scan.deconfliction_message

    if message is not None:
        return HttpResponse(message)
    else:
        return HttpResponse("404 not found.", status=404)
