import os
import stat
from uuid import UUID
from django.core.management.base import BaseCommand, CommandError
from scanner.models import Scanner


class Command(BaseCommand):
    help = 'Get private SSH keys for scanners and save them to /tmp'

    def add_arguments(self, parser):
        parser.add_argument('--ip', nargs="*", type=str, help="IP address of scanner")
        parser.add_argument('--id', nargs="*", type=UUID, help="UUID of scanner")
        parser.add_argument('--scan', nargs="*", type=UUID, help="Scan UUID")

    def parse_keys(self, scanners):
        for scanner in scanners:
            if scanner.ip is not None:
                output_file = os.path.join('/', 'tmp', "{}__{}".format(scanner.scan.id, scanner.ip))
            else:
                output_file = os.path.join('/', 'tmp', "{}__{}".format(scanner.scan.id, scanner.id))

            with open(output_file, "w") as f:
                result = f.write(scanner.key)

            os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)

    def handle(self, *args, **options):
        if options['ip'] is not None:
            scanners = Scanner.objects.filter(ip__in=options['ip']).only('id', 'ip', 'key', 'scan__id').all()
            print(scanners)
            self.parse_keys(scanners=scanners)

        if options['id'] is not None:
            scanners = Scanner.objects.filter(id__in=options['id']).only('id', 'ip', 'key', 'scan__id').all()
            self.parse_keys(scanners=scanners)

        if options['scan'] is not None:
            scanners = Scanner.objects.filter(scan_id__in=options['scan']).only('id', 'ip', 'key', 'scan__id').all()
            self.parse_keys(scanners=scanners)

        if options['scan'] is None and options['id'] is None and options['ip'] is None:
            self.stdout.write(self.style.ERROR("No keys exported because nothing was specified."))
        else:
            self.stdout.write(self.style.SUCCESS("Successfully exported keys."))
