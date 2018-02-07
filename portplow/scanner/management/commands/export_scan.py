import os
import stat
from uuid import UUID
from django.core.management.base import BaseCommand, CommandError
from scanner.models import Scan
from scanner.tasks import export_scan


class Command(BaseCommand):
    help = 'Export raw data for scan'

    def add_arguments(self, parser):
        parser.add_argument('--scan', type=UUID, help="Scan UUID")

    def handle(self, *args, **options):
        if options['scan'] is None:
            raise CommandError("Scan ID was not specified.")

        try:
            scan = Scan.objects.get(id=options['scan'])
        except Scan.DoesNotExist:
            raise CommandError("Specified scan ID {} does not exist.".format(options['scan']))

        export_scan(scan.id)

        self.stdout.write(self.style.SUCCESS("Successfully exported scan {}.".format(scan.name)))

