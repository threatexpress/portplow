import os
import stat
from uuid import UUID
from django.core.management.base import BaseCommand, CommandError
from scanner.models import Scan
from scanner.signals import add_scanner


class Command(BaseCommand):
    help = 'Add specified number of scanners to scan'

    def add_arguments(self, parser):
        parser.add_argument('--num', nargs="?", type=int, help="Number of scanners to add")
        parser.add_argument('--scan', type=UUID, help="Scan UUID")

    def handle(self, *args, **options):
        if options['scan'] is None:
            raise CommandError("Scan ID was not specified.")

        num_scanners = 1
        if options['num'] is not None:
            if options['num'] <= 0:
                raise CommandError("You must have a positive number of scanners to add.")
            num_scanners = options['num']

        try:
            scan = Scan.objects.get(id=options['scan'])
        except Scan.DoesNotExist:
            raise CommandError("Specified scan ID {} does not exist.".format(options['scan']))

        if scan.status == Scan.COMPLETE:
            raise CommandError("Cannot add scanner to an already completed job.")

        for x in range(num_scanners):
            add_scanner(scan)

        self.stdout.write(self.style.SUCCESS("Successfully added {} scanners to scan {}.".format(num_scanners, scan.name)))

