from django.core.management.base import BaseCommand

from events.detection import run_detection


class Command(BaseCommand):
    help = 'Evaluate the three T3 detection rules over stored SecurityEvents and save new Alerts.'

    def handle(self, *args, **options):
        created = run_detection()
        self.stdout.write(self.style.SUCCESS(f'Created {created} Alert(s)'))
