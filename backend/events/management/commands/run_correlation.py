from django.core.management.base import BaseCommand

from events.correlation import run_correlation


class Command(BaseCommand):
    help = 'Correlate stored Alerts, score risk and create Incidents (T4). Run after run_detection.'

    def handle(self, *args, **options):
        c = run_correlation()
        self.stdout.write(self.style.SUCCESS(
            f"Correlation scopes: {c['created']} created, {c['updated']} updated, "
            f"{c['unchanged']} unchanged, {c['removed']} removed; {c['incidents']} Incident(s) created"
        ))
