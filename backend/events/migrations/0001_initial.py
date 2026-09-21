# Initial migration written explicitly because Django is unavailable in the workspace.
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(
            name='SecurityEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('source_type', models.CharField(choices=[('nginx', 'nginx'), ('ssh', 'ssh')], max_length=5)),
                ('event_time', models.DateTimeField()),
                ('source_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('action', models.TextField()),
                ('result', models.TextField()),
                ('request_path', models.TextField(blank=True)),
                ('http_status', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('ssh_evidence', models.TextField(blank=True)),
                ('raw_log', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
