# Additive only: creates the WebBlockRecord table; no existing table or row is changed.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('events', '0007_manual_block_record'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='WebBlockRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('operation', models.CharField(choices=[('block', 'block'), ('unblock', 'unblock')], max_length=7)),
                ('requested_by_username', models.CharField(max_length=150)),
                ('target_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('execution_status', models.CharField(choices=[('succeeded', 'succeeded'), ('failed', 'failed'), ('skipped', 'skipped'), ('unknown', 'unknown')], default='failed', max_length=9)),
                ('failure_kind', models.CharField(blank=True, max_length=20)),
                ('failure_reason', models.TextField(blank=True)),
                ('victim', models.TextField(blank=True)),
                ('command', models.TextField(blank=True)),
                ('execution_result', models.TextField(blank=True)),
                ('state_before_result', models.CharField(choices=[('present', 'present'), ('absent', 'absent'), ('unchecked', 'unchecked')], default='unchecked', max_length=9)),
                ('state_before_evidence', models.TextField(blank=True)),
                ('state_after_result', models.CharField(choices=[('present', 'present'), ('absent', 'absent'), ('unchecked', 'unchecked')], default='unchecked', max_length=9)),
                ('state_after_evidence', models.TextField(blank=True)),
                ('http_check_status', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('http_check_result', models.CharField(choices=[('success', 'success'), ('failed', 'failed'), ('unchecked', 'unchecked')], default='unchecked', max_length=9)),
                ('http_check_evidence', models.TextField(blank=True)),
                ('http_checked_at', models.DateTimeField(blank=True, null=True)),
                ('requested_at', models.DateTimeField(auto_now_add=True)),
                ('executed_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('requested_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
