# Additive only: adds origin/trigger_alert/expires_at to WebBlockRecord and makes requested_by nullable.
# No existing row is changed (defaults: origin='manual', the rest NULL) and no table is dropped.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('events', '0009_ssh_reconnect_check'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='webblockrecord',
            name='origin',
            field=models.CharField(choices=[('manual', 'manual'), ('auto', 'auto')], default='manual', max_length=6),
        ),
        migrations.AddField(
            model_name='webblockrecord',
            name='trigger_alert',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='events.alert'),
        ),
        migrations.AddField(
            model_name='webblockrecord',
            name='expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='webblockrecord',
            name='requested_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
    ]
