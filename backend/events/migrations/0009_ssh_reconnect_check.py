# Additive only: three columns on ManualBlockRecord and one on UnblockRecord, all with defaults or NULL.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('events', '0008_web_block_record'),
    ]

    operations = [
        migrations.AddField(
            model_name='manualblockrecord',
            name='kali_ssh_reconnect_result',
            field=models.CharField(choices=[('failed', 'failed'), ('succeeded', 'succeeded'), ('unchecked', 'unchecked')], default='unchecked', max_length=9),
        ),
        migrations.AddField(
            model_name='manualblockrecord',
            name='reconnect_check_evidence',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='manualblockrecord',
            name='reconnect_checked_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='unblockrecord',
            name='reconnect_checked_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
