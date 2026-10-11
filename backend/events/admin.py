import shlex

from django.conf import settings
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.template.response import TemplateResponse

from .models import ManualBlockRecord, ResponseRecord, UnblockRecord
from .unblock import EXECUTE_SETTING, unblock_command, unblock_response


class ReadOnlyAdmin(admin.ModelAdmin):
    """Stored response evidence is never added, edited or deleted from the admin."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(ResponseRecord)
class ResponseRecordAdmin(ReadOnlyAdmin):
    list_display = ('id', 'target_ip', 'triggering_alert_id', 'action', 'execution_status', 'executed_at', 'unblock_attempts')
    list_filter = ('execution_status',)
    ordering = ('-id',)
    actions = ['unblock_ssh']

    @admin.display(description='Unblock attempts')
    def unblock_attempts(self, obj):
        return ', '.join(f'#{u.pk} {u.execution_status}' for u in obj.unblocks.order_by('id')) or '-'

    def get_actions(self, request):
        return super().get_actions(request) if request.user.is_superuser else {}

    @admin.action(description='SSH 차단 해제 (선택한 성공 차단 기록)')
    def unblock_ssh(self, request, queryset):
        if not request.user.is_superuser:
            raise PermissionDenied
        records = list(queryset.order_by('id'))
        eligible = [r for r in records if r.action == 'block_ssh' and r.execution_status == 'succeeded']
        if request.POST.get('confirm_unblock') == 'yes' and request.POST.get('acknowledge') == 'on':
            for record in eligible:
                audit = unblock_response(record, request.user)
                ok = audit.execution_status == 'succeeded' and audit.ufw_after_result == 'absent'
                level = messages.SUCCESS if ok else messages.WARNING if audit.execution_status == 'skipped' else messages.ERROR
                self.message_user(request, (
                    f'UnblockRecord #{audit.pk} — ResponseRecord #{record.pk} {audit.target_ip}: '
                    f'execution={audit.execution_status}, ufw_after={audit.ufw_after_result}'
                    + (f', {audit.failure_kind or "note"}: {audit.failure_reason}' if audit.failure_reason else '')
                    + '. Kali SSH 재접속은 별도 검증 항목이며 아직 unchecked입니다.'
                ), level)
            if not eligible:
                self.message_user(request, '성공한 SSH 차단 기록이 선택되지 않았습니다. 명령을 보내지 않았습니다.', messages.ERROR)
            return None
        if request.POST.get('confirm_unblock') == 'yes':
            self.message_user(request, '확인란을 선택해야 실행됩니다. 명령을 보내지 않았습니다.', messages.ERROR)
        return TemplateResponse(request, 'admin/events/unblock_confirmation.html', {
            **self.admin_site.each_context(request),
            'title': 'SSH 차단 해제 확인',
            'opts': self.model._meta,
            'rows': [{'record': r, 'command': shlex.join(unblock_command(r.target_ip))} for r in eligible],
            'ineligible': [r for r in records if r not in eligible],
            'selected': [r.pk for r in records],
            'execute_enabled': getattr(settings, EXECUTE_SETTING, False) is True,
            'execute_setting': EXECUTE_SETTING,
            'victim': f'{settings.RESPONSE_VICTIM_USER}@{settings.RESPONSE_VICTIM_HOST}:{settings.RESPONSE_VICTIM_SSH_PORT}',
        })


@admin.register(UnblockRecord)
class UnblockRecordAdmin(ReadOnlyAdmin):
    """Audit log. Only the separately observed Kali reconnect result can be filled in, by a superuser."""
    list_display = ('id', 'response_id', 'target_ip', 'requested_by_username', 'requested_at', 'execution_status',
                    'failure_kind', 'ufw_before_result', 'ufw_after_result', 'kali_ssh_reconnect_result')
    list_filter = ('execution_status', 'failure_kind')
    ordering = ('-id',)
    editable = ('kali_ssh_reconnect_result', 'reconnect_check_evidence')

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields if f.name not in self.editable]


@admin.register(ManualBlockRecord)
class ManualBlockRecordAdmin(ReadOnlyAdmin):
    list_display = ('id', 'target_ip', 'requested_by_username', 'requested_at', 'execution_status', 'failure_kind',
                    'ufw_before_result', 'ufw_after_result')
    ordering = ('-id',)
