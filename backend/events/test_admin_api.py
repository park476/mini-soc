import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from .models import ResponseVerification, UnblockRecord
from .test_response import ATTACKER, no_real_subprocess
from .test_unblock import BLOCKED, DELETE, OPEN, STATUS, UNBLOCK_ON, ScriptedExecutor, block_record, out, snapshot

API = '/api/admin-panel/'
DELETED = 'Rule deleted\n'


@override_settings(**UNBLOCK_ON)
@mock.patch('events.response.subprocess.run', no_real_subprocess)
class AdminPanelApiTests(TestCase):
    def setUp(self):
        users = get_user_model().objects
        self.admin = users.create_superuser('ROOT', password='pw-admin')
        self.staff = users.create_user('staff', password='pw-staff', is_staff=True)
        self.record = block_record()
        self.client.force_login(self.admin)

    def post(self, path, body=None, client=None):
        return (client or self.client).post(API + path, json.dumps(body or {}), content_type='application/json')

    def run_with(self, fake, path, body=None):
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake) as from_settings:
            response = self.post(path, body)
        return response, from_settings

    def assert_denied(self, client, status):
        fake = ScriptedExecutor()
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake):
            responses = [
                client.get(API + 'blocks/'), client.get(API + 'unblocks/'),
                self.post(f'blocks/{self.record.pk}/check/', client=client),
                self.post(f'blocks/{self.record.pk}/unblock/', {'confirm': True}, client=client),
            ]
        self.assertEqual([r.status_code for r in responses], [status] * 4)
        for r in responses:
            self.assertNotIn(ATTACKER, r.content.decode())
        self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))

    def test_anonymous_is_denied(self):
        self.assert_denied(Client(), 401)
        self.assertEqual(Client().get(API + 'session/').json(), {'authenticated': False, 'username': ''})

    def test_non_superuser_and_inactive_superuser_are_denied(self):
        client = Client()
        client.force_login(self.staff)
        self.assert_denied(client, 403)
        self.assertFalse(client.get(API + 'session/').json()['authenticated'])
        self.admin.is_active = False
        self.admin.save()
        self.assert_denied(self.client, 401)  # Django drops the session of an inactive user

    def test_login_logout_and_session(self):
        client = Client()
        self.assertEqual(self.post('login/', {'username': 'ROOT', 'password': 'wrong'}, client).status_code, 401)
        self.assertEqual(self.post('login/', {'username': 'staff', 'password': 'pw-staff'}, client).status_code, 403)
        self.assertEqual(self.post('login/', {'username': 'ROOT'}, client).status_code, 400)
        self.assertEqual(client.get(API + 'blocks/').status_code, 401)
        response = self.post('login/', {'username': 'ROOT', 'password': 'pw-admin'}, client)
        self.assertEqual((response.status_code, response.json()), (200, {'authenticated': True, 'username': 'ROOT'}))
        self.assertNotIn('pw-admin', response.content.decode())
        self.assertEqual(client.get(API + 'session/').json()['username'], 'ROOT')
        self.assertEqual(client.get(API + 'blocks/').status_code, 200)
        self.assertEqual(self.post('logout/', client=client).status_code, 200)
        self.assertEqual(client.get(API + 'blocks/').status_code, 401)
        self.admin.is_active = False
        self.admin.save()
        self.assertEqual(self.post('login/', {'username': 'ROOT', 'password': 'pw-admin'}, client).status_code, 401)

    def test_csrf_is_required_for_every_change(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        fake = ScriptedExecutor()
        with mock.patch('events.unblock.SshExecutor.from_settings', return_value=fake):
            statuses = [
                self.post('login/', {'username': 'ROOT', 'password': 'pw-admin'}, Client(enforce_csrf_checks=True)).status_code,
                self.post('logout/', client=client).status_code,
                self.post(f'blocks/{self.record.pk}/check/', client=client).status_code,
                self.post(f'blocks/{self.record.pk}/unblock/', {'confirm': True}, client=client).status_code,
            ]
        self.assertEqual(statuses, [403] * 4)
        self.assertEqual((fake.calls, UnblockRecord.objects.count()), ([], 0))
        self.assertEqual(client.get(API + 'blocks/').status_code, 200)  # still logged in
        # With the cookie issued by the session endpoint, the same POST is accepted.
        token = client.get(API + 'session/').cookies['csrftoken'].value
        response = client.post(API + 'logout/', '{}', content_type='application/json', HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)

    def test_get_cannot_change_anything(self):
        for path in ('login/', 'logout/', f'blocks/{self.record.pk}/check/', f'blocks/{self.record.pk}/unblock/'):
            self.assertEqual(self.client.get(API + path).status_code, 405)
        self.assertEqual(self.post('blocks/').status_code, 405)

    def test_blocks_list_shows_history_not_current_state(self):
        ResponseVerification.objects.create(response=self.record, ufw_rule_result='present', kali_ssh_reconnect_result='failed')
        failed = block_record('failed')
        data = self.client.get(API + 'blocks/').json()
        self.assertTrue(data['unblock_enabled'])
        by_id = {b['id']: b for b in data['blocks']}
        block = by_id[self.record.pk]
        self.assertEqual((block['target_ip'], block['triggering_alert_id'], block['execution_status'],
                          block['verification_status'], block['eligible'], block['unblocks']),
                         (ATTACKER, self.record.triggering_alert_id, 'succeeded', 'success', True, []))
        self.assertNotIn('ufw_state', block)
        self.assertFalse(by_id[failed.pk]['eligible'])

    def test_check_reads_state_without_changing_or_recording(self):
        for stdout, expected in ((BLOCKED, 'present'), (OPEN, 'absent')):
            fake = ScriptedExecutor(out(stdout=stdout))
            response, from_settings = self.run_with(fake, f'blocks/{self.record.pk}/check/')
            self.assertEqual((response.status_code, response.json()['ufw_state']), (200, expected))
            self.assertEqual(fake.calls, [STATUS])
            from_settings.assert_called_once_with('RESPONSE_UNBLOCK_EXECUTE')
        fake = ScriptedExecutor(out(255, stderr='Connection refused'))
        data = self.run_with(fake, f'blocks/{self.record.pk}/check/')[0].json()
        self.assertEqual((data['ufw_state'], data['failure_kind']), ('unchecked', 'ssh_error'))
        with self.settings(RESPONSE_UNBLOCK_EXECUTE=False):
            fake = ScriptedExecutor()
            data = self.run_with(fake, f'blocks/{self.record.pk}/check/')[0].json()
        self.assertEqual((data['ufw_state'], data['failure_kind'], fake.calls), ('unchecked', 'config', []))
        self.assertEqual(UnblockRecord.objects.count(), 0)

    def test_unblock_success_records_admin_and_keeps_past_evidence(self):
        verification = ResponseVerification.objects.create(
            response=self.record, ufw_rule_result='present', kali_ssh_reconnect_result='failed')
        before = snapshot(self.record)
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout=DELETED), out(stdout=OPEN))
        response, _ = self.run_with(fake, f'blocks/{self.record.pk}/unblock/',
                                    {'confirm': True, 'target_ip': '203.0.113.9', 'command': 'sudo reboot'})
        data = response.json()
        self.assertEqual((response.status_code, data['outcome']), (200, 'unblocked'))
        self.assertEqual(fake.calls, [STATUS, DELETE, STATUS])
        audit = UnblockRecord.objects.get()
        self.assertEqual((audit.requested_by, audit.target_ip, data['unblock']['requested_by']), (self.admin, ATTACKER, 'ROOT'))
        self.assertEqual(snapshot(self.record), before)
        verification.refresh_from_db()
        self.assertEqual(verification.verification_status, 'success')
        history = self.client.get(API + 'unblocks/').json()['unblocks']
        self.assertEqual([u['id'] for u in history], [audit.pk])
        self.assertEqual(self.client.get(API + 'blocks/').json()['blocks'][0]['unblocks'][0]['id'], audit.pk)

    def test_unblock_requires_explicit_confirm(self):
        for body in ({}, {'confirm': 'true'}, {'confirm': False}, [1]):
            fake = ScriptedExecutor()
            response, _ = self.run_with(fake, f'blocks/{self.record.pk}/unblock/', body)
            self.assertEqual((response.status_code, fake.calls), (400, []))
        self.assertEqual(UnblockRecord.objects.count(), 0)

    def test_skipped_attempt_does_not_block_a_later_real_unblock(self):
        first, _ = self.run_with(ScriptedExecutor(out(stdout=OPEN)), f'blocks/{self.record.pk}/unblock/', {'confirm': True})
        self.assertEqual((first.status_code, first.json()['outcome']), (200, 'already_unblocked'))
        # The same IP is blocked again later; the earlier skipped audit must not get in the way.
        fake = ScriptedExecutor(out(stdout=BLOCKED), out(stdout=DELETED), out(stdout=OPEN))
        second, _ = self.run_with(fake, f'blocks/{self.record.pk}/unblock/', {'confirm': True})
        self.assertEqual((second.status_code, second.json()['outcome']), (200, 'unblocked'))
        self.assertEqual(fake.calls, [STATUS, DELETE, STATUS])
        self.assertEqual(list(UnblockRecord.objects.order_by('id').values_list('execution_status', flat=True)),
                         ['skipped', 'succeeded'])

    def test_unblock_failures_have_distinct_responses(self):
        cases = [
            ([out(255, stderr='Connection refused')], 502, 'ssh_error'),
            ([out(stdout=BLOCKED), out(1, stderr='sudo: a password is required')], 502, 'sudo_denied'),
            ([out(stdout=BLOCKED), out(stdout=DELETED), out(stdout=BLOCKED)], 502, 'rule_still_present'),
        ]
        for script, status, kind in cases:
            with self.subTest(kind=kind):
                response, _ = self.run_with(ScriptedExecutor(*script), f'blocks/{self.record.pk}/unblock/', {'confirm': True})
                self.assertEqual((response.status_code, response.json()['outcome'], response.json()['unblock']['failure_kind']),
                                 (status, 'failed', kind))
        failed = block_record('failed')
        response, _ = self.run_with(ScriptedExecutor(), f'blocks/{failed.pk}/unblock/', {'confirm': True})
        self.assertEqual((response.status_code, response.json()['unblock']['failure_kind']), (409, 'not_eligible'))
        with self.settings(RESPONSE_UNBLOCK_EXECUTE=False, RESPONSE_EXECUTE=True):
            fake = ScriptedExecutor()
            response, _ = self.run_with(fake, f'blocks/{self.record.pk}/unblock/', {'confirm': True})
        self.assertEqual((response.status_code, response.json()['unblock']['failure_kind'], fake.calls), (503, 'config', []))
        self.assertEqual(self.post('blocks/999999/unblock/', {'confirm': True}).status_code, 404)
