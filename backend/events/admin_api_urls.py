from django.urls import path

from . import admin_api

urlpatterns = [
    path('session/', admin_api.session_view, name='admin-panel-session'),
    path('login/', admin_api.login_view, name='admin-panel-login'),
    path('logout/', admin_api.logout_view, name='admin-panel-logout'),
    path('blocks/', admin_api.blocks_view, name='admin-panel-blocks'),
    path('blocks/<int:pk>/check/', admin_api.check_view, name='admin-panel-check'),
    path('blocks/<int:pk>/unblock/', admin_api.unblock_view, name='admin-panel-unblock'),
    path('unblocks/', admin_api.unblocks_view, name='admin-panel-unblocks'),
    path('threats/', admin_api.threats_view, name='admin-panel-threats'),
    path('threats/block/', admin_api.threat_block_view, name='admin-panel-threat-block'),
    path('threats/unblock/', admin_api.threat_unblock_view, name='admin-panel-threat-unblock'),
    path('ufw-status/', admin_api.ufw_status_view, name='admin-panel-ufw-status'),
]
