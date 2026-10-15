# 미니 PC Nginx 8080 웹 차단 설치 안내 (사용자 승인 후 직접 실행)

Django 쪽 코드는 `backend/events/web_block.py`다. 이 디렉터리의 파일은 피해 서버(미니 PC 172.18.20.161)에
사용자가 직접 설치한다. 아래 명령은 Apache 80, Juice Shop 3000, 기존 Cloudflare real-IP 설정과 UFW 22번
규칙·sudoers를 바꾸지 않는다.

**대상 IP (2026-10-15 최신 결정):** 고정 IP가 아니라, Django Alert가 발생한 임의의 정상 공인 IP를 관리자가
패널에서 선택해 차단·해제한다. 헬퍼도 검증된 임의 IP를 받는다. 사설 IP는 기본 거부이며
`/etc/mini-soc/web-private-allowed.txt`(선택)에 명시한 범위만 허용한다. 자동 웹 차단은 구현하지 않았다.

헬퍼 자체 검증: 명령은 status/block/unblock만, IP는 정규 형식 1개만(셸 문자열·경로 불가). block은 루프백·링크 로컬·
예약·멀티캐스트·미지정 주소와 보호 목록을 거부한다. root로 실행되는지, 헬퍼·nginx·systemctl·목록 파일·디렉터리가
root 소유이며 group/world 쓰기 불가이고 심볼릭 링크가 아닌지 매번 확인한다.

## 0. 읽기 전용 사전 확인

```sh
sudo nginx -T 2>/dev/null | grep -nE 'listen|server_name|real_ip|set_real_ip_from|log_format|access_log|allow|deny|include'
sudo -l -U mini-soc-response
ls -l /usr/local/sbin/mini-soc-webblock /etc/nginx/mini-soc /etc/mini-soc 2>&1
```

확인할 것:
- `real_ip_header`와 `set_real_ip_from`이 8080 server에 적용되고, 신뢰 범위가 cloudflared 주소(예: 127.0.0.1)로 좁은지
- 8080 server의 `location` 안에 `allow`/`deny`가 없는지. 있으면 server 단계 `deny`가 상속되지 않으므로 설치 전에 보고
- access.log의 IP가 `$remote_addr`(real-IP 적용 결과)인지

## 1. 백업

```sh
sudo cp -a /etc/nginx /root/nginx-backup-$(date +%Y%m%d-%H%M%S)
sudo cp -a /etc/sudoers.d /root/sudoers.d-backup-$(date +%Y%m%d-%H%M%S)
```

## 2. 헬퍼와 목록 파일

```sh
sudo install -o root -g root -m 0755 mini-soc-webblock /usr/local/sbin/mini-soc-webblock
sudo install -d -o root -g root -m 0755 /etc/nginx/mini-soc /etc/mini-soc
echo '# mini-soc web blocklist (Nginx 8080). Managed by mini-soc-webblock; do not edit by hand.' \
  | sudo tee /etc/nginx/mini-soc/web-blocklist.conf >/dev/null
sudo install -o root -g root -m 0644 web-protected.txt /etc/mini-soc/web-protected.txt
# 사설 IP 공격 실습을 별도로 승인한 경우에만:
# sudo install -o root -g root -m 0644 web-private-allowed.txt.example /etc/mini-soc/web-private-allowed.txt  (범위 편집)
```

## 3. Nginx 8080 server 블록에 include 한 줄 추가

8080을 `listen`하는 server 블록 안(최상단, location 밖)에만 추가한다.

```nginx
include /etc/nginx/mini-soc/web-blocklist.conf;
```

```sh
sudo nginx -t && sudo systemctl reload nginx
```

## 4. sudoers (root 소유 고정 헬퍼만, IP는 헬퍼가 검증)

`block *`의 `*`는 sudoers에서 공백도 포함할 수 있지만, 헬퍼가 인자 개수·형식을 다시 검사하므로 추가 인자는 거부된다.
`ufw`, `nginx`, `tee`, 셸 등 다른 명령 권한은 주지 않는다.

```sh
sudo visudo -f /etc/sudoers.d/mini-soc-web   # 내용은 sudoers-mini-soc-web.example
sudo visudo -c
sudo -l -U mini-soc-response
```

## 5. 동작 확인 (사용자 승인 후)

```sh
sudo -u mini-soc-response sudo -n /usr/local/sbin/mini-soc-webblock status
sudo -u mini-soc-response sudo -n /usr/local/sbin/mini-soc-webblock block 127.0.0.1    # 거부(exit 6)되어야 함
sudo -u mini-soc-response sudo -n /usr/bin/id                                          # sudo가 거부해야 함
```

## 복구

- 웹 차단 해제: `sudo /usr/local/sbin/mini-soc-webblock unblock <ip>` (현재 목록: `... status`)
- 기능 전체 제거: 8080 server의 include 줄을 삭제하고 `sudo nginx -t && sudo systemctl reload nginx`, 그다음
  `sudo rm /etc/sudoers.d/mini-soc-web /usr/local/sbin/mini-soc-webblock`
- 최악의 경우: 1단계 백업 디렉터리에서 `/etc/nginx`를 복원한 뒤 `nginx -t`와 reload

---

# 미니 PC SSH(UFW 22/tcp) 수동 차단 실행기 설치 (사용자 별도 승인 후 직접 실행)

Django 쪽은 `backend/events/ip_actions.py`. 관리자 패널에서 `ssh_brute_force` 경보가 있는 IP만 선택해
`sudo -n /usr/local/sbin/mini-soc-sshblock block|unblock <ip>`를 보낸다. 상태는 기존 `sudo -n ufw status`로 읽는다.
실행기는 `ufw prepend|delete deny proto tcp from <ip> to any port 22` 한 형태만 다루며, 다른 UFW 규칙(사람이 만든 규칙
포함)과 UFW 활성화 상태는 건드리지 않는다. 자동 대응(`RESPONSE_EXECUTE`)과 웹 차단 실행기는 변경하지 않는다.

**경고:** SSH 차단은 관리 접속을 끊을 수 있다. 모든 단계 전에 미니 PC 콘솔(모니터·키보드) 접근을 확보한다.

## S0. 읽기 전용 사전 확인

```sh
sudo ufw status numbered
sudo -l -U mini-soc-response
grep -E 'Accepted|Failed' /var/log/auth.log | tail -20     # 관리 접속·공격 장비의 실제 출발지 확인
echo "$SSH_CLIENT"                                         # 현재 관리 세션의 출발지
```

확인할 것: UFW가 active인지, 관리 SSH 출발지(관제 PC 172.18.20.65 등)가 `ssh-protected.txt`에 모두 있는지,
공격 장비의 출발지가 보호 대상과 다른지.

## S1. 백업

```sh
sudo cp -a /etc/ufw /root/ufw-backup-$(date +%Y%m%d-%H%M%S)
sudo cp -a /etc/sudoers.d /root/sudoers.d-backup-$(date +%Y%m%d-%H%M%S)
```

## S2. 실행기와 목록

```sh
sudo install -o root -g root -m 0755 mini-soc-sshblock /usr/local/sbin/mini-soc-sshblock
sudo install -d -o root -g root -m 0755 /etc/mini-soc
sudo install -o root -g root -m 0644 ssh-protected.txt /etc/mini-soc/ssh-protected.txt   # 필수, 관리 출발지 모두 포함
# 공격 장비 LAN IP 확인 후에만 (/32):
# echo '<공격IP>/32' | sudo tee /etc/mini-soc/ssh-private-allowed.txt && sudo chmod 0644 /etc/mini-soc/ssh-private-allowed.txt
```

## S3. sudoers

```sh
sudo visudo -f /etc/sudoers.d/mini-soc-ssh     # 내용은 sudoers-mini-soc-ssh.example
sudo visudo -c && sudo -l -U mini-soc-response
```

기존 `ufw status` 정확 줄은 유지한다. 기존 172.22.16.235 전용 `ufw prepend/delete` 줄은 실행기 검증 후 별도 승인으로 제거한다.

## S4. 거부 동작 확인 (UFW를 바꾸지 않음)

```sh
sudo -u mini-soc-response sudo -n /usr/local/sbin/mini-soc-sshblock block 172.18.20.65   # exit 6 (보호/사설)
sudo -u mini-soc-response sudo -n /usr/local/sbin/mini-soc-sshblock block 127.0.0.1      # exit 6
sudo -u mini-soc-response sudo -n /usr/local/sbin/mini-soc-sshblock block any            # exit 2
sudo -u mini-soc-response sudo -n /usr/sbin/ufw disable                                   # sudo가 거부해야 함
```

## S5. 첫 실차단 (별도 승인) — 15분 복구 타이머

```sh
sudo systemd-run --on-active=15m --unit=minisoc-ssh-failsafe \
  /usr/sbin/ufw delete deny proto tcp from <공격IP> to any port 22
```

패널에서 SSH 차단 → 공격 장비에서 새 접속 `nc -vz -w 5 172.18.20.161 22`(타임아웃이어야 함) → 관제 PC 관리 SSH 정상 확인
→ `record_ssh_check block <id> failed --evidence "..."` → 패널에서 SSH 차단 해제 → `nc` 성공 →
`record_ssh_check unblock <id> succeeded --evidence "..."` → 타이머 취소 `sudo systemctl stop minisoc-ssh-failsafe.timer`.
이미 연결된 SSH 세션은 UFW의 ESTABLISHED 허용으로 유지되므로 반드시 새 접속으로 확인한다.

## SSH 복구

- 1순위: 관리자 패널 SSH 차단 해제
- 콘솔: `sudo ufw delete deny proto tcp from <ip> to any port 22` 후 `sudo ufw status numbered`
- 최악: S1 백업의 `user.rules`·`user6.rules`를 `/etc/ufw/`에 복원하고 `sudo ufw reload`
- 기능 제거: `sudo rm /etc/sudoers.d/mini-soc-ssh /usr/local/sbin/mini-soc-sshblock`
- Django: override 파일에 `RESPONSE_MANUAL_BLOCK_EXECUTE=false` 추가 후 `touch backend/config/settings.py`
