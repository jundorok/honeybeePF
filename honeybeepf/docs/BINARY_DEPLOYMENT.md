# HoneybeePF Binary Deployment Guide

HoneybeePF는 eBPF 기반 모니터링 도구입니다. 이 문서는 바이너리 직접 배포 방법을 설명합니다.

## 📦 빌드

### Linux에서 빌드 (권장)

```bash
# 릴리스 빌드
cargo xtask build --release

# 바이너리 위치
ls -la target/release/honeybeepf
```

### macOS에서 Linux용 크로스 컴파일

macOS에서 Linux 바이너리를 빌드하려면 `cross` 도구가 필요합니다:

```bash
# cross 설치 (Docker 필요)
cargo install cross

# Docker가 실행 중인지 확인
docker info

# Linux용 빌드
cargo xtask build --release --target x86_64-unknown-linux-gnu

# ARM64 Linux용 (AWS Graviton, Apple Silicon Linux VM 등)
cargo xtask build --release --target aarch64-unknown-linux-gnu
```

## 🚀 배포

### 방법 1: xtask를 이용한 자동 배포

```bash
# 원격 서버에 배포 (빌드 + scp + 설치)
cargo xtask deploy --host user@192.168.1.100 --release

# systemd 서비스로 설치 후 재시작
cargo xtask deploy --host user@192.168.1.100 --release --restart

# 특정 경로에 배포
cargo xtask deploy --host root@server.com --path /opt/honeybeepf/bin/honeybeepf --release
```

### 방법 2: 수동 배포

```bash
# 1. 빌드
cargo xtask build --release

# 2. 바이너리 복사
scp target/release/honeybeepf user@server:/tmp/

# 3. 서버에서 설치
ssh user@server
sudo mv /tmp/honeybeepf /usr/local/bin/
sudo chmod +x /usr/local/bin/honeybeepf
```

### 방법 3: 패키지 생성 후 배포

```bash
# 배포 패키지 생성
cargo xtask package --output dist

# 생성된 tarball 확인
ls dist/*.tar.gz

# 서버로 전송 및 설치
scp dist/honeybeepf-*.tar.gz user@server:/tmp/
ssh user@server "cd /tmp && tar xzf honeybeepf-*.tar.gz && cd honeybeepf-* && sudo ./install.sh"
```

## 🔐 권한 요구사항

HoneybeePF는 eBPF 프로그램을 커널에 로드해야 하므로 **특별한 권한이 필요**합니다.

### 옵션 1: root로 실행 (간단)

```bash
sudo /usr/local/bin/honeybeepf
```

### 옵션 2: Capabilities 설정 (권장, 보안상 더 안전)

```bash
# 필요한 capabilities 부여
sudo setcap 'cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin+ep' /usr/local/bin/honeybeepf

# 일반 유저로 실행 가능
/usr/local/bin/honeybeepf
```

**필요한 Capabilities:**
| Capability | 용도 |
|------------|------|
| `CAP_SYS_ADMIN` | eBPF 프로그램 로드 (커널 5.8 이전) |
| `CAP_BPF` | eBPF 프로그램 로드 (커널 5.8+) |
| `CAP_PERFMON` | perf 이벤트 접근 |
| `CAP_NET_ADMIN` | 네트워크 관련 eBPF 프로그램 |

### 커널 버전 확인

```bash
uname -r
# 5.8 이상 권장 (CAP_BPF 지원)
```

## 🔧 Systemd 서비스 설정

### 자동 설치

```bash
cargo xtask install-service --host user@server
```

### 수동 설치

1. 서비스 파일 생성:

```bash
sudo tee /etc/systemd/system/honeybeepf.service << 'EOF'
[Unit]
Description=HoneybeePF eBPF Monitoring
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/honeybeepf
Restart=on-failure
RestartSec=5
EnvironmentFile=-/etc/honeybeepf/honeybeepf.env

# Security hardening (root로 실행하지 않을 경우)
# User=honeybeepf
# Group=honeybeepf

# eBPF에 필요한 capabilities
NoNewPrivileges=no
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
```

2. 환경 설정 파일 (선택사항):

```bash
sudo mkdir -p /etc/honeybeepf
sudo tee /etc/honeybeepf/honeybeepf.env << 'EOF'
# HoneybeePF Configuration
# RUST_LOG=info
# HONEYBEEPF_METRICS_PORT=9090
EOF
```

3. 서비스 활성화 및 시작:

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeybeepf
sudo systemctl start honeybeepf

# 상태 확인
sudo systemctl status honeybeepf

# 로그 확인
sudo journalctl -u honeybeepf -f
```

## 📊 상태 확인

### 프로세스 확인

```bash
ps aux | grep honeybeepf
```

### eBPF 프로그램 확인

```bash
# 로드된 eBPF 프로그램 목록
sudo bpftool prog list

# 로드된 eBPF 맵 목록
sudo bpftool map list
```

### 로그 확인

```bash
# systemd 로그
sudo journalctl -u honeybeepf -f

# verbose 모드로 실행
sudo /usr/local/bin/honeybeepf --verbose
```

## 🛠 트러블슈팅

### "Operation not permitted" 에러

```bash
# 해결: root로 실행하거나 capabilities 설정
sudo /usr/local/bin/honeybeepf
# 또는
sudo setcap 'cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin+ep' /usr/local/bin/honeybeepf
```

### "BPF not supported" 에러

```bash
# 커널 설정 확인
cat /boot/config-$(uname -r) | grep BPF
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_JIT=y 가 있어야 함
```

### BTF (BPF Type Format) 에러

```bash
# BTF 지원 확인
ls /sys/kernel/btf/vmlinux

# BTF가 없으면 커널 업그레이드 필요 (5.4+ 권장)
```

## 📁 파일 위치

| 파일 | 경로 | 설명 |
|------|------|------|
| 바이너리 | `/usr/local/bin/honeybeepf` | 실행 파일 |
| 서비스 | `/etc/systemd/system/honeybeepf.service` | systemd 유닛 |
| 환경설정 | `/etc/honeybeepf/honeybeepf.env` | 환경 변수 |
| 로그 | `journalctl -u honeybeepf` | systemd journal |

## 🔄 업데이트

```bash
# 새 버전 배포
cargo xtask deploy --host user@server --release --restart

# 또는 수동으로
scp target/release/honeybeepf user@server:/tmp/
ssh user@server "sudo mv /tmp/honeybeepf /usr/local/bin/ && sudo systemctl restart honeybeepf"
```

## 🗑 제거

```bash
# 서비스 중지 및 비활성화
sudo systemctl stop honeybeepf
sudo systemctl disable honeybeepf

# 파일 삭제
sudo rm /etc/systemd/system/honeybeepf.service
sudo rm /usr/local/bin/honeybeepf
sudo rm -rf /etc/honeybeepf

# systemd 재로드
sudo systemctl daemon-reload
```
