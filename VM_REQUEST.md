# De xuat cau hinh may ao cho Adaptive Honeypot RL

Muc dich: xin may ao de chay full Docker stack, thu thap log runtime, export replay buffer va train offline RL bang Discrete CQL. He thong khong can GPU vi model hien tai rat nho (`nn.Linear(16, 8)`), LLM dung API ben ngoai khi can.

## 1) Cau hinh toi thieu de nghi

De chay on dinh full demo + training nhe:

- OS: Ubuntu Server 22.04 LTS hoac 24.04 LTS.
- CPU: 4 vCPU.
- RAM: 8 GB.
- Disk: 50 GB SSD.
- Network:
  - Inbound SSH port 22.
  - Outbound HTTPS/HTTP de pull Docker images va goi API LLM neu can.
  - Khong can public cac port web/Kibana; co the dung SSH tunnel.
- Quyen user:
  - Tao user `nhan` hoac user sinh vien tuong duong.
  - User co `sudo`.
  - User nam trong group `docker`.
- Cai san:
  - Docker Engine.
  - Docker Compose plugin (`docker compose`).
  - Git.
  - Python 3.11+ la tot, nhung training chinh co the chay trong Docker.

Toi thieu tuyet doi neu chi train offline, khong chay ELK/full stack: 2 vCPU, 4 GB RAM, 30 GB disk. Tuy nhien cau hinh nay khong nen dung cho demo full flow vi Elasticsearch/Kibana/Docker build de cham hoac thieu RAM.

## 2) Giai thich tinh toan tai nguyen

Model RL hien tai:

- State dim: 16.
- Action dim: 8.
- So tham so model: `16 * 8 + 8 = 136` tham so.
- GPU: khong can.

Memory khi train:

- Tensor thuan cho 1 transition gom `state` 16 float + `next_state` 16 float + action/reward/done metadata.
- Xap xi raw tensor: `~150 bytes/transition`.
- 100,000 transitions: khoang 15-50 MB tensor sau khi load.
- 1,000,000 transitions: khoang 150-500 MB tensor/metadata tuy cach luu.
- Bottleneck that su khong phai model, ma la Docker stack + Elasticsearch/Kibana + build cache.

Memory full stack uoc tinh:

- Elasticsearch + JVM overhead: 1.2-2.0 GB.
- Kibana: 0.5-1.0 GB.
- Filebeat: 0.1-0.2 GB.
- Gateway, frontend, backend, 4 honeypots: 1.0-2.0 GB.
- Control plane (`llm_analyzer`, `routing_controller`, `rl_agent` Torch): 1.0-2.0 GB.
- OS + Docker overhead + margin: 1.0-2.0 GB.

Tong toi thieu hop ly: 6-8 GB RAM. Vi vay xin 8 GB la muc toi thieu an toan.

Disk uoc tinh:

- Docker images Elastic/Kibana/Filebeat/Torch/Python/app: 10-20 GB tuy cache.
- Elasticsearch local data/logs/replay buffer: 5-15 GB trong qua trinh benchmark.
- Build cache + OS + margin: 15-20 GB.

Tong toi thieu hop ly: 40-50 GB. Vi vay xin 50 GB SSD.

CPU:

- Training CQL hien tai CPU-only va nhe.
- Docker build + Elasticsearch + Kibana + nhieu service chay song song can CPU de demo khong giat.
- 4 vCPU la muc toi thieu hop ly; 2 vCPU chi phu hop train nhe/offline rieng.

## 3) Port va cach truy cap

Chi can public SSH:

- `22/tcp`: SSH.

Neu can xem service, dung SSH tunnel tu may local:

```bash
ssh -L 18080:localhost:18080 \
    -L 5601:localhost:5601 \
    -L 8001:localhost:8001 \
    -L 8002:localhost:8002 \
    -L 8003:localhost:8003 \
    nhan@<VM_IP>
```

Sau khi tunnel:

- Web demo: `http://localhost:18080`
- Kibana: `http://localhost:5601`
- Routing controller: `http://localhost:8001`
- LLM analyzer: `http://localhost:8002`
- RL agent: `http://localhost:8003`

## 4) SSH key

Can add public key cua sinh vien vao:

```text
/home/nhan/.ssh/authorized_keys
```

Public key se gui rieng theo mau:

```text
ssh-ed25519 AAAA... nhan@adaptive-honeypot
```

Khong gui private key.

## 5) Mau noi dung gui thay

Thay oi, em xin mot may ao de chay thuc nghiem khoa luan Adaptive Honeypot RL. He thong can chay Docker Compose gom gateway HAProxy, real service, 4 web honeypot, Elasticsearch/Kibana/Filebeat, LLM analyzer, routing controller va RL agent. Phan train RL hien tai dung offline Discrete Conservative Q-Learning (CQL) tren replay buffer log, CPU-only, khong can GPU.

Cau hinh toi thieu em xin:

- Ubuntu Server 22.04/24.04 LTS
- 4 vCPU
- 8 GB RAM
- 50 GB SSD
- Docker Engine + Docker Compose plugin
- Git
- User co sudo va nam trong group docker
- Mo SSH port 22, outbound internet de pull Docker images/API
- Add SSH public key cua em vao `authorized_keys`

Neu tai nguyen han che, 2 vCPU/4 GB RAM/30 GB disk chi phu hop train offline nhe, khong phu hop chay full demo voi Elasticsearch/Kibana. Cau hinh 4 vCPU/8 GB/50 GB la muc toi thieu an toan de em demo full flow va benchmark.
