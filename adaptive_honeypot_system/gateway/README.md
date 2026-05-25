# Gateway

Component nay la data-plane HTTP gateway dung HAProxy.

Chuc nang:

- Nhan traffic tai `localhost:18080`.
- Phuc vu frontend mac dinh.
- Route `/api/*` vao real backend hoac web honeypots.
- Doc `sid` cookie de ho tro mid-session rerouting cho Web.
- Doc source-IP map de ho tro test split-client.
- Expose HAProxy stats tai `localhost:8404/stats` trong debug mode.

File chinh:

- `entrypoint.sh`: chon config theo `TEST_HONEYPOT` va an stats UI theo `EXPOSURE_MODE`.
- `haproxy.normal.cfg`: normal-first mode, mac dinh API vao `normal_api`.
- `haproxy.honeypot.cfg`: honeypot test mode, map endpoint sang web honeypot.
- `routing_update.sh`: cap nhat HAProxy map file va runtime map qua admin socket.
Legacy `haproxy.cfg` da duoc xoa de tranh nham lan; runtime chi dung hai config tren.

Dynamic maps:

- `/etc/haproxy/maps/session_routes.map`: `sid -> backend`.
- `/etc/haproxy/maps/ip_honeypot.map`: `source_ip -> backend`.

Luu y quan trong: map tren chi luu target backend, nhung HAProxy ap dung route theo dung API surface:

- `sqli_api` chi ap dung cho `/api/articles/search`.
- `cmdi_api` chi ap dung cho `/api/tools/ping`.
- `ssti_api` chi ap dung cho `/api/tools/preview`.
- `ssrf_api` chi ap dung cho `/api/tools/fetch`.

Vi du neu `sid` duoc map toi `sqli_api`, chi request search cua session do vao SQLi honeypot; markdown preview, ping va fetch van di real backend trong normal-first mode.

Luu y:

- Gateway hien la HTTP-only theo scope Web cua do an hien tai.
- Control plane khong nam tren request path; no chi cap nhat map bat dong bo.
- `EXPOSURE_MODE=attack` cat block Stats UI khoi HAProxy config runtime; admin socket van duoc giu trong container de routing controller cap nhat map.
