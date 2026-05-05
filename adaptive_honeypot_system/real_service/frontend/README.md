# Frontend

Component nay la React UI duoc build bang Vite va serve bang Nginx.

Chuc nang:

- Render trang Home, Articles, ArticleDetail, Tools, Login.
- Goi API qua relative path `/api/*`.
- Tao `sid` cookie trong `src/api/client.js` de HAProxy co the route theo session.

File chinh:

- `src/api/client.js`: API wrapper va session cookie.
- `src/App.jsx`: routing client-side.
- `src/pages/Tools.jsx`: markdown preview, ping, URL inspector.
- `nginx.conf`: serve SPA va proxy `/api` khi frontend container duoc truy cap truc tiep.

Luu y:

- Frontend khong chua logic bao mat.
- Khi gateway route session sang honeypot, response van nen giu contract de UI khong crash.

