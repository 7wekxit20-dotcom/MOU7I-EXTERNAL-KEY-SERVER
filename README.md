# OGIOS Key Server

Simple Flask + SQLite key system for OGIOS app.

## Run locally (Kali)
```bash
cd /home/kali/key-server
pip install -r requirements.txt
ADMIN_KEY="YourSecret123" python app.py
# open http://localhost:5000  login with ADMIN_KEY
```

## API
- `POST /api/verify` `{"key":"OGIOS-XXXX-XXXX-XXXX"}` -> `{"valid":true}` used by iOS app
- `POST /api/generate` header `X-Admin-Key: ADMIN_KEY` body `{"count":5,"days":30,"prefix":"OGIOS","max_uses":1}`
- `GET /api/keys` list, `POST /api/revoke` `{"key":"..."}`
- `GET /api/health` public

## Host publicly
**Option A - Render (free):**
1. Push this folder to GitHub `your/key-server`
2. render.com -> New Web Service -> connect repo -> Build: `pip install -r requirements.txt` Start: `gunicorn -w 2 -b 0.0.0.0:$PORT app:app` -> Env `ADMIN_KEY=...`
3. Copy URL `https://your-key-server.onrender.com` -> put in iOS app `LicenseManager.swift`

**Option B - Kali with cloudflare tunnel (instant public URL, no port forward):**
```bash
cloudflared tunnel --url http://localhost:5000
# gives https://xxxx.trycloudflare.com  -> use that as API URL
```

**Option C - VPS/Ubuntu:**
```bash
sudo apt install docker.io
docker build -t ogios-keys . && docker run -d -p 5000:5000 -e ADMIN_KEY=YourSecret123 -v /root/keys.db:/app/keys.db ogios-keys
# nginx reverse proxy -> https
```

## Connect OGIOS app
Edit `ThreeOneOSFive/helpers/LicenseManager.swift:7` or replace `activate` with API code (see patch below). Then `./build_unsigned.sh` and push to GitHub Action.

Legacy key `OGIOS` is auto-created for testing.
