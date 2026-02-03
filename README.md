SSW Feedback

## PIN protection

The hub (home page, Manual Feedback, and Generate Feedback Link) is protected by a PIN so only your team can access those options. Recipients of generated event links do **not** need the PIN—they can submit feedback using the link you send them.

- Set the PIN with the `FEEDBACK_HUB_PIN` environment variable (default for development is `1234`).
- After entering the correct PIN, access is remembered for 24 hours via a secure cookie.
- To change the PIN, set a new `FEEDBACK_HUB_PIN` and restart the server.

---

## Hosting (test / show people)

**Quick comparison**

| | **Hosted service (Railway, Render)** | **Your VPS** |
|---|--------------------------------------|--------------|
| **Cost** | Free tier or ~\$5/mo | You already pay for the box |
| **Effort** | Connect repo, set env vars, deploy | SSH in, install Node, run app (and optionally nginx + SSL) |
| **Best for** | Fastest way to get a URL to share | Full control, one place for multiple apps |

For “I want a link to show people quickly,” a **hosted service** is usually easiest. If you’re already comfortable on a VPS, that’s also straightforward.

### Deploy on Render

1. **Push the repo to GitHub** (if it isn’t already).

2. **Sign up / log in** at [render.com](https://render.com).

3. **New → Web Service**, then connect your GitHub account and select this repo.

4. **Configure the service:**
   - **Name:** e.g. `ssw-feedback` (your choice).
   - **Region:** pick the one closest to you.
   - **Root Directory:** set to **`server`** (so Render uses the Node app inside `server/`).
   - **Runtime:** Node.
   - **Build Command:** `npm install`
   - **Start Command:** `npm start` (runs `node index.js`).

5. **Environment variables** (Environment tab / “Add Environment Variable”):
   - **`LINK_SECRET`** – a random secret (generate one:  
     `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`).
   - **`FEEDBACK_HUB_PIN`** – the PIN to access the hub (e.g. `1234` for testing).

6. **Create Web Service.** Render will build and deploy. Your app will be at  
   `https://<your-service-name>.onrender.com`.

7. **Free tier note:** The app may spin down after inactivity; the first request after that can take 30–60 seconds. SQLite data can be lost on redeploys; fine for demos.

**Done.** Share the Render URL; visitors will hit the PIN page first, then (after entering the PIN) the Feedback Hub. Generated event links work without a PIN.

### Option B: Your VPS

1. **On the VPS** (Debian/Ubuntu example):

   ```bash
   # Install Node 20 LTS (adjust if you use a different version manager)
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. **Clone and run** (replace with your repo and paths):

   ```bash
   cd /opt   # or wherever you keep apps
   sudo git clone https://github.com/YourOrg/feedback.git
   cd feedback/server
   sudo npm install --omit=dev
   ```

3. **Environment variables** – create `/opt/feedback/server/.env`. The server loads `.env` from the `server` directory automatically:

   ```bash
   PORT=3001
   LINK_SECRET=your-secret-from-crypto-randomBytes
   FEEDBACK_HUB_PIN=your-pin
   NODE_ENV=production
   ```

4. **Run with PM2** (so it restarts on reboot and crashes):

   ```bash
   sudo npm install -g pm2
   cd /opt/feedback/server
   pm2 start index.js --name feedback-hub
   pm2 save && pm2 startup
   ```

   Then open `http://YOUR_VPS_IP:3001`. If the firewall allows port 3001, you can share that URL.

5. **Optional: nginx + HTTPS** – so you can use a domain and avoid opening 3001:

   - Point a domain (e.g. `feedback.yourdomain.com`) at the VPS.
   - Install nginx and certbot: `sudo apt install nginx certbot python3-certbot-nginx`
   - Add a server block that proxies to `http://127.0.0.1:3001` and get a cert: `sudo certbot --nginx -d feedback.yourdomain.com`

   Example minimal nginx config for that server block:

   ```nginx
   server {
       listen 80;
       server_name feedback.yourdomain.com;
       location / {
           proxy_pass http://127.0.0.1:3001;
           proxy_http_version 1.1;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

**Summary:** For “easiest low-cost way to get a link,” use **Option A** (Railway or Render). If you prefer to use your **VPS**, follow **Option B**; add nginx + certbot when you want a proper domain and HTTPS.
