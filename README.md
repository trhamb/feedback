# SSW Feedback

A simple app to easily collect feedback after SSW events.

***Features:***
- Manual Feedback: A simple screen where a user can submit a feedback score and optional comment consecutively.
- Generate Feedback Link - Input an event name to create a custom url to send out to a mailing list. Recipients of the link can then submit feedback remotely.
- Staff dashboard: Login protected dashboard for staff to view and retrieve submitted feedback. Admins can manage users (add, edit roles) and create API keys for programmatic access (e.g. Power Automate, SharePoint).


## Management
Should one need a refresher on how this is set-up:

### Configuration (LINK_SECRET)
The app needs a secret for signing feedback links and staff sessions. **In production the server will not start without it.**

**Option A – `.env` file (recommended)**  
On the server, create `server/.env` (copy from `server/.env.example`). Add a line:
```bash
LINK_SECRET=your-generated-secret-here
```
Generate a value with:  
`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

**Option B – PM2 / process manager**  
Set the variable when starting the process, e.g. with PM2 ecosystem:
```javascript
env: { LINK_SECRET: 'your-generated-secret-here', NODE_ENV: 'production' }
```
Or in the shell before starting: `export LINK_SECRET=...` then `pm2 start ...`

### Running the app
```
cd server
npm install
npm start
```

At the time of writing, this is kept running as a process using `pm2`.

`pm2 start index.js --name name`
`pm2 status name`

### Access
The app is made available via nginx.

### Updating
Should changes be made externally to the application:

Once changes are pushed to the repo, pull to the server. 
```
npm ci --omit=dev
pm2 restart name
```





