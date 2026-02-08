# SSW Feedback

A simple app to easily collect feedback after SSW events.

***Features:***
- Manual Feedback: A simple screen where a user can submit a feedback score and optional comment consecutively.
- Generate Feedback Link - Input an event name to create a custom url to send out to a mailing list. Recipients of the link can then submit feedback remotely.
- Staff dashboard: Login protected dashboard for staff to be able to view and retrieve submitted feedback. Logins with admin privileges will also be able to manage users and pin protection.


## Management
Should one need a refresher on how this is set-up:

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
npm ci --omit=DEV
pm2 restart name
```





