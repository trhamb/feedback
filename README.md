SSW Feedback

## PIN protection

The hub (home page, Manual Feedback, and Generate Feedback Link) is protected by a PIN so only your team can access those options. Recipients of generated event links do **not** need the PIN—they can submit feedback using the link you send them.

- Set the PIN with the `FEEDBACK_HUB_PIN` environment variable (default for development is `1234`).
- After entering the correct PIN, access is remembered for 24 hours via a secure cookie.
- To change the PIN, set a new `FEEDBACK_HUB_PIN` and restart the server.
