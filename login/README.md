Sidecar web service for central.artipie.com which performs GitHub authentication by calling GitHub API and encrypting username cookies:
 1. This service receives authentication code from GitHub redirect at `/auth?code=<code>`
 2. Exchanges auth code to access token using OAuth client key and secret key
 3. Authenticates user by access token and fetches GitHub username
 4. Encrypts username using RSA public key, sets session cookie, and sends redirect to user page dashboard: `/dashboard/<username>`
