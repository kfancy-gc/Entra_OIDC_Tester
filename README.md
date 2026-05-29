## Install prerequisite
bash  
pip install requests msal

## Run
bash  
python entra_oidc_tester.py

## What the app does
- Configuration panel (left) — Enter your Entra ID details: Tenant ID, Client ID, Client Secret, Redirect URI, Scopes, and callback port. Settings are saved automatically to ~/.entra_oidc_tester.json between sessions.  
- Three auth flows you can choose between:  
  - Authorization Code + PKCE — Best for public clients (no secret needed, most secure)  
  - Authorization Code + Client Secret — For confidential clients  
  - Client Credentials — For machine-to-machine (service-to-service), no user login

- Login flow — Opens your browser to the Entra ID login page, starts a local HTTP server on your configured port to catch the callback, then exchanges the code for tokens automatically.  
- Result panel (right) — Shows the decoded ID Token, raw Access Token, and UserInfo endpoint response in separate tabs. JWT payloads are automatically decoded for easy inspection.  
- Logout — Clears local token state and opens the Entra ID logout URL in your browser.
  
Entra ID setup reminder: Make sure http://localhost:8765/callback (or whatever port you use) is listed as an allowed Redirect URI in your app registration under Authentication → Platform configurations.  
