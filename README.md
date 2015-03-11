

### Installation
Run the following SQL queries in strict order:

```SQL
CREATE TABLE oauth2_nonce(id CHAR(36) PRIMARY KEY, created UNSIGNED BIG INT);
CREATE TABLE oauth2_token(id VARCHAR(255) PRIMARY KEY, access_token VARCHAR(255), refresh_token VARCHAR(255), resource VARCHAR(255), user_id UNSIGNED BIG INT, created UNSIGNED BIG INT, changed UNSIGNED BIG INT, ttl UNSIGNED BIG INT);
CREATE UNIQUE INDEX uidx_oauth2_token_res ON oauth2_token(resource);
CREATE INDEX idx_oauth2_token_user_id ON oauth2_token(user_id);
CREATE INDEX idx_oauth2_token_rucct ON oauth2_token(resource, user_id, created, changed, ttl);
```

### Configuration

Open your app in Google Developer Console(https://console.developers.google.com),
click APIs & auth, click Credentials, then 'Create new Client ID', pick 'Web
application'. It will generate the Client ID and Client Secret.

Add the following to settings.lua:

```Lua
settings.oauth2 = {
  nonce_ttl = 2*60, -- default: 2 minutes
  client_id = [client_id],
  client_secret = [client_secret],
}
```
