# Ophal OAuth2 module

## Installation

### Google

Run the following SQL queries in strict order:

```SQL
-- SQLite3
CREATE TABLE oauth2_google_nonce(id CHAR(36) PRIMARY KEY, created UNSIGNED BIG INT);
CREATE TABLE oauth2_google_token(id VARCHAR(255) PRIMARY KEY, access_token VARCHAR(255), refresh_token VARCHAR(255), resource VARCHAR(255), user_id UNSIGNED BIG INT, created UNSIGNED BIG INT, changed UNSIGNED BIG INT, ttl UNSIGNED BIG INT);
CREATE UNIQUE INDEX uidx_oauth2_google_token_ru ON oauth2_google_token(resource, user_id);
CREATE INDEX idx_oauth2_google_token_user_id ON oauth2_google_token(user_id);
CREATE INDEX idx_oauth2_google_token_rucct ON oauth2_google_token(resource, user_id, created, changed, ttl);
CREATE TABLE oauth2_google_users(g_id CHAR(21), user_id UNSIGNED BIG INT, created UNSIGNED BIG INT);
CREATE UNIQUE INDEX uidx_oauth2_token_gu ON oauth2_google_users(g_id, user_id);
```

```SQL
-- PostgreSQL
CREATE TABLE oauth2_google_nonce(id char (36) PRIMARY KEY NOT NULL, created bigint NOT NULL);
CREATE TABLE oauth2_google_token(id varchar(255) PRIMARY KEY NOT NULL, access_token varchar(255), refresh_token varchar(255), resource varchar(255), user_id BIGINT NOT NULL, created BIGINT NOT NULL, changed BIGINT NOT NULL, ttl BIGINT NOT NULL);
CREATE UNIQUE INDEX uidx_oauth2_google_token_ru ON oauth2_google_token USING btree (resource COLLATE pg_catalog."default", user_id);
CREATE INDEX idx_oauth2_google_token_user_id ON oauth2_google_token USING btree (user_id);
CREATE INDEX idx_oauth2_google_token_rucct ON oauth2_google_token USING btree (resource COLLATE pg_catalog."default", user_id, created, changed, ttl);
CREATE TABLE oauth2_google_users(g_id CHAR(21) NOT NULL, user_id BIGINT NOT NULL, created BIGINT NOT NULL);
CREATE UNIQUE INDEX uidx_oauth2_token_gu ON oauth2_google_users USING btree (g_id, user_id);
```

### Facebook

Run the following SQL queries in strict order:

```SQL
-- SQLite3
CREATE TABLE oauth2_facebook_nonce(id CHAR(36) PRIMARY KEY, created UNSIGNED BIG INT);
CREATE TABLE oauth2_facebook_users(fb_id UNSIGNED BIG INT, user_id UNSIGNED BIG INT, created UNSIGNED BIG INT);
CREATE UNIQUE INDEX uidx_oauth2_token_fu ON oauth2_facebook_users(fb_id, user_id);
```

```SQL
-- PostgreSQL
CREATE TABLE oauth2_facebook_nonce(id char (36) PRIMARY KEY NOT NULL, created bigint NOT NULL);
CREATE TABLE oauth2_facebook_users(fb_id BIGINT NOT NULL, user_id BIGINT NOT NULL, created BIGINT NOT NULL);
CREATE UNIQUE INDEX uidx_oauth2_token_fu ON oauth2_facebook_users USING btree (fb_id, user_id);
```

## Configuration

Open your app in Google Developer Console(https://console.developers.google.com),
click APIs & auth, click Credentials, then 'Create new Client ID', pick 'Web
application'. It will generate the Client ID and Client Secret.

Add the following to settings.lua:

```Lua
settings.oauth2 = {
  google = {
    client_id = [g_client_id],
    client_secret = [g_client_secret],
    nonce_ttl = 2*60, -- default: 2 minutes
    api_version = 'v4', -- default
  },
  facebook = {
    client_id = [fb_client_id],
    client_secret = [fb_client_secret],
  },
}
```

## Credits

Facebook support is inspired on the wonderful [fboauth](https://www.drupal.org/project/fboauth) Drupal module
by Nate Haug (quicksketch).
