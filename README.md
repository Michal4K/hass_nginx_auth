# Nginx Auth Home Assistant Component

This is a Home Assistant component that provides authentication for the `nginx_auth` module using Home Assistant (HA) user sessions. It validates HA session tokens and generates new tokens for authorized users.

Using this code is like going on a blind date... you might hit it off and have a great time, or you might end up wishing you'd stayed home and watched paint dry

## Features

- Validates Home Assistant session tokens
- Generates new tokens for authorized users
- Serves an HTML/JS file for extracting Home Assistant session tokens

## Installation

1. Clone or download this repository.
2. Copy the `nginx_auth` folder into the `custom_components` folder in your Home Assistant configuration directory.
3. Add the following configuration to your `configuration.yaml` file:

```yaml
nginx_auth:
  - service: <service>
    users:
      - <user1>
      - <user2>
      ...
```

Replace `<service>` with the service identifier (e.g., domain name) and `<user1>, <user2>, ...` with the authorized Home Assistant usernames.

## Usage

The component exposes two endpoints:

1. `/nginx_auth/auth`: Handles the validation of session tokens and generation of new tokens for authorized users.
2. `/nginx_auth/get_access_token`: Serves an HTML/JS file to extract the Home Assistant session token.

Use these endpoints in your Nginx configuration to authenticate users. For example:

```conf
location / {
    auth_request /nginx_auth/auth;
    error_page 401 = 302 "https://<home_assistant_ip>:<home_assistant_port>/nginx_auth/get_access_token?X-Original-URI=https://${host}${re
quest_uri}&X-Original-HOST=${host}";
    ...
}

location /nginx_auth/auth {
    internal;
    proxy_pass https://<home_assistant_ip>:<home_assistant_port>/nginx_auth/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI "https://${host}${request_uri}";
}

location /nginx_auth/get_access_token {
    proxy_pass https://<home_assistant_ip>:<home_assistant_port>/nginx_auth/get_access_token;
}

location /set_auth_cookie {
    add_header Set-Cookie "auth_token=${arg_auth_token}";
    add_header 'Access-Control-Allow-Origin' "*";
    default_type application/xml;
    return 200;
}

```

## License
**Unlicense** - I've done my part, now it's your problem.
