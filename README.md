# ovpn-mng-auth
Gateway intercepts OpenVPN Management Interface authentication requests, forwards credentials to an external REST API and returns the response. Authentication logic stays outside the VPN server, enabling any backend (OTP both static and dynamic challenge) to be used.
The tool keeps authentication logic completely separate from the VPN server, enabling any backend language or framework to handle user validation.

**Key Features of the Script**
- **Management Interface client** – opens a TCP socket to the address/port defined in `config.yml` and communicates with OpenVPN using the Management Protocol.  
- **Config‑driven** – all connection parameters (`auth_url`, `auth_token`, `ovpn_mng_ip`, `ovpn_mng_port`) are read from a YAML file at startup.  
- **Input validation** – regular expressions ensure that usernames contain only allowed characters and that numeric fields are correctly parsed.  
- **Robust socket handling** – separate `_socket_send` and `_socket_recv` helpers abstract Python‑2/3 differences and log every interaction.  
- **Extensible authentication flow** – after receiving credentials the script posts them to the external API; based on the JSON reply it can request OTP, accept the login or reject it.  
- **Detailed logging** – all events (connections, successes, failures) are written to `/var/log/openvpn-auth.log` for audit and troubleshooting.  

**Example Interaction with the External API**

| Situation | Request sent by the gateway (POST) | Expected JSON response from the backend |
|-----------|-----------------------------------|------------------------------------------|
| **Successful login** | `username=alice&password=MyPass123&otp=&ip=10.0.0.5&token=YOUR_AUTH_TOKEN` | `{ "status": true,  "message": "success" }` |
| **OTP required (2‑FA)** | Same as above but the user has 2FA enabled and no OTP yet (`otp=` is empty) | `{ "status": false, "message": "otp" }` – the gateway will prompt the client for a one‑time code and resend the request with `otp=123456`. |
| **Access denied** (incorect credentials, blocked account, etc.) | Same as above with the provided credentials | `{ "status": false, "message": "incorect credentials" }` *(or other messages such as “block 1 hour”, “password expired”)* |

The gateway parses the `status` field: `true` → send `client-auth OK` to OpenVPN; `false` → if `message` equals `"otp"` it triggers the OTP challenge, otherwise it sends `client-auth DENY`.

Feel free to adapt the backend API (Node.js, Go, FastAPI, etc.) – only the request format and the two‑field JSON response are required.


In the OpenVPN server, the following line is needed to the the auth daemon work:

```
management 0.0.0.0 8080
```

For the OpenVPN client I've the following relevant lines:

```
# Don't cache credentials in virtual memory
auth-nocache

auth-user-pass
auth-retry interact
static-challenge "RSA Token" 1
```


