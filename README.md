# Banking App OAuth Documentation

## Overview

Banking App OAuth allows third-party applications to securely authenticate users and access their Banking App data. This guide will help you integrate "Login with Banking App" into your application.

## Table of Contents

1. [Getting Started](#getting-started)
2. [OAuth Flow](#oauth-flow)
3. [API Reference](#api-reference)
4. [Available Scopes](#available-scopes)
5. [Implementation Examples](#implementation-examples)
6. [Best Practices](#best-practices)
7. [Error Handling](#error-handling)
8. [FAQ](#faq)

---

## Getting Started

### 1. Register Your Application

Before you can use Banking App OAuth, you need to register your application:

1. Contact a Banking App administrator to request OAuth client credentials
2. Provide the following information:
   - **Application Name** - The name users will see during authorization
   - **Description** - A brief description of your application
   - **Redirect URIs** - The URLs where users will be redirected after authorization
   - **Required Scopes** - What data your application needs access to
   - **Logo URL** (optional) - Your application's logo

### 2. Receive Your Credentials

After approval, you'll receive:

- **Client ID** - A public identifier for your application
- **Client Secret** - A secret key (keep this secure!)

> ⚠️ **Important**: The client secret is only shown once. Store it securely and never expose it in client-side code.

### 3. Configure Your Application

Store your credentials securely, preferably as environment variables:

```env
BANKING_APP_CLIENT_ID=your_client_id_here
BANKING_APP_CLIENT_SECRET=your_client_secret_here
BANKING_APP_REDIRECT_URI=https://yourapp.com/auth/callback
```

---

## OAuth Flow

Banking App uses the standard **OAuth 2.0 Authorization Code** flow:

```
┌──────────┐                                   ┌──────────────┐
│          │                                   │              │
│   User   │                                   │  Your App    │
│          │                                   │              │
└────┬─────┘                                   └──────┬───────┘
     │                                                │
     │ 1. User clicks "Login with Banking App"        │
     │ ◄──────────────────────────────────────────────┤
     │                                                │
     │ 2. Redirect to Banking App authorization       │
     ├───────────────────────────────────────────────►│
     │                                                │
     │                                   ┌────────────┴────────────┐
     │                                   │                         │
     │                                   │    Banking App          │
     │                                   │    Authorization        │
     │                                   │    Server               │
     │                                   │                         │
     │                                   └────────────┬────────────┘
     │                                                │
     │ 3. User logs in & approves permissions         │
     │ ◄──────────────────────────────────────────────┤
     │                                                │
     │ 4. Redirect back with authorization code       │
     ├───────────────────────────────────────────────►│
     │                                                │
     │                                                │ 5. Exchange code for tokens
     │                                                ├─────────────────────────────►
     │                                                │
     │                                                │ 6. Receive access_token
     │                                                │◄─────────────────────────────
     │                                                │
     │                                                │ 7. Fetch user data
     │                                                ├─────────────────────────────►
     │                                                │
     │ 8. User is logged in                           │
     │ ◄──────────────────────────────────────────────┤
     │                                                │
```

### Step-by-Step

1. **Initiate Authorization** - Redirect the user to the Banking App authorization URL
2. **User Authenticates** - User logs in (if needed) and reviews the permissions
3. **User Approves** - User clicks "Authorize" to grant access
4. **Receive Code** - User is redirected back to your app with an authorization code
5. **Exchange Code** - Your server exchanges the code for access and refresh tokens
6. **Access Data** - Use the access token to fetch user data from the API

---

## API Reference

### Base URL

```
https://api.acemavie.eu/bankingapp
```

### Endpoints

#### 1. Authorization Endpoint

Redirect users here to start the OAuth flow.

```
GET /oauth/authorize
```

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | Your application's client ID |
| `redirect_uri` | Yes | Must match a registered redirect URI |
| `scope` | No | Space-separated list of scopes (default: `profile`) |
| `state` | Yes | Random string to prevent CSRF attacks |

**Example:**

```
https://api.acemavie.eu/bankingapp/oauth/authorize?
  response_type=code&
  client_id=abc123&
  redirect_uri=https://yourapp.com/auth/callback&
  scope=profile%20balance:read&
  state=xyz789
```

**Successful Response:**

User is redirected to your `redirect_uri` with:

```
https://yourapp.com/auth/callback?code=AUTH_CODE_HERE&state=xyz789
```

**Error Response:**

```
https://yourapp.com/auth/callback?error=access_denied&state=xyz789
```

---

#### 2. Token Endpoint

Exchange the authorization code for tokens.

```
POST /oauth/token
```

**Headers:**

```
Content-Type: application/x-www-form-urlencoded
```

**Body Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `authorization_code` or `refresh_token` |
| `code` | Yes* | The authorization code (for `authorization_code` grant) |
| `redirect_uri` | Yes* | Must match the original redirect URI |
| `refresh_token` | Yes* | The refresh token (for `refresh_token` grant) |
| `client_id` | Yes | Your application's client ID |
| `client_secret` | Yes | Your application's client secret |

*Required depending on grant type

**Example Request (Authorization Code):**

```bash
curl -X POST https://api.acemavie.eu/bankingapp/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=https://yourapp.com/auth/callback" \
  -d "client_id=abc123" \
  -d "client_secret=your_secret"
```

**Alternative: Basic Authentication**

You can also send credentials via HTTP Basic Auth:

```bash
curl -X POST https://api.acemavie.eu/bankingapp/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=https://yourapp.com/auth/callback"
```

**Successful Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJl...",
  "scope": "profile balance:read"
}
```

---

#### 3. Refresh Token

Get a new access token using a refresh token.

```
POST /oauth/token
```

**Example Request:**

```bash
curl -X POST https://api.acemavie.eu/bankingapp/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=dGhpcyBpcyBhIHJlZnJl..." \
  -d "client_id=abc123" \
  -d "client_secret=your_secret"
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "bmV3IHJlZnJlc2ggdG9r...",
  "scope": "profile balance:read"
}
```

> **Note**: Refresh tokens are rotated on each use. The old refresh token becomes invalid.

---

#### 4. User Info Endpoint

Fetch information about the authenticated user.

```
GET /oauth/userinfo
```

**Headers:**

```
Authorization: Bearer ACCESS_TOKEN_HERE
```

**Example Request:**

```bash
curl https://api.acemavie.eu/bankingapp/oauth/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

**Response:**

The response includes data based on the granted scopes:

```json
{
  "sub": "123456789012345678",
  "username": "PlayerOne",
  "displayname": "Player One",
  "avatar_url": "https://cdn.discordapp.com/avatars/...",
  "created_at": "2024-01-15T10:30:00.000Z",
  "balance": 15000,
  "stock_portfolio": [
    {
      "symbol": "ACME",
      "company_name": "Acme Corporation",
      "amount_owned": 100,
      "last_price": 50.00
    }
  ],
  "recent_transactions": [
    {
      "id": 1234,
      "sender_id": "123456789012345678",
      "receiver_id": "987654321098765432",
      "amount": 500,
      "timestamp": "2024-01-20T14:25:00.000Z",
      "note": "Payment for services"
    }
  ]
}
```

---

#### 5. Token Revocation

Revoke an access or refresh token.

```
POST /oauth/revoke
```

**Body Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `token` | Yes | The token to revoke |
| `token_type_hint` | No | `access_token` or `refresh_token` |
| `client_id` | Yes | Your application's client ID |
| `client_secret` | Yes | Your application's client secret |

**Example Request:**

```bash
curl -X POST https://api.acemavie.eu/bankingapp/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGciOiJIUzI1NiIs..." \
  -d "token_type_hint=access_token" \
  -d "client_id=abc123" \
  -d "client_secret=your_secret"
```

**Response:**

```json
{}
```

> **Note**: This endpoint always returns 200 OK, even if the token was already invalid.

---

## Available Scopes

Request only the scopes your application needs. Users will see exactly what permissions you're requesting.

### Basic Scopes

| Scope | Description | Data Returned |
|-------|-------------|---------------|
| `profile` | Basic profile information | `username`, `displayname`, `avatar_url`, `created_at` |
| `profile:full` | Full profile including MC username | All of `profile` plus `mcusername` |

### Financial Scopes (Read-Only)

| Scope | Description | Data Returned |
|-------|-------------|---------------|
| `balance:read` | View diamond balance | `balance` |
| `chips:read` | View casino chips balance | `chips_balance` |
| `transactions:read` | View transaction history | `recent_transactions` (last 50) |
| `autopayments:read` | View scheduled payments | `autopayments` |

### Stock Market Scopes

| Scope | Description | Data Returned |
|-------|-------------|---------------|
| `stocks:read` | View stock portfolio | `stock_portfolio` |
| `orders:read` | View open stock orders | `open_orders` |

### Other Scopes

| Scope | Description | Data Returned |
|-------|-------------|---------------|
| `resources:read` | View resource inventory | `resources` |
| `timemarket:read` | View time market listings | `time_listings`, `time_owned` |
| `court:read` | View court cases | `court_cases`, `court_role` |
| `contracts:read` | View contracts | `contracts` |
| `games:read` | View game statistics | `game_stats` |

### Write Scopes (High Risk)

| Scope | Description | Actions Allowed |
|-------|-------------|-----------------|
| `balance:transfer` | Transfer diamonds | Send diamonds on behalf of the user |
| `stocks:trade` | Trade stocks | Buy/sell stocks on behalf of the user |

> ⚠️ **Warning**: Write scopes allow your application to perform actions on behalf of users. These require additional approval and users will see a warning during authorization.

---

## Implementation Examples

### JavaScript / Node.js

```javascript
// config.js
const OAUTH_CONFIG = {
  clientId: process.env.BANKING_APP_CLIENT_ID,
  clientSecret: process.env.BANKING_APP_CLIENT_SECRET,
  redirectUri: process.env.BANKING_APP_REDIRECT_URI,
  authorizationUrl: 'https://api.acemavie.eu/bankingapp/oauth/authorize',
  tokenUrl: 'https://api.acemavie.eu/bankingapp/oauth/token',
  userInfoUrl: 'https://api.acemavie.eu/bankingapp/oauth/userinfo',
};

module.exports = OAUTH_CONFIG;
```

```javascript
// routes/auth.js
const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const config = require('./config');

const router = express.Router();

// Step 1: Redirect to Banking App
router.get('/login', (req, res) => {
  // Generate a random state for CSRF protection
  const state = crypto.randomBytes(16).toString('hex');
  
  // Store state in session for verification
  req.session.oauthState = state;
  
  // Build authorization URL
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: 'profile balance:read',
    state: state,
  });
  
  res.redirect(`${config.authorizationUrl}?${params}`);
});

// Step 2: Handle the callback
router.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;
  
  // Check for errors
  if (error) {
    return res.redirect(`/login?error=${error}`);
  }
  
  // Verify state to prevent CSRF
  if (state !== req.session.oauthState) {
    return res.redirect('/login?error=invalid_state');
  }
  
  // Clear the state
  delete req.session.oauthState;
  
  try {
    // Step 3: Exchange code for tokens
    const tokenResponse = await axios.post(config.tokenUrl, 
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: config.redirectUri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );
    
    const { access_token, refresh_token, expires_in } = tokenResponse.data;
    
    // Step 4: Fetch user info
    const userResponse = await axios.get(config.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });
    
    const user = userResponse.data;
    
    // Step 5: Create session or JWT for your app
    req.session.user = {
      id: user.sub,
      username: user.username,
      avatar: user.avatar_url,
      balance: user.balance,
    };
    
    // Store tokens securely (e.g., encrypted in database)
    req.session.tokens = {
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: Date.now() + (expires_in * 1000),
    };
    
    res.redirect('/dashboard');
    
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.redirect('/login?error=auth_failed');
  }
});

// Utility: Refresh the access token
async function refreshAccessToken(refreshToken) {
  const response = await axios.post(config.tokenUrl,
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );
  
  return response.data;
}

// Logout
router.get('/logout', async (req, res) => {
  // Optionally revoke the token
  if (req.session.tokens?.accessToken) {
    try {
      await axios.post('https://api.acemavie.eu/bankingapp/oauth/revoke',
        new URLSearchParams({
          token: req.session.tokens.accessToken,
          client_id: config.clientId,
          client_secret: config.clientSecret,
        })
      );
    } catch (err) {
      // Ignore revocation errors
    }
  }
  
  req.session.destroy();
  res.redirect('/');
});

module.exports = router;
```

### Next.js (App Router)

```typescript
// lib/bankingOAuth.ts
const config = {
  clientId: process.env.BANKING_APP_CLIENT_ID!,
  clientSecret: process.env.BANKING_APP_CLIENT_SECRET!,
  redirectUri: process.env.BANKING_APP_REDIRECT_URI!,
  authorizationUrl: 'https://api.acemavie.eu/bankingapp/oauth/authorize',
  tokenUrl: 'https://api.acemavie.eu/bankingapp/oauth/token',
  userInfoUrl: 'https://api.acemavie.eu/bankingapp/oauth/userinfo',
};

export function getAuthorizationUrl(state: string): string {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: 'profile balance:read stocks:read',
    state,
  });
  
  return `${config.authorizationUrl}?${params}`;
}

export async function exchangeCodeForTokens(code: string) {
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
  });
  
  if (!response.ok) {
    throw new Error('Token exchange failed');
  }
  
  return response.json();
}

export async function getUserInfo(accessToken: string) {
  const response = await fetch(config.userInfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });
  
  if (!response.ok) {
    throw new Error('Failed to fetch user info');
  }
  
  return response.json();
}

export async function refreshToken(refreshToken: string) {
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret,
    }),
  });
  
  if (!response.ok) {
    throw new Error('Token refresh failed');
  }
  
  return response.json();
}
```

```typescript
// app/auth/login/route.ts
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getAuthorizationUrl } from '@/lib/bankingOAuth';

export async function GET() {
  // Generate state for CSRF protection
  const state = crypto.randomUUID();
  
  // Store state in a cookie
  cookies().set('oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 60 * 10, // 10 minutes
  });
  
  const authUrl = getAuthorizationUrl(state);
  return NextResponse.redirect(authUrl);
}
```

```typescript
// app/auth/callback/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { exchangeCodeForTokens, getUserInfo } from '@/lib/bankingOAuth';

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const code = searchParams.get('code');
  const state = searchParams.get('state');
  const error = searchParams.get('error');
  
  // Check for errors
  if (error) {
    return NextResponse.redirect(new URL(`/login?error=${error}`, request.url));
  }
  
  // Verify state
  const storedState = cookies().get('oauth_state')?.value;
  if (!state || state !== storedState) {
    return NextResponse.redirect(new URL('/login?error=invalid_state', request.url));
  }
  
  // Clear state cookie
  cookies().delete('oauth_state');
  
  if (!code) {
    return NextResponse.redirect(new URL('/login?error=no_code', request.url));
  }
  
  try {
    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(code);
    
    // Get user info
    const user = await getUserInfo(tokens.access_token);
    
    // Store session (use your preferred session management)
    cookies().set('session', JSON.stringify({
      user: {
        id: user.sub,
        username: user.username,
        avatar: user.avatar_url,
      },
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + (tokens.expires_in * 1000),
    }), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 30, // 30 days
    });
    
    return NextResponse.redirect(new URL('/dashboard', request.url));
    
  } catch (err) {
    console.error('OAuth callback error:', err);
    return NextResponse.redirect(new URL('/login?error=auth_failed', request.url));
  }
}
```

### Python (Flask)

```python
# config.py
import os

OAUTH_CONFIG = {
    'client_id': os.environ.get('BANKING_APP_CLIENT_ID'),
    'client_secret': os.environ.get('BANKING_APP_CLIENT_SECRET'),
    'redirect_uri': os.environ.get('BANKING_APP_REDIRECT_URI'),
    'authorization_url': 'https://api.acemavie.eu/bankingapp/oauth/authorize',
    'token_url': 'https://api.acemavie.eu/bankingapp/oauth/token',
    'userinfo_url': 'https://api.acemavie.eu/bankingapp/oauth/userinfo',
}
```

```python
# app.py
from flask import Flask, redirect, request, session, url_for
import requests
import secrets
from config import OAUTH_CONFIG

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/login')
def login():
    # Generate state for CSRF protection
    state = secrets.token_hex(16)
    session['oauth_state'] = state
    
    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id': OAUTH_CONFIG['client_id'],
        'redirect_uri': OAUTH_CONFIG['redirect_uri'],
        'scope': 'profile balance:read',
        'state': state,
    }
    
    auth_url = f"{OAUTH_CONFIG['authorization_url']}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # Check for errors
    error = request.args.get('error')
    if error:
        return redirect(f'/login?error={error}')
    
    # Verify state
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return redirect('/login?error=invalid_state')
    
    # Clear state
    session.pop('oauth_state', None)
    
    code = request.args.get('code')
    if not code:
        return redirect('/login?error=no_code')
    
    try:
        # Exchange code for tokens
        token_response = requests.post(
            OAUTH_CONFIG['token_url'],
            data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': OAUTH_CONFIG['redirect_uri'],
                'client_id': OAUTH_CONFIG['client_id'],
                'client_secret': OAUTH_CONFIG['client_secret'],
            }
        )
        token_response.raise_for_status()
        tokens = token_response.json()
        
        # Get user info
        user_response = requests.get(
            OAUTH_CONFIG['userinfo_url'],
            headers={'Authorization': f"Bearer {tokens['access_token']}"}
        )
        user_response.raise_for_status()
        user = user_response.json()
        
        # Store in session
        session['user'] = {
            'id': user['sub'],
            'username': user['username'],
            'avatar': user.get('avatar_url'),
            'balance': user.get('balance'),
        }
        session['tokens'] = {
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
        }
        
        return redirect('/dashboard')
        
    except Exception as e:
        print(f'OAuth error: {e}')
        return redirect('/login?error=auth_failed')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
```

### PHP

```php
<?php
// config.php
return [
    'client_id' => getenv('BANKING_APP_CLIENT_ID'),
    'client_secret' => getenv('BANKING_APP_CLIENT_SECRET'),
    'redirect_uri' => getenv('BANKING_APP_REDIRECT_URI'),
    'authorization_url' => 'https://api.acemavie.eu/bankingapp/oauth/authorize',
    'token_url' => 'https://api.acemavie.eu/bankingapp/oauth/token',
    'userinfo_url' => 'https://api.acemavie.eu/bankingapp/oauth/userinfo',
];
```

```php
<?php
// login.php
session_start();
$config = require 'config.php';

// Generate state for CSRF protection
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;

// Build authorization URL
$params = http_build_query([
    'response_type' => 'code',
    'client_id' => $config['client_id'],
    'redirect_uri' => $config['redirect_uri'],
    'scope' => 'profile balance:read',
    'state' => $state,
]);

header("Location: {$config['authorization_url']}?{$params}");
exit;
```

```php
<?php
// callback.php
session_start();
$config = require 'config.php';

// Check for errors
if (isset($_GET['error'])) {
    header("Location: /login?error=" . $_GET['error']);
    exit;
}

// Verify state
if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['oauth_state']) {
    header("Location: /login?error=invalid_state");
    exit;
}

unset($_SESSION['oauth_state']);

$code = $_GET['code'] ?? null;
if (!$code) {
    header("Location: /login?error=no_code");
    exit;
}

try {
    // Exchange code for tokens
    $ch = curl_init($config['token_url']);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $config['redirect_uri'],
        'client_id' => $config['client_id'],
        'client_secret' => $config['client_secret'],
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $tokens = json_decode($response, true);
    
    if (!isset($tokens['access_token'])) {
        throw new Exception('Token exchange failed');
    }
    
    // Get user info
    $ch = curl_init($config['userinfo_url']);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer {$tokens['access_token']}"
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    
    $user = json_decode($response, true);
    
    // Store in session
    $_SESSION['user'] = [
        'id' => $user['sub'],
        'username' => $user['username'],
        'avatar' => $user['avatar_url'] ?? null,
        'balance' => $user['balance'] ?? null,
    ];
    $_SESSION['tokens'] = [
        'access_token' => $tokens['access_token'],
        'refresh_token' => $tokens['refresh_token'],
    ];
    
    header("Location: /dashboard");
    exit;
    
} catch (Exception $e) {
    error_log("OAuth error: " . $e->getMessage());
    header("Location: /login?error=auth_failed");
    exit;
}
```

---

## Best Practices

### Security

1. **Always use HTTPS** - Never transmit tokens over unencrypted connections
2. **Validate the state parameter** - This prevents CSRF attacks
3. **Store client secret securely** - Never expose it in client-side code
4. **Use short-lived access tokens** - Refresh them as needed
5. **Implement token refresh** - Don't require users to re-authenticate frequently
6. **Revoke tokens on logout** - Clean up when users sign out

### User Experience

1. **Request minimal scopes** - Only ask for what you need
2. **Explain why** - Tell users why your app needs certain permissions
3. **Handle errors gracefully** - Provide clear error messages
4. **Support account disconnection** - Let users revoke access from your app

### Token Management

1. **Store tokens securely** - Use encrypted storage, never localStorage for sensitive tokens
2. **Refresh proactively** - Refresh tokens before they expire
3. **Handle token expiration** - Gracefully handle 401 errors
4. **Implement token rotation** - Update stored refresh tokens after each refresh

---

## Error Handling

### Authorization Errors

| Error | Description | Solution |
|-------|-------------|----------|
| `invalid_request` | Missing or invalid parameters | Check all required parameters |
| `invalid_client` | Client ID not found or inactive | Verify your client ID |
| `invalid_redirect_uri` | Redirect URI not registered | Use an exact registered URI |
| `invalid_scope` | Requested scope not allowed | Request only allowed scopes |
| `access_denied` | User denied the authorization | Handle gracefully in your UI |

### Token Errors

| Error | Description | Solution |
|-------|-------------|----------|
| `invalid_grant` | Code expired or already used | Codes are single-use and expire in 10 minutes |
| `invalid_client` | Invalid client credentials | Verify client ID and secret |
| `unsupported_grant_type` | Invalid grant_type | Use `authorization_code` or `refresh_token` |

### API Errors

| Status | Error | Description |
|--------|-------|-------------|
| 401 | `unauthorized` | Missing or invalid access token |
| 401 | `invalid_token` | Token expired or revoked |
| 403 | `insufficient_scope` | Token doesn't have required scope |

### Example Error Handling

```javascript
async function fetchUserData(accessToken) {
  try {
    const response = await fetch('https://api.acemavie.eu/bankingapp/oauth/userinfo', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
    
    if (response.status === 401) {
      // Token expired - try to refresh
      const newTokens = await refreshAccessToken();
      return fetchUserData(newTokens.access_token);
    }
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error_description || error.error);
    }
    
    return response.json();
    
  } catch (error) {
    console.error('API Error:', error);
    throw error;
  }
}
```

---

## FAQ

### How long do tokens last?

- **Access tokens**: 1 hour
- **Refresh tokens**: 30 days
- **Authorization codes**: 10 minutes (single use)

### Can users revoke access?

Yes, users can revoke your application's access at any time from their Banking App settings. Your application should handle this gracefully by catching 401 errors and prompting users to re-authenticate.

### What happens if my client secret is compromised?

Contact a Banking App administrator immediately to regenerate your client secret. All existing tokens will be revoked when the secret is changed.

### Can I request additional scopes later?

Yes, redirect the user through the authorization flow again with the additional scopes. They'll only see a consent screen for the new scopes.

### Do users see a consent screen every time?

No, if a user has already authorized your app with the requested scopes, they'll be automatically redirected back without seeing the consent screen.

### How do I test locally?

Register `http://localhost:3000/callback` (or your local port) as a redirect URI. This is allowed for development purposes.

### What user ID should I store?

Store the `sub` (subject) field from the userinfo response. This is the user's Discord ID and is guaranteed to be unique and stable.

---

## Support

If you need help with your integration:

1. Check this documentation first
2. Review the error messages - they're designed to be helpful
3. Contact a Banking App administrator for assistance
