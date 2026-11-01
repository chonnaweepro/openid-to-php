# openid-to-php

OpenID Connect relying-party client for PHP: Authorization Code flow with PKCE, state, nonce, and checks on the access token and ID token.

ไลบรารีขนาดเล็กสำหรับใช้กับ Keycloak (ค่าเริ่มต้นของ endpoint) และ provider อื่นที่ใช้ path คล้ายกันได้ผ่าน `endpoint_prefix`

## ติดตั้ง

```bash
composer install
```

ต้องมี extension `curl`, `json`, `openssl` และ PHP 8.2 ขึ้นไป

## การใช้งาน

```php
use OpenIdToPhp\OidcConnect;

$flow = OidcConnect::create([
    'issuer' => 'https://sso.example.com/realms/app',
    'client_id' => 'app-client',
    'client_secret' => getenv('OIDC_CLIENT_SECRET'),
    'redirect_uri' => 'https://app.example.com/callback',
    'audience' => 'app-api',
    'post_logout_redirect_uri' => 'https://app.example.com/',
    'required_claims' => ['employee_id'],
    'scope' => 'openid email',
]);

// /login: เก็บ state ฝั่ง server แล้ว redirect ไป provider
header('Location: ' . $flow->startLogin(), true, 302);

// /callback: ตรวจ callback, เก็บ identity ใน session, คืนค่าเป็น array
$identity = $flow->finishLogin($_GET, ['employee_id']); // ['sub' => '...', 'employee_id' => '1234567'] หรือ throw เมื่อไม่ผ่าน
$user = $flow->currentUser();            // อ่านค่าเดิมได้ทุกครั้งในหน้าถัดไป

// /logout: ตรวจ CSRF ของฟอร์ม POST ก่อน แล้ว redirect ไป provider logout
if ($flow->verifyCsrf($_POST['csrf'] ?? null)) {
    header('Location: ' . $flow->logout());
}
```

`OidcConnect` คือจุดที่แนะนำให้ใช้ ประกอบจาก `OidcClient` (ตรวจ token) และ `OidcSession` (เก็บ state ใน namespace `oidc`) โดยไม่มี HTTP ข้างใน ส่วน `OidcClient` และ `OidcSession` ใช้แยกได้ถ้าต้องการควบคุมเอง

## ตัวอย่าง Keycloak

ไฟล์เดียว `examples/keycloak.php` มี login, callback, หน้าแรก และ logout ตั้งค่าจาก environment variables:

```bash
export OIDC_ISSUER=https://sso.example.com/realms/app
export OIDC_CLIENT_ID=app-client
export OIDC_CLIENT_SECRET=...            # ห้าม commit
export OIDC_REDIRECT_URI=http://127.0.0.1:8080/keycloak.php?action=callback
export OIDC_AUDIENCE=app-api
export OIDC_POST_LOGOUT_URI=http://127.0.0.1:8080/keycloak.php
php -S 127.0.0.1:8080 -t examples
```

เปิด `http://127.0.0.1:8080/keycloak.php` แล้วกด login

### ตั้งค่าใน Keycloak

1. **Client**: OpenID Connect, เปิด *Client authentication* (confidential), เปิด *Standard flow*, ปิด *Direct access grants*
2. **Valid redirect URIs**: ต้องตรงกับ `OIDC_REDIRECT_URI` ทุกตัวอักษร (รวม query `?action=callback`)
3. **Valid post logout redirect URIs**: ต้องตรงกับ `OIDC_POST_LOGOUT_URI`
4. **Advanced → PKCE Code Challenge Method**: `S256`
5. **Mapper: Audience** ใส่ `app-api` ใน access token (ตรงกับ `OIDC_AUDIENCE`)
6. **Mapper: User Attribute → claim** เพิ่ม `employee_id` ลง access token (ตัวอย่างนี้ require claim นี้)

ข้อควรระวัง:
- อย่าวางโฟลเดอร์ `examples/` ไว้ใน IIS web root โดยยังไม่ตรวจ `web.config` เพราะ root config ปัจจุบันมี rule ที่ทำให้ `.php` ตอบ 500
- ตัวอย่างนี้ไม่ตั้ง cookie `Secure` ถ้าใช้จริงควรเป็น HTTPS และตั้ง `Secure`

## ทดสอบ

```bash
composer test          # ต้องมี php ใน PATH (รัน run, session, flow)
php tests/run.php      # OidcClient: การตรวจ token และ scope
php tests/session_test.php   # OidcSession
php tests/flow_test.php      # OidcConnect: login, callback, logout
```

การทดสอบไม่ต่อเครือข่ายและไม่ต้องมี provider จริง ครอบคลุม state, nonce, aud, azp, sub, at_hash, expiry, required claim, alg confusion และ signature ที่ถูกแก้ไข

บน Windows PHP CLI อาจหา `openssl.cnf` ไม่เจอ ให้ตั้งค่าก่อนรัน:

```bash
export OPENSSL_CONF=/path/to/php/extras/ssl/openssl.cnf   # ใส่ path ของ openssl.cnf ที่มากับ PHP
```

## ข้อจำกัด

- รองรับเฉพาะ `RS256`
- ไม่มี discovery (`.well-known`) ต้องระบุ endpoint ผ่าน issuer และ `endpoint_prefix`
- ไม่มี refresh token, userinfo, JWE และ back-channel logout
- `CurlTransport` ยังไม่ได้ทดสอบกับ provider จริงใน library นี้โดยตรง
