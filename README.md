# User

`src/main/resources/data.sql` initializes the `USER`, `MODERATOR`, and `ADMIN` roles and
seeds development accounts with BCrypt-encoded passwords. Sign in with `POST /auth/signin`
using JSON `{"username":"admin","password":"Admin123!"}` (or `moderator` / `Moderator123!`,
`user` / `User123!`, `alice` / `Alice123!`, or `bob` / `Bob123!`). The script inserts
missing accounts and role links on startup; edit the script to change the sample accounts.

## Controller endpoints

The backend runs at `http://localhost:8082`. Protected user endpoints require
`Authorization: Bearer <JWT>` from `/auth/signin`.

| Method | URL | Parameters / body | Access |
|---|---|---|---|
| GET | `/userdetails?name={name}` | Optional `name`; defaults to `Welcome to user controller` | Authenticated |
| GET | `/userdetails/getuser/{id}` | User ID in path | Authenticated |
| GET | `/userdetails/getuser?userid={id}` | Required `userid` | Authenticated |
| POST | `/userdetails/saveuser` | JSON `User` | Authenticated |
| POST | `/userdetails/getuser` | JSON `Input` with `lastName` | Authenticated |
| GET | `/userdetails/getuserslastnameMatch?lastNameContains={text}` | Required `lastNameContains` | Authenticated |
| POST | `/userdetails/saveallusers` | JSON array of `User` objects | Authenticated |
| GET | `/userdetails/removeallusers` | — | Admin |
| GET | `/pagination?name={name}` | Optional `name`; defaults to `Consumer` | Admin or moderator |
| GET | `/pagination/users?page={page}&size={size}` | `page` defaults to `0`; `size` defaults to `3` | Admin or moderator |
| POST | `/auth/signin` | JSON `{"username":"admin","password":"Admin123!"}` | Public |
| POST | `/auth/signup` | JSON `SignupRequest` (`username`, `email`, `password`, optional `role` array: `user`, `mod`, or `admin`; defaults to `user`) | Moderator or admin |
| GET | `/public/health` | — | Public; returns `{"status":"UP"}` when the application is running |
| GET | `/saml/login` | — | Public; begins SAML sign-in |
| GET | `/saml/profile-data?ticket={ticket}` | One-time profile ticket | Public; ticket required |
| GET | `/saml2/metadata/{registrationId}` | Registration ID defaults to `zitadel` | Public |

## Angular browser access

Shared configuration is in `application.properties`; the `local` and `prod` profiles
override it with environment-specific frontend and SAML URLs. By default, the `local`
profile is active. Select the environment with `SPRING_PROFILES_ACTIVE=local` or
`SPRING_PROFILES_ACTIVE=prod`; add optional profiles with the comma-separated
`SPRING_PROFILES_INCLUDE` variable, for example `SPRING_PROFILES_INCLUDE=feign`.
Add an `application-feign.properties` file for configuration that should be active whenever
`feign` is included. Local CORS allows
`http://localhost:4200` and
`https://localhost:4200`; production allows `https://venuchalla.github.io` (the
`/users-app-angular` path is not part of an origin). Override
`APP_CORS_ALLOWED_ORIGINS` to use different browser origins. The Angular app must also use
the backend's reachable URL for its API requests; CORS does not host or proxy the backend.

For GitHub Pages, run the backend with `SPRING_PROFILES_ACTIVE=prod`. Set
`SAML_SP_ENTITY_ID`, `SAML_ACS_URL`, and `SAML_SLO_URL` to the production service-provider
entity ID and the backend's publicly reachable SAML assertion-consumer and single-logout
endpoints. Defaults use the documented Cloud Run URL
`https://user-api-766984687989.us-central1.run.app`; override them if deploying elsewhere.
Configure the same entity ID and callback URLs in the IdP, or import the deployed SP metadata
from `/saml2/metadata/zitadel`. The production profile redirects the browser to the Angular app at
`https://venuchalla.github.io/users-app-angular`; GitHub Pages itself cannot receive the
backend's SAML POST callbacks.

In production, the SP certificate and private key are loaded from Secret Manager resources
`projects/766984687989/secrets/saml-certificate` and
`projects/766984687989/secrets/saml-private-key` (latest enabled versions). Grant the Cloud Run
service account `roles/secretmanager.secretAccessor` on both secrets. Store the certificate as
PEM and the private key as an unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`). Local configuration
continues to use the classpath defaults; override the production secret resource names with
`SAML_SP_CERTIFICATE_LOCATION` and `SAML_SP_PRIVATE_KEY_LOCATION` if needed.

## Docker image publishing

Pushes to `master` run `.github/workflows/docker-publish.yml`: it runs the tests and packages
the JAR, publishes the Maven package to GitHub Packages, deletes existing container versions,
then builds and pushes `ghcr.io/venuchalla/user:latest`. The workflow uses `GITHUB_TOKEN` for
reading the parent Maven package at
`https://maven.pkg.github.com/venuchalla/springparent` and publishing this repository's Maven
package and container image. Grant this repository's Actions access to the parent package,
and ensure `GITHUB_TOKEN` has `packages: write` permission.

To build locally, first package the application with Maven, then run `docker build -t user .`.
The image defaults to `SPRING_PROFILES_ACTIVE=prod`. Set `SAML_SP_ENTITY_ID`,
`SAML_ACS_URL`, and `SAML_SLO_URL` if the deployment uses a different public URL, and configure
the IdP with the matching values from `/saml2/metadata/zitadel`. Provide the SP signing
key and certificate through `SAML_SP_PRIVATE_KEY_LOCATION` and
`SAML_SP_CERTIFICATE_LOCATION` when they are not packaged into the image.

SAML also uses Spring Security endpoints that are not controller methods:
`GET /saml2/authenticate/{registrationId}` starts authentication,
`POST /login/saml2/sso/{registrationId}` receives the IdP response,
`POST /saml/logout` starts RP-initiated logout, and
`POST /saml/slo` receives the IdP logout response.

## SAML development integration

The Angular SAML page uses `GET /saml/login` to begin sign-in and
`GET /saml/profile-data?ticket=...` to retrieve the verified profile. Spring Security
handles the signed SAML response at `POST /login/saml2/sso/zitadel`, then redirects the
browser to the Angular profile URL with a short-lived, single-use ticket.
The profile page starts RP-initiated single logout with `POST /saml/logout`; Zitadel
returns the SAML logout response to `POST /saml/slo`. After successful validation, the
backend redirects the browser to Angular `/saml/logout-complete`, and Angular then
navigates to `/home`. The local Angular proxy
forwards both endpoints to the backend. SAML lifecycle events are logged without
including assertions, tickets, tokens, or profile attributes.

The SP advertises both HTTP-POST and HTTP-Redirect SLO endpoints and sends logout
requests using HTTP-Redirect, as in ZITADEL's `python-saml-sp` example. Redirect logout
requests include the `SAMLEncoding` DEFLATE binding parameter expected by ZITADEL. The
request `IssueInstant` defaults to five seconds in the past to tolerate small clock
differences between the app server and ZITADEL. Keep the server clock synchronized; adjust
this with `SAML_LOGOUT_ISSUE_INSTANT_OFFSET_SECONDS` only if the IdP still reports the
request as future-dated. ZITADEL's current SAML provider returns unsigned POST logout
responses, so the app accepts unsigned responses only after checking the response issuer,
destination, successful status, and matching `InResponseTo`. Set
`SAML_LOGOUT_RESPONSE_SIGNATURE_REQUIRED=true` to require a valid IdP response signature;
the current ZITADEL response will then be rejected.
Authentication requests set `ForceAuthn=true` by default to ask ZITADEL to reauthenticate
after local logout rather than silently reuse its IdP session. Set `SAML_FORCE_AUTHN=false`
to allow IdP single sign-on. ZITADEL's application configuration must also point its SLO
URL to the backend's public `/saml/slo` endpoint; the local backend URL is
`http://localhost:8082/saml/slo`.

SAML is enabled for local development and uses Zitadel's metadata URL
`https://my-dev-authentication-server-dsealt.us1.zitadel.cloud/saml/v2/metadata`. The SP
metadata is at `https://localhost:4200/saml2/metadata/zitadel`; configure the Zitadel
application with entity ID `http://localhost:4200` and ACS URL
`https://localhost:4200/login/saml2/sso/zitadel` and SLO URL
`https://localhost:4200/saml/slo` (or import the SP metadata from
`http://localhost:8082/saml2/metadata/zitadel` while the backend is running). The local
Angular proxy routes the browser-facing SAML endpoints to the backend on port 8082.

A local RSA signing key and certificate are stored outside the repository at
`~/.config/user-app/saml-sp-private-key.pem` and
`~/.config/user-app/saml-sp-certificate.pem`. The private key is used to sign AuthnRequests
and must never be committed or shared. The generated SP metadata publishes only its
certificate. On another machine, generate a matching keypair or set
`SAML_SP_PRIVATE_KEY_LOCATION` and `SAML_SP_CERTIFICATE_LOCATION` to secure local files,
then update the certificate in Zitadel's SP configuration. Set `SAML_ENABLED=false` to
disable SAML. Session cookies use `SameSite=None; Secure` for the cross-site SAML POST
callback, so use HTTPS for the browser-facing Angular app.


https://user-api-766984687989.us-central1.run.app
https://user-api-766984687989.us-central1.run.app

project-5b322b8a-b6f3-42d3-bcd
