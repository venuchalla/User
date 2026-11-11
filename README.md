# User

`src/main/resources/data.sql` initializes the `USER`, `MODERATOR`, and `ADMIN` roles and
seeds development accounts with BCrypt-encoded passwords. Sign in with `POST /auth/signin`
using JSON `{"username":"admin","password":"Admin123!"}` (or `moderator` / `Moderator123!`,
`user` / `User123!`, `alice` / `Alice123!`, or `bob` / `Bob123!`). The script inserts
missing accounts and role links on startup; edit the script to change the sample accounts.
