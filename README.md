# cerb2-goparser

A Go port of the **Cerberus 2 CLI email parser** (`cerb2-cparser`). It reads an
XML config, fetches email via POP3 **or** stdin pipe, parses each message's MIME
structure (decoding base64 / quoted-printable / uuencode / TNEF and RFC-2047
subjects), builds an XML description of the message plus its extracted
attachments, and HTTP-multipart-POSTs that to a Cerberus parser endpoint.

The port is **idiomatic Go using the standard library** (the only third-party
dependency is `golang.org/x/text`, used solely for optional charset conversion),
but it is **wire-compatible** with the original: the serialized XML matches the C
`cxml_node_tostring` output byte-for-byte and the multipart POST uses the same
form fields and file parts, so it is a drop-in replacement for the existing
Cerberus backend.

## Build & run

```sh
go build -o cerberus ./cmd/cerberus
./cerberus <xml_config_file> <log_level> <log.txt>
```

- `log_level` is matched by its first letter (case-insensitive): `Mark`, `Fatal`,
  `Error`, `Warn`, `Debug`, `Trace`.
- With a `<pop3>` and/or `<imap>` section in the config the parser runs in
  **POP3 / IMAP mode** and fetches mail from each account. Otherwise it runs in
  **pipe mode** and reads one message from stdin:

```sh
cat message.eml | ./cerberus config.xml DEBUG log.txt
```

Run the tests with `go test ./...`.

## Configuration

See [`config.xml.example`](config.xml.example) for a fully commented template
covering every option below. The config is the same XML the C tool used. Two
delivery setups are supported:

**Direct key** — the parser URL/credentials live in the config:

```xml
<configuration>
  <key>
    <parser user="name" password="password" url="http://host/cerberus-gui/parser.php" />
  </key>
  <global>
    <tmp_dir value="/tmp/" />
  </global>
</configuration>
```

**xSP key** — an encrypted license key is decrypted (Blowfish) to find the xSP
domain; the parser boots against it (`action=boot`) to obtain the parser
URL/credentials:

```xml
<configuration>
  <xsp https="true" user="name" password="password">ENCRYPTED_HEX_KEY...</xsp>
  ...
</configuration>
```

Other recognised elements (all optional):

| Path | Meaning | Default |
|------|---------|---------|
| `global/tmp_dir@value` | temp directory for saved messages and decoded parts | current dir |
| `global/max_pop3_messages@value` | max messages fetched per run | 1024 |
| `global/max_pop3_delete@value` | `false` keeps failed messages on the server | true |
| `global/pop3_timeout@value` | per-read POP3 timeout (seconds) | 30 |
| `global/libcurl@value` | accepted but ignored (Go uses `net/http`) | — |
| `global/charset_utf8@value` | `true` converts RFC-2047 subjects to UTF-8 | false |
| `global/charset_utf8_body@value` | `true` converts text/* part bodies to UTF-8 | false |
| `global/imap_state@value` | path of the IMAP dedup state file (enables cross-session dedup) | — (off) |
| `debug/xml@value` | print the parsed XML | 0 |
| `debug/curl@value` | print the server response | 0 |
| `debug/parse@value` | parse only, don't post (prints XML if `debug/xml`) | 0 |
| `debug/superclean@value` | always delete temp files | 0 |
| `ssl/cainfo@value` | CA bundle file for HTTPS | — |
| `ssl/capath@value` | CA directory for HTTPS | — |
| `ssl/verify@value` | 0 = no verify, 1/2 = verify | full verify |
| `pop3` (repeatable) | mailbox: `host`/`port`(110)/`user`/`password`/`delete` | — |
| `imap` (repeatable) | mailbox: `host`/`port`(993 if `tls`, else 143)/`user`/`password`/`auth`(login)/`tls`/`starttls`/`mailbox`(INBOX)/`search`(ALL)/`delete` | — |
| `imap` OAuth2 (when `auth="xoauth2"`) | `oauth_client_id`/`oauth_client_secret`/`oauth_refresh_token`/`oauth_tenant`/`oauth_scope`/`oauth_token_url`/`oauth_token_cache` — see [Microsoft 365](#microsoft-365-oauth2--xoauth2) | — |

### Microsoft 365 (OAuth2 / XOAUTH2)

Microsoft 365 (Exchange Online) has disabled Basic Auth for IMAP, so a mailbox is
reached with an OAuth2 bearer token via the SASL **XOAUTH2** mechanism rather than a
password. Set `<auth value="xoauth2"/>` on the `<imap>` block and supply the OAuth2
settings; on each run the parser mints a short-lived access token from a refresh
token and authenticates with it (no `<password>` is used).

**One-time setup**

1. Register an app in the Azure portal (Entra ID → **App registrations**). Note its
   **Application (client) ID** and **Directory (tenant) ID**.
2. Under **Certificates & secrets**, create a **client secret** (or use a public
   client and omit the secret).
3. Under **API permissions**, add the **delegated** Office 365 Exchange Online
   permission `IMAP.AccessAsUser.All` plus `offline_access` (so the token endpoint
   returns a refresh token), and grant admin consent.
4. Make sure IMAP is enabled for the target mailbox (Microsoft 365 admin center →
   the user → **Mail** → **Manage email apps** → IMAP).
5. Obtain an initial **refresh token** once, interactively, by running the OAuth2
   authorization-code flow for that mailbox: open the tenant `/authorize` URL in a
   browser, sign in as the mailbox user to consent, then exchange the returned
   `code` at the `/token` endpoint for a refresh token. This bootstrap is a manual
   step (a bundled helper command may be added later).

**Config keys** (a full block is in `config.xml.example`):

| key | meaning |
|-----|---------|
| `auth` | `xoauth2` selects the token flow (no `password`) |
| `user` | the mailbox address (UPN) |
| `oauth_tenant` | tenant id or domain (or `common`); builds the default token URL |
| `oauth_client_id` | Azure app (client) id |
| `oauth_client_secret` | client secret (omit for a public app) |
| `oauth_refresh_token` | the bootstrap refresh token obtained above |
| `oauth_token_cache` | writable path caching the rotated refresh + access token (recommended) |
| `oauth_scope` | optional; defaults to `https://outlook.office365.com/IMAP.AccessAsUser.All offline_access` |
| `oauth_token_url` | optional; defaults to `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` |

Set `oauth_token_cache` to a writable path: Azure **rotates the refresh token on
every refresh**, and the cache persists the newest one so an unattended parser keeps
working past the bootstrap token's sliding expiry window. Without a cache the same
bootstrap token is reused every run and eventually stops working. The cache holds
secrets, so protect it like the config file. The token request reuses the `ssl`
settings (`cainfo`/`capath`/`verify`).

The same XOAUTH2 mechanism works for other providers such as Gmail given an
appropriate `oauth_token_url` and `oauth_scope`; only the Microsoft 365 defaults are
built in.

## Architecture

Most of the hand-rolled C utility modules collapse into the Go standard library;
only the application-specific logic is ported.

| C module(s) | Go |
|-------------|-----|
| `cstring`, `cdata`, `cdict` | `string`/`[]byte`, slices, `map` |
| `cfile`, `clog`, `csocket` | `os`/`bufio`, `internal/clog`, `net` |
| `cxml` | `internal/xmltree` (custom DOM + wire-exact serializer) |
| `cmime` | `internal/mimeparse` (the core parser) |
| `cpop3` | `internal/pop3` |
| (new) IMAP support | `internal/imap` (RFC 3501, implicit TLS/STARTTLS, LOGIN + SASL XOAUTH2) |
| (new) OAuth2 tokens | `internal/oauth` (hand-rolled refresh-token grant for XOAUTH2) |
| `ccrypt/rsa` + `cer_key_info` | `internal/crypt` (Blowfish + key decode) |
| `cer_curl_*`, `cer_add_sub_files` | `internal/poster` (`net/http` + `mime/multipart`) |
| `cer_load_config` | `internal/config` |
| `cerberus.c` main, `cer_parse_files` | `internal/app` |

### Output XML shape

```
<email>
  <headers> ... <content-type case="a|..|z">…</content-type> … </headers>
  <parser_version>2.x build 649</parser_version>   (added before posting)
  <cerbmail>/tmp/cerbmail_…</cerbmail>              (added before posting)
  <sub>                                             (one per part / attachment)
    <headers>…</headers>
    <parent-boundary>…</parent-boundary>
    <file name="orig.ext"><tempname>…</tempname><filename>orig.ext</filename></file>
  </sub>
</email>
```

Children and attributes are emitted **sorted by name** (the C backed them with a
red-black dict), values containing a byte `<33`, `>126`, `&` or `<` are
CDATA-wrapped, and indentation is two spaces per level — all matching
`cxml_node_tostring`.

## Notes / intentional differences

- **No libcurl / dlopen.** The bundled `libcurl.so` machinery is replaced by
  `net/http`; a `global/libcurl` value is accepted but ignored.
- **Charset transcoding is opt-in.** By default subjects and bodies are decoded
  without charset conversion, matching the C (its ICU conversion was commented
  out). Set `global/charset_utf8` to `true` to convert RFC-2047 encoded-word
  subjects to UTF-8, and `global/charset_utf8_body` to convert text/* part bodies
  to UTF-8 (rewriting that part's `<charset>` to `utf-8` so the backend does not
  convert again). Both use `golang.org/x/text` and are controlled independently.
- **No `fork()`.** Messages are processed sequentially, like the C (whose fork
  loop waited for each child before fetching the next message). Each message is
  wrapped in a `recover()` so one malformed message cannot abort the batch.
- Debug-only `printf` noise and a config/comment discrepancy in the original
  C (`<key>` vs `<xsp>`) are not reproduced; both config shapes above work.
- Temp files for extracted parts are cleaned up after posting (the C left some
  behind).
- **IMAP is a new addition** (the C only spoke POP3). Add `<imap>` blocks with
  implicit TLS (`tls`) or `starttls`, a `search` criteria (IMAP `UID SEARCH`,
  default `ALL`), and a `mailbox` (default `INBOX`). Messages are fetched and
  marked `\Deleted` by UID, then expunged. The `max_pop3_messages` and
  `pop3_timeout` settings apply to IMAP as well. Set `global/imap_state` to a
  file path to enable **cross-session de-duplication**: processed UIDs are
  remembered per mailbox (keyed by `UIDVALIDITY`) and skipped on later runs, most
  useful with `<delete value="false"/>`. OAuth2 is supported via SASL **XOAUTH2**
  for providers that require it, such as Microsoft 365 — see
  [Microsoft 365 (OAuth2 / XOAUTH2)](#microsoft-365-oauth2--xoauth2). The
  `internal/imap` package is a hand-rolled client kept behind a small interface, so
  it can still be swapped for a full library (e.g. `emersion/go-imap`) later for
  richer features without touching the app.
