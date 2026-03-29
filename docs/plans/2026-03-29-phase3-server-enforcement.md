# Phase 3: Server-Enforcement (UCAN + DID-Auth)

## Kontext

Phase 3 des MLS + UCAN + Ed25519 Integrationsplans. Der Server wird als untrusted Relay umgebaut: Supabase JWT fällt als Auth-Methode weg, ersetzt durch UCAN (space-scoped) und DID-Signaturen (identity-scoped).

Voraussetzungen: `@haex-space/ucan` v0.1.0 (fertig), Ed25519-Umstellung (Phase 0, fertig).

## Auth-Architektur

### Drei Auth-Schemes, ein Header

| Scheme | Format | Verwendung |
|--------|--------|------------|
| `UCAN` | `Authorization: UCAN <jwt-token>` | Alle Space-scoped Operationen |
| `DID` | `Authorization: DID <payload>.<signature>` | Space erstellen, Invite akzeptieren |
| *(keins)* | Kein Auth-Header | Öffentliche Endpoints (`/identity-auth/challenge`, etc.) |

Supabase JWT fällt komplett weg als Auth-Methode. Supabase bleibt als Infrastruktur (PostgreSQL, Realtime, Shadow-User für Quota/Tier).

### DID-Auth Payload-Format

```
Authorization: DID <base64url(json)>.<base64url(signature)>
```

```json
{
  "did": "did:key:z6Mk...",
  "action": "create-space",
  "timestamp": 1743292800,
  "bodyHash": "<sha256-hex-of-request-body>"
}
```

Server prüft: Ed25519-Signatur gültig, DID existiert in `identities`, Timestamp ±30 Sek., Body-Hash matcht.

### UCAN-Auth

Token direkt aus Header parsen und mit `@haex-space/ucan` verifizieren (Signaturkette, Expiry, Capability). Issuer-DID gegen `identities`-Tabelle prüfen.

## Sicherheitsprinzipien

**Grundsatz: Der Server ist ein untrusted Relay.**

Alle Server-seitigen Daten (`space_members`, `space_invites`, etc.) sind Convenience-Indices, nicht die Quelle der Wahrheit.

| Schicht | Garantie | Kann Server umgehen? |
|---------|----------|---------------------|
| **UCAN** | Wer darf was tun | Nein — Ed25519-signiert vom Delegator |
| **MLS** | Wer kann entschlüsseln | Nein — TreeKEM, Server hat keine Keys |
| **DID-Signatur** | Wer hat den Request gesendet | Nein — Private Key nur beim User |
| **`space_members`** | Schneller Lookup | Ja — aber nutzlos ohne UCAN/MLS |

Daraus folgt:

1. **Server-Enforcement ist Optimierung, nicht Sicherheit.** Frühes Reject spart Bandbreite und schützt vor Spam. Finale Prüfung ist IMMER die Vault (Phase 4).
2. **Server-State darf nie allein entscheiden.** Kein Endpoint darf eine Aktion nur auf Basis von `space_members.role` erlauben — es muss immer ein kryptographischer Beweis vorliegen (UCAN oder DID-Signatur).
3. **Server-State wird durch Client-Aktionen befüllt.** `space_members` wird aktualisiert wenn ein signierter Invite-Accept oder MLS-Add durchkommt — nie durch den Server selbst.

## Middleware-Architektur

```
src/middleware/
├── auth.ts              → entfernt (Supabase JWT)
├── spaceTokenAuth.ts    → entfernt (Space Access Tokens)
├── didAuth.ts           → NEU: DID-signierte Requests
├── ucanAuth.ts          → NEU: UCAN-Verifikation
└── authDispatcher.ts    → NEU: Dispatcht anhand des Schemes
```

### authDispatcher

Zentrale Middleware für alle geschützten Routen:

```
Authorization Header lesen
    │
    ├─ "UCAN ..." → ucanAuth → setzt c.ucanContext
    ├─ "DID ..."  → didAuth  → setzt c.didContext
    └─ fehlt/unbekannt → 401
```

### ucanAuth

- Token parsen mit `decodeUcan()`
- Signaturkette verifizieren mit `verifyUcan()`
- Issuer-DID gegen `identities`-Tabelle prüfen
- Setzt `UcanContext`: `{ issuerDid, capabilities, verifiedUcan }`
- Capability-Check passiert pro Route via `requireCapability()`

### didAuth

- Payload + Signatur parsen
- Ed25519-Signatur verifizieren gegen Public Key aus `identities`
- Timestamp ±30 Sek. prüfen
- Body-Hash gegen tatsächlichen Request-Body prüfen
- Setzt `DidContext`: `{ did, publicKey, userId, tier }`

## Endpoint-Mapping

### DID-Auth Endpoints

| Endpoint | Action | Zusätzliche Prüfungen |
|----------|--------|----------------------|
| `POST /spaces` | `create-space` | Identity existiert, Quota/Tier |
| `POST /:spaceId/invites/:id/accept` | `accept-invite` | Invite existiert, DID matcht |

### UCAN-Auth Endpoints

| Endpoint | Capability |
|----------|-----------|
| `GET /spaces` | — (Spaces aus Issuer-DID ableiten) |
| `GET /spaces/:spaceId` | `space/read` |
| `PATCH /spaces/:spaceId` | `space/admin` |
| `DELETE /spaces/:spaceId` | `space/admin` |
| `POST /:spaceId/invites` | `space/invite` |
| `GET /:spaceId/invites` | `space/read` |
| `DELETE /:spaceId/invites/:id` | `space/invite` |
| `POST /:spaceId/invites/:id/decline` | — (Invitee-DID aus UCAN, muss matchen) |
| `POST /:spaceId/members` | `space/invite` |
| `DELETE /:spaceId/members/:key` | `space/admin` (oder Self-Leave) |
| `POST /:spaceId/mls/key-packages` | `space/read` |
| `GET /:spaceId/mls/key-packages/:did` | `space/invite` |
| `POST /:spaceId/mls/messages` | `space/write` |
| `GET /:spaceId/mls/messages` | `space/read` |
| `POST /:spaceId/mls/welcome` | `space/invite` |
| `GET /:spaceId/mls/welcome` | `space/read` |
| `POST /sync/push` (shared) | `space/write` |
| `GET /sync/pull` (shared) | `space/read` |
| `POST /sync/pull-columns` | `space/read` |

### Unveränderte Endpoints

| Endpoint | Auth |
|----------|------|
| `/identity-auth/*` | Challenge-Response (wie bisher) |
| `/identity-auth/storage-credentials` | DID-Auth (verschoben von `/auth/`) |
| `/storage/*` | AWS Sig v4 (unverändert) |

## Datenbank-Änderungen

### Tabellen die wegfallen

| Tabelle | Grund |
|---------|-------|
| `space_access_tokens` | Ersetzt durch UCAN |
| `space_key_grants` | Ersetzt durch MLS (Phase 4) |

### Tabellen die sich ändern

| Tabelle | Änderung |
|---------|----------|
| `space_members` | Neue Spalte `did` (text, not null) |
| `space_members` | `role` bleibt als Server-Side-Cache (autoritativ ist UCAN) |

Keine neuen Tabellen nötig. UCANs sind self-contained Tokens, brauchen keinen Server-State.

## Implementierungs-Reihenfolge

1. **`@haex-space/ucan` als Dependency** einbinden, WebCrypto-Verifier erstellen
2. **Neue Middleware** implementieren (didAuth, ucanAuth, authDispatcher, requireCapability)
3. **Identity-Auth-Endpoints** anpassen (`/auth/storage-credentials` → `/identity-auth/storage-credentials`)
4. **Space-Endpoints** umstellen (DID-Auth für Create/Accept, UCAN für Rest)
5. **Sync-Endpoints** umstellen (push → space/write, pull → space/read)
6. **Aufräumen** (Supabase JWT Middleware, spaceTokenAuth, space_access_tokens entfernen)
7. **Tests** (Unit + Integration für beide Auth-Wege, Negativtests)

## Federation (Phase 7, nicht jetzt)

UCAN-Middleware erkennt `server/relay` Capability bereits. Server-Keypair, Challenge-Response-Endpoints und Relay-Logik kommen in Phase 7.
