# cloud-serv user guide

cloud-serv is a private cloud drive: files, folders and notes on a server you own, reachable from your browser, phone or the command line.

## Getting in

**Sign in** with your email and password, or with the **Sign in with ...** button if your server has single sign-on (authentik) set up.

**Getting an account**, depending on how your admin set the server up:
- **Invite code:** paste it in Register. You're in straight away. Codes work once.
- **Request:** register without a code. You'll see *"Request sent. You can log in once an admin approves it."*
- **Single sign-on:** sign in with the SSO button. If you're in the allowed group, an account is made for you.

**Install it as an app:** in Chrome or Edge (desktop or Android), use the menu's *Install app*. It opens in its own window and the shell loads offline.

### Your recovery key
When your account is created you're shown a **recovery key** (`csr_...`). It unlocks your notes and encrypted files when the password can't (and a recovery-key password reset is planned). Nobody can reset it for you, not even an admin. Use *Download key file* and keep it in a password manager.

## Files

- **Browse:** click folders. The trail at the top (Home > Photos > 2026) jumps back up. The browser's **Back/Forward** buttons move between folders and pages too.
- **Upload:**
  - *+ New*: *Upload files* or *Upload folder (with subfolders)*;
  - or drag files or folders onto the page (*"Drop files here to upload into this folder"*).
  - Big files go up in pieces and resume after a dropped connection.
- **Right-click** any file or folder (long-press on Android) for: open, download, rename, move, star, delete. On a folder: **Download (.zip)** gets the whole thing with subfolders.
- **Select:** tick several items to move or delete them together.
- **Preview:** click a file. Images, video, audio, PDFs and text open in a preview card. Other types download.
- **Sort and view:** *Name* / date / size sorting and a grid view. Filter chips: Images, Videos, Audio, Docs.
- **Search** finds files and folders by name.
- **Recent** lists what you uploaded last. **Starred** lists everything you starred.

### When you run out of space
If an upload won't fit your storage limit, a **Not enough space** box shows what fits and what doesn't:
- **Upload** what fits and skip the rest;
- **Request more storage**: sends the admin how much space this upload needs (you don't type an amount). The box updates live when they approve, and you can carry on;
- **Cancel upload.**

## Notes
**Notes** in the sidebar. *+ New note*, type, *Save*. Notes are always end-to-end encrypted: the server stores only scrambled text.

## Encryption: what's protected
| | Who can read it |
|---|---|
| Notes | only you, always encrypted in your browser |
| Files with *Encrypt my files* **off** (default) | you, and anyone with access to the server's disk (normal files, easy to back up and recover) |
| Files with *Encrypt my files* **on** | only you, encrypted in your browser before upload |
| File and folder **names** of encrypted uploads | only you |

Switch it in **Settings > Files**. It affects new uploads only.

**Locked devices.** On a new browser, encrypted things show *"Notes and encrypted files are locked on this device."* Unlock it one of two ways:
- your password, or your recovery key;
- **approval from a device you already trust.** The new device shows a 6-digit code. On your trusted device, go to **Settings > Devices**, check the same code shows there, and approve.

Approved devices keep a key that can't be copied out of the browser, so they open encrypted things without the password. Revoke a lost device under **Settings > Devices**.

## Settings (your picture, top right > Settings)
- **Account:** display name, profile picture (JPEG, PNG or WebP, under 300 KB).
- **Files:** *Encrypt my files* on or off. Shows storage used and your limit, with *Request more storage*.
- **Devices:** trusted devices, approve or revoke.
- **Sign-in methods:** *Link SSO* to also sign in with authentik. Unlinking keeps the account.
- **Change password:** your files, notes and recovery key keep working. **Other signed-in devices are signed out.**
- **API keys:** for scripts and the `cloud` command-line tool (below). A key is shown once. Revoke keys you no longer use.

Everything updates live across your devices: upload on your phone and it appears on your PC without refreshing.

## Admin (admins only: your picture > Admin)
The red number on *Admin* counts things waiting for you.
- **Sign-up requests:** approve or deny people who registered without a code.
- **Storage requests:** approve gives them what they asked for, or use *Other amount* to choose.
- **Invite codes:** *Create code* (optional label and expiry). Each code works once and skips approval. It's shown once, so copy it.
- **Users:** make admin, suspend, set a storage limit, or:
  - **Remove:** moves the account's data into a backup and shows them the removal notice;
  - **Restore:** brings removed data back;
  - **Wipe:** deletes a removed account's data permanently, and needs the email typed to confirm.

Admins manage accounts only. Nobody, admins included, can read anyone's encrypted files or notes.

## From the command line
With an API key from Settings:
```bash
cloud login https://my-cloud.example.ts.net:8443
cloud ls /                       cloud put -r ~/Pictures/Trip /Photos
cloud get -r /Photos/Trip .      cloud usage
```
See [COMPANION_APPS.md](COMPANION_APPS.md#cloud-the-command-line-client) for every command.

## Troubleshooting
| Problem | Fix |
|---|---|
| Browser warns about the certificate | The server uses its own certificate. Accept it once, or ask the admin to run `cloudctl cert` for a trusted one. |
| "Unlock this device first" | Unlock with your password or recovery key, or approve this device from a trusted one (Settings > Devices). |
| "Your sign-up is waiting for an admin to approve it" | Ask your admin to approve it on the Admin page. |
| "too many failed attempts" | Wait a minute: each wrong password makes the next try wait longer. |
| Forgot password | There's no self-service reset yet, and admins can't reset passwords either. If a device is still signed in, encrypted data can be unlocked there with the recovery key. A recovery-key password reset is on the [roadmap](ROADMAP.md). |
