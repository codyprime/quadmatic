# Migrating `openwebui` on `services-02` to `quadmatic`

This checklist migrates an existing hand-placed rootless `openwebui` Podman Quadlet deployment on `services-02` to `quadmatic` **without** recreating the user, changing file ownership, or losing Podman volumes/storage.

`quadmatic`'s `pkg/users` reconciler adopts an existing host account by `(name, uid)` without ever calling `usermod` or touching `/var/home/openwebui`.

---

## Step 1: Inspect Existing User, SubIDs, Volumes, and Units on `services-02`

Run the following read-only checks on `services-02` as root (or via `sudo`):

```bash
# 1. Record the exact numeric UID and GID of openwebui
id openwebui

# 2. Record the current /etc/passwd entry (home directory and shell)
getent passwd openwebui

# 3. Record existing subuid and subgid ranges for openwebui AND all other users
cat /etc/subuid
cat /etc/subgid

# 4. Check linger status and existing Podman volumes/secrets
ls -la /var/lib/systemd/linger/openwebui
systemd-run --machine=openwebui@.host --user --pipe --wait --quiet podman volume ls
systemd-run --machine=openwebui@.host --user --pipe --wait --quiet podman secret ls

# 5. Locate all existing hand-placed quadlet or systemd unit files
ls -la /var/home/openwebui/.config/containers/systemd/ 2>/dev/null || true
ls -la /var/home/openwebui/.config/systemd/user/ 2>/dev/null || true
ls -la /etc/containers/systemd/users/ 2>/dev/null || true
```

Note down:
- **`<EXISTING_UID>`** (for example `2001`, or `1001`, etc.)
- **`<SUBUID_START>`** and **`<SUBUID_COUNT>`** from `/etc/subuid` and `/etc/subgid`
- **`<EXISTING_VOLUME_NAME>`** from `podman volume ls` (note whether Podman created `systemd-open-webui` from a `.volume` quadlet or a manually named volume such as `open-webui` or `open-webui-data`)

---

## Step 2: Pin `openwebui` in `users.toml`

Add `openwebui` to `users.toml` in your GitOps manifests repository using the exact UID from Step 1.

Calculate what `quadmatic`'s default formula would assign (`1000000 + (uid - 2000) * 65536`):
- If `openwebui`'s existing `/etc/subuid` and `/etc/subgid` match that formula (for example UID `2001` with `1065536:65536`), you only need `uid`:

```toml
[users.openwebui]
uid = 2001
```

- If `openwebui` was provisioned earlier with a different range (for example `100000:65536` or `165536:65536`), pin `subuid_start` and `subuid_count` explicitly so `quadmatic` preserves the existing user-namespace UID mapping on `/var/home/openwebui/.local/share/containers/storage` without triggering a `podman system migrate`:

```toml
[users.openwebui]
uid = 2001
subuid_start = 165536
subuid_count = 65536
```

> **Important:** Ensure the pinned `(subuid_start, subuid_count)` does not overlap any other user in `/etc/subuid` or `/etc/subgid` (such as `core:100000:65536`). `quadmatic` validates non-overlap before mutating anything.

---

## Step 3: Author `components/open-webui/` and `hosts/services-02.toml`

Create `components/open-webui/` matching the existing volume name and container configuration:

1. `components/open-webui/open-webui.volume`:
   - If the existing volume is `systemd-open-webui` (standard Quadlet default for `open-webui.volume`), use:
     ```ini
     [Volume]
     ```
   - If the existing volume has a custom name without the `systemd-` prefix (for example `open-webui`), set `VolumeName=` explicitly so Podman reuses the existing volume instead of creating an empty `systemd-open-webui` volume:
     ```ini
     [Volume]
     VolumeName=open-webui
     ```

2. `components/open-webui/open-webui.container` (or `.container.tmpl`):
   Reference `Volume=open-webui.volume:/app/backend/data` (matching the existing mount path) and any encrypted `Secret=` entries declared in `components/open-webui/component.toml`.

3. Encrypt secrets (if any) to `services-02`'s host `age` recipient key and reference them in `components/open-webui/component.toml`:
   ```toml
   [secrets]
   webui_secret_key = "secrets/open-webui-secret-key.age"
   ```

4. Register the component in `hosts/services-02.toml`:
   ```toml
   hostname = "services-02"

   [[component]]
   name = "open-webui"
   user = "openwebui"
   ```

5. Validate offline from your workstation or CI before committing/pushing:
   ```bash
   quadmatic validate --repo-path /path/to/manifests --host services-02
   ```

6. Create a signed commit with an SSH key listed in `/etc/quadmatic/allowed-signers` and push to the configured branch:
   ```bash
   git add users.toml hosts/services-02.toml components/open-webui secrets/
   git commit -S -m "feat(services-02): adopt open-webui under quadmatic"
   git push
   ```

---

## Step 4: Verify Zero-Touch Adoption via `quadmatic apply --dry-run`

Before making any host changes, run `--dry-run` on `services-02`:

```bash
sudo quadmatic apply --config /etc/quadmatic/config.toml --dry-run
```

Verify every line of the printed plan:
1. **No `create_user` action:** `User action: create_user openwebui` must **not** appear. (If `openwebui` currently has a login shell instead of `/usr/sbin/nologin`, `User warning: adopted user "openwebui" has shell ...` is expected and harmless — `quadmatic` leaves `/etc/passwd` untouched.)
2. **No unexpected `update_subuid` / `update_subgid`:** Verify neither action appears unless you intentionally chose to migrate ranges.
3. **Target quadlet path:** Files plan targets `/etc/containers/systemd/users/<EXISTING_UID>/open-webui.container` and `open-webui.volume`.
4. **Zero errors** from static validation, `age` secret decryption, or `/usr/libexec/podman/quadlet --dryrun`.

---

## Step 5: Cut Over from Hand-Placed Units

Because Podman's Quadlet generator reads both user-owned (`~/.config/containers/systemd/`) and root-owned (`/etc/containers/systemd/users/<uid>/`) directories — with user-owned files taking precedence on filename collision — you must remove the hand-placed unit before or during cutover so the managed unit in `/etc/containers/systemd/users/<uid>/` owns `open-webui.service`.

1. Stop the existing hand-placed service and back up (then remove) the hand-placed quadlet/unit files:
   ```bash
   sudo systemctl --user -M openwebui@ stop open-webui.service
   sudo mkdir -p /var/home/openwebui/quadmatic-migration-backup
   sudo mv /var/home/openwebui/.config/containers/systemd/open-webui.* \
     /var/home/openwebui/quadmatic-migration-backup/ 2>/dev/null || true
   sudo systemctl --user -M openwebui@ daemon-reload
   ```
   *(If you previously installed units directly in `/var/home/openwebui/.config/systemd/user/`, disable and move those as well.)*

2. Run a single live `quadmatic apply` (or reload the `quadmatic` daemon):
   ```bash
   sudo quadmatic apply --config /etc/quadmatic/config.toml
   ```

3. Verify the managed unit, storage, and metrics:
   ```bash
   # Confirm root-owned quadlet files are installed
   ls -la /etc/containers/systemd/users/<EXISTING_UID>/

   # Confirm service is active and generated from /etc/containers/systemd/users/<EXISTING_UID>/
   sudo systemctl --user -M openwebui@ status open-webui.service

   # Confirm container is running and using the preserved volume
   sudo systemd-run --machine=openwebui@.host --user --pipe --wait --quiet podman ps
   sudo systemd-run --machine=openwebui@.host --user --pipe --wait --quiet podman volume ls

   # Confirm state and Prometheus metrics reflect success
   sudo cat /var/lib/quadmatic/state.json
   curl -fsS http://<MGMT_IP>:9100/metrics | grep quadmatic_
   ```

4. Once verified in production, delete `/var/home/openwebui/quadmatic-migration-backup` (after confirming data/history in the Open WebUI UI is intact).
