# Lab: Use PAM to Limit User Access (`/etc/nologin`)

**Series:** linux-ops-mastery — RHCSA TCP Wrappers & PAM
**Subjects covered:** **`/etc/nologin`** file semantics, **`pam_nologin.so`**, impact on **non-root** interactive logins, **SSH** vs **login** behavior, custom **denial message**, removing lock, relationship to **scheduled maintenance**
**Career arcs covered:** RHCSA (user lockout patterns), RHCE (maintenance playbooks), SRE (controlled downtime banners), DevOps (release freeze signaling), AI (status page automation)
**Prerequisite:** Lab 72 — Explore PAM Config Files
**Time Estimate:** 30 to 45 minutes
**Difficulty arc:** Task 1 trace pam_nologin · 2–3 create nologin message · 4 observe user denial · 5 confirm root still works · 6 capstone + delete nologin + pam restore N/A

---

## Objective

Use **`/etc/nologin`** — the classic **"go away, we're closed"** flag for **non-root interactive logins**. When the file exists, PAM's **`pam_nologin.so`** (in **`account`** or **`auth`** stacks depending on service) blocks normal users while typically allowing **root** (policy-dependent) so administrators can still fix things.

You will write a **custom message** inside `/etc/nologin`, verify that a **regular user** cannot open an SSH session or local login while the file exists, then **remove** the file to reopen the system. You will document why **`nologin` is not a substitute** for **`userdel`**, **`usermod -L`**, or **firewall blocks** — it is a **coarse maintenance gate**.

> **Lab safety note:** Creating `/etc/nologin` on a shared lab host will block classmates. Coordinate timing. Always keep **root or console sudo** path verified before enabling.

---

## Concept: `/etc/nologin` Is a Global Switch Read by `pam_nologin.so`

Many services' PAM stacks include a line referencing **`pam_nologin.so`**. If **`/etc/nologin`** exists, the module fails the **`account`** phase for non-privileged users (exact behavior can vary slightly by service configuration).

```
User tries SSH key/password
        │
        ▼
pam_nologin sees /etc/nologin exists
        │
        ├─ user is root? → often bypass (do not rely blindly)
        └─ regular user → ACCOUNT failure with file contents as message
```

> **Why this matters:** **Fast maintenance window** — flip one file instead of editing every account.

---

## 📜 Why `/etc/nologin` Exists — The Story

Before live patching and graceful draining, admins halted multi-user logins during **kernel upgrades** or **filesystem checks** by dropping a file: **`/etc/nologin`**. `shutdown` historically created it; **`pam_nologin`** standardized the behavior across **`login`**, **`sshd`**, and display managers.

The file contents are shown to the user — making it an early **status banner** mechanism ("Logins disabled until 02:00 UTC for storage migration"). Modern shops still use it alongside **`/etc/issue.net`**, but **`nologin`** is special because it is **enforced** by PAM, not merely displayed.

> **The point of the story:** **`nologin`** is **operational communication** plus **access control** in one inode.

---

## 👪 The nologin Family — Who Lives There

| Artifact | Role |
|---|---|
| `/etc/nologin` | Message body + presence flag |
| `pam_nologin.so` | Enforces presence in PAM stacks |
| `/sbin/nologin` | Shell for disabled users (different concept!) |
| `/var/run/nologin` | Some distributions check alternate paths — know your man page |

### Distinct from

| Item | Meaning |
|---|---|
| `usermod -s /sbin/nologin user` | Per-user shell lock |
| `/etc/hosts.deny` | TCP Wrappers (often absent for sshd on RHEL9) |

> **The point of the family tree:** **Filename collision confusion** — `/etc/nologin` (policy file) vs `/sbin/nologin` (shell program).

---

## 🔬 The Anatomy of `/etc/nologin` Contents — In One Diagram

```
/etc/nologin:
  +-----------------------------------+
  | PLANNED MAINTENANCE IN PROGRESS   |
  | ETA: 30 minutes                   |
  | ticket: CHG-2026-0526            |
  +-----------------------------------+

Displayed to blocked users as denial text.
```

> **Reading rule:** First line should be human-readable summary — users panic less with ETA.

---

## 📚 /etc/nologin Reference Table

| Task | Command | Notes |
|---|---|---|
| Enable | `printf 'msg\n' > /etc/nologin` | Immediate effect |
| Disable | `rm -f /etc/nologin` | Restore logins |
| Find module | `grep -R pam_nologin /etc/pam.d` | See which services honor it |
| Test user | `su - labuser2` / `ssh labuser2@localhost` | Expect failure with message |

> **Rule one of nologin:** **Communicate** — blank file blocks without explanation.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | Classic "prevent user logins during maintenance" task |
| **RHCE candidate** | Ansible `file` state=absent/present with `notify` |
| **SRE / Platform** | Pair with load balancer drain |
| **DevOps** | GitOps change ticket ID in message body |

---

## 🔧 The 6 Tasks

---

### Task 1 — Map which stacks reference `pam_nologin`

**Purpose:** Evidence before behavior change.

```bash
sudo -i
grep -R --line-number 'pam_nologin' /etc/pam.d | head -n 20
```

**Human-Readable Breakdown:** Recursive grep for module name.

**Reading it left to right:** `grep -R` across pam.d.

**The story:** Know **which services** will honor the flag.

**Expected output:**

```text
/etc/pam.d/sshd:7:account required pam_nologin.so
/etc/pam.d/login:4:account required pam_nologin.so
```

**Switches**

| Token | Meaning |
|---|---|
| `grep -R` | Recursive |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| No hits | Image unusual — read `man pam_nologin` and `sshd` vendor config |

---

### Task 2 — Create lab users for testing

**Purpose:** Never test lockouts only on strangers — use **`labuser2`**.

```bash
useradd -m labuser2
echo 'labuser2:TempPass-2026-A!' | chpasswd
id labuser2
```

**Human-Readable Breakdown:** User + password for interactive tests.

**Reading it left to right:** `useradd -m` → `chpasswd` → `id`.

**The story:** Disposable users are how senior admins experiment.

**Expected output:**

```text
uid=1002(labuser2) gid=1002(labuser2) groups=1002(labuser2)
```

**Switches**

| Token | Meaning |
|---|---|
| `-m` | Create home directory |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| User exists | `userdel -r labuser2` then recreate |

---

### Task 3 — Write `/etc/nologin` with a custom message

**Purpose:** Maintenance banner.

```bash
cat > /etc/nologin <<'EOF'
LOGINS TEMPORARILY DISABLED — RHCSA LAB 76
Reason: /etc/nologin demonstration
Contact: instructor@lab.local
EOF

ls -l /etc/nologin
```

**Human-Readable Breakdown:** Multi-line message with who/why.

**Reading it left to right:** heredoc → list inode.

**The story:** **Operational kindness** — always include contact/ETA when possible.

**Expected output:**

```text
-rw-r--r--. 1 root root ... /etc/nologin
```

**Switches**

| Token | Meaning |
|---|---|
| `cat >` | Overwrite file |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Still able to login | Service lacks pam_nologin — revisit Task 1 |

---

### Task 4 — Verify non-root login is blocked (SSH local test)

**Purpose:** Observe denial with message excerpt.

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no labuser2@127.0.0.1 'echo SHOULD_NOT_RUN' || true
```

**Human-Readable Breakdown:** Force password path for test — may prompt; in scripted labs expect failure with nologin text on stderr.

**Reading it left to right:** `ssh` to localhost as `labuser2`.

**The story:** **SSH** is the common RHCSA verification surface.

**Expected output:**

```text
LOGINS TEMPORARILY DISABLED — RHCSA LAB 76
Permission denied (publickey,password).
```

**Switches**

| Token | Meaning |
|---|---|
| `|| true` | Keep script flowing in class demos |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Key-only auth bypasses password demo | Adjust sshd or use `su - labuser2` from root tty |

---

### Task 5 — Confirm root can still work (do not rely blindly)

**Purpose:** Document emergency path.

```bash
test -f /etc/nologin && echo 'nologin present (expected)'
sudo -n true 2>/dev/null && echo 'root non-interactive sudo still ok' || echo 'check sudo policy manually'
```

**Human-Readable Breakdown:** Presence check + non-interactive sudo smoke.

**Reading it left to right:** file test → sudo `-n`.

**The story:** **Maintenance flag should not brick admins** — validate your break-glass path.

**Expected output:**

```text
nologin present (expected)
root non-interactive sudo still ok
```

**Switches**

| Token | Meaning |
|---|---|
| `sudo -n` | Non-interactive sudo |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Root SSH also blocked | Good hardening — ensure console |

---

### Task 6 — Capstone + cleanup (remove `/etc/nologin`, delete lab user)

**Purpose:** Reopen logins; remove artifacts.

```bash
rm -f /etc/nologin
userdel -r labuser2 2>/dev/null || userdel labuser2

test ! -f /etc/nologin && echo 'OK: nologin removed'
```

**Cleanup**

```bash
# No pam.d edits in this lab — nothing to restore beyond user/nologin
exit
```

**Human-Readable Breakdown:** Delete flag file → remove user → assert absence.

**Reading it left to right:** `rm` → `userdel` → `test !`.

**The story:** **Leaving nologin behind** is how night shift hates day shift.

**Expected output:**

```text
OK: nologin removed
```

**Switches**

| Token | Meaning |
|---|---|
| `rm -f` | No error if already absent |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Users still blocked | Check `/run/nologin` or display manager equivalents |

---

## 🔍 nologin Decision Guide

```
Need to block interactive users quickly?
  │
  ├── Whole system maintenance?
  │       └── ✅ /etc/nologin + clear message
  │
  ├── Single misbehaving user?
  │       └── ✅ usermod -L / passwd -l / ACL tools — not nologin
  │
  ├── Need SSH banner only (no block)?
  │       └── /etc/issue.net + sshd Banner
  │
  └── Need application-only lock?
          └── app-level feature flags
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 `grep -R pam_nologin /etc/pam.d`
- [ ] 02 Create `labuser2` with known password
- [ ] 03 Write `/etc/nologin` message body
- [ ] 04 Verify `labuser2` cannot SSH while file exists
- [ ] 05 Confirm admin/root path still viable
- [ ] 06 Remove `/etc/nologin`, delete `labuser2`

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| Confusing `/etc/nologin` with `/sbin/nologin` | Wrong mental model | Re-read family table |
| No message in file | Angry users | Always add text |
| Forgetting removal | Permanent outage | Monitoring alert on file age |
| Testing only one service | Incomplete | Check `login` + `sshd` |
| Locking emergency break-glass | Sev-1 | Console-first policy |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Memorize: **`pam_nologin.so` + presence of `/etc/nologin`**.

**RHCE candidate**
- Use `block/rescue`: create nologin → verify → always remove in rescue.

**SRE / Platform interview**
- Pair with **status page** + **LB drain** — nologin alone is not user-visible externally.

**DevOps**
- ChatOps command `/maintenance on` writes file; `/off` deletes.

**AI / MLOps**
- Automated maintenance windows should **assert** file removal post-task.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab 75 — pam_securetty | Different PAM gate |
| Lab 77 — pam_listfile | Selective deny list |
| Lab 72 — Explore PAM Config Files | Stack literacy |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
