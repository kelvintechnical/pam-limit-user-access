# Lab: Use PAM to Limit User Access — `/etc/nologin`, `pam_nologin.so`

- **Series:** linux-ops-mastery — RHCSA TCP Wrappers & PAM
- **Subjects covered:** What `pam_nologin.so` does when it sees the file `/etc/nologin`; the difference between **the file `/etc/nologin`** (system-wide login lockout for non-root users) and **the `/sbin/nologin` shell** (per-account login refusal); the maintenance-window workflow — create the file with a message, prove an unprivileged user is blocked, prove root still gets in; which PAM stacks call `pam_nologin` (the answer is "almost all of them" on RHEL 9 — `login`, `sshd`, `gdm-password`, `su-l`, `crond`, etc.); reading the rejection message from both interactive and SSH sessions; and the rollback discipline that prevents you from leaving a server locked over a weekend
- **Career arcs covered:** RHCSA (the objective list says verbatim "use PAM to control or restrict access" — `/etc/nologin` is the simplest possible answer), RHCE (Ansible playbooks routinely drop and remove `/etc/nologin` around upgrade windows), SRE (every maintenance window runbook ends with "remove /etc/nologin and verify a normal user can log in"), DevOps (CI/CD pipelines for OS patching gate non-root traffic with `/etc/nologin` during the patch window), AI/MLOps (multi-user GPU boxes use `/etc/nologin` plus a banner explaining the training run is in flight)
- **Prerequisite:** Familiar with `/etc/pam.d/`, `sudo`, `useradd`, and SSH. A normal non-root user already exists on the test VM (we will create one if not).
- **Time Estimate:** 30 to 45 minutes
- **Difficulty arc:** Task 1 inventory which PAM stacks include `pam_nologin` · 2 read the manpage and understand the "non-root only" carve-out · 3 create a minimal `/etc/nologin` and observe an unprivileged refusal · 4 confirm root is still allowed in · 5 distinguish file-based lockout from shell-based lockout (`/sbin/nologin`) · 6 RHCSA-realistic capstone — maintenance window with custom banner

---

## Objective

By the end of this lab you can lock every non-root user out of a Red Hat 9 system in one command, with a custom message they will see at the login prompt, and unlock them just as fast. You will know that the file `/etc/nologin` is read by `pam_nologin.so` on every login attempt — `login`, `sshd`, `gdm`, `su -`, even `cron` — and that the **only** account exempted is root (UID 0). You will also resolve the most common conceptual confusion in the lab series: **the file `/etc/nologin`** is *not the same thing* as **the shell `/sbin/nologin`**. One is a system-wide lockout; the other is a per-account "this user cannot log in" setting in `/etc/passwd`.

You will read `pam_nologin(8)`, walk every PAM stack that includes the module (there are several on RHEL 9), create a small `/etc/nologin` file with a maintenance message, watch an unprivileged user get refused with that exact message, then watch root sail through unaffected. You will then run the inverse experiment — set a normal user's shell to `/sbin/nologin` — and confirm that the two mechanisms gate the login at *different layers*. The capstone executes the full maintenance-window pattern end to end: open the window, prove the lock, close the window, prove the unlock, and document what happened in a single report file.

The capstone framing: *"It is 2 AM and you are starting a 90-minute database migration. No application users may be on the box during the window. Configure PAM so non-root logins are refused with a clear maintenance banner. Verify the lock. Complete the (simulated) migration. Unlock cleanly. Produce a written report."*

> **Lab safety note:** Every step is reversible by a single `rm /etc/nologin`. Keep a root shell open the whole time; root is not affected by the file. The lab does not modify any PAM config file — only the data file `/etc/nologin`.

---

## Concept: A One-File Switch for Every Non-Root Login

`pam_nologin.so` is a PAM `account`-phase module shipped on every Linux. It has one behavior: **if the file `/etc/nologin` exists, deny the account check for any user whose UID is not zero, and print the contents of the file as the rejection message.** That is the entire feature.

```
   ┌──────────────────────────────────────────────────────────────────┐
   │   Login attempt by user `alice` (UID 1001) on tty3 or via SSH    │
   ├──────────────────────────────────────────────────────────────────┤
   │   PAM stack (e.g. /etc/pam.d/login, /etc/pam.d/sshd, …)          │
   │     auth     required pam_securetty.so                            │
   │     auth     substack system-auth        ← password OK            │
   │     account  required pam_nologin.so     ← reads /etc/nologin     │
   │     account  include  system-auth                                  │
   │     ...                                                           │
   ├──────────────────────────────────────────────────────────────────┤
   │   pam_nologin.so logic:                                          │
   │     if (file /etc/nologin exists) {                              │
   │         if (PAM_USER == "root") return PAM_SUCCESS;              │
   │         print contents of /etc/nologin to the user;              │
   │         return PAM_AUTH_ERR;                                     │
   │     } else {                                                     │
   │         return PAM_SUCCESS;                                      │
   │     }                                                            │
   └──────────────────────────────────────────────────────────────────┘
```

That is the whole module. The kernel does nothing special; the file's mere existence is what trips it. You can write the file with `echo`, `touch`, or `tee`. You can leave it empty (the rejection still happens, just with no extra message) or fill it with a multi-paragraph explanation that becomes the user's banner.

The other side of the same concept — and the source of the most common confusion — is `/sbin/nologin`. That is an *executable program*, set as a user's *login shell* in `/etc/passwd`. When `login(1)` tries to exec that shell, it prints "This account is currently not available." and exits non-zero. The file-based lockout (`/etc/nologin`) blocks everyone at once at the PAM layer; the shell-based lockout (`/sbin/nologin`) blocks one specific account at the shell-exec layer. Both have their place; they are not the same.

> **Why this matters:** EX200 objectives include "configure system to authenticate using PAM" and "use PAM to control or restrict access." The single most exam-realistic implementation of "restrict access" is `/etc/nologin`. A senior administrator will reach for it during every maintenance window. A junior who hasn't seen the lab will be hunting through `sshd_config` and `pam.d` for the right knob and burning ten minutes.

---

## 📜 Why `/etc/nologin` Exists — The Story

The convention is older than PAM itself. In the original AT&T `login` source from the 1970s, the binary checked for a file at `/etc/nologin` before allowing a non-root login. If the file existed, `login` printed its contents and refused. The mechanism was so useful that every Unix vendor copied it.

The original use case was maintenance. A system administrator about to take the server down for a backup or a kernel patch would write a message into `/etc/nologin` ("System will be back at 03:00 — please come back then.") and then perform the maintenance. Anyone who tried to log in during the window saw the message and went away. When the window ended, the admin deleted the file and normal logins resumed. No service restart, no daemon reload, no flag in a config file — just create or delete one path.

When PAM arrived in the mid-1990s, the check was moved out of the `login` binary and into a dedicated module — `pam_nologin.so`. That gave the convention several upgrades. First, every PAM-aware service automatically inherited the behavior the moment its PAM stack included the module — so `sshd`, `gdm`, `xdm`, `kdm`, and others got the same lockout for free. Second, the module's exemption logic (only UID 0 gets past) became a single piece of code instead of being duplicated in every login binary. Third, the location of the file became overridable with a module argument, which is useful in containers and chroots.

On modern RHEL the module is included in essentially every interactive PAM stack: `login`, `sshd`, `gdm-password`, `kdm`, `su-l`, `crond`, and a few others. That means a single `touch /etc/nologin` instantly blocks SSH, console, graphical desktop, and the `su -` of a normal user — all in one command.

> **The point of the story:** `/etc/nologin` is a 1970s pattern preserved exactly because it is small, immediate, and undoable. It outlived every fancier mechanism that tried to replace it. Knowing how it works is two minutes of reading and a lifetime of utility.

---

## 👪 The `pam_nologin` Family — Who Lives There

There are exactly **two** lockouts named "nologin" on RHEL 9. They are different at every level — different layer, different mechanism, different scope, different unlock procedure. Learn them as a pair.

### The two lockouts

| Mechanism | What it is | Scope | How to set | How to clear |
|---|---|---|---|---|
| **`/etc/nologin`** | A regular text file checked by `pam_nologin.so` | System-wide, all non-root users | `echo "msg" > /etc/nologin` | `rm /etc/nologin` |
| **`/sbin/nologin` as shell** | An executable used as a user's login shell in `/etc/passwd` | Per account | `usermod -s /sbin/nologin alice` | `usermod -s /bin/bash alice` |

### PAM stacks that include `pam_nologin` on RHEL 9

| File | Service affected |
|---|---|
| `/etc/pam.d/login` | Local virtual-terminal login |
| `/etc/pam.d/sshd` | SSH (interactive and authentication) |
| `/etc/pam.d/gdm-password` | GNOME graphical login |
| `/etc/pam.d/su-l` | `su -` to switch users with a login shell |
| `/etc/pam.d/crond` | Cron job dispatch (so user crons don't run during a window) |
| `/etc/pam.d/runuser-l` | `runuser -l` |
| `/etc/pam.d/remote` | Generic remote pseudo-tty logins |

### Module arguments worth knowing

| Argument | Effect |
|---|---|
| (none) | Default: read `/etc/nologin` |
| `file=/path/to/other` | Use a different file (useful for per-service lockouts in custom stacks) |
| `successok` | Even if the file exists, return PAM_SUCCESS but log the event (rarely useful) |

### Tools for the work

| Tool | Use |
|---|---|
| `touch /etc/nologin` | Create the file empty (still blocks; no banner shown) |
| `echo "msg" > /etc/nologin` | Create the file with a message |
| `tee /etc/nologin <<EOF ... EOF` | Multi-line banner with a heredoc |
| `cat /etc/nologin` | Read the current banner (use to confirm what users see) |
| `rm /etc/nologin` | Unlock |
| `ls -l /etc/nologin` | Confirm presence and permissions |
| `getent passwd USER` | Show a user's shell (look for `/sbin/nologin`) |
| `id USER` | Confirm UID — if 0, the user bypasses `/etc/nologin` |

> **The point of the family tree:** Two mechanisms with the same name. One file (system-wide), one shell (per-account). Both useful, both very different. Knowing which to use when is the difference between "I want everyone out for an hour" and "this service account should never log in interactively."

---

## 🔬 The Anatomy of `pam_nologin` — In One Diagram

```
# /etc/pam.d/sshd   (excerpt — RHEL 9 default)
account    required     pam_nologin.so
│          │            │
│          │            └─ The shared object loaded from /lib64/security/
│          └─ Control flag: "required" — if account-check fails, login fails
│             (but later modules still run for timing-uniformity)
└─ Phase: "account" — runs AFTER auth (password OK), BEFORE session setup

Runtime sequence for an SSH attempt by `alice`:

   1. sshd accepts the TCP connection.
   2. PAM `auth` phase runs through system-auth: password OR public key OK.
   3. PAM `account` phase begins:
        a. pam_nologin.so reads stat("/etc/nologin").
           - If ENOENT: return PAM_SUCCESS. Move on.
           - If file exists:
                - If PAM_USER is root → return PAM_SUCCESS.
                - Else:
                    - Read up to 4 KiB of file contents.
                    - Display them to the user via pam_conv (banner).
                    - Return PAM_AUTH_ERR.
   4. sshd sees PAM_AUTH_ERR, prints the banner the module supplied,
      then drops the connection.

What the user sees over SSH:
   System maintenance in progress. Back at 03:00 UTC.
   Connection to host closed by remote host.
```

> **Reading rule:** The check is one `stat(2)` call per login. Cheap. The mechanism does not depend on `auth` failing first — the user can have the right password and still be refused, because the gate is in the `account` phase that runs after `auth`.

---

## 📚 User-Lockout PAM Reference Table

| Task | Command | Notes |
|---|---|---|
| Block all non-root logins, no message | `sudo touch /etc/nologin` | Existence alone trips the gate |
| Block with a one-line banner | `echo "Down for maint" \| sudo tee /etc/nologin` | The banner is shown verbatim to the user |
| Block with a multi-line banner | `sudo tee /etc/nologin <<'EOF' ... EOF` | Heredoc into the file |
| Confirm the lock is in place | `ls -l /etc/nologin && cat /etc/nologin` | Both presence and content |
| Unlock | `sudo rm /etc/nologin` | Effective immediately, no reload needed |
| Confirm a specific stack includes `pam_nologin` | `grep -l pam_nologin /etc/pam.d/*` | Lists every service that honors the lockout |
| Inspect a single stack | `cat /etc/pam.d/sshd` | Look for `account required pam_nologin.so` |
| Block one account at the shell level | `sudo usermod -s /sbin/nologin alice` | Different mechanism; per-account |
| Restore a shell-blocked account | `sudo usermod -s /bin/bash alice` | Per-account undo |
| Lock the password too | `sudo passwd -l alice` | Combines with `nologin` for full lockout |
| Read PAM events | `tail -n 30 /var/log/secure` | Both `pam_nologin` and ssh denials log here |
| Check from the user's side, locally | `su - alice` | If `/etc/nologin` exists, `su -l` should refuse |

> **Rule one of `/etc/nologin`:** It blocks **everyone except root**. UID 0 always gets past. Plan around that — *especially* if you have given a non-root user `sudo`, because their *interactive* session is still gated by `/etc/nologin`, even though their privilege escalation is not.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | "Use PAM to control or restrict access" — `/etc/nologin` is the cleanest, smallest answer the exam can ask for. Two commands and a verification. |
| **RHCE candidate** | Ansible playbooks that perform OS upgrades drop `/etc/nologin` at the start of the play and remove it at the end, gated by `handlers:` and `when: not ansible_check_mode`. |
| **SRE / Platform** | Every maintenance-window runbook on a fleet ends with "rm /etc/nologin and confirm a normal user can log in." The unlock is the single most-missed step in incident reviews. |
| **DevOps** | OS-patching CI jobs create `/etc/nologin` at the start of patching, run the patch, reboot, then remove the file. The banner is the maintenance ticket number. |
| **AI / MLOps** | Shared GPU hosts use `/etc/nologin` plus a banner ("Training run in progress, contact …") to keep researchers off during sensitive jobs. |

---

## 🔧 The 6 Tasks

> Six exam-realistic phases that build the **inventory → understand → lock → verify → distinguish → run-a-window** habit for non-root user lockout.

---

### Task 1 — Inventory which PAM stacks call `pam_nologin`

**Purpose:** Document the full reach of the file. Knowing that `sshd`, `login`, `gdm-password`, `su-l`, `crond`, and a handful of others all consult `pam_nologin` is what makes a single `touch /etc/nologin` so effective. You will produce a list of those files for your own reference.

```bash
sudo -i
cd /root

grep -l pam_nologin /etc/pam.d/*
echo
echo "Total stacks that honor /etc/nologin:"
grep -l pam_nologin /etc/pam.d/* | wc -l
echo
echo "Show the actual line in each:"
grep -n pam_nologin /etc/pam.d/* | head -n 15
```

**Human-Readable Breakdown:** Walk `/etc/pam.d/` looking for every file that includes `pam_nologin.so`. Print the bare filenames, the count, and then the actual matching lines so you can see the control flag (`required`) and the phase (`account`).

**Reading it left to right:** `grep -l pam_nologin /etc/pam.d/*` prints just the filenames where the pattern matches (no line content). The pipe to `wc -l` counts them. The second `grep -n` (without `-l`) shows the matching line and its line number. `head -n 15` keeps the output readable.

**The story:** Before you press the button, look at the blast radius. RHEL 9 ships `pam_nologin` in close to a dozen stacks. That is by design — it means one file controls login across every realistic entry point. Knowing the list helps you reason about a corner case ("did `pam_nologin` block the cron job?") and helps you reassure a stakeholder ("yes, GDM is gated by the same file").

**Expected output:**

```text
/etc/pam.d/crond
/etc/pam.d/gdm-password
/etc/pam.d/login
/etc/pam.d/remote
/etc/pam.d/runuser-l
/etc/pam.d/sshd
/etc/pam.d/su-l

Total stacks that honor /etc/nologin:
7

Show the actual line in each:
/etc/pam.d/crond:1:account    required   pam_nologin.so
/etc/pam.d/gdm-password:3:account   required   pam_nologin.so
/etc/pam.d/login:4:account    required   pam_nologin.so
/etc/pam.d/remote:2:account   required   pam_nologin.so
/etc/pam.d/runuser-l:3:account required   pam_nologin.so
/etc/pam.d/sshd:5:account     required   pam_nologin.so
/etc/pam.d/su-l:3:account     required   pam_nologin.so
```

*(Exact stack count and filenames vary slightly between minor releases. The point is to see that the module is in many places, not in just one.)*

**Switches**

| Token | Meaning |
|---|---|
| `grep -l PATTERN FILE...` | Print just matching filenames |
| `grep -n PATTERN FILE...` | Print filename:line:content for matches |
| `wc -l` | Count lines |
| `head -n N` | First N lines |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `grep` returns nothing | Wrong pattern — confirm it is `pam_nologin` exactly |
| Only one or two files match | `pam-docs` is the wrong package; the module itself ships in `pam` — re-install if missing |
| `/etc/pam.d/sshd` is missing | `openssh-server` may not be installed; install it for the full lab |
| The line uses `account include` not `required` | A custom stack — read the included file to see the actual control flag |

---

### Task 2 — Read the `pam_nologin(8)` manpage and confirm the root carve-out

**Purpose:** Verify the exact behavior from the documentation, not from memory. The two key claims you will confirm: (a) "the contents of the file are displayed to the user" and (b) "root logins are exempt."

```bash
sudo -i

man -P cat pam_nologin | sed -n '/^DESCRIPTION/,/^OPTIONS/p'
echo
echo "--- FILES section ---"
man -P cat pam_nologin | sed -n '/^FILES/,/^SEE ALSO/p'
```

**Human-Readable Breakdown:** Pull the `DESCRIPTION` section (which explains the carve-out for root) and the `FILES` section (which names `/etc/nologin` explicitly). Reading these two sections at the start of the lab anchors every later experiment in the documented behavior.

**Reading it left to right:** Same `man -P cat ... | sed -n` pattern used in Lab 75. `man -P cat` runs `man` with `cat` as the pager so the output is plain text. `sed -n '/A/,/B/p'` prints from the heading `A` to the heading `B` inclusive.

**The story:** The manpage is short. The two facts it documents — "blocks non-root" and "displays the file contents" — are everything you need. Practice extracting these sections quickly; on the exam you will read them under time pressure.

**Expected output:**

```text
DESCRIPTION
       pam_nologin is a PAM module that prevents users from logging into the
       system when /var/run/nologin or /etc/nologin exists. The contents of the
       file are displayed to the user. The pam_nologin module has no effect on
       the root user's ability to log in.

       This module is typically used as an `account' management module.

--- FILES section ---
FILES
       /var/run/nologin
       /etc/nologin
           Files which, if present, cause pam_nologin to deny login to non-root
           users. Their contents are displayed to the user before login is refused.

SEE ALSO
       nologin(5), pam.conf(5), pam.d(5), pam(7)
```

*(Some distributions also check `/var/run/nologin`. Red Hat traditionally only ships the `/etc/nologin` convention. If both files exist, either triggers the lockout.)*

**Switches**

| Token | Meaning |
|---|---|
| `man -P cat NAME` | Run `man` with `cat` as the pager (no paging) |
| `sed -n '/PATTERN1/,/PATTERN2/p'` | Print from PATTERN1 to PATTERN2 |
| `nologin(5)` | The companion manpage describing the file format (just plain text) |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `No manual entry for pam_nologin` | `sudo dnf install -y pam-docs` |
| `DESCRIPTION` is empty | Manpage version mismatch — reinstall `pam-docs` |
| Manpage mentions `/var/run/nologin` only | Some distros migrated to runtime-state path; on RHEL 9 both are checked |

---

### Task 3 — Create `/etc/nologin` with a banner and confirm a non-root login is refused

**Purpose:** Execute the core operation of the lab — drop a `/etc/nologin` file with a clear banner, then prove that an unprivileged account is refused with that exact banner showing in the rejection message. This is the *whole job* on real systems.

```bash
sudo -i

id alice >/dev/null 2>&1 || useradd -m alice
echo "alice:demo-passw0rd" | chpasswd

cat > /etc/nologin <<'EOF'
*** SYSTEM MAINTENANCE WINDOW ***

This system is undergoing scheduled maintenance.
Estimated return time: 03:00 UTC.
Contact: ops@example.com

Root sessions are unaffected during the window.
EOF
chmod 0644 /etc/nologin
ls -l /etc/nologin
echo "--- banner contents ---"
cat /etc/nologin

echo
echo "--- attempt local login as alice from another tty or via su ---"
echo "Run:  su -l alice"
echo "Expected: banner is displayed, then 'su: Permission denied' or similar."
```

**Human-Readable Breakdown:** Make sure a normal user `alice` exists with a known password (creating her if necessary). Write a four-line maintenance banner into `/etc/nologin`. Set the file mode so non-root users can `cat` it themselves for diagnostic purposes. Display the banner so you know what users will see. Then narrate the verification step — `su -l alice` from a root shell will trip the gate without you having to leave the terminal.

**Reading it left to right:** The `id alice >/dev/null 2>&1 || useradd -m alice` pattern creates `alice` only if she does not already exist (so the lab is idempotent). `chpasswd` accepts `user:password` pairs on stdin and sets passwords without interactive prompts. The heredoc writes the banner. `chmod 0644` makes the banner world-readable, which is fine because PAM is going to display it to every refused user anyway.

**The story:** This is "what `/etc/nologin` does" in one demonstration. Open file. Drop banner. Watch a normal user be refused with that exact banner. There is nothing else to learn about the file itself — the rest of the lab is about edge cases (root carve-out, distinguishing from `/sbin/nologin`, the maintenance-window workflow).

**Expected output:**

```text
-rw-r--r--. 1 root root 198 May 26 14:10 /etc/nologin
--- banner contents ---
*** SYSTEM MAINTENANCE WINDOW ***

This system is undergoing scheduled maintenance.
Estimated return time: 03:00 UTC.
Contact: ops@example.com

Root sessions are unaffected during the window.

--- attempt local login as alice from another tty or via su ---
Run:  su -l alice
Expected: banner is displayed, then 'su: Permission denied' or similar.
```

*(When you run `su -l alice` as root, PAM's `account` phase trips and you should see:)*

```text
*** SYSTEM MAINTENANCE WINDOW ***

This system is undergoing scheduled maintenance.
Estimated return time: 03:00 UTC.
Contact: ops@example.com

Root sessions are unaffected during the window.
su: Permission denied
```

**Switches**

| Token | Meaning |
|---|---|
| `useradd -m USER` | Create user with home directory |
| `chpasswd` | Batch password setter via stdin |
| `su -l USER` | Switch user with a full login shell (triggers `/etc/pam.d/su-l`) |
| `chmod 0644` | World-readable, owner-writable file |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `useradd: command not found` | You forgot to `sudo -i` |
| Banner does not appear when `su -l alice` is run | You may have used `su` without `-l`; PAM stack differs |
| Banner appears but `su` succeeds anyway | You ran as root, then forgot `-l`; root's `su` does not trigger `account` |
| `su` says "User does not have a valid password" | `passwd -l alice` was set previously; `passwd -u alice` to unlock the password |

---

### Task 4 — Confirm root is *not* affected by `/etc/nologin`

**Purpose:** Demonstrate the root carve-out experimentally. With `/etc/nologin` still in place from Task 3, verify that switching to root or logging in as root over SSH still succeeds without seeing the banner.

```bash
sudo -i

echo "Confirm /etc/nologin is still in place:"
ls -l /etc/nologin

echo
echo "--- become a non-root user, then su back to root ---"
su -l alice -c "su -l root"   # this WILL prompt for root password
                              # if /etc/nologin exempts root, you get a shell

echo
echo "--- now from a separate ssh session as root ---"
echo "Run:  ssh root@127.0.0.1   (from a different shell, if PermitRootLogin allows)"
echo "Expected: NO banner, login proceeds normally (subject to sshd_config)."
```

**Human-Readable Breakdown:** Confirm `/etc/nologin` is still there. Then run a tricky-but-illustrative chain: `su` to `alice` (which would normally be blocked, but since you are already root and `su -l alice` was about to fail in Task 3 too — we use a different demo). Better: simply confirm root's own SSH login or `su -l` from a non-root user shell.

**Reading it left to right:** The `ls -l` is a sanity check — the file from Task 3 should still exist. The conceptual point is that root's PAM `account` phase still calls `pam_nologin.so`, but the module short-circuits with `PAM_SUCCESS` because `PAM_USER == "root"`.

**The story:** The root carve-out is what makes `/etc/nologin` a maintenance-window tool, not a system-shutdown tool. You retain the ability to administer the system during the window. Every senior administrator who has dropped `/etc/nologin` on a Friday afternoon and then SSH'd back in over the weekend to confirm something has relied on this exact behavior.

**Expected output:**

```text
-rw-r--r--. 1 root root 198 May 26 14:10 /etc/nologin

--- become a non-root user, then su back to root ---
*** SYSTEM MAINTENANCE WINDOW ***

This system is undergoing scheduled maintenance.
Estimated return time: 03:00 UTC.
Contact: ops@example.com

Root sessions are unaffected during the window.
su: Permission denied

--- now from a separate ssh session as root ---
Run:  ssh root@127.0.0.1   (from a different shell, if PermitRootLogin allows)
Expected: NO banner, login proceeds normally (subject to sshd_config).
```

*(The interesting demonstration is `su -l alice -c "su -l root"` failing at the first hop because alice is blocked; but a direct root login on another tty succeeds and prints no banner. Try both to see the contrast.)*

**Switches**

| Token | Meaning |
|---|---|
| `su -l USER -c CMD` | Become USER as a login shell, run CMD, exit |
| `ssh root@127.0.0.1` | SSH to local host as root (subject to sshd_config) |
| `PermitRootLogin prohibit-password` | RHEL 9 default: root SSH allowed with key only |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Root SSH refused | Check `PermitRootLogin` in `/etc/ssh/sshd_config` — it is a separate switch |
| Root login on tty shows banner | You logged in as a different user; confirm with `whoami` |
| `su -l root` works from inside `su -l alice` | Expected — the inner `su -l` evaluates `account` with PAM_USER=root, which exempts |
| You see the banner *then* root succeeds | Some PAM stacks print pam_nologin's message even on success — purely cosmetic |

---

### Task 5 — Distinguish `/etc/nologin` from `/sbin/nologin` (the shell)

**Purpose:** Resolve the most common naming-collision confusion in the lab series. The file `/etc/nologin` is a system-wide PAM lock; the program `/sbin/nologin` is a per-account login refusal that lives in the user's `passwd` shell field. Demonstrate both side-by-side.

```bash
sudo -i

rm -f /etc/nologin
ls -l /etc/nologin 2>/dev/null || echo "system-wide lock removed"

id bob >/dev/null 2>&1 || useradd -m -s /sbin/nologin bob
echo "bob:demo-passw0rd" | chpasswd

getent passwd alice bob

echo
echo "--- attempt to login as bob ---"
su -l bob -c 'echo got-shell'

echo
echo "--- compare what each mechanism produces ---"
file /sbin/nologin
echo
cat /usr/share/man/man8/nologin.8.gz 2>/dev/null | gunzip 2>/dev/null | head -n 20 || \
    man -P cat nologin | head -n 20
```

**Human-Readable Breakdown:** Remove `/etc/nologin` so the system-wide gate is open. Create user `bob` with `/sbin/nologin` as his shell. Compare `alice` (normal shell) and `bob` (nologin shell) in `getent passwd`. Try `su -l bob` and watch it print the canonical "This account is currently not available." message and exit. Confirm that `/sbin/nologin` is a real executable program, not a config file.

**Reading it left to right:** `useradd -m -s /sbin/nologin bob` creates `bob` with the nologin shell. `getent passwd alice bob` prints the `/etc/passwd` lines for both users; you will see `/bin/bash` for alice and `/sbin/nologin` for bob. `su -l bob` tries to exec `/sbin/nologin` as bob's login shell; that program prints the standard refusal banner and exits. `file /sbin/nologin` confirms it is an ELF binary, not a script or data file.

**The story:** Same name, different layer. `/etc/nologin` blocks **the PAM account phase** for everyone except root. `/sbin/nologin` is a tiny **C program** that, when used as a login shell, prints a refusal and exits. You can have both in effect on the same system; they are independent. The exam loves this question.

**Expected output:**

```text
system-wide lock removed
alice:x:1001:1001::/home/alice:/bin/bash
bob:x:1002:1002::/home/bob:/sbin/nologin

--- attempt to login as bob ---
This account is currently not available.

--- compare what each mechanism produces ---
/sbin/nologin: ELF 64-bit LSB pie executable, x86-64, ...
NOLOGIN(8)
NAME
       nologin - politely refuse a login

SYNOPSIS
       nologin

DESCRIPTION
       nologin displays a message that an account is not available and exits non-zero.
       It is intended as a replacement shell field to deny login access to an account.
       If the file /etc/nologin.txt exists, nologin displays its contents to the user
       instead of the default message.

       The exit code returned by nologin is always 1.
```

**Switches**

| Token | Meaning |
|---|---|
| `useradd -s SHELL` | Create user with explicit login shell |
| `getent passwd USER` | Print the `/etc/passwd` line for USER |
| `/sbin/nologin` | Login-refusal binary used as a shell |
| `/etc/nologin.txt` | Optional banner read by `/sbin/nologin` (different file from `/etc/nologin`!) |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Confused which file blocks what | Remember: file `/etc/nologin` = PAM lock for everyone; binary `/sbin/nologin` = shell for one account |
| `su -l bob` prints the default message but you wanted a custom one | Create `/etc/nologin.txt` (text) — read by the *binary*, distinct from `/etc/nologin` |
| `su -l bob` returns no message and exits zero | bob's shell is not actually `/sbin/nologin`; check `getent passwd bob` |
| Cannot read `/usr/share/man/man8/nologin.8.gz` | Use `man -P cat nologin` instead |

---

### Task 6 — Capstone: simulate a maintenance window end-to-end and produce a report

**Task statement:** *"Open a 90-minute maintenance window. Create `/etc/nologin` with a banner naming the change ticket. Prove that user `alice` cannot log in by attempting `su -l alice`. Confirm root is unaffected by logging in via SSH as root in a separate session. Complete the (simulated) work. Close the window. Prove `alice` can log in again. Save a written report to `/root/maint-window-report.txt`."*

**Purpose:** Execute the full maintenance-window pattern an operations engineer runs in production, then produce a single artifact a change manager could attach to the ticket.

```bash
sudo -i
cd /root

TICKET="CHG-2026-0526-DB-MIGRATION"
WINDOW="2026-05-26 02:00 UTC — 2026-05-26 03:30 UTC"

cat > /etc/nologin <<EOF
*** MAINTENANCE WINDOW IN PROGRESS ***

Change ticket : ${TICKET}
Window         : ${WINDOW}
Contact        : ops@example.com

Non-root logins are refused for the duration of the window.
Please try again after the window closes.
EOF
chmod 0644 /etc/nologin

{
  echo "=== window open ==="
  date
  ls -l /etc/nologin
  echo "--- banner ---"
  cat /etc/nologin
  echo
  echo "=== verify alice is blocked ==="
  su -l alice -c 'echo got-shell' 2>&1 || echo "alice refused: expected"
  echo
  echo "=== verify root is exempt ==="
  su -l root -c 'whoami'
} > /root/maint-window-report.txt 2>&1

sleep 2

rm -f /etc/nologin

{
  echo
  echo "=== window closed ==="
  date
  ls -l /etc/nologin 2>/dev/null || echo "/etc/nologin removed"
  echo
  echo "=== verify alice can log in again ==="
  su -l alice -c 'echo got-shell'
} >> /root/maint-window-report.txt 2>&1

echo
echo "Report ready at /root/maint-window-report.txt"
test -s /root/maint-window-report.txt && echo "VERIFY: report exists and is non-empty"
```

**Human-Readable Breakdown:** Set the ticket and window strings as shell variables. Create `/etc/nologin` whose banner contains both. Lock down the file's mode. Then write a structured report into `/root/maint-window-report.txt` containing: open-window timestamp, banner, blocked-user proof, exempt-root proof. Sleep briefly to simulate the work. Remove `/etc/nologin`. Append a close-window section with timestamp and unblocked-user proof. The result is a single audit-quality artifact.

**Layer stack you built:**

```text
/root/maint-window-report.txt        <- the artifact a change manager reads
  ├── window-open timestamp + banner   <- proves the lock went in
  ├── su -l alice failure              <- proves non-root is blocked
  ├── su -l root success               <- proves root is exempt
  ├── window-closed timestamp           <- proves the unlock happened
  └── su -l alice success               <- proves the system returned to normal
```

**The story:** This is the **canonical RHCSA maintenance answer**. The grader cares that you can open the window, prove the lock, and close it cleanly — all without leaving a server in a locked-out state for the weekend. The report file is exactly what your manager wants to see attached to the change ticket. Memorize the spine: `echo banner > /etc/nologin → prove block → do work → rm /etc/nologin → prove unblock`.

**Expected verification output:**

```text
=== window open ===
Tue May 26 14:25:01 UTC 2026
-rw-r--r--. 1 root root 248 May 26 14:25 /etc/nologin
--- banner ---
*** MAINTENANCE WINDOW IN PROGRESS ***

Change ticket : CHG-2026-0526-DB-MIGRATION
Window         : 2026-05-26 02:00 UTC — 2026-05-26 03:30 UTC
Contact        : ops@example.com

Non-root logins are refused for the duration of the window.
Please try again after the window closes.

=== verify alice is blocked ===
*** MAINTENANCE WINDOW IN PROGRESS ***
... (banner repeated by PAM) ...
su: Permission denied
alice refused: expected

=== verify root is exempt ===
root

=== window closed ===
Tue May 26 14:25:03 UTC 2026
/etc/nologin removed

=== verify alice can log in again ===
got-shell
Report ready at /root/maint-window-report.txt
VERIFY: report exists and is non-empty
```

**Cleanup**

```bash
sudo -i

rm -f /etc/nologin
userdel -r alice 2>/dev/null
userdel -r bob 2>/dev/null
rm -f /root/maint-window-report.txt

ls -l /etc/nologin 2>/dev/null || echo "no lockout file present"
getent passwd alice bob || echo "test users removed"
exit
```

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `alice can log in` during the window | `/etc/nologin` is empty or zero-byte — confirm with `cat /etc/nologin` |
| Banner does not appear in the report | The shell redirected stderr separately; use `2>&1` as shown |
| `userdel: user alice is currently used by process` | A session is still active — `pkill -KILL -u alice` first |
| Report is empty | The whole block ran in a subshell; re-check the `{ ... } > FILE` syntax |
| `su -l alice` succeeded during the window | `/etc/nologin` was removed before the test; re-do the sequence |

---

## 🔍 User-Lockout Decision Guide

```
Need to block a user from logging in?
  │
  ├── "Block EVERYONE non-root, system-wide, for a maintenance window"
  │       └── ✅ echo "banner" | sudo tee /etc/nologin
  │             - Affects: login, sshd, gdm, su -l, cron, ...
  │             - Affects: every non-root account
  │             - Root: still allowed
  │             - Unlock: rm /etc/nologin
  │
  ├── "Block ONE account permanently from interactive use"
  │       └── ✅ sudo usermod -s /sbin/nologin alice
  │             - Affects: alice only
  │             - Mechanism: shell exec refuses
  │             - Unlock: usermod -s /bin/bash alice
  │
  ├── "Block one account temporarily (lock the password)"
  │       └── ✅ sudo passwd -l alice
  │             - Affects: password auth for alice
  │             - SSH key auth: still allowed (use AllowUsers to lock that too)
  │             - Unlock: passwd -u alice
  │
  ├── "Block by service: deny SSH to a specific user list"
  │       └── ✅ pam_listfile.so or sshd_config DenyUsers (Lab 77)
  │
  └── "Block by IP (network layer)"
          └── ✅ firewalld / hosts.allow / sshd_config Match address ...
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Inventory which PAM stacks include `pam_nologin.so` (login, sshd, gdm-password, su-l, crond, …)
- [ ] 02 Read `pam_nologin(8)` and confirm the root carve-out
- [ ] 03 Create `/etc/nologin` with a banner, confirm a normal user (`alice`) is refused with that banner
- [ ] 04 Confirm root is unaffected while `/etc/nologin` is in place
- [ ] 05 Distinguish `/etc/nologin` (system-wide PAM lock) from `/sbin/nologin` (per-account shell)
- [ ] 06 Execute the full maintenance-window capstone and produce `/root/maint-window-report.txt`

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| Confused `/etc/nologin` with `/sbin/nologin` | Wrong mechanism applied | One is a file (system-wide), the other is a shell (per-account) |
| Forgot to remove `/etc/nologin` after the window | Users locked out indefinitely | Always end the runbook with `rm /etc/nologin && getent passwd ...` |
| Made `/etc/nologin` mode `0600` | Banner not visible to refused users in some PAM configs | `chmod 0644` so PAM can read and display content |
| Expected `/etc/nologin` to block root | Root still got in | By design — read `pam_nologin(8)` DESCRIPTION |
| Edited `/etc/pam.d/sshd` to "add nologin" | Already there on RHEL 9 | Confirm with `grep pam_nologin /etc/pam.d/sshd` before editing |
| Made the banner with a heredoc that ate variables | Banner shows literal `${TICKET}` | Use `EOF` (no quotes) to enable variable expansion; `'EOF'` to disable |
| Did not test from a non-root account | Did not realize the lock worked | Always `su -l alice -c ...` as the verification step |
| Forgot the file is consulted on cron | Scheduled jobs run as users fail during the window | This is sometimes desired; document it in the runbook |
| Used `touch /etc/nologin` (empty file) | Lock works, but users see no message | Acceptable, but a banner is better for end users |
| Created `/etc/nologin.txt` and expected it to lock | No effect | That filename is read by the `/sbin/nologin` binary, not by PAM |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- A direct exam answer to "prevent any non-administrative login" is one command: `echo "..." | sudo tee /etc/nologin`. Verify with `su -l <normal user>`. Total time: 30 seconds.

**RHCE candidate**
- Ansible: a `community.general.pamd` or `ansible.builtin.copy` task drops the banner, the play does its work, an `always:` block in `block:/rescue:/always:` removes the file. The `always:` is what makes the playbook safe.

**SRE / Platform interview**
- "How do you keep users off a host during a 30-minute migration?" → `/etc/nologin`. Bonus: explain how it interacts with cron, gdm, and SSH so the interviewer knows you have actually used it.

**DevOps**
- Patching pipelines (e.g. `dnf-automatic` + Ansible) drop `/etc/nologin` at the start and remove it after reboot. The banner contains the change-management ticket number for traceability.

**AI / MLOps**
- Multi-tenant GPU boxes lock with `/etc/nologin` plus a banner explaining the training run and the contact for emergencies. The block survives reboots if you leave the file in place (which is fine).

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab — Configure PAM to Limit root Access | The root-side counterpart — `pam_securetty.so` and `/etc/securetty` |
| Lab — Restrict Service Access by User List | Per-service lockout with `pam_listfile.so` |
| Lab — PAM Config Files | The `auth account password session` stack mechanics |
| Lab — SSH Key-Based Auth | The companion control plane for the SSH side |
| Lab — TCP Wrappers (`hosts.allow` / `hosts.deny`) | The IP-layer companion to PAM's user-layer policy |
| Lab — File Searching with `find` | Used in cleanup verification (search for stray nologin files) |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
