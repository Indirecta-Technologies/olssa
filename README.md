# 🐧 OLSSA
### Obfuscated Luau Script Security Auditor

![Rojo](https://img.shields.io/badge/Rojo-v7.0.0-red)
![StyLua](https://img.shields.io/badge/StyLua-v0.15.0-blue)
![Selene](https://img.shields.io/badge/Selene-v0.25.0-green)
![License](https://img.shields.io/badge/License-GPLv3-yellow)

OLSSA is a professional-grade security hypervisor for the Roblox Luau engine. It intercepts and logs every interaction between an untrusted "Guest" script and the DataModel by siloing execution into a sandboxed environment. OLSSA reveals malicious logic, prevents exfiltration, and assists in the deobfuscation of protected code without being detected by standard anti-tamper suites.

---

## 🚀 Quick Start

To audit a script, paste the OLSSA source at the **absolute top** of the target script.

```lua
--!native
--!nonstrict
--[[
    ASCII Header Truncated ...
]]

-- [ ... OLSSA Source Code ... ]

-- !! OLSSA Auditor Snippet End !!

-- Target guest code to audit starts here
print(game.PlaceId) 
```

---

## 📊 Understanding Logs

OLSSA implements a non-intrusive logging pipeline that caches and flushes traces via `Heartbeat` to avoid deoptimizing the guest's execution loop.

**Format:** `[OLSSA] ScriptPath (l<Level> <Time>ms) <Content>`

| Level | Type | Description |
| :--- | :--- | :--- |
| **l1** | **Activity** | Standard service calls (Http, DataStore), property reads, and engine interactions. |
| **l2** | **Spoof** | Notifications when a native value is intercepted and substituted for a spoofed result. |
| **l3** | **Meta** | Metamethod triggers (index/newindex). Automatically includes stack traces for site analysis. |
| **l4** | **Deep** | Full recursive `_dump` of tables, allowing analysis of complex argument structures. |

---

## 📖 Exhaustive Configuration Documentation

The `CFG` table is the control center of the OLSSA Auditor. Below is a deep-dive into every configurable parameter, its internal behavior, and the security implications of its use.

### 🛡️ 1. Environment & Sandboxing (`CFG.environment`)
The core of the "Hypervisor" model. This section determines how the guest script's global table is virtualized.

#### `environment.wrap` (Default: `true`)
*   **Behavior:** When enabled, OLSSA executes `setfenv(1, _fenv)` at the end of initialization. This forks the environment, meaning any access to a global (like `_G`, `game`, or `print`) is routed through OLSSA's proxy table.
*   **Security Implication:** Mandatory for full stealth. Without this, the guest can access the real global environment and bypass all hooks. Note that calling `setfenv` disables Luau's "fastcall" optimizations for the script.

#### `environment.light` (Default: `true`)
*   **Behavior:** Controls the depth of the recursive wrapping engine. In "light" mode, OLSSA attempts to pass through non-essential primitive values without generating heavy metadata caches.
*   **Usage:** Disable (`false`) only if the guest script is performing highly sophisticated type-checks on primitive returns.

---

### 🧱 2. Stack Protection (`CFG.stack`)
Modern anti-tamper scripts scan the call stack via `getfenv(level)` to find evidence of an auditor.

#### `stack.mode` (Options: `"guarded"`, `"strict"`, `"passthrough"`)
*   **`guarded` (Recommended):** Returns the spoofed environment (`_fenv`) for levels 0 through `CFG.stack.depth`. Access beyond that depth results in a native engine error. This perfectly mimics native behavior while protecting the auditor's local scope.
*   **`strict`:** Returns `_fenv` for *every* numeric level. This is highly secure but technically a deviation from native behavior, as `getfenv(9999)` would normally error.
*   **`passthrough`:** Only protects levels 0 and 1. Vulnerable to stack-scanning scripts that check `getfenv(2)`.

#### `stack.depth` (Default: `12`)
*   **Behavior:** The maximum level at which `getfenv` returns the sandbox environment when in `guarded` mode.

---

### 🕵️ 3. Stealth & Logging (`CFG.logs`)
Controls the visibility of the auditor's footprint and the granularity of its traces.

#### `logs.verbose` (Default: `2`)
*   **Levels:**
    *   `0`: Silent mode.
    *   `1`: Logs activity (service calls, method executions).
    *   `2`: Logs spoof notifications (when a value is swapped).
    *   `3`: Logs metamethod access + stack traces for every `__index`.
    *   `4`: Recursive table dumps for all arguments.

#### `logs.stealth` (Default: `true`)
*   **Behavior:** Intercepts `LogService.MessageOut` and `ScriptContext.Error`. It wraps these signals and filters out any message string containing the internal session `_ID`.
*   **Security Implication:** Prevents the guest from using a "bottom-up" detection strategy by monitoring its own logs for OLSSA identifiers.

#### `logs.shadow` (Default: `true`)
*   **Behavior:** Hooks the guest's `print()` and `warn()` functions. If the guest attempts to print the session `_ID` (to "prove" an auditor is present), OLSSA suppresses the output.

---

### ⚡ 4. Runtime Performance (`CFG.performance`)
Advanced optimizations for auditing scripts that perform hundreds of thousands of operations per second (e.g., LST or fix).

#### `performance.fast_resolve` (Default: `true`)
*   **Behavior:** The `resolve()` engine normally performs a recursive validation chain. In `fast_resolve` mode, it performs an O(1) check against the inverse cache (`_U`). If the object is already a proxy, it returns immediately.
*   **Security Implication:** Reduces the compute footprint of the auditor, making it harder to detect via performance-timing attacks.

#### `performance.shared_meta` (Default: `true`)
*   **Behavior:** Forces Instance Userdata proxies to use globally pre-allocated metamethods.
*   **Direct Benefit:** Eliminates 11 closure allocations per Instance proxy. This prevents "exhausted allowed execution time" errors caused by massive Garbage Collection (GC) sweeps.

#### `performance.memoize_globals` (Default: `true`)
*   **Behavior:** Caches resolved globals inside the `_fenv` table for O(1) rawget speed.
*   **Benefit:** Resolves timeouts in scripts that perform intensive global lookups in hot loops.

#### `performance.stealth_getfenv` (Default: `true`)
*   **Behavior:** Adds a stealthy `__iter` hook to the environment.
*   **Benefit:** Ensures `pairs(getfenv())` matches native behavior and bypasses "empty environment" detection.

---

### 🕰️ 5. Temporal Dilation (`CFG.time`)
Spoofing the script's perception of time to hide high-latency hooks.

#### `time.hook` (Default: `true`)
*   **Behavior:** Hooks `tick()`, `time()`, `os.clock()`, `os.time()`, and `DateTime.now`.

#### `time.dilation` (Default: `0.15`)
*   **Behavior:** The guest's perceived time runs at 15% of real-world speed.
*   **Why:** Hypervisor hooks introduce latency. By dilating time, the guest script perceives a `0.1s` hook execution as lasting only `0.015s`, making the hook appear instantaneous.

---

### 📦 6. Module & Identity Hooking (`CFG.require`, `CFG.game`, `CFG.players`)

#### `require.hook` (Default: `true`)
*   **Behavior:** Intercepts `require(id)`. If `CFG.require.mock` is true, it can return a generic proxy table. Otherwise, it looks for a ModuleScript named `OLSSA:<ID>` inside `CFG.require.folder` (Default: `workspace`).
*   **Usage:** Drop a ModuleScript named `OLSSA:12345` into Workspace to override any script attempting to load asset ID 12345.

#### `game.creator` / `university` / `place`
*   **Behavior:** Spoofs the DataModel identity.
*   **Example:** `{ spoof = true, type = "User", id = 123456789 }` makes `game.CreatorId` return 123456789.

#### `players.localplayer`
*   **Behavior:** Forces the identity of the `LocalPlayer`.
*   **Usage:** Set `CFG.players.localplayer.name = "Guest"` to fool scripts that whitelist specific usernames.

---

### 🧪 7. Diagnostics (`CFG.selftest`)
Internal suite to verify the integrity of the resolution engine and proxy caches before allowing the guest script to execute.

#### `selftest.enabled` (Default: `true`)
*   **Behavior:** On boot, OLSSA runs a sequence of ~50 functional tests (Categories: `typeof`, `pairs`, `getfenv`, `rawget`, etc.) inside a local test harness. 
*   **Recommendation:** Always leave enabled to catch regressions or engine-side profile changes that might break proxy identity.

#### `selftest.halt_on_fail` (Default: `false`)
*   **Behavior:** If `true`, the auditor calls `error()` and terminates if a single test fails. Helpful for CI/CD pipelines but potentially risky in a production audit.

---

### 🧱 8. Blacklisting & Raw Access (`CFG.wrapper`)
Determines which objects or keys should bypass the hypervisor and remain native (unwrapped).

#### `wrapper.blacklist.enabled` (Default: `true`)
*   **Behavior:** The master toggle for the bypass engine.

#### `wrapper.blacklist.values` (Default: `{ pairs, ipairs, next }`)
*   **Why:** These are high-frequency iteration primitives. Wrapping them introduces significant O(N) overhead. By keeping them raw, OLSSA maintains near-native performance during table scans.

#### `wrapper.blacklist.keys` (Default: `{}`)
*   **Behavior:** A list of string keys (e.g., `"GetFullName"`) that, when indexed on ANY object, always return the raw C++ function instead of a proxy. 

---

### 🛡️ 9. Advanced Hooking (`CFG.require`, `CFG.debug`)

#### `require.mock` (Default: `true`)
*   **Behavior:** If the redirection lookup fails (no `OLSSA:` module found), OLSSA returns an empty proxy table `{}`. 
*   **Use Case:** Allows the audit to continue past missing dependency scripts to find further malicious logic.

#### `debug.cmask` (Default: `true`)
*   **Internal Logic:** Uses a C-function name map (`_CFNS`). When `debug.info(wrapped_fn, "s")` is called, OLSSA intercepts it and returns `"[C]"` if the function originates from the native environment.
*   **Security Implication:** Hard-counters "lazy" stack-checking scripts that look for Lua-based function sources.

#### `debug.stealth` (Default: `true`)
*   **Behavior:** If a guest script "steals" a C metamethod (e.g. `getmetatable(game).__index`) and attempts to call it raw, OLSSA detects the theft and replaces the stolen reference with a safe, wrapped proxy.

---

### 🛠️ 10. Manual Injection (`CFG.globals`)
Allows force-injecting custom proxies into the guest's environment.

#### `globals` (Array)
*   **String Entry:** `globals = { "script" }`. Automatically wraps the native `script` global with default permissions.
*   **Table Entry:** `{ k="SecretAPI", v=myProxy }`. Injects `myProxy` into the guest's global table under the key `"SecretAPI"`.

---

## 🚦 Common Audit Scenarios

---

## 🛡️ Ethical Disclaimer

**USE RESPONSIBLY.** OLSSA is a tool designed for **educational research, security auditing, and malware analysis**. 
*   **Permissions:** Only use OLSSA on codebases where you have explicit authorization to perform security audits.
*   **Compliance:** Respect all license agreements associated with audited software.
*   **Intent:** OLSSA is a passive auditor. It is not designed to assist in unauthorized access or service disruption.

The developers of OLSSA are not responsible for any misuse of this tool.

---

## ⚓ License & Copyright

OLSSA is open-source software licensed under the **GNU General Public License v3.0**. 
