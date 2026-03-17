# 🐧 OLSSA
## Obfuscated Luau Script Security Auditor by Indirecta

> [!WARNING]
> The main OLSSA script is currently being refactored. Please use the original `olssa.v3.alpha.server.lua` for the time being.

OLSSA is a powerful tool designed for Roblox developers to analyze, reverse engineer, and secure their games from malicious obfuscated scripts. It provides a suite of spoofing and logging utilities to help you "liberate" your code.

---

## 📌 Introduction

OLSSA (Obfuscated Luau Script Security Auditor) allows you to gain visibility into what obfuscated scripts are doing. By intercepting core Luau functions and Roblox services, OLSSA can log activity, prevent malicious requests, and help you understand the internal logic of otherwise opaque code.

---

## 🔩 How to Use

### 1. Copy the Snippet
Navigate to the latest OLSSA snippet file (e.g., `src/olssa.v3.alpha.server.lua`) and copy the contents to your clipboard.

### 2. Inject into Script
In Roblox Studio, paste the OLSSA snippet at the **very top** of the obfuscated script you wish to inspect.

> [!IMPORTANT]
> Ensure all original code from the obfuscated script is placed **under** the `-- !! OLSSA Auditor Snippet End !!` comment.

### 3. Analyze & Adapt
- **Monitor Output:** Watch the output window for logs from OLSSA.
- **Handle Dependencies:** If the script requires other modules, you may need to use the `REQUIRE_SPOOF` utility.
- **Tinker:** Adjust settings in the configuration section of the snippet to suit the specific obfuscation you are facing.

---

## ⚙️ Configuration

OLSSA is highly configurable. Below are the primary settings you can adjust within the snippet.

### 🛠️ General Settings
| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `VERBOSE` | `boolean` | `true` | Log all spoof actions and script activity. |
| `EXTRA_VERBOSE` | `boolean` | `false` | Enable experimental logs (e.g., metamethods). Use with caution. |
| `REVISION` | `string` | `"alpha-v2.4"` | The revision label for the snippet. |
| `LOG_WHITELIST` | `string` | `nil` | Lua pattern to filter logs (only show matches). |
| `LOG_BLACKLIST` | `string` | `nil` | Lua pattern to exclude specific logs. |

### 📦 Require Spoofing
| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `REQUIRE_SPOOF` | `boolean` | `true` | Spoof `require` to load local modules instead of online IDs. |
| `REQUIRE_PREFIX` | `string` | `"_OLSSA-"` | Prefix for local spoofed modules (e.g., `_OLSSA-12345`). |
| `REQUIRE_SPOOF_FOLDER` | `Instance` | `workspace` | The container where OLSSA looks for spoofed modules. |

### 🔒 Security & Sandboxing
| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `GAME_SPOOF` | `boolean` | `true` | Enables service-level spoofs (Marketplace, Http, etc). |
| `SANDBOX_FUNCS` | `boolean` | `true` | Attempts to set environments of functions found in modules to the base script env. |
| `SPOOF_FENV` | `boolean` | `true` | Uses metatables on the environment instead of manual redefinition. |
| `WRAP_GAME_SEC` | `boolean` | `true` | Wraps the `game` global for deeper interception. |

---

## 🛠️ Developer Tooling

This repository follows standard Roblox Luau development practices for maintainability and code quality.

### 💂 Toolchain
We use [Aftman](https://github.com/LPGhatguy/aftman) to manage our tools:
- **Rojo**: For syncing code into Roblox Studio.
- **StyLua**: For consistent code formatting.
- **Selene**: For static analysis and linting.

### 🚀 Commands
- **Format Code:** `stylua src`
- **Lint Code:** `selene src`
- **Run Tests:** Use `test.project.json` with Rojo to sync and run tests via TestEZ.

---

## ⚠️ Disclaimer

### 👤 User Responsibility
You are responsible for using OLSSA in an ethical and responsible manner. OLSSA is intended for **educational purposes and security auditing**. Always respect intellectual property rights and licensing agreements.

### 🗒️ License
OLSSA is released under the [GNU General Public License (GPL) V3](https://www.gnu.org/licenses/gpl-3.0.html).

---

### [GitHub Repository](https://github.com/Indirecta-Technologies/olssa)
