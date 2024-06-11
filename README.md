# 🐧 OLSSA
## Obfuscated Luau Script Security Auditor by Indirecta

## 📌 Introduction

OLSSA by Indirecta is a short code snippet that allows Roblox game developers to analyze, reverse engineer and liberate their game from malicious obfuscated scripts.

## 🔩 How to use
### 1. Copy to clipboard
- Navigate to the latest OLSSA snippet file and copy it to the clipboard
### 2. Insert inside script
- Navigate to studio, and paste the contents of the OLSSA snippet file at the top of the obfuscated script you wish to inspect.  
- ⚠️ Make sure the previous contents of the obfuscated scripts are all under `-- !! OLSSA Auditor Snippet End !!`
### 3. Tinker & Adapt
- After pasting the OLSSA snippet, it's natural that the altered script might encounter some errors during the course of it's execution.  
- If you see other obfuscated module scripts being required, it is recommended to use the built-in require spoofing utilit and inserting OLSSA in all required modules
- The default OLSSA configuration might not work for your usecase, try tinkering with different combinations of settings related to OLSSA security/efficiency  
- 🏷️ If you still encounter issues, open an issue in the [OLSSA GitHub repository](https://github.com/Indirecta-Technologies/olssa/issues), and a new OLSSA version with increased general support will be released ASAP! 

## ⚙️ Configuration
What each setting does, explained as best as possible. Keep in mind everything's experimental and some settings might break others.
### General
- ### `VERBOSE` **boolean**
  ```js
  true
  ```
  - Whether or not to log all spoof actions, requests, script activity  
  - Set this to false if you do not want to see anything from OLSSA printed to output
- ### `EXTRA_VERBOSE` **boolean**
  ```js
  false
  ```
  - Set this to true to enable output from extra, experimental, logs like metamethods that may potentially spam the output or crash the script
- ### `REVISION` **string**
  ```js
  "alpha-v2.3"
  ```
  - OLSSA Snippet Revision  
  - It is recommended not to change this, but you can use it to label different OLSSA snippet configurations
- ### `LOG_WHITELIST` **string**
  ```js
  nil
  ```
   - Set this to a string with a valid lua pattern that will match your desired logs  
   - When the pattern matches it will prevent __all other__ verbose logs from printing to console
- ### `LOG_BLACKLIST` **string**
  ```js
  nil
  ```
   - Set this to a string with a valid lua pattern that will match your undesired logs  
   - When the pattern matches it will prevent the undesired verbose log from printing to console

### Require
- ### `REQUIRE_SPOOF` **boolean**
  ```js
  true
  ```
   - With this enabled, OLSSA will spoof the script's require function so that local modules with a prefix (see next setting) will be required instead of external Roblox MainModules
- ### `REQUIRE_PREFIX` **string**
  ```js
  "_OLSSA-"
  ```
   - The prefix used in the name of spoofed modules (eg. _OLSSA-1234567890)  
   - Each spoofed module has to be inside `REQUIRE_SPOOF_FOLDER` (by default workspace)
- ### `REQUIRE_LOCALMODRDF` **function**
  ```js
  nil
  ```
   - Redefine a local module's instance variable working up from one of it's parents  
   - When a local modulescript is being required, call a function (REQUIRE_LOCALMODRDF) with the modulescript's parent as the first argument, and the modulescript's name as the second  
   The value in this function is nil by default, but can be set to searching functions like `FindFirstChild`, `FindFirstAncestor`, `FindFirstDescendant`, `WaitForChild`, etc.
- ### `REQUIRE_SPOOF_FOLDER` **instance**
  ```js
  workspace
  ```
  - The instance that will contain all of the local versions of the modulescripts that OLSSA will look for when spoofing
## Game & Services
- ### `GAME_SPOOF` **boolean**
  ```js
  true
  ```
    - Enables all the game services spoofs below
- ### `CREATOR_SPOOF` **instance**
  ```js
  true
  ```
    - Spoofs / returns fake information about the game creator when enabled
- ### `CREATOR_OBJ` **table**
    - Contains the spoofed creator information. CreatorType can be either User or Group
    - By default set to user Roblox
    ```js
    ["CreatorType"] = Enum.CreatorType.User,
    ["CreatorId"] = 1,
     ```  
    - ### `CreatorType` **Enum.CreatorType**
    - ### `CreatorId` **number**
- ### `GAMEID_SPOOF` **boolean**
- Spoofs / returns fake information about the game when enabled
- ### `GAMEID_OBJ` **table**
    - Contains the spoofed game information.
    - By default set to the Welcome to Roblox Building
     ```js
    ["GameId"] = 18836269;
	["PlaceId"] = 41324860;
     ```  
    - ### `GameId` **number**
    - ### `PlaceId` **number**
- ### `MARKETPLACESERVICE_SPOOF` **boolean**
     ```js
    true
     ```
    - Returns true on all MarketplaceService UserOwnsGamePassAsync checks
- ### `MARKETPLACESERVICE_SPOOF_SEC` **boolean**
    ```js
     true
     ```
    - Enables the spoof only if the original check was successful (didn't error)
- ### `RUNSERVICE_ISSTUDIO_SPOOF` **boolean**
  ```js
     true
     ```
  - Spoofs all RunService:IsStudio() checks with the value of the setting below

- ### `RUNSERVICE_ISSTUDIO_VALUE` **boolean**
  ```js
     false
     ```
  - The value to spoof all RunService:IsStudio() checks with
- ### `HTTPSERVICE_ENABLED_SPOOF` **boolean**
  ```js
     true
     ```
  - Spoofs the HttpService.HttpEnabled value to true
- ### `HTTPSERVICE_REQUEST_SPOOF` **function**
  ```js
     function(oldhttpservice, url, method, body, headers)

			return nil
		end;
     ```
  - This function is called by the spoofed HttpService every time a request is sent
  - You can return data instead of nil and it will be used to spoof the incoming Http Response
  - The return data format is that of the Roblox's [HttpService RequestAsync response table](https://create.roblox.com/docs/it-it/reference/engine/classes/HttpService#RequestAsync)
- ### `HTTPSERVICE_OPTIONS_SPOOF` **function**
  ```js
     function(oldhttpservice, url, method, body, headers)

			return nil
		end;
     ```
  - This function is called by the spoofed HttpService every time a request is sent
  - You can return data instead of nil and it will be used to spoof the outgoing Http Options
  - The return data format is that of the Roblox's [HttpSerice RequestAsync request table](https://create.roblox.com/docs/it-it/reference/engine/classes/HttpService#RequestAsync)
## Spoof
- ### `SPOOF_ANTISET_SEC` **boolean**
   ```js
    false
     ```
  - Attempts to prevent spoofed variables from being changed using rawset
  - Some obfuscated scripts' VMs (like Luraph) loop or crash when rawset, rawget globals are redefined 
- ### `SPOOF_GAMESERVICES_SEC` **boolean**
  ```js
    true
     ```
  - Wraps service instances so that when their Parent is indexed, the same spoofed game instance is returned
- ### `WRAP_GAMESERVICES_SEC` **boolean**
  ```js
    true
     ```
  - Works in conjuction with SPOOF_GAMESERVICES_SEC to wrap the service instances using __olssa_wrap
- ### `WRAP_SCRIPT_SEC` **boolean**
  ```js
    true
     ```
  - Wraps the script global instance using __olssa_wrap
- ### `LOCAL_MAINMODULE_NAME_SEC` **boolean**
  ```js
    true
     ```
  - When spoofed online modules are required, attempts to return the usual "MainModule" name for the required Module Instance instead of the original name
- ### `SANDBOX_FUNCS` **boolean**
  ```js
    true
     ```
  - If any functions* are found inside required ModuleScripts, attempt to set their environment to the base script env (the requiring script)
  - * Some ModuleScripts (funnily enough) could voluntarily return tables with modified metatable pointers to loop the OLSSA function that recursively searches for functions in the returned data, as such, there is a max amount of `16380 - 5` supported tables inside tables, before halting the search.
  - As this function currently (and undesirably) sets the env to that of the base env, without manually spoofing other unique variables, it could set the same script global and cause instance parent & "identity" conflicts, it is recommended to simply spoof the online modules & re-use the olssa snippet on top of those instead of using `SANDBOX_FUNCS`.
- ### `SPOOF_FENV_SEC` **boolean**
  ```js
    false
     ```
  - Prevents getfenv and setfenv from targeting the base script environment (redefining certain variables)
  - Some obfuscated scripts' VMs (like Luraph) loop or crash when getfenv, setfenv globals are redefined 
- ### `FENV_WHITELIST` **table**
  ```js
    {"require"; "game"; "workspace"}
     ```
    - The list of globals to protect using `SPOOF_FENV_SEC`
- ### `SPOOF_FENV` **boolean**
  ```js
    true
     ```
  - Replaces the baseEnv meta table with the custom globals instead of redefining them manually


## ⚠️ Disclaimer

### 👤 User Responsibility

You are responsible for using OLSSA in an ethical and responsible manner.  
OLSSA is intended for educational purposes, it is your own responsibility to respect intellectual property rights, licensing agreements, and the creative efforts of fellow developers.  

### 🗒️ GPL v3 License

OLSSA is released under the [GNU General Public License (GPL) V3](https://www.gnu.org/licenses/gpl-3.0.html).  
This license provides you with the freedom to study, modify, and distribute the code under certain conditions. 

### [GitHub Repo](https://github.com/Indirecta-Technologies/olssa)
