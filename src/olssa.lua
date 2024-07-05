--[[

    `/shdmmmmmmmmmd-`ymmmddyo:`       //                sm- /h/                        --
  `yNMMMMMMMMMMMMm-.dMMMMMMMMMN+     `MN  `-:::.`   .-:-hM- -o-  .-::.  .::-.   `.:::` MN--. `-::-.
  yMMMMMMMMMMMMMd.:NMMMMMMMMMMMM+    `MN  yMs+oNh  oNy++mM- +Mo -Mm++:`hmo+yN+ .dmo++- MNoo/ `o+odN:
  yMMMMMMMMMMMMy`+NMMMMMMMMMMMMM+    `MN  yM:  dM. MN   yM- +Mo -Mh   /Mmss    sM+     MN    +h ohMo
  `yNMMMMMMMMMo`sMMMMMMMMMMMMMNo     `MN  yM:  dM. oNy//dM- +Mo -Mh   `dNs++o. -mm+//- dM+/+ mN+/sMo
    `/shddddd/ odddddddddddho:`       ::  .:`  -:   `:///-` .:. `:-     .://:`  `-///. `-//: `-///:.
   ___  _     ____ ____    _
  / _ \| |   / ___/ ___|  / \     (v)
 | | | | |   \___ \___ \ / _ \   //-\\
 | |_| | |___ ___) |__) / ___ \  (\_/)
  \___/|_____|____/____/_/   \_\ _v v_

  Obfuscated Luau Script Security Audtor (OLSSA) by  ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
		<https://www.gnu.org/licenses/gpl-3.0.html>
]]

-- ⚠️ Make sure to use the auditor at the top of any script to prevent environment leaks ⚠️

local baseEnv = getfenv()
do
	local __olssa_configuration = {

		["REVISION"] = "expalpha-v3"; -- OLSSA Snippet Revision

		------ LOGGING ------
		["VERBOSE"] = true; -- Whether or not to log all spoof actions, requests, script activity
		["EXTRA_VERBOSE"] = false; -- Experimental, logs activity such as indexes from metamethods
		["LOG_WHITELIST"] = nil; -- Set this to a string with a valid lua pattern that will match your desired logs. When the pattern matches it will
		-- **only allow the desired OLSSA log to send** to console
		["LOG_BLACKLIST"] = nil; -- Set this to a string with a valid lua pattern that will match your desired logs. When the pattern matches it will
		-- **prevent the undesired OLSSA log from sending** to console

		------ REQUIRE ------

		["REQUIRE_SPOOF"] = true; -- Whether or not to spoof the modules required with custom scripts in workspace
		["REQUIRE_PREFIX"] = "_OLSSA-"; -- The prefix used in the name of spoofed modules (eg. _OLSSA-1234567890)
		["REQUIRE_LOCALMODRDF"] = nil; -- Redefine a local module's instance variable working up from one of it's parents
		["REQUIRE_SPOOF_FOLDER"] = workspace; -- Where to look for the local modules when spoofing

		------ GAME & SERVICE SPECIFIC SPOOFS ------

		["GAME_SPOOF"] = true; -- Handles all the game service and variable spoofs below

		["CREATOR_SPOOF"] = true; -- Whether or not to return a spoofed version of CreatorId and CreatorType
		["CREATOR_OBJ"] = {
			["CreatorType"] = Enum.CreatorType.User,
			["CreatorId"] = 1,
		}; -- Spoofed object to return, respectively game.CreatorType and game.CreatorId

		["GAMEID_SPOOF"] = true; -- Whether or not to spoof game.PlaceId and game.GameId
		["GAMEID_OBJ"] = {
			["GameId"] = 18836269;
			["PlaceId"] = 41324860;
		};

		["MARKETPLACESERVICE_SPOOF"] = true; -- Returns true on all MarketplaceService UserOwnsGamePassAsync checks
		["MARKETPLACESERVICE_SPOOF_SEC"] = true; -- Reutrns true on all checks only if the check was successful (no errors)

		["RUNSERVICE_ISSTUDIO_SPOOF"] = true; -- Returns the value below on all RunService:IsStudio() checks if set to true
		["RUNSERVICE_ISSTUDIO_VALUE"] = false; -- The value to spoof the :IsStudio() check with

		["HTTPSERVICE_ENABLED_SPOOF"] = true; -- Spoofs the HttpService.HttpEnabled value to true

		["HTTPSERVICE_REQUEST_SPOOF"] = function(oldhttpservice, url, method, body, headers)
			-- This function is fired by the spoofed HttpService every time an online request is attempted
			-- Use this function to implement advanced spoofs on different types of requests
			-- Return a value other than nil and it will replace the value returned by the called HTTP request

			return nil
		end;

		["HTTPSERVICE_OPTIONS_SPOOF"] = function(oldhttpservice, url, method, body, headers)
			-- This function is fired by the spoofed HttpService every time an online request is attempted
			-- Use this function to implement advanced spoofs on different types of requests
			-- Return a value other than nil and it will replace the options used for the HTTP request

			return nil
		end;

		------ OBJECT WRAPPING & SPOOFING BEHAVIOR ------

		["RAWSET_SEC"] = false; -- Attempts to lock the spoofed variables (game and require) from being changed using rawset
		["WRAP_GAMESERVICES_SEC"] = true; -- Wraps any Instance accessed from SERVICE with a proxy
		["WRAP_SCRIPT_SEC"] = true; -- Same as above, for script global
		["WRAPPED_PARENT_SPOOF_SEC"] = true; -- Attempts to return the same game spoof when SERVICE.Parent is indexed. (requires WRAP enabled)
		["LOCAL_MAINMODULE_NAME_SEC"] = true; -- Attempts to return original "MainModule" as the name for local spoofed online modules instead of the different name
		["UNWRAP_TYPEFUNCTIONS_SEC"] = true; -- Wraps typechecking functions like type, typeof, Instance.new so that the arguments get unwrapped, resulting in normal behavior

		["SANDBOX_FUNCS"] = true; -- A limited attempt to spoof the require and game variables inside all functions found in require results
		-- Works only if REQUIRE_SPOOF is enabled, and spoofs game only if GAME_SPOOF is enabled
		-- For more advanced auditing, please spoof the modules as local copies in workspace and reuse this script at the top.

		["GETSETFENV_SEC"] = false; -- Attempts to prevent further getfenv and setfenv calls from targeting the base script environment
		["FENV_WHITELIST"] = {"require"; "game"; "workspace"}; -- List of globals to protect using previous setting

		["FENV_MODE"] = -1; -- Replaces the baseEnv meta table with the custom globals instead of redefining them manually (-1: disabled, 0: fenv level 0; 1: fenv level 1; etc.)
		["WRAP_OTHER_GLOBALS"] = {}; -- Requires 'FENV_MODE' to be >= 0, wraps other globals and global functions so that their arguments will always be unwrapped
	}
	
	debug.setmemorycategory(script.Name.." - OLSSA "..__olssa_configuration.REVISION)

	local oldGame = game
	local oldWorkspace = workspace
	local oldScript = script

	local oldTypeof = typeof
	local oldType = type

	local __olssa_starttime = os.clock()
	local __olssa_verb = function(...)
		if __olssa_configuration.VERBOSE then

			if __olssa_configuration.LOG_BLACKLIST and table.concat({...}):match(__olssa_configuration.LOG_BLACKLIST) then return end;
			if __olssa_configuration.LOG_WHITELIST and not table.concat({...}):match(__olssa_configuration.LOG_WHITELIST) then return end;

			print("OLSSA LOG","::",...,":: SCRIPT",oldScript.Name,":: TIMESTAMP", math.round((os.clock() - __olssa_starttime)*10))
		end
	end


	local __olssa_cache = setmetatable({}, {__mode = "k"})

	local function __olssa_unwrap(wrapped)
		local real = __olssa_cache[wrapped]
		if real == nil then
			--theoretically, if it's not in the cache, it's not wrapped, so we'll just return the object without doing anything
			return wrapped
		end
		return real
	end

	local function __olssa_wrap(obj, data)
		data = data or {}

		-- Check if already wrapped
		for w,r in next,__olssa_cache do
			if r == obj then
				return w
			end
		end

		if oldType(obj) == "userdata" then
			local fake = newproxy(true)
			local meta = getmetatable(fake)

			meta.__index = function(s,k)
				-- Shouldn't need to do this for actual game services, as it would be redundant.
				if __olssa_configuration.WRAPPED_PARENT_SPOOF_SEC and obj[k] == oldGame then
					__olssa_verb("Service Game Key spoofed from: "..tostring(obj))
					return game
				elseif __olssa_configuration.WRAPPED_PARENT_SPOOF_SEC and obj[k] == oldWorkspace then
					__olssa_verb("Service Workspace Key spoofed from: "..tostring(obj))
					return workspace
				elseif __olssa_configuration.WRAP_SCRIPT_SEC and obj[k] == oldScript then
					__olssa_verb("Service Script Key spoofed from: "..tostring(obj))
					return script
				--TO:DO; elseif, add support for returning custom wrapped userdatas
				end
				local result = data[k] or __olssa_wrap(obj[k])

				-- Wraps any methods in an extra function to fix the "expect ':', not '.'" error
				if __olssa_configuration.LOCAL_MAINMODULE_NAME_SEC and oldTypeof(obj) == "Instance" and obj:IsA("ModuleScript") and obj.Name:match(__olssa_configuration.REQUIRE_PREFIX) then
					result = "MainModule"
				end

				if __olssa_configuration.EXTRA_VERBOSE then
					__olssa_verb("[MT INDEX] "..tostring(obj)..": '"..tostring(k).."' --> "..tostring(result)..(result == data[k] and " !*" or " !°"))
				end


				-- Wraps any methods in an extra function to fix the "expect ':', not '.'" error
				if oldType(result) == "function" then
					if __olssa_configuration.EXTRA_VERBOSE then
						__olssa_verb("[FUNC WRAP] "..debug.info(result,"n").."/"..tostring(result))
					end
					local fake = function(_, ...)
						local args = {};
				
						for k,v in next,{...} do
							-- Unwrap the arguments so the real method can process the real versions of the objects
							args[k] = __olssa_unwrap(v)
						end

						local results = __olssa_wrap{result(obj, unpack(args))}

						return unpack(results)
					end

					__olssa_cache[fake] = result
					return fake
				end
				return result
			end

			meta.__newindex = function(s,k,v)
				if __olssa_configuration.EXTRA_VERBOSE then
					__olssa_verb("[MT NEWINDEX] "..tostring(obj)..": '"..tostring(k).."' --> "..tostring(v))
				end
				obj[k] = v
			end

			meta.__tostring = function(s)
				return tostring(obj)
			end

			meta.__metatable = getmetatable(obj)

			-- Store the object in the cache, then return
			__olssa_cache[fake] = obj
			return fake
		elseif oldType(obj) == "table" then
			local fake = {}
			for k,v in next,obj do
				fake[k] = __olssa_wrap(v)
			end
			return fake
		elseif oldType(obj) == "function" then
			if __olssa_configuration.EXTRA_VERBOSE then
				__olssa_verb("[FUNC WRAP] "..debug.info(obj,"n").."/"..tostring(obj))
			end
			-- The goal is to return a fake function that behaves like the real one, then returns wrapped results
			local fake = function(...)
				local args = {};
				
				for k,v in next,{...} do
					-- Unwrap the arguments so the real method can process the real versions of the objects
					args[k] = __olssa_unwrap(v)
				end

				-- Call the method with the real arguments, then catch the return values in a table and wrap them
				local results = __olssa_wrap{obj(unpack(args))}

				-- Return the wrapped results
				return unpack(results)
			end

			-- Put fake functions into the cache as well for consistency
			__olssa_cache[fake] = obj
			return fake
		else
			return obj
		end

	end
	----- require SPOOF -----
	local __olssa_oldrequire = require
	local __olssa__oldhttpenc = {game:GetService("HttpService"), game:GetService("HttpService").JSONEncode}
	local __olssa_oldhttpenc = function(...) return __olssa__oldhttpenc[2](__olssa__oldhttpenc[1], ...) end

	local oldGetFenv = getfenv
	local oldSetFenv = setfenv

	_require = function(...)
		local module = ({...})[1]
		if oldType(module) == 'number' then
			__olssa_verb("Require called with online module: "..tostring(module))

			if __olssa_configuration.REQUIRE_SPOOF then
				local mobj = __olssa_configuration.REQUIRE_SPOOF_FOLDER:WaitForChild(__olssa_configuration.REQUIRE_PREFIX .. module, 15)
				if mobj then
					module = mobj
					__olssa_verb("Require spoof requiring module '".. mobj.Name .."' instead of original")
				else
					__olssa_verb("Require spoof module not found, using original")
				end
			end
		elseif oldType(module) == 'userdata' then
			__olssa_verb("Require called with local module: ".. tostring(module.Parent.Name) .." > " .. tostring(module.Name))
			module = __olssa_unwrap(module) -- Unwrap module, as it could cause issues being accepted by require function
			if __olssa_configuration.REQUIRE_LOCALMODRDF then
				module = __olssa_configuration.REQUIRE_LOCALMODRDF(module.Parent, module.Name)
			end
		end


		local success, output = pcall(__olssa_oldrequire, module)
		if not success then
			error(output)
		else
			__olssa_verb("Require call data (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(output)))
		end

		local stack_limit = 16380 - 5 -- Prevents results with "infinite" metatables from halting the stack
		local function sandbox(result)
			if oldType(result) == "function" then
				__olssa_verb("Require sandboxing result function '"..tostring(debug.info(result, "n")).."' with base environment")
				oldSetFenv(result, baseEnv)
			elseif oldType(result) == "table" then
				for k, v in result do
					stack_limit -= 1;
					if stack_limit < 1 then break end;
					sandbox(v)
				end
			end
		end

		if __olssa_configuration.SANDBOX_FUNCS then sandbox(output) end

		return output
	end

	if __olssa_configuration.FENV_MODE == -1 then
		require = _require
	end




	local oldMarketplaceService = game:GetService("MarketplaceService")
	local oldRunService = game:GetService("RunService")
	local oldHttpService = game:GetService("HttpService")

	if __olssa_configuration.GAME_SPOOF then
		do
			----- MarketPlaceService SPOOF -----
			local customMarketplaceService = setmetatable({
				UserOwnsGamePassAsync = function(self, userid, gamepass)

					__olssa_verb("UserOwnsGamePassAsync called with GamePass: ".. tostring(gamepass) .."; and UserId: " .. tostring(userid))

					local success, result = pcall(function()
						return oldMarketplaceService:UserOwnsGamePassAsync(userid, gamepass)
					end)

					if __olssa_configuration.MARKETPLACESERVICE_SPOOF then
						if not __olssa_configuration.MARKETPLACESERVICE_SPOOF_SEC then
							__olssa_verb("UserOwnsGamePassAsync result spoofed as true")
							return true
						else
							__olssa_verb("UserOwnsGamePassAsync result spoofed as "..tostring(success and true or result))
							return success and true or result
						end
					end

					return result
				end,
				GetProductInfo = function(self, assetid, infotype)
					__olssa_verb("GetProductInfo called with AssetId: ".. tostring(assetid) .."; and InfoType: " .. tostring(infotype))
					return oldMarketplaceService:GetProductInfo(assetid, infotype)
				end,
			}, { __service = oldMarketplaceService, __index = __olssa_wrap(oldMarketplaceService)})

			----- RunService SPOOF -----
			local customRunService = setmetatable({
				IsStudio = function(self)
					__olssa_verb("IsStudio called")
					if __olssa_configuration.RUNSERVICE_ISSTUDIO_SPOOF then
						__olssa_verb("IsStudio result spoofed as "..tostring(__olssa_configuration.RUNSERVICE_ISSTUDIO_VALUE))
						return __olssa_configuration.RUNSERVICE_ISSTUDIO_VALUE
					end
					return oldRunService:IsStudio()
				end,
			}, { __service = oldRunService, __index = __olssa_wrap(oldRunService)})

			----- HttpService SPOOF -----
			local customHttpService = __olssa_wrap(oldHttpService, {
				RequestAsync = function(self, options)
					__olssa_verb("RequestAsync called with RequestOptions (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(options)))

					-- Options spoof
					local success, result = pcall(function()
						local spoof = __olssa_configuration.HTTPSERVICE_OPTIONS_SPOOF(oldHttpService, options.Url, options.Method, options.Body, options.Headers)
						if spoof ~= nil then
							__olssa_verb("RequestAsync spoofed with custom options: ".. __olssa_oldhttpenc(table.pack(spoof)))
							options = spoof
						end
					end)

					-- Result spoof
					local success, result = pcall(function()
						local spoof = __olssa_configuration.HTTPSERVICE_REQUEST_SPOOF(oldHttpService, options.Url, options.Method, options.Body, options.Headers)
						if spoof ~= nil then
							__olssa_verb("RequestAsync result spoofed as (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(spoof)))
							return spoof
						else
							local result = oldHttpService:RequestAsync(options)
							__olssa_verb("RequestAsync result is (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(result)))
							return result
						end
					end)


					return result
				end,
				GetAsync = function(self, url, nocache, headers)
					__olssa_verb("GetAsync called with URL, NoCache and Headers (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(url, nocache, headers)))

					-- Options spoof
					local success, result = pcall(function()
						local spoof = __olssa_configuration.HTTPSERVICE_OPTIONS_SPOOF(oldHttpService, url, "GET", "", headers)
						if spoof ~= nil then
							__olssa_verb("GetAsync spoofed with custom options: ".. __olssa_oldhttpenc(table.pack(spoof)))
							url = spoof.Url
							headers = spoof.Headers
						end
					end)

					-- Result spoof
					local success, result = pcall(function()
						local spoof = __olssa_configuration.HTTPSERVICE_REQUEST_SPOOF(oldHttpService, url, "GET", "", headers)
						if spoof ~= nil then
							__olssa_verb("GetAsync result spoofed as (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(spoof)))
							return spoof
						else
							local result = oldHttpService:GetAsync(url, nocache, headers)
							__olssa_verb("GetAsync result is (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(result)))
							return result
						end
					end)
					return result
				end,
				PostAsync = function(self, url, body, contenttype, compress, headers)
					__olssa_verb("PostAsync called with URL, Body, NoCache and Headers (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(url, body, nocache, headers)))

					-- Options spoof
					local success, result = pcall(function()
						local spoof = __olssa_configuration.HTTPSERVICE_OPTIONS_SPOOF(oldHttpService, url, "POST", body, headers)
						if spoof ~= nil then
							__olssa_verb("PostAsync spoofed with custom options: ".. __olssa_oldhttpenc(table.pack(spoof)))
							url = spoof.Url
							body = spoof.Body
							headers = spoof.Headers
						end
					end)

					-- Result spoof
					local success, result = pcall(function()
						local spoof = __olssa_configuration.HTTPSERVICE_REQUEST_SPOOF(oldHttpService, url, "POST", body, headers)
						if spoof ~= nil then
							__olssa_verb("PostAsync result spoofed as (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(spoof)))
							return spoof
						else
							local result = oldHttpService:PostAsync(url, body, contenttype, compress, headers)
							__olssa_verb("PostAsync result is (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(result)))
							return result
						end
					end)
					return result
				end,
				JSONEncode = function(self, data)
					__olssa_verb("JSONEncode called with data (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(data)))
					return oldHttpService:JSONEncode(data)
				end,
				JSONDecode = function(self, data)
					__olssa_verb("JSONDecode called with data (wrapped in a table and JSON encoded): ".. __olssa_oldhttpenc(table.pack(data)))
					return oldHttpService:JSONDecode(data)
				end,
	--[[GetHttpEnabled = function(self)
        return oldHttpService.HttpEnabled or spoofs.HttpEnabledSpoof
    end,]]
				HttpEnabled = __olssa_configuration.HTTPSERVICE_ENABLED_SPOOF--oldHttpService.HttpEnabled or spoofs.HttpEnabledSpoof,
			})

			----- game SPOOF -----
			local oldWorkspace = workspace
			_game = __olssa_wrap(oldGame,{
				GetService = function(self, service)
					__olssa_verb("GetService called with Service: "..tostring(service))
					if service == "HttpService" then
						return customHttpService or oldHttpService
					elseif service == "MarketplaceService" then
						return customMarketplaceService or oldMarketplaceService
					elseif service == "RunService" then
						return customRunService or oldRunService
					elseif __olssa_configuration.WRAP_GAMESERVICES_SEC then
						return __olssa_wrap(oldGame:GetService(service))
					end
					return oldGame:GetService(service)
				end,
				CreatorId = __olssa_configuration.CREATOR_SPOOF and tonumber(__olssa_configuration.CREATOR_OBJ["CreatorId"]) or oldGame.CreatorId,
				CreatorType = __olssa_configuration.CREATOR_SPOOF and __olssa_configuration.CREATOR_OBJ["CreatorType"] or oldGame.CreatorType,
				GameId = __olssa_configuration.GAMEID_SPOOF and tonumber(__olssa_configuration.GAMEID_OBJ["GameId"]) or oldGame.GameId,
				PlaceId = __olssa_configuration.GAMEID_SPOOF and tonumber(__olssa_configuration.GAMEID_OBJ["PlaceId"]) or oldGame.PlaceId,
			})

			-- This and all subsequent -1 FENV_MODE checks are there so that in -1, instead of spoofing the fenv with a custom metatable, globals are set directly
			if __olssa_configuration.FENV_MODE == -1 then
				game = _game
			end

			if __olssa_configuration.WRAP_GAMESERVICES_SEC then
				_workspace = __olssa_wrap(oldWorkspace)
				if __olssa_configuration.FENV_MODE == -1 then
					workspace = _workspace
				end
			end;

			if __olssa_configuration.WRAP_SCRIPT_SEC then
				_script = __olssa_wrap(oldScript)
				if __olssa_configuration.FENV_MODE == -1 then
					script = _script
				end
			end
		end
	end

	if __olssa_configuration.UNWRAP_TYPEFUNCTIONS_SEC then
		if __olssa_configuration.FENV_MODE >= 0 then
			-- Let WRAP_OTHER_GLOBALS handle the wrapping
			table.insert(__olssa_configuration.WRAP_OTHER_GLOBALS, "type")
			table.insert(__olssa_configuration.WRAP_OTHER_GLOBALS, "typeof")
			table.insert(__olssa_configuration.WRAP_OTHER_GLOBALS, "Instance")
		else 
			-- Check if oldType, oldTypeof, oldInstance are necessary or value can be replaced directly like this
			type = __olssa_wrap(type)
			typeof = __olssa_wrap(typeof)
			Instance = __olssa_wrap(Instance)
		end
	end

	local OldRawset = rawset
	if __olssa_configuration.RAWSET_SEC then
		do
			_rawset = function(self, k, v)
				if self == require or self == game then
					error("Attempt to modify a readonly table", 2)
				else
					return OldRawset(self, k, v)
				end
			end
			if __olssa_configuration.FENV_MODE == -1 then
				rawset = _rawset
			end
		end
	end

	if __olssa_configuration.GETSETFENV_SEC then
		_getfenv = function(stack)
			__olssa_verb("getfenv called with stack number: ".. tostring(stack or 0))
			return oldGetFenv(stack) == baseEnv and setmetatable({}, {
				__metatable = function()
					return "The metatable is locked"
				end,
				__index = function(_, ind)
					return baseEnv[ind] -- Access the constants, privateEnv, or original environment
				end,
				__newindex = function(_, ind, val)
					if table.find(__olssa_configuration.FENV_WHITELIST, ind) then
						__olssa_verb("Script attempted to modify protected globals in base environment: "..tostring(ind))
						return
					else
						baseEnv[ind] = val -- Assign the value to the private environment
					end
				end,
			}) or oldGetFenv(stack)
		end;
		_setfenv = function(stack, env)
			__olssa_verb("setfenv called with stack number: ".. tostring(stack or 0))
			return oldGetFenv(stack) == baseEnv and true or oldSetFenv(stack, env)
		end;
		if __olssa_configuration.FENV_MODE == -1 then
			getfenv = _getfenv
			setfenv = _setfenv
		end
	end

	if __olssa_configuration.WRAP_SCRIPT_SEC then
		_script = __olssa_wrap(oldScript)
		if __olssa_configuration.FENV_MODE == -1 then
			script = _script
		end
	end

	if __olssa_configuration.FENV_MODE > -1 then
		local oldenv = getfenv()
		local meta = setmetatable({},{
			__index = function(self,index)
				if index == 'require' and __olssa_configuration.REQUIRE_SPOOF then
					return _require
				elseif index == 'game' and __olssa_configuration.GAME_SPOOF then
					return _game
				elseif index == 'workspace' and __olssa_configuration.WRAP_GAMESERVICES_SEC then
					return _workspace
				elseif index == 'script' and __olssa_configuration.WRAP_SCRIPT_SEC then
					return _script
				elseif index == 'rawset' and __olssa_configuration.RAWSET_SEC then
					return _rawset
				elseif index == 'getfenv' and __olssa_configuration.GETSETFENV_SEC then
					return _getfenv
				elseif index == 'setfenv' and __olssa_configuration.GETSETFENV_SEC then
					return _setfenv
				elseif table.find(__olssa_configuration.WRAP_OTHER_GLOBALS, index) then
					return __olssa_wrap(oldenv[index])
				end
				return oldenv[index]
			end,
			__newindex = function(self,index,val)
				oldenv[index] = val
			end,
		})
		setfenv(__olssa_configuration.FENV_MODE,meta) 
	end

	debug.resetmemorycategory()
end -- ⚠️ OLSSA Auditor Snippet End ⚠️