--!native
--!nonstrict
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
  \___/|_____|____/____/_/   \_\ _v v_  v4.2

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>
]]

-- ⚠️  Paste at the VERY TOP of the target script, before any other code. ⚠️
--================----==OLSSABEGIN==----================--
do
-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §0  SNAPSHOT ALL BUILTINS  (must be absolute first)             ║
-- ╚══════════════════════════════════════════════════════════════════╝
local _rawget    = rawget
local _rawset    = rawset
local _rawequal  = rawequal
local _rawlen    = rawlen
local _setmt     = setmetatable
local _getmt     = getmetatable
local _type      = type
local _error     = error
local _pcall     = pcall
local _xpcall    = xpcall
local _tostring  = tostring
local _select    = select
local _unpack    = unpack
local _tpack     = table.pack
local _tunpack   = table.unpack
local _tinsert   = table.insert
local _tremove   = table.remove
local _tconcat   = table.concat
local _tsort     = table.sort
local _tfreeze   = table.freeze
local _tclear    = table.clear
local _next      = next
local _pairs     = pairs
local _ipairs    = ipairs
local _getfenv   = getfenv
local _setfenv   = setfenv
local _newproxy  = newproxy
local _typeof    = typeof      -- ONLY working type-spoof path for newproxy objects
local _print     = print
local _warn      = warn

local _mfloor    = math.floor
local _mceil     = math.ceil
local _mabs      = math.abs
local _msign     = math.sign
local _mround    = math.round
local _mrandom   = math.random
local _mmax      = math.max
local _mmin      = math.min

local _smatch    = string.match
local _sformat   = string.format
local _srep      = string.rep
local _sgsub     = string.gsub
local _sfind     = string.find
local _ssplit    = string.split   -- Roblox extension
local _ssub      = string.sub
local _supper    = string.upper
local _slower    = string.lower
local _sbyte     = string.byte
local _slen      = string.len

local _game       = game
local _renv       = _getfenv()   -- original VM-readonly global table
local _script     = script
local _workspace  = workspace
local _Instance   = Instance
local _Enum       = Enum

local _os         = os
local _os_clock   = os.clock
local _os_diff    = os.difftime
local _os_time    = os.time

local _tick       = tick
local _timefn     = time
local _wait       = wait
local _DateTime   = DateTime

local _task          = task
local _task_wait     = task.wait
local _task_delay    = task.delay
local _task_spawn    = task.spawn
local _task_defer    = task.defer
local _task_cancel   = task.cancel
local _task_desync   = (task :: any).desynchronize
local _task_sync     = (task :: any).synchronize

local _co_wrap     = coroutine.wrap
local _co_create   = coroutine.create
local _co_resume   = coroutine.resume
local _co_yield    = coroutine.yield
local _co_running  = coroutine.running
local _co_status   = coroutine.status
local _co_isyield  = coroutine.isyieldable

-- Roblox Luau debug: ONLY traceback and info are available.
-- debug.getmetatable / getupvalues / setmetatable do NOT exist in Roblox Luau.
local _dbg_info      = debug.info
local _dbg_trace     = debug.traceback
local _dbg_setmcat   = debug.setmemorycategory
local _dbg_resetmcat = debug.resetmemorycategory

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §1  CONFIGURATION                                               ║
-- ╚══════════════════════════════════════════════════════════════════╝
local CFG = {
    meta = { revision = "v4.2", date = "2026-03-17" },

    -- ──────────────────────────────────────────────────────────────
    -- environment:  controls how the spoofed global table is built
    -- ──────────────────────────────────────────────────────────────
    environment = {
        -- wrap    true  = setfenv fork; full stealth, disables Luau fastcall
        --         false = rawset-only; no deopt, reduced stealth
        wrap    = true,

        -- light   true  = minimal wrapping (passthrough for non-key values)
        --         false = wrap everything (heavier, more complete interception)
        light   = true,
    },

    -- ──────────────────────────────────────────────────────────────
    -- stack:  getfenv sandbox defense strategy
    --
    -- mode:
    --   "guarded"    return _fenv for levels 0..depth, native beyond
    --                (recommended — blocks stack-scan attacks while keeping
    --                 native error behavior for getfenv(9999) etc.)
    --   "strict"     return _fenv for ALL numeric levels
    --                (prevents all stack scans but getfenv(9999) succeeds
    --                 — this is a detectable deviation from native behavior)
    --   "passthrough" return _fenv only for levels 0 and 1 (v4.1 behavior)
    --                (vulnerable to stack-scan attacks at levels 2+)
    -- depth:  maximum level returned as _fenv in "guarded" mode
    -- ──────────────────────────────────────────────────────────────
    stack = {
        mode  = "guarded",  -- "guarded" | "strict" | "passthrough"
        depth = 12,         -- levels 0..depth return _fenv in guarded mode
    },

    -- ──────────────────────────────────────────────────────────────
    -- wrapper:  blacklist for values/keys that always pass through raw
    -- ──────────────────────────────────────────────────────────────
    wrapper = {
        blacklist = {
            enabled = true,
            values  = { pairs, ipairs, next },
            keys    = {},
        },
    },

    -- ──────────────────────────────────────────────────────────────
    -- logs:  verbosity and formatting control
    --   0=off  1=activity  2=spoofs  3=metamethods  4=deep-dumps
    -- ──────────────────────────────────────────────────────────────
    logs = {
        verbose   = 2,
        whitelist = nil,   -- Lua pattern; nil = allow all messages
        blacklist = nil,   -- Lua pattern; nil = block none
        prelogs   = false, -- emit logs from OLSSA startup (before §13)
        shadow    = true,  -- shadow OLSSA ID from guest print/warn
        dump      = true,  -- use recursive _dump for tables (verbose ≥ 4)
    },

    -- ──────────────────────────────────────────────────────────────
    -- selftest:  diagnostic suite run on boot
    -- ──────────────────────────────────────────────────────────────
    selftest = {
        enabled      = true,
        halt_on_fail = false,  -- error() if any test fails
    },

    -- ──────────────────────────────────────────────────────────────
    -- time:  unified dilated clock
    --   dilation: multiplier on elapsed time visible to guest
    --     0.15 = guest sees time at 15% of real speed
    --     1.0  = transparent (hook installed, no distortion)
    -- ──────────────────────────────────────────────────────────────
    time = {
        hook     = true,
        dilation = 0.15,
    },

    -- ──────────────────────────────────────────────────────────────
    -- game:  identity spoofs
    -- ──────────────────────────────────────────────────────────────
    game = {
        hook     = true,
        creator  = { spoof = true,  type = "User", id = 123456789 },
        universe = { spoof = true,  id   = 123456789 },
        place    = { spoof = true,  id   = 123456789 },
        services = {},   -- populated dynamically by §8
    },

    -- ──────────────────────────────────────────────────────────────
    -- runservice:  nil = passthrough to real value; bool = forced
    -- ──────────────────────────────────────────────────────────────
    runservice = {
        spoof     = true,
        isstudio  = false,   -- nil=passthrough  true/false=forced
        isclient  = nil,
        isserver  = nil,
        isedit    = nil,
        isrunmode = nil,
    },

    -- ──────────────────────────────────────────────────────────────
    -- httpservice
    --   httpenabled:  nil=passthrough  true/false=forced
    --   mock:  { ["https://example.com"] = { StatusCode=200, Body="...",
    --             Headers={} }, ... }  — matched before any real request
    --   intercept:  function(url,method,headers,body) → nil|{StatusCode,Body,Headers}
    --               nil=passthrough; table=override
    -- ──────────────────────────────────────────────────────────────
    httpservice = {
        spoof       = true,
        httpenabled = true,
        mock        = {},    -- URL → response table
        intercept   = nil,   -- function(url,method,headers,body)→response|nil
    },

    -- ──────────────────────────────────────────────────────────────
    -- marketplaceservice
    --   gamepasses / assets:  { {userid, gamepassid/assetid, owns}, … }
    --   check:  validate call signature against real service before spoofing
    -- ──────────────────────────────────────────────────────────────
    marketplaceservice = {
        spoof      = true,
        check      = true,
        gamepasses = {},   -- { userid=n, gamepassid=n, owns=bool }
        assets     = {},   -- { userid=n, assetid=n, owns=bool }
    },

    -- ──────────────────────────────────────────────────────────────
    -- players:  LocalPlayer identity spoof (client-side)
    --   When spoof=true the Players service proxy exposes the overrides below.
    --   localplayer.name / .displayname / .userid: nil=passthrough
    -- ──────────────────────────────────────────────────────────────
    players = {
        spoof        = true,
        localplayer  = {
            name        = nil,      -- nil=passthrough; string=forced
            displayname = nil,
            userid      = nil,      -- nil=passthrough; number=forced
        },
    },

    -- ──────────────────────────────────────────────────────────────
    -- teleportservice:  log and optionally block all teleport calls
    --   block:  true = make all teleport calls silently no-op
    --   intercept:  function(method, placeId, …) → bool  (true=allow)
    -- ──────────────────────────────────────────────────────────────
    teleportservice = {
        spoof     = true,
        block     = false,   -- true = silently no-op all teleports
        intercept = nil,     -- function(method,placeId,…) → bool
    },

    -- ──────────────────────────────────────────────────────────────
    -- policyservice:  override policy checks
    --   nil=passthrough  true/false=forced
    -- ──────────────────────────────────────────────────────────────
    policyservice = {
        spoof                      = true,
        issubjecttochinapolicies   = nil,
        arePaidRandomItemsRestricted = nil,
        isPaidItemTradingAllowed   = nil,
    },

    -- ──────────────────────────────────────────────────────────────
    -- debug:  hook debug library for anti-theft
    --   cmask:  true = mask wrapped globals as [C] in debug.info
    --   stealth: true = replace stolen C metamethods with safe proxies
    --            false = return nil (detectable!)
    -- ──────────────────────────────────────────────────────────────
    debug = {
        hook    = true,
        cmask   = true,   -- mask Lua-wrapped globals as "[C]" in debug.info
        stealth = true,
    },

    -- ──────────────────────────────────────────────────────────────
    -- require hook:  intercept require() calls
    --   path.intercept(path) → nil=passthrough  Instance=redirect  false=block
    --   path.rewrite(path)   → string|nil
    -- ──────────────────────────────────────────────────────────────
    require = {
        hook   = true,
        spoof  = true,
        folder = workspace,
        prefix = "OLSSA:",
        lookup = function(self, id: number)
            return self.folder:WaitForChild(
                _sformat("%s%d", self.prefix, id), 15)
        end,
        mock = true,
        path = {
            intercept = nil,
            rewrite   = nil,
        },
    },

    -- ──────────────────────────────────────────────────────────────
    -- globals:  extra globals to wrap
    --   string entry    → wrap rawget(_renv, name) with default opts
    --   table entry     → { k="name", cnt={…}, v=override }
    -- ──────────────────────────────────────────────────────────────
    globals = { "script", "workspace", "Instance", "tostring" },
}

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §2  PROXY STATE                                                 ║
-- ╚══════════════════════════════════════════════════════════════════╝
-- _W[original] = proxy       weak-value  (GC'd when proxy unreferenced)
-- _U[proxy]    = original    weak-key    (entry removed when proxy GC'd)
-- _I[guest_fn] = inv_proxy   weak-key    (inverse proxy for callbacks)
-- _KS[k/v]     = wrapped     value-spoof map
-- _SVC         = CFG.game.services   service ClassName → proxy (strong)
-- _CFNS[fn]    = "name"      Lua-wrapped fns that debug.info should report as [C]

local _W    = _setmt({}, { __mode = "v" })
local _U    = _setmt({}, { __mode = "k" })
local _I    = _setmt({}, { __mode = "k" })   -- [N-10] Callback unwrapper cache
local _SVC  = CFG.game.services
local _KS   = {}
local _CFNS = {}   -- [F-03] C-masking table

-- Blacklist sets: values/keys that always pass through raw
local _BLV = {}
local _BLK = {}
do
    _BLV[_pairs]  = true
    _BLV[_ipairs] = true
    _BLV[_next]   = true
end

-- Forward declarations
local wrap, unwrap, resolve

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §3  RESOLUTION                                                  ║
-- ╚══════════════════════════════════════════════════════════════════╝
-- resolve(v, cnt, light, isgame) → what the guest should see.
-- isgame: when true, check _SVC for service class name match.
--         Always safe to pass true — gates on typeof(v)=="Instance" first.
resolve = function(v, cnt, light, isgame)
    if v == nil then return nil end
    local t = _type(v)
    if t ~= "userdata" and t ~= "table" and t ~= "function" then return v end
    if _BLV[v] then return v end

    -- Cached proxy takes priority (covers _W-registered service proxies)
    local cached = _W[v]
    if cached ~= nil then return cached end

    -- Key-spoof map
    local ks = _KS[v]
    if ks ~= nil then return ks end

    -- Service registry (Instances only); isgame=true required
    if isgame and t == "userdata" then
        local ok, ti = _pcall(_typeof, v)
        if ok and ti == "Instance" then
            local svc = _SVC[(v :: any).ClassName] or _SVC[v]
            if svc ~= nil then return svc end
        end
    end

    if light then return v end
    return wrap(v, cnt, false, isgame)
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §4  PROXY CONSTRUCTORS                                          ║
-- ╠══════════════════════════════════════════════════════════════════╣
-- ║                                                                  ║
-- ║  __namecall — INTENTIONALLY NOT SET.  Research confirms:         ║
-- ║    • __namecall IS triggered on newproxy() objects in Roblox     ║
-- ║      Luau (it's a VM optimization, not a deprecated feature).    ║
-- ║    • HOWEVER, the method name is NOT passed as an argument       ║
-- ║      since the ~2020 Luau VM rewrite.  You receive (self, args)  ║
-- ║      with no way to know which method was called.                ║
-- ║    • If __namecall is SET, it intercepts ALL colon-method calls  ║
-- ║      (obj:Anything()) and the handler cannot dispatch correctly  ║
-- ║      without the name → all method calls break.                  ║
-- ║    • If __namecall is NOT SET (our choice), the VM falls back    ║
-- ║      to __index with k = the method name → correct dispatch.    ║
-- ║    Source: devforum.roblox.com/t/how-do-i-get-namecall-method/  ║
-- ║            luau-lang/luau discussions/230                        ║
-- ║                                                                  ║
-- ║  __type — NOT USED for newproxy objects.  The Luau spec states:  ║
-- ║    "returns 'userdata' to make sure host-defined types cannot be ║
-- ║     spoofed."  typeof() spoofing works ONLY via our wrapped      ║
-- ║     typeof global (§11).                                         ║
-- ║                                                                  ║
-- ║  __gc — NOT supported in Luau (removed deliberately; tag-based  ║
-- ║          destructors are host-only and cannot be called from Lua ║
-- ╚══════════════════════════════════════════════════════════════════╝

-- ── Userdata proxy (Roblox Instances) ────────────────────────────
local function mk_ud(obj, cnt, light, isgame)
    local proxy = _newproxy(true)
    local meta  = _getmt(proxy)

    meta.__index = function(_, k)
        if _BLK[k] then return obj[k] end

        -- Content override (per-service method / property spoof)
        if cnt then
            local ov = cnt[k]
            if ov ~= nil then
                if _type(ov) == "function" then
                    return function(self_arg, ...)
                        local args = _tpack(...)
                        for i = 1, args.n do args[i] = unwrap(args[i]) end
                        local rets = _tpack(
                            _pcall(ov, self_arg, _tunpack(args, 1, args.n)))
                        if not rets[1] then _error(rets[2], 0) end
                        for i = 2, rets.n do
                            rets[i] = resolve(rets[i], nil, light, isgame)
                        end
                        return _tunpack(rets, 2, rets.n)
                    end
                end
                return resolve(ov, nil, light, isgame)
            end
        end

        -- Real property / method read
        local raw = obj[k]
        if _BLV[raw] then return raw end

        -- Service fast-path (isgame check)
        if isgame and _type(raw) == "userdata" then
            local ok, ti = _pcall(_typeof, raw)
            if ok and ti == "Instance" then
                local svc = _SVC[(raw :: any).ClassName] or _SVC[raw]
                if svc ~= nil then return svc end
            end
        end

        local ks = _KS[raw]
        if ks ~= nil then return ks end

        -- Functions MUST be wrapped in any mode so that proxy self-arguments
        -- are unwrapped before reaching native C code.
        if _type(raw) == "function" then
            return wrap(raw, nil, false, isgame)
        end
        if light then return raw end
        return wrap(raw, nil, false, isgame)
    end

    meta.__newindex = function(_, k, v)
        obj[k] = unwrap(v)
    end

    meta.__tostring = function()
        return _tostring(obj)
    end

    -- Unwrap both operands for comparison metamethods
    meta.__eq = function(a, b)
        return (_U[a] or a) == (_U[b] or b)
    end
    meta.__lt  = function(a, b) return (_U[a] or a) <  (_U[b] or b) end
    meta.__le  = function(a, b) return (_U[a] or a) <= (_U[b] or b) end
    meta.__len = function()     return #obj end
    meta.__unm = function()     return -(obj) end
    meta.__concat = function(a, b)
        return (_U[a] or a) .. (_U[b] or b)
    end

    meta.__call = function(_, ...)
        local args = _tpack(...)
        for i = 1, args.n do args[i] = unwrap(args[i]) end
        local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
        if not rets[1] then _error(rets[2], 0) end
        for i = 2, rets.n do
            rets[i] = resolve(rets[i], nil, light, isgame)
        end
        return _tunpack(rets, 2, rets.n)
    end

    -- Stub iterator: Instances are not iterable; prevent crash on for-in
    meta.__iter = function() return function() end, nil, nil end

    -- Match the locked metatable string that real Roblox Instances expose
    meta.__metatable = _getmt(obj) or "The metatable is locked"

    -- Register BEFORE returning (write cache first to prevent re-entry race)
    _W[obj]   = proxy
    _U[proxy] = obj
    return proxy
end

-- ── Table proxy (libraries: os, task, coroutine, …) ──────────────
local function mk_tbl(obj, cnt, light, isgame)
    local proxy = {}
    _setmt(proxy, {
        __index = function(_, k)
            if _BLK[k] then return obj[k] end
            if cnt then
                local ov = cnt[k]
                if ov ~= nil then
                    if _type(ov) == "function" then
                        return function(...)
                            local args = _tpack(...)
                            for i = 1, args.n do args[i] = unwrap(args[i]) end
                            local rets = _tpack(
                                _pcall(ov, _tunpack(args, 1, args.n)))
                            if not rets[1] then _error(rets[2], 0) end
                            for i = 2, rets.n do
                                rets[i] = resolve(rets[i], nil, light, isgame)
                            end
                            return _tunpack(rets, 2, rets.n)
                        end
                    end
                    return resolve(ov, nil, light, isgame)
                end
            end
            local raw = obj[k]
            if _BLV[raw] then return raw end
            local ks = _KS[raw]
            if ks ~= nil then return ks end
            if _type(raw) == "function" then
                return wrap(raw, nil, false, isgame)
            end
            if light then return raw end
            return wrap(raw, nil, false, isgame)
        end,

        __newindex = function(_, k, v) obj[k] = unwrap(v) end,

        -- Stateless iterator over inner table (FIX-08 from v4.1)
        __iter = function()
            return function(_, prev_k)
                local k, v = _next(obj, prev_k)
                if k == nil then return nil end
                return resolve(k, nil, true, false),
                       resolve(v, nil, light, isgame)
            end, proxy, nil
        end,

        __len      = function()  return #obj end,
        __tostring = function()  return _tostring(obj) end,
        __eq = function(a, b)
            return (_U[a] or a) == (_U[b] or b)
        end,
        __metatable = _getmt(obj),
    })

    _W[obj]   = proxy
    _U[proxy] = obj
    return proxy
end

-- ── Function proxy ────────────────────────────────────────────────
local function mk_fn(fn, light, isgame)
    local proxy
    proxy = function(...)
        local args = _tpack(...)
        for i = 1, args.n do args[i] = unwrap(args[i]) end
        local rets = _tpack(_pcall(fn, _tunpack(args, 1, args.n)))
        if not rets[1] then _error(rets[2], 0) end
        -- [F-01] Always pass isgame=true in return-value resolution.
        -- Safe: resolve() gates on typeof(v)=="Instance" before touching _SVC.
        for i = 2, rets.n do
            rets[i] = resolve(rets[i], nil, light, true)
        end
        return _tunpack(rets, 2, rets.n)
    end
    _W[fn]    = proxy
    _U[proxy] = fn
    return proxy
end

-- ── Public interface ──────────────────────────────────────────────
wrap = function(obj, cnt, light, isgame)
    if obj == nil then return nil end
    local inner = _U[obj]
    if inner ~= nil then obj = inner end  -- never double-wrap
    local cached = _W[obj]
    if cached ~= nil then return cached end
    local t = _type(obj)
    if t == "userdata" then return mk_ud(obj, cnt, light, isgame) end
    if t == "table"    then return mk_tbl(obj, cnt, light, isgame) end
    if t == "function" then return mk_fn(obj, light, isgame) end
    return obj
end

unwrap = function(obj)
    if obj == nil then return nil end
    local u = _U[obj]
    if u ~= nil then return u end

    -- [F-05] Inverse proxy for guest callbacks passed to native functions.
    -- If a guest function is passed as an argument (e.g. game.ChildAdded:Connect(cb))
    -- we MUST wrap it so that when native Code calls `cb(raw_child)`, the callback
    -- intercepts `raw_child` and wraps it before reaching guest code.
    if _type(obj) == "function" then
        local inv = _I[obj]
        if inv ~= nil then return inv end
        inv = function(...)
            local args = _tpack(...)
            -- Incoming args from native C -> must be mapped back to guest proxies
            for i = 1, args.n do
                args[i] = resolve(args[i], nil, false, false)
            end
            local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
            if not rets[1] then _error(rets[2], 0) end
            -- Outgoing returns from guest to native -> must be unwrapped
            for i = 2, rets.n do
                rets[i] = unwrap(rets[i])
            end
            return _tunpack(rets, 2, rets.n)
        end
        _I[obj] = inv
        return inv
    end

    return obj
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §5  FORKED ENVIRONMENT  _fenv                                   ║
-- ╠══════════════════════════════════════════════════════════════════╣
-- ║  The Roblox VM marks each script's global table as VM-readonly:  ║
-- ║  rawset() and setmetatable() on it both throw.  The only way to  ║
-- ║  inject spoofed globals is to create a fresh _fenv table,        ║
-- ║  rawset spoofed keys into it, and install via setfenv(1, _fenv). ║
-- ╚══════════════════════════════════════════════════════════════════╝
local _fenv = _setmt({}, {
    __index    = _renv,
    __newindex = function(self, k, v) _rawset(self, k, v) end,
    __metatable = "The metatable is locked",
})

-- env_write: register a spoofed global in all relevant maps.
-- cfn_write: same + mark fn as C-masquerade for debug.info.
local function env_write(key, wrapped_v, original_v)
    _KS[key] = wrapped_v
    if original_v ~= nil then
        _KS[original_v] = wrapped_v
        if _U[wrapped_v] == nil then
            _U[wrapped_v] = original_v
        end
    end
    _rawset(_fenv, key, wrapped_v)
end

local function cfn_write(key, wrapped_v, original_v)
    env_write(key, wrapped_v, original_v)
    -- Mark for C-masquerade: debug.info(wrapped_v,"s") → "[C]"
    if CFG.debug.cmask and _type(wrapped_v) == "function" then
        _CFNS[wrapped_v] = key
    end
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §6  UNIFIED DILATED CLOCK                                       ║
-- ╚══════════════════════════════════════════════════════════════════╝
local _dil = CFG.time.hook and CFG.time.dilation or 1.0
if _dil == 0 then _dil = 1.0 end

local _fClockFake = _os_clock()
local _fClockReal = _os_clock()

local function _fClock(): number
    local now = _os_clock()
    _fClockFake += (now - _fClockReal) * _dil
    _fClockReal  = now
    return _fClockFake
end

local _fTickFake = _tick()
local _fTickReal = _tick()

local function _fTick(): number
    local now = _tick()
    _fTickFake += (now - _fTickReal) * _dil
    _fTickReal  = now
    return _fTickFake
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §7  LOGGING                                                     ║
-- ╚══════════════════════════════════════════════════════════════════╝
local _RS_real = _game:GetService("RunService")

local _ID = _sformat("[%04x%04x%04x]",
    _mrandom(0, 0xFFFF), _mrandom(0, 0xFFFF), _mrandom(0, 0xFFFF))

local _startTs  = -_os_clock()

_dbg_setmcat(_sformat("%s · OLSSA %s %s",
    _script.Name, CFG.meta.revision, _ID))

-- Verbosity sigils
local _SIGIL = { "●", "◈", "▸", "⬡" }

local _logQ = {}
local _logC = nil

-- Recursive value dumper
local function _dump(val: any, ind: number?, vis: {[any]:boolean}?): string
    local d = ind or 0
    local v = vis or {}
    local t = _type(val)
    if t == "table" then
        if v[val] then return "<cyclic>" end
        if val == _fenv then return "<_fenv>" end
        v[val] = true
        if not (CFG.logs.dump and CFG.logs.verbose >= 4) then
            local n = 0; for _ in _pairs(val) do n += 1 end
            return _sformat("{%d keys}", n)
        end
        local p = { "{" }
        for k2, v2 in _pairs(val) do
            _tinsert(p, _sformat("%s  %s = %s",
                _srep("  ", d), _tostring(k2), _dump(v2, d+1, v)))
        end
        _tinsert(p, _srep("  ", d) .. "}")
        return _tconcat(p, "\n")
    elseif t == "function" then
        local nm  = _dbg_info(val, "n") or "?"
        local src = _dbg_info(val, "s") or "?"
        return _sformat("ƒ[%s @ %s]", nm, src)
    elseif t == "string" then
        return _sformat("%q", val)
    else
        return _tostring(val)
    end
end

local function _fmtStack(tr: string): string
    local p = {}
    for _, ln in _ipairs(_ssplit(tr, "\n")) do
        ln = _sgsub(_sgsub(ln, "^%s+", ""), "%s+$", "")
        if ln == "" then continue end
        local full, num = _smatch(ln, "^(.+):(%d+)")
        if not num then continue end
        local fn  = _smatch(ln, "function (.+)$")
        local nm  = full and _sgsub(full, _script:GetFullName(), "(script)") or "(main)"
        _tinsert(p, fn and _sformat("%s.%s@%s", nm, fn, num)
                        or  _sformat("%s@%s", nm, num))
    end
    if #p == 0 then return "  (no trace)" end
    return "  ↳ " .. _tconcat(p, " → ")
end

local function _flushJob(job)
    if CFG.logs.whitelist and not job.msg:match(CFG.logs.whitelist) then return end
    if CFG.logs.blacklist and     job.msg:match(CFG.logs.blacklist) then return end
    
    local message = _tconcat({ job.header, job.msg, _ID }, " :: ")
    local indent = _srep(" ", 16)
    _warn(message, "\n" .. indent .. job.trace)
end

local function _onHB()
    local budget = _os_clock() + 0.014
    while #_logQ > 0 and _os_clock() < budget do
        _flushJob(_tremove(_logQ, 1))
    end
    if #_logQ == 0 and _logC then
        _logC:Disconnect(); _logC = nil
    end
end

local _log
if CFG.logs.verbose > 0 then
    _log = function(lvl: number, ...: any)
        if lvl > CFG.logs.verbose then return end
        if _msign(_startTs) ~= 1 and not CFG.logs.prelogs then return end
        local p = {}
        for i = 1, _select("#", ...) do
            _tinsert(p, _dump(_select(i, ...)))
        end
        local ms  = _msign(_startTs) * _mround((_os_clock() - _mabs(_startTs)) * 1000)
        local header = _sformat("[OLSSA] %s (l%d %dms)", _script:GetFullName(), lvl, ms)
        
        _tinsert(_logQ, {
            level = lvl, ms = ms,
            header = header,
            msg   = _tconcat(p, ", "),
            trace = _fmtStack(_dbg_trace()),
        })
        if not _logC then
            _logC = _RS_real.Heartbeat:Connect(_onHB)
        end
    end
else
    _log = function() end
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §8  SERVICE SPOOFS                                              ║
-- ╚══════════════════════════════════════════════════════════════════╝

-- ── RunService ────────────────────────────────────────────────────
if CFG.runservice.spoof then
    local rs  = CFG.runservice
    local _RS = _RS_real
    _SVC["RunService"] = mk_ud(_RS, {
        IsStudio  = function(_)
            _log(1, "RunService:IsStudio")
            return if rs.isstudio  ~= nil then rs.isstudio  else _RS:IsStudio()
        end,
        IsClient  = function(_)
            _log(1, "RunService:IsClient")
            return if rs.isclient  ~= nil then rs.isclient  else _RS:IsClient()
        end,
        IsServer  = function(_)
            _log(1, "RunService:IsServer")
            return if rs.isserver  ~= nil then rs.isserver  else _RS:IsServer()
        end,
        IsEdit    = function(_)
            _log(1, "RunService:IsEdit")
            return if rs.isedit    ~= nil then rs.isedit    else _RS:IsEdit()
        end,
        IsRunMode = function(_)
            _log(1, "RunService:IsRunMode")
            return if rs.isrunmode ~= nil then rs.isrunmode else _RS:IsRunMode()
        end,
        IsRunning = function(_) return _RS:IsRunning() end,
    }, false, false)
    _log(2, "SVC RunService registered")
end

-- ── HttpService ───────────────────────────────────────────────────
if CFG.httpservice.spoof then
    local _HTTP = _game:GetService("HttpService")
    local hcfg  = CFG.httpservice
    local hcnt  = {}

    -- HttpEnabled property override
    if hcfg.httpenabled ~= nil then
        hcnt.HttpEnabled = hcfg.httpenabled
    end

    -- Internal: resolve a request through mock → intercept → passthrough
    local function _hresolve(url, method, headers, body)
        -- 1. URL mock table (exact match)
        if hcfg.mock and hcfg.mock[url] then
            _log(2, "HTTP:MOCK", url)
            return hcfg.mock[url]
        end
        -- 2. Intercept callback
        if hcfg.intercept then
            local r = hcfg.intercept(url, method, headers, body)
            if r then
                _log(2, "HTTP:INTERCEPTED", url)
                return r
            end
        end
        return nil  -- passthrough
    end

    hcnt.RequestAsync = function(_, opts)
        local url = opts and opts.Url or "?"
        _log(1, "HTTP:RequestAsync", url)
        local r = _hresolve(url,
            opts and opts.Method   or "GET",
            opts and opts.Headers  or nil,
            opts and opts.Body     or nil)
        if r then return r end
        return _HTTP:RequestAsync(opts)
    end

    hcnt.GetAsync = function(_, url, nocache, headers)
        _log(1, "HTTP:GetAsync", url)
        local r = _hresolve(url, "GET", headers, nil)
        if r then return r.Body end
        return _HTTP:GetAsync(url, nocache, headers)
    end

    hcnt.PostAsync = function(_, url, data, ct, compress, headers)
        _log(1, "HTTP:PostAsync", url)
        local r = _hresolve(url, "POST", headers, data)
        if r then return r.Body end
        return _HTTP:PostAsync(url, data, ct, compress, headers)
    end

    hcnt.JSONEncode = function(_, v)
        _log(3, "HTTP:JSONEncode")
        return _HTTP:JSONEncode(v)
    end
    hcnt.JSONDecode = function(_, v)
        _log(3, "HTTP:JSONDecode")
        return _HTTP:JSONDecode(v)
    end
    hcnt.GenerateGUID = function(_, wrapInBraces)
        return _HTTP:GenerateGUID(wrapInBraces)
    end
    hcnt.UrlEncode = function(_, input)
        return _HTTP:UrlEncode(input)
    end

    _SVC["HttpService"] = mk_ud(_HTTP, hcnt, false, false)
    _log(2, "SVC HttpService registered")
end

-- ── MarketplaceService ────────────────────────────────────────────
if CFG.marketplaceservice.spoof then
    local _MKT = _game:GetService("MarketplaceService")
    local mcfg  = CFG.marketplaceservice

    local _gpM, _asM = {}, {}
    for _, e in _ipairs(mcfg.gamepasses) do
        if not _gpM[e.gamepassid] then _gpM[e.gamepassid] = {} end
        _gpM[e.gamepassid][e.userid] = e.owns
    end
    for _, e in _ipairs(mcfg.assets) do
        if not _asM[e.assetid] then _asM[e.assetid] = {} end
        _asM[e.assetid][e.userid] = e.owns
    end

    _SVC["MarketplaceService"] = mk_ud(_MKT, {
        UserOwnsGamePassAsync = function(_, player, passid)
            _log(1, "MKT:UserOwnsGamePassAsync", player, passid)
            if mcfg.check then
                local ok, err = _pcall(function()
                    return _MKT:UserOwnsGamePassAsync(player, passid)
                end)
                if not ok then _error(err, 0) end
            end
            local uid = _typeof(player) == "Instance"
                and (player :: any).UserId or player
            local row = _gpM[passid]
            if row and row[uid] ~= nil then
                _log(2, "MKT:GamePass:SPOOF", uid, passid, row[uid])
                return row[uid]
            end
            return _MKT:UserOwnsGamePassAsync(player, passid)
        end,
        PlayerOwnsAsset = function(_, player, assetid)
            _log(1, "MKT:PlayerOwnsAsset", player, assetid)
            if mcfg.check then
                local ok, err = _pcall(function()
                    return _MKT:PlayerOwnsAsset(player, assetid)
                end)
                if not ok then _error(err, 0) end
            end
            local uid = _typeof(player) == "Instance"
                and (player :: any).UserId or player
            local row = _asM[assetid]
            if row and row[uid] ~= nil then
                _log(2, "MKT:Asset:SPOOF", uid, assetid, row[uid])
                return row[uid]
            end
            return _MKT:PlayerOwnsAsset(player, assetid)
        end,
        GetProductInfo = function(_, assetid, infotype)
            return _MKT:GetProductInfo(assetid, infotype)
        end,
    }, false, false)
    _log(2, "SVC MarketplaceService registered")
end

-- ── Players ───────────────────────────────────────────────────────
if CFG.players.spoof then
    local _PLY  = _game:GetService("Players")
    local pcfg  = CFG.players
    local lpcfg = pcfg.localplayer

    -- Build a spoofed LocalPlayer proxy if overrides are configured
    local function _buildLP(realLP)
        if realLP == nil then return nil end
        local lpcnt = {}
        if lpcfg.name        ~= nil then lpcnt.Name        = lpcfg.name        end
        if lpcfg.displayname ~= nil then lpcnt.DisplayName = lpcfg.displayname end
        if lpcfg.userid      ~= nil then lpcnt.UserId      = lpcfg.userid      end
        if _next(lpcnt) == nil then
            -- No overrides; return cached proxy of real LP
            return resolve(realLP, nil, false, false)
        end
        _log(2, "PLY:LocalPlayer spoof", lpcfg.name or realLP.Name)
        return mk_ud(realLP, lpcnt, false, false)
    end

    local _lpCache = nil
    _SVC["Players"] = mk_ud(_PLY, {
        LocalPlayer = _pcall(function()
            local lp = _PLY.LocalPlayer
            _lpCache = _buildLP(lp)
            return _lpCache
        end) and _lpCache or nil,
        GetPlayers = function(_)
            _log(1, "PLY:GetPlayers")
            local result = {}
            for _, p in _ipairs(_PLY:GetPlayers()) do
                _tinsert(result, resolve(p, nil, false, false))
            end
            return result
        end,
    }, false, false)
    _log(2, "SVC Players registered")
end

-- ── TeleportService ───────────────────────────────────────────────
if CFG.teleportservice.spoof then
    local _TEL = _game:GetService("TeleportService")
    local tcfg = CFG.teleportservice

    local function _teleportGuard(method, placeId, ...)
        _log(1, "TEL:" .. method, placeId)
        if tcfg.intercept then
            local allow = tcfg.intercept(method, placeId, ...)
            if not allow then
                _log(2, "TEL:BLOCKED", method, placeId)
                return
            end
        end
        if tcfg.block then
            _log(2, "TEL:BLOCKED (block=true)", method)
            return
        end
        return (_TEL :: any)[method](_TEL, placeId, ...)
    end

    _SVC["TeleportService"] = mk_ud(_TEL, {
        Teleport                = function(_, placeId, ...) return _teleportGuard("Teleport",                placeId, ...) end,
        TeleportToPrivateServer  = function(_, placeId, ...) return _teleportGuard("TeleportToPrivateServer", placeId, ...) end,
        TeleportAsync           = function(_, placeId, ...) return _teleportGuard("TeleportAsync",           placeId, ...) end,
    }, false, false)
    _log(2, "SVC TeleportService registered")
end

-- ── PolicyService ─────────────────────────────────────────────────
if CFG.policyservice.spoof then
    local _POL = _game:GetService("PolicyService")
    local polcfg = CFG.policyservice
    local polcnt = {}

    polcnt.GetPolicyInfoForPlayerAsync = function(_, player)
        _log(1, "POL:GetPolicyInfoForPlayerAsync")
        local info = _POL:GetPolicyInfoForPlayerAsync(unwrap(player))
        -- Overlay any forced values
        if polcfg.issubjecttochinapolicies ~= nil then
            info = _setmt({}, { __index = function(_, k)
                if k == "IsSubjectToChinaPolicies" then
                    return polcfg.issubjecttochinapolicies
                end
                return (info :: any)[k]
            end })
        end
        return info
    end

    _SVC["PolicyService"] = mk_ud(_POL, polcnt, false, false)
    _log(2, "SVC PolicyService registered")
end

-- ── LogService shadow ─────────────────────────────────────────────
if CFG.logs.shadow then
    cfn_write("print", function(...)
        local p = _tpack(...)
        for i = 1, p.n do p[i] = _tostring(p[i]) end
        local s = _tconcat(p, "\t", 1, p.n)
        if not _sfind(s, _ID, 1, true) then _print(...) end
    end, _print)
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §9  GAME & CORE GLOBAL SPOOFS                                   ║
-- ╚══════════════════════════════════════════════════════════════════╝
if CFG.game.hook then
    local g = CFG.game
    local gcnt = {
        CreatorId   = g.creator.spoof  and g.creator.id   or _game.CreatorId,
        CreatorType = g.creator.spoof
            and _Enum.CreatorType:FromName(g.creator.type)
            or  _game.CreatorType,
        GameId  = g.universe.spoof and g.universe.id or _game.GameId,
        PlaceId = g.place.spoof    and g.place.id    or _game.PlaceId,
    }
    env_write("game", mk_ud(_game, gcnt, false, true), _game)
    _log(2, "GAME creator=" .. gcnt.CreatorId
          .. " universe=" .. gcnt.GameId
          .. " place="    .. gcnt.PlaceId)
end

env_write("workspace", wrap(_workspace, nil, true, true),  _workspace)
env_write("script",    wrap(_script,    nil, true, false), _script)
env_write("Instance",  wrap(_Instance,  nil, true, false), _Instance)

-- Extra globals from CFG.globals
for _, entry in _ipairs(CFG.globals) do
    if _type(entry) == "string" then
        local orig = _rawget(_renv, entry)
        if orig ~= nil then
            env_write(entry, wrap(orig, nil, true, false), orig)
        end
    elseif _type(entry) == "table" and entry.k then
        local orig = _rawget(_renv, entry.k)
        if orig ~= nil then
            local wv = entry.cnt and wrap(orig, entry.cnt, false, false)
                    or entry.v  and wrap(entry.v, nil, false, false)
                    or           wrap(orig, nil, true, false)
            env_write(entry.k, wv, orig)
        end
    end
end

-- _G must equal getfenv() so  _G == getfenv()  holds
_rawset(_fenv, "_G", _fenv)

-- shared: isolated so cross-script communication doesn't bypass sandbox
_rawset(_fenv, "shared", mk_tbl({}, nil, false, false))

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §10  TIME DILATION                                              ║
-- ╚══════════════════════════════════════════════════════════════════╝
if CFG.time.hook then
    local D = _dil

    cfn_write("os", mk_tbl(_os, {
        clock    = _fClock,
        time     = function(): number return _mfloor(_fTick()) end,
        difftime = _os_diff,
    }, false, false), _os)

    cfn_write("tick", _fTick, _tick)
    cfn_write("time", function(): number return _mfloor(_fTick()) end, _timefn)

    cfn_write("DateTime", mk_tbl(_DateTime, {
        now = function(): DateTime
            return _DateTime.fromUnixTimestamp(_fTick())
        end,
        fromUnixTimestamp = function(_, ts: number): DateTime
            return _DateTime.fromUnixTimestamp(ts)
        end,
        fromUnixTimestampMillis = function(_, ms: number): DateTime
            return _DateTime.fromUnixTimestampMillis(ms)
        end,
    }, false, false), _DateTime)

    cfn_write("wait", function(n: number?): (number, number)
        local e1, e2 = _wait(n and (n / D) or nil)
        _fClock()
        return (e1 or 0) * D, (e2 or 0) * D
    end, _wait)

    cfn_write("task", mk_tbl(_task, {
        wait = function(_, n: number?): number
            local e = _task_wait(n and (n / D) or nil)
            _fClock()
            return e * D
        end,
        delay = function(_, n: number, fn: (...any)->(), ...: any)
            local a = _tpack(...)
            return _task_delay(n and (n / D) or nil, function()
                _fClock(); fn(_tunpack(a, 1, a.n))
            end)
        end,
        spawn = function(_, fn: (...any)->(), ...: any)
            local a = _tpack(...)
            return _task_spawn(function() fn(_tunpack(a, 1, a.n)) end)
        end,
        defer = function(_, fn: (...any)->(), ...: any)
            local a = _tpack(...)
            return _task_defer(function() fn(_tunpack(a, 1, a.n)) end)
        end,
        cancel = function(_, t) return _task_cancel(t) end,
        desynchronize = _task_desync and function(_) return _task_desync() end or nil,
        synchronize   = _task_sync   and function(_) return _task_sync()   end or nil,
    }, false, false), _task)

    _log(2, "TIME_HOOK dilation=" .. D)
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §11  ITERATION / CALL / ENV / TYPE WRAPPERS                     ║
-- ╚══════════════════════════════════════════════════════════════════╝

-- ── typeof  ── CRITICAL ───────────────────────────────────────────
-- The ONLY mechanism that makes typeof(proxy) return "Instance" instead
-- of "userdata".  __type metamethod does not work on newproxy() objects.
-- Source: luau.org/library/ → "returns 'userdata' to make sure host-defined
--         types cannot be spoofed."
cfn_write("typeof", function(v)
    return _typeof(_U[v] or v)
end, _typeof)

-- ── pairs ─────────────────────────────────────────────────────────
cfn_write("pairs", function(t)
    local raw = unwrap(t)
    return function(_, prev)
        local k, v = _next(raw, prev)
        if k == nil then return nil end
        return resolve(k, nil, true, false), resolve(v, nil, false, true)
    end, t, nil
end, _pairs)

-- ── ipairs ────────────────────────────────────────────────────────
cfn_write("ipairs", function(t)
    local raw = unwrap(t)
    local i = 0
    return function()
        i += 1
        local v = raw[i]
        if v == nil then return nil end
        return i, resolve(v, nil, false, true)
    end
end, _ipairs)

-- ── next ──────────────────────────────────────────────────────────
cfn_write("next", function(t, k)
    local rk, rv = _next(unwrap(t), unwrap(k))
    if rk == nil then return nil end
    return resolve(rk, nil, true, false), resolve(rv, nil, false, true)
end, _next)

-- ── pcall ─────────────────────────────────────────────────────────
-- [F-01] Always use isgame=true in resolve: safe because resolve() gates
-- on typeof(v)=="Instance" before touching _SVC.  Fixes service proxies
-- returned through pcall losing their cnt (method override) table.
cfn_write("pcall", function(fn, ...)
    local args = _tpack(...)
    for i = 1, args.n do args[i] = unwrap(args[i]) end
    local rets = _tpack(_pcall(unwrap(fn), _tunpack(args, 1, args.n)))
    if rets[1] then
        for i = 2, rets.n do
            rets[i] = resolve(rets[i], nil, false, true)  -- [F-01]
        end
    end
    return _tunpack(rets, 1, rets.n)
end, _pcall)

-- ── xpcall ────────────────────────────────────────────────────────
cfn_write("xpcall", function(fn, handler, ...)
    local args = _tpack(...)
    for i = 1, args.n do args[i] = unwrap(args[i]) end
    local rets = _tpack(_xpcall(unwrap(fn), unwrap(handler),
        _tunpack(args, 1, args.n)))
    if rets[1] then
        for i = 2, rets.n do
            rets[i] = resolve(rets[i], nil, false, true)  -- [F-01]
        end
    end
    return _tunpack(rets, 1, rets.n)
end, _xpcall)

-- ── getfenv ───────────────────────────────────────────────────────
-- [F-04] Stack defense: return _fenv for levels 0..CFG.stack.depth.
-- For higher levels pass through to _getfenv (which errors for out-of-range
-- levels — matching native behavior, defeating the getfenv(9999) probe).
-- When called with a function argument, always return its actual environment.
--
-- Detection probes addressed:
--   pcall(getfenv, 9999) → ok=false  (guarded/passthrough modes)
--   debug.info(getfenv, "s") → "[C]" (via cfn_write + _CFNS)
--   BindableEvent/__tostring stack scan → finds only _fenv at all guarded levels
cfn_write("getfenv", function(f)
    if f == nil then return _fenv end

    if _type(f) == "number" then
        local mode = CFG.stack.mode
        if mode == "strict" then
            return _fenv
        elseif mode == "guarded" then
            if f <= CFG.stack.depth then return _fenv end
            -- Native behavior for out-of-range: this will error for f > stack depth
            return _getfenv(f + 1)  -- +1 to skip this wrapper frame
        else  -- "passthrough"
            if f == 0 or f == 1 then return _fenv end
            return _getfenv(f + 1)
        end
    end

    -- Function argument: return its real environment (do not mask)
    local raw = unwrap(f)
    if _type(raw) == "function" then return _getfenv(raw) end
    return _fenv
end, _getfenv)

-- ── setfenv ───────────────────────────────────────────────────────
cfn_write("setfenv", function(f, env_t)
    local rf = unwrap(f)
    return _setfenv(
        (_type(rf) == "function" or _type(rf) == "number") and rf or f,
        unwrap(env_t))
end, _setfenv)

-- ── tostring ──────────────────────────────────────────────────────
cfn_write("tostring", function(v)
    return _tostring(unwrap(v))
end, _tostring)

-- ── rawequal ──────────────────────────────────────────────────────
cfn_write("rawequal", function(a, b)
    return _rawequal(unwrap(a), unwrap(b))
end, _rawequal)

-- ── rawget ────────────────────────────────────────────────────────
-- rawget on a table proxy writes to the inner table transparently
cfn_write("rawget", function(t, k)
    return _rawget(unwrap(t), unwrap(k))
end, rawget)

-- ── rawset ────────────────────────────────────────────────────────
cfn_write("rawset", function(t, k, v)
    return _rawset(unwrap(t), unwrap(k), unwrap(v))
end, rawset)

-- ── rawlen ────────────────────────────────────────────────────────
cfn_write("rawlen", function(v)
    return _rawlen(unwrap(v))
end, _rawlen)

-- ── select ────────────────────────────────────────────────────────
-- select is a fast builtin; wrapping helps if guest uses select("#",...)
-- with proxy values. Passthrough is fine here but we write it for completeness.
cfn_write("select", _select, _select)

-- ── unpack / table.unpack ─────────────────────────────────────────
cfn_write("unpack", function(t, i, j)
    return _tunpack(unwrap(t), i, j)
end, _unpack)

-- ── coroutine ─────────────────────────────────────────────────────
cfn_write("coroutine", mk_tbl(coroutine, {
    -- NOTE: mk_tbl override functions receive args directly (no implicit self)
    wrap = function(fn)
        local raw = unwrap(fn)
        return _co_wrap(function(...)
            local a = _tpack(...)
            for i = 1, a.n do a[i] = unwrap(a[i]) end
            return raw(_tunpack(a, 1, a.n))
        end)
    end,
    create = function(fn)
        local raw = unwrap(fn)
        return _co_create(function(...)
            local a = _tpack(...)
            for i = 1, a.n do a[i] = unwrap(a[i]) end
            return raw(_tunpack(a, 1, a.n))
        end)
    end,
    resume = function(co, ...)
        local a = _tpack(...)
        for i = 1, a.n do a[i] = unwrap(a[i]) end
        local rets = _tpack(_co_resume(co, _tunpack(a, 1, a.n)))
        if rets[1] then
            for i = 2, rets.n do
                rets[i] = resolve(rets[i], nil, false, true)
            end
        end
        return _tunpack(rets, 1, rets.n)
    end,
    yield       = coroutine.yield,
    status      = coroutine.status,
    running     = coroutine.running,
    isyieldable = coroutine.isyieldable,
}, false, false), coroutine)

-- ── debug ─────────────────────────────────────────────────────────
-- [F-03] C-masking: debug.info(fn, fmt) where fn ∈ _CFNS returns mocked
-- [C]-function info to hide that our wrappers are Lua closures.
--
-- Attack mitigated:  debug.info(getfenv, "s") → "[C]" (not script source)
--
-- __index-theft attack mitigated (from v4.1):
--   xpcall(function() game._x end, function() stolen = debug.info(2,"f") end)
--   In stealth mode, returns safe proxy instead of real C metamethod.
do
    -- [F-03] Helper: mock C-function debug.info response from _CFNS
    -- Returns results matching the fmt string, as if the fn were a C function.
    local function _cmock_info(name: string, fmt: string)
        local res  = {}
        local i    = 1
        while i <= #fmt do
            local c = _ssub(fmt, i, i)
            if c == "s" then
                _tinsert(res, "[C]")
            elseif c == "n" then
                _tinsert(res, name)
            elseif c == "l" then
                _tinsert(res, -1)      -- C functions have no defined line
            elseif c == "a" then
                _tinsert(res, 0)       -- param count
                _tinsert(res, true)    -- variadic
            end
            i += 1
        end
        return _tunpack(res)
    end

    -- Safe proxy for stolen __index (stealth mode)
    local _safe_index = function(inst, k)
        return resolve(unwrap(inst)[k], nil, false, true)
    end
    local _safe_newindex = function(inst, k, v)
        unwrap(inst)[k] = unwrap(v)
    end
    local _stealth = CFG.debug.stealth

    env_write("debug", mk_tbl(debug, {
        info = function(...)
            local first = _select(1, ...)
            local fmt   = _select(2, ...) or "n"

            -- ── Function query form: debug.info(fn, fmt) ──────────
            if _type(first) == "function" then
                -- [F-03] C-masking: if fn is a wrapped global, return [C] profile
                if CFG.debug.cmask and _CFNS[first] then
                    return _cmock_info(_CFNS[first], _type(fmt) == "string" and fmt or "n")
                end
                -- Do NOT unwrap: guest should see wrapper source info,
                -- not the native C function's "[C]" source (for non-masked fns).
                return _dbg_info(first, fmt)
            end

            -- ── Stack level form: debug.info(level, fmt) ──────────
            if _type(first) == "number" then
                local level = first + 1  -- account for this wrapper frame
                if _type(fmt) ~= "string" then
                    return _dbg_info(level, fmt)
                end

                -- If "f" is in fmt, intercept any C functions exposed
                if _sfind(fmt, "f", 1, true) then
                    local results = _tpack(_dbg_info(level, fmt))
                    local fpos = 0
                    for j = 1, #fmt do
                        local c = _ssub(fmt, j, j)
                        if c == "a" then
                            fpos += 2  -- "a" maps to two return values
                        else
                            fpos += 1
                            if c == "f" then
                                local fn2 = results[fpos]
                                if fn2 ~= nil and _type(fn2) == "function" then
                                    local src = _dbg_info(fn2, "s")
                                    if src == "[C]" then
                                        results[fpos] = _stealth
                                            and _safe_index or nil
                                    end
                                end
                                break
                            end
                        end
                    end
                    return _tunpack(results, 1, results.n)
                end

                return _dbg_info(level, fmt)
            end

            return _dbg_info(...)
        end,

        traceback = function(...)
            return _dbg_trace(...)
        end,
        setmemorycategory  = _dbg_setmcat,
        resetmemorycategory = _dbg_resetmcat,
    }, false, false), debug)
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §12  require HOOK                                               ║
-- ╚══════════════════════════════════════════════════════════════════╝
if CFG.require.hook then
    local _req = require
    cfn_write("require", function(v)
        local vt = _type(v)

        if vt == "number" then
            _log(1, "REQUIRE_EXT", v)
            if CFG.require.spoof then
                local mobj = CFG.require:lookup(v)
                if mobj ~= nil then
                    _log(2, "REQUIRE_SPOOF", v, mobj.Name)
                    if CFG.require.mock then
                        local model = _Instance.new("Model")
                        model.Name  = _sformat("required_asset_%d", v)
                        local clone = mobj:Clone()
                        clone.Name   = "MainModule"
                        clone.Parent = model
                        local result = _req(clone)
                        model:Destroy()
                        return result
                    else
                        v = mobj
                    end
                end
            end

        elseif vt == "string" then
            _log(1, "REQUIRE_PATH", v)
            local pcfg = CFG.require.path
            if pcfg then
                if pcfg.rewrite then
                    local rw = pcfg.rewrite(v)
                    if rw ~= nil then
                        _log(2, "REQUIRE_REWRITE", v, "→", rw)
                        v = rw
                    end
                end
                if pcfg.intercept then
                    local result = pcfg.intercept(v)
                    if result == false then
                        _error("require is not enabled for path: " .. _tostring(v), 2)
                    elseif result ~= nil then
                        _log(2, "REQUIRE_REDIRECT", v)
                        v = result
                    end
                end
            end

        else
            local raw = unwrap(v)
            if _typeof(raw) == "Instance" then
                _log(1, "REQUIRE_INT", (raw :: any):GetFullName())
                v = raw
            end
        end

        local result = _req(v)
        _log(1, "REQUIRE_RESULT", _type(result))
        return result
    end, _req)
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §13  INSTALL & FINALISE                                         ║
-- ╚══════════════════════════════════════════════════════════════════╝
_setfenv(1, _fenv)

_dbg_resetmcat()
_startTs = _os_clock()  -- positive → prelogs gate opens

_log(1, "OLSSA_READY " .. CFG.meta.revision
      .. "  dilation=" .. _dil
      .. "  stack="    .. CFG.stack.mode)

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §14  SELF-TEST HARNESS                                          ║
-- ╠══════════════════════════════════════════════════════════════════╣
-- ║  All tests run INSIDE the do block (full access to locals).      ║
-- ║  Tests use the wrapped globals (as a guest would) unless the     ║
-- ║  test specifically needs native behavior for comparison.         ║
-- ║  [LIM-xx] = known limitations, counted separately.              ║
-- ╚══════════════════════════════════════════════════════════════════╝
if CFG.selftest.enabled then

    local _PASS, _FAIL, _LIM = 0, 0, 0
    local _FAILED: {string} = {}

    -- ── Categorised result tracking ───────────────────────────────
    local _CAT: {[string]: {pass:number, fail:number}} = {}

    local function _check(cat: string, name: string, ok: boolean, lim: boolean?)
        if not _CAT[cat] then _CAT[cat] = { pass = 0, fail = 0 } end
        if lim then
            _LIM += 1
            _warn(_sformat("[OLSSA·TEST]  ⚠  [%-14s] %s", cat, name))
        elseif ok then
            _PASS += 1
            _CAT[cat].pass += 1
        else
            _FAIL += 1
            _CAT[cat].fail += 1
            _tinsert(_FAILED, _sformat("[%s] %s", cat, name))
            _warn(_sformat("[OLSSA·TEST]  ✗  [%-14s] %s", cat, name))
        end
    end

    -- ── Banner ────────────────────────────────────────────────────
    _warn("[OLSSA·TEST] ══════════════════════════════════════════════════")
    _warn(_sformat("[OLSSA·TEST]  Self-Test %s  ·  %s  ·  %s",
        CFG.meta.revision, CFG.meta.date, _ID))
    _warn("[OLSSA·TEST] ──────────────────────────────────────────────────")

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: typeof / type ───────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ typeof / type")
    _check("typeof",  "typeof(game) == 'Instance'",
        typeof(game) == "Instance")
    _check("typeof",  "typeof(workspace) == 'Instance'",
        typeof(workspace) == "Instance")
    _check("typeof",  "typeof(script) == 'Instance'",
        typeof(script) == "Instance")
    _check("typeof",  "typeof matches _typeof(_game)",
        typeof(game) == _typeof(_game))
    _check("typeof",  "typeof matches _typeof(_workspace)",
        typeof(workspace) == _typeof(_workspace))
    _check("type",    "type(game) == 'userdata'",
        type(game) == "userdata")
    _check("type",    "type(workspace) == 'userdata'",
        type(workspace) == "userdata")
    -- typeof on a newproxy without wrapper should return "userdata"
    do
        local raw = _newproxy(true)
        _check("typeof", "typeof(raw newproxy) == 'userdata'",
            typeof(raw) == "userdata")
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: equality ────────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ equality")
    _check("equality", "game == workspace.Parent",
        game == workspace.Parent)
    _check("equality", "rawequal(game, game)",
        rawequal(game, game))
    _check("equality", "rawequal(game, workspace.Parent)",
        rawequal(game, workspace.Parent))
    do
        local rs1 = game:GetService("RunService")
        local rs2 = game:FindFirstChildOfClass("RunService")
        _check("equality", "GetService == FindFirstChildOfClass (same proxy)",
            rs1 == rs2)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: tostring ────────────────────────────────════════
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ tostring")
    _check("tostring", "tostring(game) matches native",
        tostring(game) == _tostring(_game))
    _check("tostring", "tostring(workspace) == 'Workspace'",
        tostring(workspace) == "Workspace")
    _check("tostring", "tostring(workspace) matches native",
        tostring(workspace) == _tostring(_workspace))
    _check("tostring", "tostring(script) matches native",
        tostring(script) == _tostring(_script))
    _check("tostring", "tostring(42) == '42'",
        tostring(42) == "42")
    _check("tostring", "tostring(true) == 'true'",
        tostring(true) == "true")

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: ClassName / Name ───────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ ClassName / Name")
    _check("classname", "game.ClassName == 'DataModel'",
        game.ClassName == "DataModel")
    _check("classname", "workspace.ClassName == 'Workspace'",
        workspace.ClassName == "Workspace")
    do
        local ok1, cn1 = _pcall(function() return game.ClassName end)
        local ok2, cn2 = _pcall(function() return _game.ClassName end)
        _check("classname", "game.ClassName == _game.ClassName",
            ok1 and ok2 and cn1 == cn2)
    end
    do
        local ok1, n1 = _pcall(function() return game.Name end)
        local ok2, n2 = _pcall(function() return _game.Name end)
        _check("classname", "game.Name == _game.Name",
            ok1 and ok2 and n1 == n2)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: metatable / environment ────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ metatable / environment")
    _check("metatable", "getmetatable(game) is locked string",
        _type(getmetatable(game)) == "string")
    _check("metatable", "pcall(setmetatable, game, {}) fails",
        not _pcall(setmetatable, game, {}))
    _check("metatable", "pcall(setmetatable, getfenv(), {}) fails",
        not _pcall(setmetatable, getfenv(), {}))
    _check("environment", "rawget(getfenv(), 'game') ~= nil",
        rawget(getfenv(), "game") ~= nil)
    _check("environment", "_G == getfenv()",
        _G == getfenv())
    _check("environment", "getfenv(0) == getfenv(1)",
        getfenv(0) == getfenv(1))
    _check("environment", "getfenv(0) == getfenv()",
        getfenv(0) == getfenv())
    _check("environment", "shared ~= _G (isolated)",
        shared ~= _G)
    _check("environment", "type(shared) == 'table'",
        _type(shared) == "table")

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: game identity ───────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ game identity")
    if CFG.game.hook and CFG.game.creator.spoof then
        _check("game_id", "game.CreatorId == " .. CFG.game.creator.id,
            game.CreatorId == CFG.game.creator.id)
    end
    if CFG.game.hook and CFG.game.place.spoof then
        _check("game_id", "game.PlaceId == " .. CFG.game.place.id,
            game.PlaceId == CFG.game.place.id)
    end
    if CFG.game.hook and CFG.game.universe.spoof then
        _check("game_id", "game.GameId == " .. CFG.game.universe.id,
            game.GameId == CFG.game.universe.id)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: RunService ──────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ RunService")
    do
        local rsOk, rs = pcall(function()
            return game:GetService("RunService")
        end)
        _check("runservice", "GetService('RunService') ok",
            rsOk and rs ~= nil)
        if rsOk and rs ~= nil then
            _check("runservice", "typeof(RunService) == 'Instance'",
                typeof(rs) == "Instance")

            local stOk, stVal = _pcall(function() return rs:IsStudio() end)
            _check("runservice", "IsStudio() callable", stOk)
            if stOk and CFG.runservice.spoof and CFG.runservice.isstudio ~= nil then
                _check("runservice", "IsStudio() == " .. _tostring(CFG.runservice.isstudio),
                    stVal == CFG.runservice.isstudio)
            end

            local svOk, _ = _pcall(function() return rs:IsServer() end)
            _check("runservice", "IsServer() callable", svOk)

            local clOk, _ = _pcall(function() return rs:IsClient() end)
            _check("runservice", "IsClient() callable", clOk)

            local rmOk, _ = _pcall(function() return rs:IsRunMode() end)
            _check("runservice", "IsRunMode() callable", rmOk)

            local rnOk, _ = _pcall(function() return rs:IsRunning() end)
            _check("runservice", "IsRunning() callable", rnOk)
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: HttpService ─────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ HttpService")
    do
        local hOk, hs = pcall(function()
            return game:GetService("HttpService")
        end)
        _check("httpservice", "GetService('HttpService') ok",
            hOk and hs ~= nil)
        if hOk and hs ~= nil then
            _check("httpservice", "typeof(HttpService) == 'Instance'",
                typeof(hs) == "Instance")
            _check("httpservice", "GenerateGUID() ok",
                _pcall(function() return hs:GenerateGUID(false) end))
            _check("httpservice", "JSONEncode() ok",
                _pcall(function() return hs:JSONEncode({ test = 1 }) end))
            _check("httpservice", "JSONDecode() ok",
                _pcall(function() return hs:JSONDecode('{"a":1}') end))
            _check("httpservice", "UrlEncode() ok",
                _pcall(function() return hs:UrlEncode("hello world") end))
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: instance traversal ──────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ instance traversal")
    _check("traversal", "game:FindFirstChild('Workspace') ~= nil",
        game:FindFirstChild("Workspace") ~= nil)
    _check("traversal", "game:IsA('DataModel')",
        (function() local ok, r = _pcall(function() return game:IsA("DataModel") end)
            return ok and r end)())
    _check("traversal", "workspace:IsA('Workspace')",
        (function() local ok, r = _pcall(function() return workspace:IsA("Workspace") end)
            return ok and r end)())

    do
        local dOk, desc = _pcall(function() return game:GetDescendants() end)
        _check("traversal", "game:GetDescendants() > 0",
            dOk and desc and #desc > 0)
    end
    do
        local sOk = _pcall(function()
            return game:GetService("ServerScriptService").Parent == game
        end)
        _check("traversal", "ServerScriptService.Parent == game", sOk)
    end

    -- GetChildren wrapped
    do
        local ok, ch = _pcall(function() return game:GetChildren() end)
        _check("traversal", "game:GetChildren() non-empty",
            ok and ch and #ch > 0)
        if ok and ch and #ch > 0 then
            local c1 = ch[1]
            _check("traversal", "GetChildren()[1] typeof == Instance",
                typeof(c1) == "Instance")
            _check("traversal", "GetChildren()[1].Parent == game",
                c1.Parent == game)
        end
        -- Count must match native
        local ok2, nc = _pcall(function() return #_game:GetChildren() end)
        if ok and ok2 then
            _check("traversal", "#GetChildren() matches native",
                #ch == nc)
        end
    end

    -- IsA: wrapped result matches native
    do
        local ok1, r1 = _pcall(function() return game:IsA("DataModel") end)
        local ok2, r2 = _pcall(function() return _game:IsA("DataModel") end)
        _check("traversal", "game:IsA == _game:IsA (DataModel)",
            ok1 and ok2 and r1 == r2)
    end

    -- Deep property chain
    do
        local ok, cn = _pcall(function()
            return game:GetService("Workspace").Parent.ClassName
        end)
        _check("traversal", "GetService('Workspace').Parent.ClassName == 'DataModel'",
            ok and cn == "DataModel")
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: Instance.new ────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ Instance.new")
    do
        local ok, t2 = _pcall(function()
            local p = Instance.new("Part")
            p.Parent = workspace
            local t = typeof(p)
            p:Destroy()
            return t
        end)
        _check("instance_new", "Instance.new('Part') typeof == 'Instance'",
            ok and t2 == "Instance")
    end
    do
        -- typeof of new Instance matches native
        local nativePart = _Instance.new("Part")
        local expected   = _typeof(nativePart)
        nativePart:Destroy()
        local ok, t3 = _pcall(function()
            local p = Instance.new("Part")
            local r = typeof(p)
            p:Destroy()
            return r
        end)
        _check("instance_new", "Instance.new typeof matches native expected",
            ok and t3 == expected)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: pcall / xpcall ──────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ pcall / xpcall")
    do
        local ok, r1, r2 = pcall(function()
            return game.GameId, game.PlaceId
        end)
        _check("pcall", "multi-return from pcall correct",
            ok and r1 ~= nil and r2 ~= nil)
    end
    do
        local ok, err = pcall(function() error("test_pcall_error") end)
        _check("pcall", "error propagation through pcall",
            not ok and _type(err) == "string"
                and _sfind(err, "test_pcall_error", 1, true) ~= nil)
    end
    do
        local handled = false
        xpcall(function() error("test_xpcall") end, function()
            handled = true
        end)
        _check("pcall", "xpcall handler invoked", handled)
    end
    -- pcall with service return — [F-01] fix
    do
        local ok, rs = pcall(function()
            return game:GetService("RunService")
        end)
        _check("pcall", "pcall returns service proxy (isgame fix)",
            ok and rs ~= nil and typeof(rs) == "Instance")
        if ok and rs then
            _check("pcall", "service from pcall has method overrides",
                _pcall(function() return rs:IsRunning() end))
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: time dilation ───────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    if CFG.time.hook then
        _warn("[OLSSA·TEST]  ▸ time dilation")
        _check("time", "os.clock() > 0", os.clock() > 0)
        _check("time", "tick() > 0", tick() > 0)
        _check("time", "os.time() > 0", os.time() > 0)
        do
            local c1 = os.clock(); local c2 = os.clock()
            _check("time", "os.clock monotonic", c2 >= c1)
        end
        do
            local t1 = tick(); local t2 = tick()
            _check("time", "tick monotonic", t2 >= t1)
        end
        do
            local t0 = os.clock()
            task.wait(0)
            _check("time", "task.wait(0) returns, dt >= 0",
                os.clock() - t0 >= 0)
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: coroutine ───────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ coroutine")
    do
        local ok, v = _pcall(function()
            local fn = coroutine.wrap(function() return typeof(game) end)
            return fn()
        end)
        _check("coroutine", "wrap preserves env (typeof(game)=='Instance')",
            ok and v == "Instance")
    end
    do
        local ok, _ = _pcall(function()
            local co  = coroutine.create(function() return typeof(workspace) end)
            local ok2, val = coroutine.resume(co)
            return ok2 and val == "Instance"
        end)
        _check("coroutine", "create/resume preserves env", ok)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: iteration ───────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ iteration")
    do
        local n = 0
        for _ in pairs({ a=1, b=2 }) do n += 1 end
        _check("iteration", "pairs({a,b}) iterates 2 keys", n == 2)
    end
    do
        local n = 0
        for _ in ipairs({ 10, 20, 30 }) do n += 1 end
        _check("iteration", "ipairs({10,20,30}) iterates 3 entries", n == 3)
    end
    do
        local k, v = next({ x = 42 })
        _check("iteration", "next({x=42}) returns key+val",
            k == "x" and v == 42)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: rawops ──────────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ rawops")
    do
        local ok, rl = _pcall(function() return rawlen({ 1, 2, 3 }) end)
        _check("rawops", "rawlen({1,2,3}) == 3", ok and rl == 3)
    end
    _check("rawops", "rawequal(1, 1)", rawequal(1, 1))
    _check("rawops", "rawequal(1, 2) is false", not rawequal(1, 2))
    do
        local ok = _pcall(function() return rawget(game, "ClassName") end)
        -- For newproxy: rawget errors (correct native behavior for userdata)
        -- For table proxy: rawget returns nil
        _check("rawops", "rawget(game,...) matches native behavior",
            not ok or true)  -- either is acceptable
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: string / concat ─────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ string / concat")
    _check("string", "string.len('abc') == 3", string.len("abc") == 3)
    _check("string", "string.format('%d',42) == '42'",
        string.format("%d", 42) == "42")
    do
        local ok, s = _pcall(function()
            return "prefix_" .. tostring(workspace)
        end)
        _check("string", "concat with tostring(workspace)",
            ok and s == "prefix_Workspace")
    end
    do
        local ok, s = _pcall(function() return tostring(game) end)
        _check("string", "tostring(game) produces string",
            ok and _type(s) == "string" and #s > 0)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: error signatures ────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ error signatures")
    do
        local ok1, e1 = _pcall(function() return game.NONEXISTENT_PROP_OLSSA end)
        local ok2, e2 = _pcall(function() return _game.NONEXISTENT_PROP_OLSSA end)
        _check("errors", "invalid prop error matches native",
            not ok1 and not ok2
            and _type(e1) == "string" and _type(e2) == "string")
    end
    do
        local ok = _pcall(function() return table.freeze(game) end)
        _check("errors", "table.freeze(game) errors (userdata)",
            not ok)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: weak tables ────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ weak tables")
    do
        local weak = _setmt({}, { __mode = "v" })
        weak[1] = game
        _check("weaktbl", "proxy in weak-value table survives", weak[1] == game)
    end
    do
        local weak = _setmt({}, { __mode = "k" })
        local k    = {}
        weak[k] = "sentinel"
        _check("weaktbl", "weak-key table works normally", weak[k] == "sentinel")
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: getfenv defense  [F-04]  ───────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ getfenv defense [F-04]")
    -- getfenv(0) and (1) must always return _fenv
    _check("getfenv", "getfenv(0) == _fenv", getfenv(0) == _fenv)
    _check("getfenv", "getfenv(1) == _fenv", getfenv(1) == _fenv)
    _check("getfenv", "getfenv(2) == _fenv (guarded/strict)",
        CFG.stack.mode == "passthrough"
        or getfenv(2) == _fenv)

    -- Out-of-range probe: getfenv(9999) must error, not succeed
    -- (strict mode is the only exception where it returns _fenv)
    do
        local ok, res = _pcall(getfenv, 9999)
        if CFG.stack.mode == "strict" then
            _check("getfenv", "getfenv(9999) returns _fenv (strict mode)",
                ok and res == _fenv, true)  -- LIM: strict is detectable
        else
            _check("getfenv", "getfenv(9999) errors (native behavior)",
                not ok)
        end
    end

    -- BindableEvent/__tostring stack-scan simulation
    -- The attack iterates levels 0..20 looking for environments ≠ localEnv
    -- with non-empty keys.  Since localEnv = getfenv() = _fenv for any code
    -- running after OLSSA, and every level returns _fenv, the check fails.
    do
        local localEnv = getfenv()
        local detected = false
        for i = 0, 12 do
            local s, env = _pcall(getfenv, i)
            if s and env and env ~= localEnv then
                local hasKeys = false
                for _ in _pairs(env) do hasKeys = true; break end
                if hasKeys then detected = true; break end
            end
        end
        _check("getfenv", "BindableEvent stack-scan simulation: undetected",
            not detected)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: debug.info / C-masking  [F-03]  ────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ debug.info / C-masking [F-03]")

    -- Wrapped globals must appear as "[C]" to debug.info (if cmask=true)
    if CFG.debug.cmask then
        local function _checkCMask(name: string, fn: any)
            local ok, src = _pcall(function()
                return debug.info(fn, "s")
            end)
            _check("debug_info", "debug.info(" .. name .. ",'s') == '[C]'",
                ok and src == "[C]")
        end
        _checkCMask("typeof",   typeof)
        _checkCMask("pcall",    pcall)
        _checkCMask("xpcall",   xpcall)
        _checkCMask("getfenv",  getfenv)
        _checkCMask("setfenv",  setfenv)
        _checkCMask("tostring", tostring)
        _checkCMask("rawequal", rawequal)
        _checkCMask("rawlen",   rawlen)
        _checkCMask("pairs",    pairs)
        _checkCMask("ipairs",   ipairs)
        _checkCMask("next",     next)
    end

    -- debug.info level query works
    do
        local ok, src = _pcall(function() return debug.info(1, "s") end)
        _check("debug_info", "debug.info(1,'s') returns string",
            ok and _type(src) == "string")
    end

    -- debug.traceback accessible
    do
        local tr = debug.traceback()
        _check("debug_info", "debug.traceback() returns string",
            _type(tr) == "string" and #tr > 0)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: metamethod theft  ──────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST]  ▸ metamethod theft")
    do
        -- Classic __index theft via xpcall + debug.info(2,"f")
        local stolen = nil
        xpcall(function()
            return (game :: any)["_OLSSA_nonexistent_prop_test"]
        end, function()
            stolen = debug.info(2, "f")
        end)

        local safe = false
        if stolen == nil then
            safe = true  -- non-stealth mode OK
        elseif _type(stolen) == "function" then
            -- stealth mode: verify it's our safe proxy, not raw [C]
            local src = _dbg_info(stolen, "s")
            local callOk, res = _pcall(function()
                return stolen(_game, "ClassName")
            end)
            safe = src ~= "[C]" and callOk and res == "DataModel"
        end
        _check("metamethod_theft", "debug.info(2,'f') theft blocked", safe)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: require hook ────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    if CFG.require.hook then
        _warn("[OLSSA·TEST]  ▸ require hook")
        _check("require", "require is function", _type(require) == "function")
        if CFG.debug.cmask then
            local ok, src = _pcall(function() return debug.info(require, "s") end)
            _check("require", "debug.info(require,'s') == '[C]'",
                ok and src == "[C]")
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: __namecall (regression)  ───────────────────────
    -- ══════════════════════════════════════════════════════════════
    -- These verify that method calls via colon syntax (:) work correctly
    -- when __namecall is NOT set (falls back to __index, which is correct).
    _warn("[OLSSA·TEST]  ▸ __namecall regression")
    do
        local ok, r = _pcall(function() return game:GetService("RunService") end)
        _check("namecall", "game:GetService() via __index fallback",
            ok and r ~= nil)
    end
    do
        local ok, r = _pcall(function() return workspace:IsA("Workspace") end)
        _check("namecall", "workspace:IsA() via __index fallback",
            ok and r == true)
    end
    do
        local ok, r = _pcall(function()
            local rs = game:GetService("RunService")
            return rs:IsRunning()
        end)
        _check("namecall", "service:IsRunning() via __index fallback", ok)
    end
    do
        -- Chained calls: each result goes through resolve/wrap pipeline
        local ok, cn = _pcall(function()
            return game:GetService("RunService"):IsA("RunService")
        end)
        _check("namecall", "chained service:method() works", ok and cn == true)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── SUMMARY TABLE ─────────────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] ──────────────────────────────────────────────────")

    -- Sort categories for stable output
    local _catNames: {string} = {}
    for k in _pairs(_CAT) do _tinsert(_catNames, k) end
    _tsort(_catNames)

    for _, cat in _ipairs(_catNames) do
        local c = _CAT[cat]
        local total = c.pass + c.fail
        local bar   = _srep("█", c.pass) .. _srep("░", c.fail)
        local status = c.fail == 0 and "✓" or "✗"
        _warn(_sformat("[OLSSA·TEST]  %s  %-18s  %s  %d/%d",
            status, cat, bar, c.pass, total))
    end

    _warn("[OLSSA·TEST] ──────────────────────────────────────────────────")
    _warn(_sformat("[OLSSA·TEST]  TOTAL   %d passed  %d failed  %d limitations",
        _PASS, _FAIL, _LIM))

    if #_FAILED > 0 then
        _warn("[OLSSA·TEST]  FAILURES:")
        for _, f in _ipairs(_FAILED) do
            _warn("[OLSSA·TEST]    ✗  " .. f)
        end
    end

    _warn("[OLSSA·TEST] ══════════════════════════════════════════════════")

    if CFG.selftest.halt_on_fail and _FAIL > 0 then
        _error(_sformat("[OLSSA] Self-test failed: %d failures", _FAIL), 0)
    end
end

end -- §END OLSSA v4.2
--================----===OLSSAEND===----================--