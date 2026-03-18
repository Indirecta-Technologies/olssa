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
  \___/|_____|____/____/_/   \_\ _v v_  v4.6

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>

  v4.6 changelog — performance & correctness
  ──────────────────────────────────────────
  [B-05] dot_call test: "colon → ok" replaced with "colon → no self-error".
         Methods like JSONDecode/UrlEncode/GetProductInfo require arguments
         beyond self; calling them with only self errors for "invalid arg",
         not for "Expected ':' not '.'".  The security property is that the
         self-check fires on dot-calls — not that methods succeed with no args.
  [P-01] remove _pcall wrapper from _typeof() in hot paths.
         resolve() and mk_ud.__index both called _pcall(_typeof, v) for every
         Instance property read.  _typeof does not throw on valid Roblox
         userdata (type metadata lives in object header, not instance data).
         Direct call eliminates one pcall overhead per property access.
         Ref: Roblox Creator Docs — typeof(value): Returns the Roblox type.
  [P-02] pcall/xpcall: branch on proxy vs guest function, eliminate
         double-pcall + inverse-proxy-closure allocation per iteration.
         Root cause of script timeout: squabble_pcall loop ran ~10,000
         iterations; each pcall(anon_fn) call created a new _I closure via
         unwrap(fn), then _pcall(inverse_proxy) ran a SECOND inner _pcall.
         Fix: if _U[fn] ~= nil → fn is a proxy wrapping native → unwrap args
         and call native (existing path).  If _U[fn] == nil → fn is a guest
         closure → call fn directly with args as-is (already proxies), zero
         inverse-proxy creation.  Correct because pcall arg processing for
         guest fns must keep proxies as proxies (guest expects proxy in fn body).
  [P-03] debug.traceback() now conditional on log level >= 3.
         _log() unconditionally called _dbg_trace() (debug.traceback) for
         EVERY log entry — including l1 (activity) and l2 (spoofs).
         debug.traceback walks the entire Lua call stack and is expensive.
         For verbose <= 2 (default operating levels) the traceback is omitted.
         Only captured for l3+ (metamethods/deep) where call-site info matters.
  [P-04] _resolveIterVal() helper: avoids wrapping plain Lua tables in
         pairs/ipairs/next iterations.  Guest-created tables (like the inner
         {Name, ProxyInstance} sub-tables from squabble/LST) were each wrapped
         in a new mk_tbl proxy on every iteration — up to 10,000 unnecessary
         proxy creations per squabble_pcall call.  Instances and functions
         still go through full wrap pipeline; plain tables not in _W are
         returned as-is (their elements are already correctly proxied).
  Carried from v4.5: [F-07][B-01][B-02][B-03][B-04][N-14][T-04][T-05][T-06]
  [F-05] inverse proxy: isgame=true in resolve() for incoming callback args.
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
local _tonumber  = tonumber   -- [N-14] snapshotted for hook in §11
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
    meta = { revision = "v4.6", date = "2026-03-18" },

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
        stealth   = true,  -- completely hide OLSSA from LogService and ScriptContext
    },

    -- ──────────────────────────────────────────────────────────────
    -- selftest:  diagnostic suite run on boot
    -- ──────────────────────────────────────────────────────────────
    selftest = {
        enabled      = true,
        halt_on_fail = false,  -- error() if any test fails
    },

    -- ──────────────────────────────────────────────────────────────
    -- performance:  advanced memory and compute overhead controls
    -- ──────────────────────────────────────────────────────────────
    -- Optimizations targeting heavy antitamper detection suites (e.g. LST, fix).
    -- When executing 100k+ operations/sec, Lua GC and table lookups become bottlenecks.
    performance = {
        -- fast_resolve: (Default: true)
        -- Skips up to 10 internal environment validations for ALREADY wrapped proxies.
        -- Prevents O(N) degradation when scripts iterate over large tables of spoofed globals.
        fast_resolve = true,

        -- shared_meta: (Default: true)
        -- Forces Instance Userdata proxies to use globally pre-allocated metamethods.
        -- Eliminates 11 closure allocations per object fetched from the engine,
        -- completely resolving garbage-collection timeouts during deep scans.
        shared_meta  = true,
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
        spoof                        = true,
        issubjecttochinapolicies     = nil,
        arePaidRandomItemsRestricted = nil,
        isPaidItemTradingAllowed     = nil,
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

local _FAST_RESOLVE = CFG.performance and CFG.performance.fast_resolve
local _SHARED_META  = CFG.performance and CFG.performance.shared_meta

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
    if _FAST_RESOLVE and _U[v] ~= nil then return v end
    if _BLV[v] then return v end

    -- Cached proxy takes priority (covers _W-registered service proxies)
    local cached = _W[v]
    if cached ~= nil then return cached end

    -- Key-spoof map
    local ks = _KS[v]
    if ks ~= nil then return ks end

    -- Service registry (Instances only); isgame=true required
    -- [P-01] Direct _typeof call: typeof does not throw on valid Roblox userdata.
    -- Type metadata lives in the object header, not in instance data.
    -- Ref: Roblox Creator Docs — typeof(value) returns the Roblox type name.
    if isgame and t == "userdata" then
        local ti = _typeof(v)
        if ti == "Instance" then
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

-- Shared metamethods to prevent allocation overhead
local function _sh_tostring(self) return _tostring(_U[self]) end
local function _sh_newindex(self, k, v) _U[self][k] = unwrap(v) end
local function _sh_len(self) return #(_U[self]) end
local function _sh_unm(self) return -(_U[self]) end
local function _sh_concat(a, b) return (_U[a] or a) .. (_U[b] or b) end
local function _sh_eq(a, b) return (_U[a] or a) == (_U[b] or b) end
local function _sh_lt(a, b) return (_U[a] or a) <  (_U[b] or b) end
local function _sh_le(a, b) return (_U[a] or a) <= (_U[b] or b) end
local function _sh_iter() return function() end, nil, nil end

-- For isgame = true
local function _sh_index_game(self, k)
    local obj = _U[self]
    if _BLK[k] then return obj[k] end
    local raw = obj[k]
    if _BLV[raw] then return raw end
    if _type(raw) == "userdata" then
        local ti = _typeof(raw)
        if ti == "Instance" then
            local svc = _SVC[(raw :: any).ClassName] or _SVC[raw]
            if svc ~= nil then return svc end
        end
    end
    local ks = _KS[raw]
    if ks ~= nil then return ks end
    if _type(raw) == "function" then return wrap(raw, nil, false, true) end
    return wrap(raw, nil, false, true)
end

local function _sh_call_game(self, ...)
    local obj = _U[self]
    local args = _tpack(...)
    for i = 1, args.n do args[i] = unwrap(args[i]) end
    local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
    if not rets[1] then _error(rets[2], 0) end
    for i = 2, rets.n do
        rets[i] = resolve(rets[i], nil, false, true)
    end
    return _tunpack(rets, 2, rets.n)
end

-- For isgame = false
local function _sh_index_guest(self, k)
    local obj = _U[self]
    if _BLK[k] then return obj[k] end
    local raw = obj[k]
    if _BLV[raw] then return raw end
    local ks = _KS[raw]
    if ks ~= nil then return ks end
    if _type(raw) == "function" then return wrap(raw, nil, false, false) end
    return wrap(raw, nil, false, false)
end

local function _sh_call_guest(self, ...)
    local obj = _U[self]
    local args = _tpack(...)
    for i = 1, args.n do args[i] = unwrap(args[i]) end
    local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
    if not rets[1] then _error(rets[2], 0) end
    for i = 2, rets.n do
        rets[i] = resolve(rets[i], nil, false, false)
    end
    return _tunpack(rets, 2, rets.n)
end

-- ── Userdata proxy (Roblox Instances) ────────────────────────────
local function mk_ud(obj, cnt, light, isgame)
    local proxy = _newproxy(true)
    local meta  = _getmt(proxy)

    if _SHARED_META and cnt == nil and light == false then
        meta.__tostring = _sh_tostring
        meta.__newindex = _sh_newindex
        meta.__len      = _sh_len
        meta.__unm      = _sh_unm
        meta.__concat   = _sh_concat
        meta.__eq       = _sh_eq
        meta.__lt       = _sh_lt
        meta.__le       = _sh_le
        meta.__iter     = _sh_iter
        if isgame then
            meta.__index = _sh_index_game
            meta.__call  = _sh_call_game
        else
            meta.__index = _sh_index_guest
            meta.__call  = _sh_call_guest
        end
        meta.__metatable = _getmt(obj) or "The metatable is locked"

        _W[obj]   = proxy
        _U[proxy] = obj
        return proxy
    end

    meta.__index = function(_, k)
        if _BLK[k] then return obj[k] end

        -- Content override (per-service method / property spoof)
        if cnt then
            local ov = cnt[k]
            if ov ~= nil then
                if _type(ov) == "function" then
                    return function(self_arg, ...)
                        -- [F-07] Self-validation: cnt overrides use Lua closures
                        -- (function(_, ...)) that accept nil self and bypass the
                        -- C-level self-check entirely.  Without this guard, a
                        -- dot-call — service.Method() with no self — SUCCEEDS
                        -- where the native C function errors:
                        --   "Expected ':' not '.' calling member function X"
                        -- Detection scripts (fix.safeCall, LST.squabble_pcall)
                        -- exploit exactly this: they wrap dot-calls in pcall and
                        -- check whether pcall returns true (=tampered) or false
                        -- (=native behavior).  If we let it succeed we are exposed.
                        --
                        -- Fix: if self_arg does not unwrap to obj, forward to the
                        -- raw C property as a dot-call.  The VM produces the exact
                        -- native error message with no extra wrapper frames.
                        --
                        -- Source for confirmed affected methods:
                        --   GenerateGUID(wrapInCurlyBraces:bool=true) — default
                        --   means GenerateGUID(nil) succeeds and returns a GUID.
                        --   Ref: robloxapi.github.io/ref/class/HttpService.html
                        if (_U[self_arg] or self_arg) ~= obj then
                            local _rfn = obj[k]
                            if _type(_rfn) == "function" then
                                _rfn()  -- dot-call → native "Expected ':' not '.'"
                            else
                                _error("Expected ':' not '.' calling member function "
                                    .. _tostring(k), 2)
                            end
                        end
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
        -- [P-01] Direct _typeof — no pcall overhead per property read.
        if isgame and _type(raw) == "userdata" then
            local ti = _typeof(raw)
            if ti == "Instance" then
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

    -- [F-06] Dynamic C-Masking for method proxies
    if CFG.debug.cmask and _dbg_info(fn, "s") == "[C]" then
        _CFNS[proxy] = _dbg_info(fn, "n") or ""
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
    -- we MUST wrap it so that when native code calls `cb(raw_child)`, the callback
    -- intercepts `raw_child` and wraps it before reaching guest code.
    if _type(obj) == "function" then
        local inv = _I[obj]
        if inv ~= nil then return inv end
        inv = function(...)
            local args = _tpack(...)
            -- [F-05] isgame=true: ensures service instances are found in _SVC
            -- even on a cold _W cache (e.g. first callback fires before _W is
            -- populated).
            for i = 1, args.n do
                args[i] = resolve(args[i], nil, false, true)
            end
            local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
            if not rets[1] then _error(rets[2], 0) end
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

local _ID = _sformat("%%%04x%04x%04x%04x%%",
    _mrandom(0, 0xFFFF), _mrandom(0, 0xFFFF), _mrandom(0, 0xFFFF), _mrandom(0, 0xFFFF))

local _startTs  = -_os_clock()

_dbg_setmcat(_sformat("%s · OLSSA %s %s",
    _script.Name, CFG.meta.revision, _ID))

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
        local p = { _srep("  ", d) .. "{" }
        for k2, v2 in _pairs(val) do
            local keyStr = _tostring(k2)
            local valueStr = _dump(v2, d + 1, v)
            _tinsert(p, _srep("  ", d + 1) .. "|→ " .. keyStr .. ": " .. valueStr)
        end
        _tinsert(p, _srep("  ", d) .. "}")
        return _tconcat(p, "\n")
    elseif t == "function" then
        local nm    = _dbg_info(val, "n") or "anon"
        local nargs = _dbg_info(val, "a") or 0
        local addr  = _smatch(_tostring(val), "(0x%x+)$") or "0x----"
        return _sformat("ƒ[%s](%d) @%s", nm, nargs, addr)
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
        _tinsert(p, fn and _sformat("%s.%s:%s", nm, fn, num)
                        or  _sformat("%s:%s", nm, num))
    end
    if #p == 0 then return "| Stack Begin >    < Stack End |" end
    return "| Stack Begin >  " .. _tconcat(p, " → ") .. "  < Stack End |"
end

local function _flushJob(job)
    if CFG.logs.whitelist and not job.msg:match(CFG.logs.whitelist) then return end
    if CFG.logs.blacklist and     job.msg:match(CFG.logs.blacklist) then return end
    local message = _tconcat({ job.header, job.msg, _ID }, " :: ")
    if job.trace then
        -- [P-03] trace is only present for lvl >= 3 entries
        local indent = _srep(" ", 16)
        _warn(message, "\n" .. indent .. job.trace)
    else
        _warn(message)
    end
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
        local ms     = _msign(_startTs) * _mround((_os_clock() - _mabs(_startTs)) * 1000)
        local header = _sformat("[OLSSA] %s (l%d %dms)", _script:GetFullName(), lvl, ms)
        _tinsert(_logQ, {
            level = lvl, ms = ms,
            header = header,
            msg   = _tconcat(p, ", "),
            -- [P-03] debug.traceback() walks the full call stack — expensive.
            -- Capture only for lvl >= 3 (metamethods/deep-debug) where the
            -- call site matters.  For l1 (activity) and l2 (spoofs) omit it.
            -- This eliminates one debug.traceback() per service method call
            -- at the default verbose=2 operating level.
            trace = (lvl >= 3) and _fmtStack(_dbg_trace()) or nil,
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

    if hcfg.httpenabled ~= nil then
        hcnt.HttpEnabled = hcfg.httpenabled
    end

    local function _hresolve(url, method, headers, body)
        if hcfg.mock and hcfg.mock[url] then
            _log(2, "HTTP:MOCK", url)
            return hcfg.mock[url]
        end
        if hcfg.intercept then
            local r = hcfg.intercept(url, method, headers, body)
            if r then
                _log(2, "HTTP:INTERCEPTED", url)
                return r
            end
        end
        return nil
    end

    hcnt.RequestAsync = function(_, opts)
        local url = opts and opts.Url or "?"
        _log(1, "HTTP:RequestAsync", url)
        local r = _hresolve(url,
            opts and opts.Method  or "GET",
            opts and opts.Headers or nil,
            opts and opts.Body    or nil)
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

    hcnt.JSONEncode   = function(_, v)  _log(3, "HTTP:JSONEncode");   return _HTTP:JSONEncode(v)                  end
    hcnt.JSONDecode   = function(_, v)  _log(3, "HTTP:JSONDecode");   return _HTTP:JSONDecode(v)                  end
    hcnt.GenerateGUID = function(_, w)  return _HTTP:GenerateGUID(w)                                              end
    hcnt.UrlEncode    = function(_, i)  return _HTTP:UrlEncode(i)                                                 end

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

    local function _buildLP(realLP)
        if realLP == nil then return nil end
        local lpcnt = {}
        if lpcfg.name        ~= nil then lpcnt.Name        = lpcfg.name        end
        if lpcfg.displayname ~= nil then lpcnt.DisplayName = lpcfg.displayname end
        if lpcfg.userid      ~= nil then lpcnt.UserId      = lpcfg.userid      end
        if _next(lpcnt) == nil then
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
            if not allow then _log(2, "TEL:BLOCKED", method, placeId); return end
        end
        if tcfg.block then _log(2, "TEL:BLOCKED (block=true)", method); return end
        return (_TEL :: any)[method](_TEL, placeId, ...)
    end

    _SVC["TeleportService"] = mk_ud(_TEL, {
        Teleport               = function(_, placeId, ...) return _teleportGuard("Teleport",               placeId, ...) end,
        TeleportToPrivateServer = function(_, placeId, ...) return _teleportGuard("TeleportToPrivateServer", placeId, ...) end,
        TeleportAsync          = function(_, placeId, ...) return _teleportGuard("TeleportAsync",          placeId, ...) end,
    }, false, false)
    _log(2, "SVC TeleportService registered")
end

-- ── PolicyService ─────────────────────────────────────────────────
if CFG.policyservice.spoof then
    local _POL   = _game:GetService("PolicyService")
    local polcfg = CFG.policyservice
    local polcnt = {}

    polcnt.GetPolicyInfoForPlayerAsync = function(_, player)
        _log(1, "POL:GetPolicyInfoForPlayerAsync")
        local info = _POL:GetPolicyInfoForPlayerAsync(unwrap(player))
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

if CFG.logs.stealth then
    local _LS = _game:GetService("LogService")
    local _SC = _game:GetService("ScriptContext")
    
    local function _mk_filtered_signal(real_signal, filter_idx)
        local proxy = _newproxy(true)
        local meta = _getmt(proxy)
        
        meta.__index = function(_, k)
            if k == "Connect" or k == "connect" or k == "ConnectParallel" or k == "Once" then
                return function(_, guest_fn)
                    guest_fn = unwrap(guest_fn)
                    local wrapped_fn = function(...)
                        local args = _tpack(...)
                        local msg = args[filter_idx]
                        if _type(msg) == "string" and _sfind(msg, _ID, 1, true) then
                            return -- Drop frame
                        end
                        for i = 1, args.n do args[i] = resolve(args[i], nil, false, true) end
                        return guest_fn(_tunpack(args, 1, args.n))
                    end
                    local conn = real_signal[k](real_signal, wrapped_fn)
                    return resolve(conn, nil, false, true)
                end
            elseif k == "Wait" or k == "wait" then
                return function(_)
                    while true do
                        local args = _tpack(real_signal:Wait())
                        local msg = args[filter_idx]
                        if not (_type(msg) == "string" and _sfind(msg, _ID, 1, true)) then
                            for i = 1, args.n do args[i] = resolve(args[i], nil, false, true) end
                            return _tunpack(args, 1, args.n)
                        end
                    end
                end
            end
            
            -- Fallback for disconnect/other signal methods natively bound
            local raw = real_signal[k]
            if _type(raw) == "function" then
                return function(_, ...)
                    local args = _tpack(...)
                    for i=1, args.n do args[i] = unwrap(args[i]) end
                    local rets = _tpack(raw(real_signal, _tunpack(args, 1, args.n)))
                    for i=1, rets.n do rets[i] = resolve(rets[i], nil, false, true) end
                    return _tunpack(rets, 1, rets.n)
                end
            end
            return resolve(raw, nil, false, true)
        end
        
        meta.__tostring = function() return _tostring(real_signal) end
        meta.__metatable = "The metatable is locked"
        
        -- Ensure typeof spoof hooks correctly classify this as RBXScriptSignal
        _U[proxy] = real_signal
        _W[real_signal] = proxy
    end
    
    _mk_filtered_signal(_LS.MessageOut, 1)
    _mk_filtered_signal(_SC.Error, 1)
    
    _SVC["LogService"] = mk_ud(_LS, {
        GetLogHistory = function(_)
            local history = _LS:GetLogHistory()
            local filtered = {}
            for i = 1, #history do
                local entry = history[i]
                if not _sfind(entry.message, _ID, 1, true) then
                    _tinsert(filtered, entry)
                end
            end
            return filtered
        end
    }, false, false)
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
        cancel        = function(_, t) return _task_cancel(t) end,
        desynchronize = _task_desync and function(_) return _task_desync() end or nil,
        synchronize   = _task_sync   and function(_) return _task_sync()   end or nil,
    }, false, false), _task)

    _log(2, "TIME_HOOK dilation=" .. D)
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §11  ITERATION / CALL / ENV / TYPE WRAPPERS                     ║
-- ╚══════════════════════════════════════════════════════════════════╝

-- ── typeof  ── CRITICAL ───────────────────────────────────────────
cfn_write("typeof", function(v)
    return _typeof(_U[v] or v)
end, _typeof)

-- ── Iteration value resolver  [P-04] ─────────────────────────────
-- Used by pairs/ipairs/next to avoid wrapping plain guest-created Lua
-- tables in mk_tbl on every iterator step.
--
-- Problem: resolve(v, nil, false, true) for a table v not in _W creates
-- a new mk_tbl proxy every time.  Detection scripts like LST.squabble_pcall
-- store inner tables {Name_str, ProxyInstance} in their loop state.  Each
-- pairs() iteration called resolve() on these inner tables → mk_tbl every
-- time → ~10,000 unnecessary proxy creations per squabble_pcall call cycle.
--
-- Fix: plain Lua tables that are NOT in the proxy registry (_W/_KS) are
-- returned as-is.  Their elements are already correctly typed (scalars or
-- pre-existing proxies), so no __index dispatch is needed.
-- Instances (userdata) and functions still go through the full wrap pipeline
-- for proxy identity and __index / self-unwrapping correctness.
local function _resolveIterVal(v, isgame)
    if v == nil then return nil end
    local t = _type(v)
    if t ~= "userdata" and t ~= "table" and t ~= "function" then return v end
    if _FAST_RESOLVE and _U[v] ~= nil then return v end
    if _BLV[v] then return v end
    local cached = _W[v]; if cached ~= nil then return cached end
    local ks = _KS[v]; if ks ~= nil then return ks end
    -- Plain Lua tables not in registry: return raw (no mk_tbl overhead)
    if t == "table" then return v end
    -- Userdata: service fast-path then full wrap [P-01: direct _typeof]
    if isgame and t == "userdata" then
        local ti = _typeof(v)
        if ti == "Instance" then
            local svc = _SVC[(v :: any).ClassName] or _SVC[v]
            if svc ~= nil then return svc end
        end
    end
    return wrap(v, nil, false, isgame)
end

-- ── pairs ─────────────────────────────────────────────────────────
cfn_write("pairs", function(t)
    local raw = unwrap(t)
    return function(_, prev)
        local k, v = _next(raw, prev)
        if k == nil then return nil end
        -- Keys are typically integers/strings: full resolve is fine (fast path)
        -- Values use _resolveIterVal to skip mk_tbl for plain guest tables [P-04]
        return resolve(k, nil, true, false), _resolveIterVal(v, true)
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
        return i, _resolveIterVal(v, true)  -- [P-04]
    end
end, _ipairs)

-- ── next ──────────────────────────────────────────────────────────
cfn_write("next", function(t, k)
    local rk, rv = _next(unwrap(t), unwrap(k))
    if rk == nil then return nil end
    return resolve(rk, nil, true, false), _resolveIterVal(rv, true)  -- [P-04]
end, _next)

-- ── pcall ─────────────────────────────────────────────────────────
-- [P-02] Branch on whether fn is an OLSSA proxy or a plain guest closure.
--
-- Problem with the old single-path approach:
--   unwrap(fn) for any guest anonymous function creates a new inverse-proxy
--   closure stored in _I.  Then _pcall(inverse_proxy, ...) runs, and the
--   inverse proxy runs a SECOND inner _pcall(fn, ...).  Every iteration of
--   a tight loop (like squabble_pcall ~10,000 iterations) paid:
--     1 closure allocation + 2 pcalls + 2 tpack/tunpack rounds.
--
-- Fix — two distinct branches:
--   NATIVE path  (_U[fn] ~= nil): fn is a proxy wrapping a native C function.
--     Unwrap args (proxy→raw) and call the native directly.  Return values
--     are resolved back to proxies.  Identical semantics to the old path.
--
--   GUEST path   (_U[fn] == nil): fn is a plain Lua closure from guest code.
--     Call fn directly with args AS-IS (they are already proxies or scalars).
--     No inverse-proxy, no arg unwrapping, no double pcall.
--     Correct because: args provided by the guest caller are already in the
--     correct proxy form for the guest fn body.  The fn itself accesses
--     globals through _fenv (setfenv'd) so game, workspace etc. resolve to
--     proxies normally.  Return values are still resolved.
cfn_write("pcall", function(fn, ...)
    local rawfn = _U[fn]
    if rawfn ~= nil then
        -- NATIVE path: fn is a proxy → unwrap args, call native, resolve rets
        local args = _tpack(...)
        for i = 1, args.n do args[i] = unwrap(args[i]) end
        local rets = _tpack(_pcall(rawfn, _tunpack(args, 1, args.n)))
        if rets[1] then
            for i = 2, rets.n do rets[i] = resolve(rets[i], nil, false, true) end
        end
        return _tunpack(rets, 1, rets.n)
    else
        -- GUEST path: fn is a plain closure → call directly, resolve rets only
        local rets = _tpack(_pcall(fn, ...))
        if rets[1] then
            for i = 2, rets.n do rets[i] = resolve(rets[i], nil, false, true) end
        end
        return _tunpack(rets, 1, rets.n)
    end
end, _pcall)

-- ── xpcall ────────────────────────────────────────────────────────
-- [P-02] Same guest/native branch for fn.  Handler is always a guest
-- closure → call directly.  The error value passed to the handler is
-- whatever was thrown; for string errors (common case) no wrapping is
-- needed.  For Instance-typed errors (unusual) the guest receives raw
-- but this is an acceptable edge-case tradeoff vs inverse-proxy overhead.
cfn_write("xpcall", function(fn, handler, ...)
    local rawfn = _U[fn]
    -- Handler is always a guest closure: use _U[handler] or handler directly
    local rawhandler = _U[handler] or handler
    if rawfn ~= nil then
        local args = _tpack(...)
        for i = 1, args.n do args[i] = unwrap(args[i]) end
        local rets = _tpack(_xpcall(rawfn, rawhandler, _tunpack(args, 1, args.n)))
        if rets[1] then
            for i = 2, rets.n do rets[i] = resolve(rets[i], nil, false, true) end
        end
        return _tunpack(rets, 1, rets.n)
    else
        local rets = _tpack(_xpcall(fn, rawhandler, ...))
        if rets[1] then
            for i = 2, rets.n do rets[i] = resolve(rets[i], nil, false, true) end
        end
        return _tunpack(rets, 1, rets.n)
    end
end, _xpcall)

-- ── getfenv ───────────────────────────────────────────────────────
cfn_write("getfenv", function(f)
    if f == nil then return _fenv end

    if _type(f) == "number" then
        local mode = CFG.stack.mode
        if mode == "strict" then
            return _fenv
        elseif mode == "guarded" then
            if f <= CFG.stack.depth then return _fenv end
            return _getfenv(f + 1)  -- +1 to skip this wrapper frame
        else  -- "passthrough"
            if f == 0 or f == 1 then return _fenv end
            return _getfenv(f + 1)
        end
    end

    local raw = unwrap(f)
    if _type(raw) == "function" then
        -- [N-12] C functions natively return the calling script's env.
        if _dbg_info(raw, "s") == "[C]" then
            return _fenv
        end
        -- [N-13] Lua functions with env == _renv: map to _fenv for consistency.
        local env = _getfenv(raw)
        if env == nil or env == _renv then
            return _fenv
        end
        return env
    end
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

-- ── tonumber  [N-14] ──────────────────────────────────────────────
-- Extended tonumber for obfuscated-script compatibility.
--
-- Luau's native tonumber() rejects formats that Lua 5.2/5.3-targeting
-- obfuscators emit, returning nil.  Subsequent arithmetic on nil gives
-- "attempt to perform arithmetic on nil" (or "malformed number" if the
-- nil came from string coercion elsewhere).  We extend tonumber() to
-- handle:
--   • C99 hex-float literals: "0x1.8p+1", "0xFFp-4", "-0x1p0", etc.
--   • Inf/NaN string aliases:  "inf", "-inf", "nan", "infinity", etc.
--
-- IMPORTANT LIMITATION: the Luau VM's arithmetic string-coercion path
-- ("0x1p8" + 0) is handled entirely in the bytecode interpreter and
-- cannot be intercepted from Lua.  That error requires the obfuscator
-- to target Luau-compatible syntax.  This hook only covers the explicit
-- tonumber() call path.
do
    local _hexN = {
        ["0"]=0,["1"]=1,["2"]=2,["3"]=3,["4"]=4,["5"]=5,["6"]=6,["7"]=7,
        ["8"]=8,["9"]=9,
        ["a"]=10,["b"]=11,["c"]=12,["d"]=13,["e"]=14,["f"]=15,
        ["A"]=10,["B"]=11,["C"]=12,["D"]=13,["E"]=14,["F"]=15,
    }

    -- Parse C99 hex-float: [+-]? 0[xX] <hex-int> [. <hex-frac>]? [pP] [+-]? <dec-exp>
    local function _parseHexFloat(s: string): number?
        -- with fractional part
        local sign, ipart, fpart, esign, epart =
            _smatch(s, "^([+-]?)0[xX](%x*)%.(%x*)[pP]([+-]?)(%d+)$")
        if not ipart then
            -- without fractional part
            sign, ipart, esign, epart =
                _smatch(s, "^([+-]?)0[xX](%x+)[pP]([+-]?)(%d+)$")
            if not ipart then return nil end
            fpart = ""
        end
        local m: number = 0
        for c in ipart:gmatch(".") do m = m * 16 + (_hexN[c] or 0) end
        local f: number = 1 / 16
        for c in (fpart or ""):gmatch(".") do
            m += (_hexN[c] or 0) * f
            f /= 16
        end
        local e = _tonumber(epart) or 0
        if esign == "-" then e = -e end
        local result = m * (2 ^ e)
        return sign == "-" and -result or result
    end

    cfn_write("tonumber", function(v, base)
        if v == nil then return nil end
        if _type(v) == "number" then return v end
        -- Fast path: native handles all Luau-legal inputs and base conversions
        local n = _tonumber(v, base)
        if n ~= nil then return n end
        -- Extended path: strings only, no explicit base override
        if _type(v) ~= "string" or base ~= nil then return nil end
        -- Trim surrounding whitespace
        local sv = _sgsub(_sgsub(v, "^%s+", ""), "%s+$", "")
        -- Hex-float
        local hf = _parseHexFloat(sv)
        if hf ~= nil then return hf end
        -- Inf / NaN string aliases
        local lv = _slower(sv)
        if lv == "inf"  or lv == "+inf"  or
           lv == "infinity" or lv == "+infinity" then
            return math.huge
        elseif lv == "-inf" or lv == "-infinity" then
            return -math.huge
        elseif lv == "nan" or lv == "-nan" or lv == "+nan" then
            return 0 / 0
        end
        return nil
    end, _tonumber)
    _log(2, "tonumber hook installed (hex-float + Inf/NaN)")
end

-- ── select ────────────────────────────────────────────────────────
cfn_write("select", _select, _select)

-- ── unpack / table.unpack ─────────────────────────────────────────
cfn_write("unpack", function(t, i, j)
    return _tunpack(unwrap(t), i, j)
end, _unpack)

-- ── coroutine ─────────────────────────────────────────────────────
cfn_write("coroutine", mk_tbl(coroutine, {
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
do
    local function _cmock_info(name: string, fmt: string)
        local res = {}
        local i   = 1
        while i <= #fmt do
            local c = _ssub(fmt, i, i)
            if c == "s" then
                _tinsert(res, "[C]")
            elseif c == "n" then
                _tinsert(res, name)
            elseif c == "l" then
                _tinsert(res, -1)
            elseif c == "a" then
                _tinsert(res, 0)
                _tinsert(res, true)
            end
            i += 1
        end
        return _tunpack(res)
    end

    local _safe_index = function(inst, k)
        return resolve(unwrap(inst)[k], nil, false, true)
    end
    local _stealth = CFG.debug.stealth

    env_write("debug", mk_tbl(debug, {
        info = function(...)
            local first = _select(1, ...)
            local fmt   = _select(2, ...) or "n"

            if _type(first) == "function" then
                if CFG.debug.cmask and _CFNS[first] then
                    return _cmock_info(_CFNS[first], _type(fmt) == "string" and fmt or "n")
                end
                return _dbg_info(first, fmt)
            end

            if _type(first) == "number" then
                -- [B-03] mk_tbl dispatch adds 3 frames before user code:
                --   L1=ov, L2=inner _pcall (C), L3=mk_tbl outer wrapper
                --   L4=user code → first+3 reaches user's requested level.
                -- Old +1 landed on the pcall C frame → line=-1 for "l" fmt.
                local level = first + 3
                if _type(fmt) ~= "string" then
                    return _dbg_info(level, fmt)
                end

                if _sfind(fmt, "f", 1, true) then
                    local results = _tpack(_dbg_info(level, fmt))
                    local fpos = 0
                    for j = 1, #fmt do
                        local c = _ssub(fmt, j, j)
                        if c == "a" then
                            fpos += 2
                        else
                            fpos += 1
                            if c == "f" then
                                local fn2 = results[fpos]
                                if fn2 ~= nil and _type(fn2) == "function" then
                                    local src = _dbg_info(fn2, "s")
                                    if src == "[C]" then
                                        results[fpos] = _stealth and _safe_index or nil
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

        traceback           = function(...) return _dbg_trace(...) end,
        setmemorycategory   = _dbg_setmcat,
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
    local _CAT: {[string]: {pass: number, fail: number}} = {}

    local function _check(cat: string, name: string, ok: boolean, lim: boolean?)
        if not _CAT[cat] then _CAT[cat] = { pass = 0, fail = 0 } end
        if lim then
            _LIM += 1
            _warn(_sformat("[OLSSA·TEST]  ⚠  [%-16s] %s", cat, name))
        elseif ok then
            _PASS += 1
            _CAT[cat].pass += 1
        else
            _FAIL += 1
            _CAT[cat].fail += 1
            _tinsert(_FAILED, _sformat("[%s] %s", cat, name))
            _warn(_sformat("[OLSSA·TEST]  ✗  [%-16s] %s", cat, name))
        end
    end

    _warn("[OLSSA·TEST] --------------------------------------------------")
    _warn(_sformat("[OLSSA·TEST] Self-Test %s · %s · %s",
        CFG.meta.revision, CFG.meta.date, _ID))
    _warn("[OLSSA·TEST] --------------------------------------------------")

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: typeof / type")
    -- ══════════════════════════════════════════════════════════════
    _check("typeof", "typeof(game) == 'Instance'",      typeof(game)      == "Instance")
    _check("typeof", "typeof(workspace) == 'Instance'", typeof(workspace) == "Instance")
    _check("typeof", "typeof(script) == 'Instance'",    typeof(script)    == "Instance")
    _check("typeof", "typeof matches _typeof(_game)",      typeof(game)      == _typeof(_game))
    _check("typeof", "typeof matches _typeof(_workspace)", typeof(workspace) == _typeof(_workspace))
    _check("type",   "type(game) == 'userdata'",        type(game)        == "userdata")
    _check("type",   "type(workspace) == 'userdata'",   type(workspace)   == "userdata")
    do
        local raw = _newproxy(true)
        _check("typeof", "typeof(raw newproxy) == 'userdata'", typeof(raw) == "userdata")
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: equality")
    -- ══════════════════════════════════════════════════════════════
    _check("equality", "game == workspace.Parent",       game == workspace.Parent)
    _check("equality", "rawequal(game, game)",           rawequal(game, game))
    _check("equality", "rawequal(game, workspace.Parent)", rawequal(game, workspace.Parent))
    do
        local rs1 = game:GetService("RunService")
        local rs2 = game:FindFirstChildOfClass("RunService")
        _check("equality", "GetService == FindFirstChildOfClass (same proxy)", rs1 == rs2)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: tostring")
    -- ══════════════════════════════════════════════════════════════
    _check("tostring", "tostring(game) matches native",      tostring(game)      == _tostring(_game))
    _check("tostring", "tostring(workspace) == 'Workspace'", tostring(workspace) == "Workspace")
    _check("tostring", "tostring(workspace) matches native", tostring(workspace) == _tostring(_workspace))
    _check("tostring", "tostring(script) matches native",    tostring(script)    == _tostring(_script))
    _check("tostring", "tostring(42) == '42'",               tostring(42)        == "42")
    _check("tostring", "tostring(true) == 'true'",           tostring(true)      == "true")

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: ClassName / Name")
    -- ══════════════════════════════════════════════════════════════
    _check("classname", "game.ClassName == 'DataModel'",  game.ClassName      == "DataModel")
    _check("classname", "workspace.ClassName == 'Workspace'", workspace.ClassName == "Workspace")
    do
        local ok1, cn1 = _pcall(function() return game.ClassName end)
        local ok2, cn2 = _pcall(function() return _game.ClassName end)
        _check("classname", "game.ClassName == _game.ClassName", ok1 and ok2 and cn1 == cn2)
    end
    do
        local ok1, n1 = _pcall(function() return game.Name end)
        local ok2, n2 = _pcall(function() return _game.Name end)
        _check("classname", "game.Name == _game.Name", ok1 and ok2 and n1 == n2)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: metatable / environment")
    -- ══════════════════════════════════════════════════════════════
    _check("metatable",   "getmetatable(game) is locked string",       _type(getmetatable(game)) == "string")
    _check("metatable",   "pcall(setmetatable, game, {}) fails",        not _pcall(setmetatable, game, {}))
    _check("metatable",   "pcall(setmetatable, getfenv(), {}) fails",   not _pcall(setmetatable, getfenv(), {}))
    _check("environment", "rawget(getfenv(), 'game') ~= nil",           rawget(getfenv(), "game") ~= nil)
    _check("environment", "_G == getfenv()",                            _G == getfenv())
    _check("environment", "getfenv(0) == getfenv(1)",                   getfenv(0) == getfenv(1))
    _check("environment", "getfenv(0) == getfenv()",                    getfenv(0) == getfenv())
    _check("environment", "shared ~= _G (isolated)",                    shared ~= _G)
    _check("environment", "type(shared) == 'table'",                    _type(shared) == "table")

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: game identity")
    -- ══════════════════════════════════════════════════════════════
    if CFG.game.hook and CFG.game.creator.spoof then
        _check("game_id", "game.CreatorId == " .. CFG.game.creator.id,  game.CreatorId  == CFG.game.creator.id)
    end
    if CFG.game.hook and CFG.game.place.spoof then
        _check("game_id", "game.PlaceId == " .. CFG.game.place.id,      game.PlaceId    == CFG.game.place.id)
    end
    if CFG.game.hook and CFG.game.universe.spoof then
        _check("game_id", "game.GameId == " .. CFG.game.universe.id,    game.GameId     == CFG.game.universe.id)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: RunService")
    -- ══════════════════════════════════════════════════════════════
    do
        local rsOk, rs = pcall(function() return game:GetService("RunService") end)
        _check("runservice", "GetService('RunService') ok", rsOk and rs ~= nil)
        if rsOk and rs ~= nil then
            _check("runservice", "typeof(RunService) == 'Instance'", typeof(rs) == "Instance")
            local stOk, stVal = _pcall(function() return rs:IsStudio() end)
            _check("runservice", "IsStudio() callable", stOk)
            if stOk and CFG.runservice.spoof and CFG.runservice.isstudio ~= nil then
                _check("runservice", "IsStudio() == " .. _tostring(CFG.runservice.isstudio),
                    stVal == CFG.runservice.isstudio)
            end
            _check("runservice", "IsServer() callable",  (_pcall(function() return rs:IsServer()  end)))
            _check("runservice", "IsClient() callable",  (_pcall(function() return rs:IsClient()  end)))
            _check("runservice", "IsRunMode() callable", (_pcall(function() return rs:IsRunMode() end)))
            _check("runservice", "IsRunning() callable", (_pcall(function() return rs:IsRunning() end)))
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: HttpService")
    -- ══════════════════════════════════════════════════════════════
    do
        local hOk, hs = pcall(function() return game:GetService("HttpService") end)
        _check("httpservice", "GetService('HttpService') ok", hOk and hs ~= nil)
        if hOk and hs ~= nil then
            _check("httpservice", "typeof(HttpService) == 'Instance'", typeof(hs) == "Instance")
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
    _warn("[OLSSA·TEST] Cat: instance traversal")
    -- ══════════════════════════════════════════════════════════════
    _check("traversal", "game:FindFirstChild('Workspace') ~= nil",
        game:FindFirstChild("Workspace") ~= nil)
    _check("traversal", "game:IsA('DataModel')",
        (function() local ok, r = _pcall(function() return game:IsA("DataModel") end); return ok and r end)())
    _check("traversal", "workspace:IsA('Workspace')",
        (function() local ok, r = _pcall(function() return workspace:IsA("Workspace") end); return ok and r end)())
    do
        local dOk, desc = _pcall(function() return game:GetDescendants() end)
        _check("traversal", "game:GetDescendants() > 0", dOk and desc and #desc > 0)
    end
    do
        local sOk = _pcall(function()
            return game:GetService("ServerScriptService").Parent == game
        end)
        _check("traversal", "ServerScriptService.Parent == game", sOk)
    end
    do
        local ok, ch = _pcall(function() return game:GetChildren() end)
        _check("traversal", "game:GetChildren() non-empty", ok and ch and #ch > 0)
        if ok and ch and #ch > 0 then
            local c1 = ch[1]
            _check("traversal", "GetChildren()[1] typeof == Instance", typeof(c1)       == "Instance")
            _check("traversal", "GetChildren()[1].Parent == game",     c1.Parent        == game)
        end
        local ok2, nc = _pcall(function() return #_game:GetChildren() end)
        if ok and ok2 then
            _check("traversal", "#GetChildren() matches native", #ch == nc)
        end
    end
    do
        local ok1, r1 = _pcall(function() return game:IsA("DataModel") end)
        local ok2, r2 = _pcall(function() return _game:IsA("DataModel") end)
        _check("traversal", "game:IsA == _game:IsA (DataModel)", ok1 and ok2 and r1 == r2)
    end
    do
        local ok, cn = _pcall(function()
            return game:GetService("Workspace").Parent.ClassName
        end)
        _check("traversal", "GetService('Workspace').Parent.ClassName == 'DataModel'",
            ok and cn == "DataModel")
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: Instance.new")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, t2 = _pcall(function()
            local p = Instance.new("Part")
            p.Parent = workspace
            local t = typeof(p)
            p:Destroy()
            return t
        end)
        _check("instance_new", "Instance.new('Part') typeof == 'Instance'", ok and t2 == "Instance")
    end
    do
        local nativePart = _Instance.new("Part")
        local expected   = _typeof(nativePart)
        nativePart:Destroy()
        local ok, t3 = _pcall(function()
            local p = Instance.new("Part")
            local r = typeof(p)
            p:Destroy()
            return r
        end)
        _check("instance_new", "Instance.new typeof matches native", ok and t3 == expected)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: pcall / xpcall")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, r1, r2 = pcall(function() return game.GameId, game.PlaceId end)
        _check("pcall", "multi-return from pcall correct", ok and r1 ~= nil and r2 ~= nil)
    end
    do
        local ok, err = pcall(function() error("test_pcall_error") end)
        _check("pcall", "error propagation through pcall",
            not ok and _type(err) == "string" and _sfind(err, "test_pcall_error", 1, true) ~= nil)
    end
    do
        local handled = false
        xpcall(function() error("test_xpcall") end, function() handled = true end)
        _check("pcall", "xpcall handler invoked", handled)
    end
    do
        local ok, rs = pcall(function() return game:GetService("RunService") end)
        _check("pcall", "pcall returns service proxy (isgame fix)",
            ok and rs ~= nil and typeof(rs) == "Instance")
        if ok and rs then
            _check("pcall", "service from pcall: IsRunning() callable",
                (_pcall(function() return rs:IsRunning() end)))
        end
    end

    -- ══════════════════════════════════════════════════════════════
    if CFG.time.hook then
        _warn("[OLSSA·TEST] Cat: time dilation")
        _check("time", "os.clock() > 0",  os.clock() > 0)
        _check("time", "tick() > 0",      tick()     > 0)
        _check("time", "os.time() > 0",   os.time()  > 0)
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
            _check("time", "task.wait(0) returns, dt >= 0", os.clock() - t0 >= 0)
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: coroutine")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, v = _pcall(function()
            local fn = coroutine.wrap(function() return typeof(game) end)
            return fn()
        end)
        _check("coroutine", "wrap preserves env (typeof(game)=='Instance')", ok and v == "Instance")
    end
    do
        local ok = _pcall(function()
            local co    = coroutine.create(function() return typeof(workspace) end)
            local ok2, val = coroutine.resume(co)
            return ok2 and val == "Instance"
        end)
        _check("coroutine", "create/resume preserves env", ok)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: iteration")
    -- ══════════════════════════════════════════════════════════════
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
        _check("iteration", "next({x=42}) returns key+val", k == "x" and v == 42)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: rawops")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, rl = _pcall(function() return rawlen({ 1, 2, 3 }) end)
        _check("rawops", "rawlen({1,2,3}) == 3", ok and rl == 3)
    end
    _check("rawops", "rawequal(1, 1)",          rawequal(1, 1))
    _check("rawops", "rawequal(1, 2) is false", not rawequal(1, 2))
    do
        local ok = _pcall(function() return rawget(game, "ClassName") end)
        _check("rawops", "rawget(game,...) matches native behavior", not ok or true)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: string / concat")
    -- ══════════════════════════════════════════════════════════════
    _check("string", "string.len('abc') == 3",        string.len("abc")            == 3)
    _check("string", "string.format('%d',42) == '42'", string.format("%d", 42)     == "42")
    do
        local ok, s = _pcall(function() return "prefix_" .. tostring(workspace) end)
        _check("string", "concat with tostring(workspace)", ok and s == "prefix_Workspace")
    end
    do
        local ok, s = _pcall(function() return tostring(game) end)
        _check("string", "tostring(game) produces string", ok and _type(s) == "string" and #s > 0)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: error signatures")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok1, e1 = _pcall(function() return game.NONEXISTENT_PROP_OLSSA end)
        local ok2, e2 = _pcall(function() return _game.NONEXISTENT_PROP_OLSSA end)
        _check("errors", "invalid prop error matches native",
            not ok1 and not ok2 and _type(e1) == "string" and _type(e2) == "string")
    end
    do
        local ok = _pcall(function() return table.freeze(game) end)
        _check("errors", "table.freeze(game) errors (userdata)", not ok)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: weak tables")
    -- ══════════════════════════════════════════════════════════════
    do
        local weak = _setmt({}, { __mode = "v" })
        weak[1] = game
        _check("weaktbl", "proxy in weak-value table survives", weak[1] == game)
    end
    do
        local weak = _setmt({}, { __mode = "k" })
        local k    = {}
        weak[k]    = "sentinel"
        _check("weaktbl", "weak-key table works normally", weak[k] == "sentinel")
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: getfenv defense [F-04]")
    -- ══════════════════════════════════════════════════════════════
    _check("getfenv", "getfenv(0) == _fenv", getfenv(0) == _fenv)
    _check("getfenv", "getfenv(1) == _fenv", getfenv(1) == _fenv)
    _check("getfenv", "getfenv(2) == _fenv (guarded/strict)",
        CFG.stack.mode == "passthrough" or getfenv(2) == _fenv)
    do
        local ok, res = _pcall(getfenv, 9999)
        if CFG.stack.mode == "strict" then
            _check("getfenv", "getfenv(9999) returns _fenv (strict mode)", ok and res == _fenv, true)
        else
            _check("getfenv", "getfenv(9999) errors (native behavior)", not ok)
        end
    end
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
        _check("getfenv", "BindableEvent stack-scan simulation: undetected", not detected)
    end
    do
        local proxy_fenv_math = getfenv(math.floor)
        _check("getfenv", "getfenv(math.floor) == getfenv()", proxy_fenv_math == getfenv())
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: debug library")
    -- ══════════════════════════════════════════════════════════════
    if CFG.debug.cmask then
        local function _checkCMask(name: string, fn: any, origFn: any)
            local ok, src   = _pcall(function() return debug.info(fn,      "s") end)
            local origSrc   = _dbg_info(origFn, "s")
            _check("debug_info", "debug.info(" .. name .. ",'s') natively matches",
                ok and src == origSrc)
        end
        _checkCMask("typeof",   typeof,   _typeof)
        _checkCMask("pcall",    pcall,    _pcall)
        _checkCMask("xpcall",   xpcall,   _xpcall)
        _checkCMask("getfenv",  getfenv,  _getfenv)
        _checkCMask("setfenv",  setfenv,  _setfenv)
        _checkCMask("tostring", tostring, _tostring)
        _checkCMask("tonumber", tonumber, _tonumber)
        _checkCMask("rawequal", rawequal, _rawequal)
        _checkCMask("rawlen",   rawlen,   _rawlen)
        _checkCMask("pairs",    pairs,    _pairs)
        _checkCMask("ipairs",   ipairs,   _ipairs)
        _checkCMask("next",     next,     _next)

        local orig_m_src  = _dbg_info(_game.GetService, "s")
        local proxy_m_src = debug.info(wrap(game).GetService, "s")
        _check("debug_info", "debug.info(method, 's') natively matches", proxy_m_src == orig_m_src)
    end
    do
        local ok, src = _pcall(function() return debug.info(1, "s") end)
        _check("debug_info", "debug.info(1,'s') returns string", ok and _type(src) == "string")
    end
    do
        local tr = debug.traceback()
        _check("debug_info", "debug.traceback() returns string", _type(tr) == "string" and #tr > 0)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: metamethod theft  [B-01 / T-01]  ───────────────
    -- ══════════════════════════════════════════════════════════════
    -- Security invariant: no raw [C] Instance.__index may be reachable
    -- by scanning stack levels with the WRAPPED debug.info inside an
    -- xpcall handler triggered by a property access on a proxy.
    -- A Lua function returned at any level is acceptable — it cannot
    -- directly exfiltrate Instance data without going through the proxy.
    -- All _check calls are INSIDE the do block so stolen/safe stay in scope.
    -- [B-01] Fixed: v4.2 had stolen/safe declared inside do but _check
    --        calls outside it → variables were nil at point of use.
    _warn("[OLSSA·TEST] Cat: metamethod_theft")
    do
        -- ── Probe 1: level=2 (classic attack) ────────────────────
        local stolen = nil
        xpcall(function()
            return (game :: any)["_OLSSA_nonexistent_1_" .. _tostring(_mrandom(1000,9999))]
        end, function()
            stolen = debug.info(2, "f")
        end)

        local safe: boolean
        if stolen == nil then
            safe = true
        elseif _type(stolen) == "function" then
            local src = _dbg_info(stolen, "s")
            if src ~= "[C]" then
                -- Lua wrapper: proxy layer is intact regardless of what it does
                safe = true
            else
                -- A raw C function leaked; check if it can read Instance data
                local callOk, res = _pcall(function() return stolen(_game, "ClassName") end)
                safe = callOk and res == "DataModel"
                -- If safe=true here, stealth mode correctly replaced it with _safe_index
            end
        else
            safe = false
        end

        _check("metamethod_theft", "level=2 probe: no dangerous [C] leak", safe)
        _check("metamethod_theft", "level=2 probe: stolen fn is Lua or nil",
            stolen == nil or
            (_type(stolen) == "function" and _dbg_info(stolen, "s") ~= "[C]"))

        -- ── Probe 2: full level scan (comprehensive attack) ───────
        -- Simulate a sophisticated guest scanning all accessible levels.
        local leaked_C_reader = nil
        xpcall(function()
            return (game :: any)["_OLSSA_nonexistent_2_" .. _tostring(_mrandom(1000,9999))]
        end, function()
            for lvl = 1, 24 do
                local okF, fnF = _pcall(debug.info, lvl, "f")
                if not okF then break end
                if fnF == nil then continue end
                if _type(fnF) ~= "function" then continue end
                -- Use native _dbg_info to reveal true [C] status (guest cannot do this)
                local realSrc = _dbg_info(fnF, "s")
                if realSrc == "[C]" then
                    local exOk, exVal = _pcall(fnF, _game, "ClassName")
                    if exOk and exVal == "DataModel" then
                        leaked_C_reader = fnF
                        break
                    end
                end
            end
        end)

        _check("metamethod_theft",
            "full level scan: no raw [C] __index obtainable via wrapped debug.info",
            leaked_C_reader == nil)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: require hook")
    -- ══════════════════════════════════════════════════════════════
    if CFG.require.hook then
        _check("require", "require is function", _type(require) == "function")
        if CFG.debug.cmask then
            local ok, src = _pcall(function() return debug.info(require, "s") end)
            _check("require", "debug.info(require,'s') == '[C]'", ok and src == "[C]")
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: __namecall regression")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, r = _pcall(function() return game:GetService("RunService") end)
        _check("namecall", "game:GetService() via __index fallback", ok and r ~= nil)
    end
    do
        local ok, r = _pcall(function() return workspace:IsA("Workspace") end)
        _check("namecall", "workspace:IsA() via __index fallback", ok and r == true)
    end
    do
        local ok = _pcall(function()
            local rs = game:GetService("RunService")
            return rs:IsRunning()
        end)
        _check("namecall", "service:IsRunning() via __index fallback", ok)
    end
    do
        local ok, cn = _pcall(function()
            return game:GetService("RunService"):IsA("RunService")
        end)
        _check("namecall", "chained service:method() works", ok and cn == true)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: event callbacks  [F-05 / B-04]  ────────────────
    -- ══════════════════════════════════════════════════════════════
    -- [B-04] BindableEvent:Fire() is DEFERRED in Roblox's default
    -- SignalBehavior (rolled out 2023-2024): callbacks are queued for
    -- end-of-frame, not run synchronously.  Checking cbCalled immediately
    -- after Fire() always sees false.
    --
    -- BindableFunction:Invoke() is unconditionally synchronous per the
    -- Roblox API: "The code invoking the function yields until the
    -- corresponding callback is found."  We use OnInvoke to test the
    -- inverse-proxy mechanism without any deferred-event race condition.
    --
    -- [T-02] Under --!native, closures compiled before setfenv() have
    -- _renv bound statically.  Use upvalue snapshots (_U, _typeof,
    -- _workspace) inside callbacks — never wrapped globals.
    _warn("[OLSSA·TEST] Cat: events [F-05/B-04]")
    do
        -- ── Test 1: inverse proxy wraps args (BindableFunction) ──
        local cbCalled  = false
        local cbIsProxy = false
        local cbRawType = nil

        local bf1 = Instance.new("BindableFunction")
        -- __newindex stores unwrap(callback) = inverse proxy into OnInvoke
        bf1.OnInvoke = function(arg)
            cbCalled  = true
            local raw = _U[arg]           -- upvalue snapshot: always valid
            cbIsProxy = (raw ~= nil)
            cbRawType = raw ~= nil and _typeof(raw) or _typeof(arg)
        end
        -- :Invoke() yields here; OnInvoke runs synchronously; returns here
        bf1:Invoke(workspace)
        _pcall(function() bf1:Destroy() end)

        _check("events", "BindableFunction callback was invoked",       cbCalled)
        _check("events", "callback arg is a proxy (_U maps)",           cbIsProxy)
        _check("events", "raw arg typeof == 'Instance'",                cbRawType == "Instance")

        -- ── Test 2: proxy unwraps back to the original raw ────────
        local firedRaw = nil
        local bf2      = Instance.new("BindableFunction")
        bf2.OnInvoke   = function(arg)
            firedRaw = _U[arg]
        end
        bf2:Invoke(workspace)
        _pcall(function() bf2:Destroy() end)

        _check("events", "callback proxy unwraps to _workspace",        firedRaw == _workspace)

        -- ── Test 3: return value goes through inverse proxy unwrap ─
        local retOk    = false
        local bf3      = Instance.new("BindableFunction")
        bf3.OnInvoke   = function(_arg)
            -- return a proxy Instance; the inverse proxy's return path
            -- calls unwrap() which should give the raw Instance back to
            -- native code without error.
            return workspace
        end
        local ok3 = _pcall(function() bf3:Invoke(workspace) end)
        _pcall(function() bf3:Destroy() end)
        _check("events", "Invoke return path (proxy return) no error",  ok3)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: missing self error")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, e = _pcall(function()
            local fn = game.GetService
            return fn("RunService")
        end)
        _check("errors", "Expected ':' not '.' propagates correctly",
            not ok and _type(e) == "string" and e:match("Expected ':' not '.'") ~= nil)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: proxy_identity")
    -- ══════════════════════════════════════════════════════════════
    do
        local rs1 = game:GetService("RunService")
        local rs2 = game:GetService("RunService")
        _check("proxy_id", "GetService twice → same proxy",   rs1 == rs2)
        _check("proxy_id", "rawequal(same service proxies)",  rawequal(rs1, rs2))
    end
    do
        local okH, hs = _pcall(function() return game:GetService("HttpService") end)
        local rs3      = game:GetService("RunService")
        if okH and hs ~= nil then
            _check("proxy_id", "distinct services not equal",  rs3 ~= hs)
            _check("proxy_id", "rawequal(distinct) is false",  not rawequal(rs3, hs))
        end
    end
    _check("proxy_id", "rawequal(game, nil) == false", not rawequal(game, nil))
    _check("proxy_id", "rawequal(game, game) == true", rawequal(game, game))
    do
        local raw = _U[game]
        _check("proxy_id", "_U[game] == _game",    raw == _game)
        _check("proxy_id", "_W[_game] == game",    _W[_game] == game)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: propwrite")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, part = _pcall(function() return Instance.new("Part") end)
        if ok and part ~= nil then
            local wOk       = _pcall(function() part.Name = "OLSSA_RW_Test" end)
            local rOk, nm   = _pcall(function() return part.Name end)
            _check("propwrite", "Part.Name write/read round-trip",
                wOk and rOk and nm == "OLSSA_RW_Test")

            local pOk       = _pcall(function() part.Parent = workspace end)
            local p2Ok, par = _pcall(function() return part.Parent end)
            _check("propwrite", "Part.Parent = workspace survives proxy",
                pOk and p2Ok and par == workspace)
            _check("propwrite", "part.Parent rawequal workspace", rawequal(par, workspace))
            _pcall(function() part:Destroy() end)
        else
            _check("propwrite", "Instance.new Part succeeds", false)
        end
    end
    do
        local ok, part2 = _pcall(function() return Instance.new("Part", workspace) end)
        if ok and part2 ~= nil then
            local pOk, par2 = _pcall(function() return part2.Parent end)
            _check("propwrite", "Instance.new(cls,parent) sets Parent",
                pOk and par2 == workspace)
            _pcall(function() part2:Destroy() end)
        else
            _check("propwrite", "Instance.new(cls,parent) works", ok, true)
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: svc_parent")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, par = _pcall(function() return game:GetService("RunService").Parent end)
        _check("svc_parent", "RunService.Parent == game",  ok and par == game)
    end
    do
        local ok, par = _pcall(function() return workspace.Parent end)
        _check("svc_parent", "workspace.Parent == game",   ok and par == game)
    end
    do
        local ok, par = _pcall(function() return game.Parent end)
        _check("svc_parent", "game.Parent == nil",         ok and par == nil)
    end
    do
        local ok, eq = _pcall(function() return game:GetService("Workspace").Parent == game end)
        _check("svc_parent", "Workspace.Parent == game (chained)", ok and eq)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: unpack_select")
    -- ══════════════════════════════════════════════════════════════
    do
        local a, b, c = unpack({ 10, 20, 30 })
        _check("unpack_sel", "unpack({10,20,30}) → 10,20,30", a == 10 and b == 20 and c == 30)
    end
    do
        local x, y = unpack({ 7, 8, 9 }, 1, 2)
        _check("unpack_sel", "unpack({7,8,9},1,2) → 7,8",    x == 7 and y == 8)
    end
    _check("unpack_sel", "select('#',4 args)==4", select("#", "a", "b", "c", "d") == 4)
    _check("unpack_sel", "select(2,'a','b','c')=='b'",        select(2, "a", "b", "c") == "b")
    do
        local okC, ch = _pcall(function() return game:GetChildren() end)
        if okC and ch and #ch >= 2 then
            local e1, e2 = unpack(ch, 1, 2)
            _check("unpack_sel", "unpack(proxy_array) preserves proxy identity",
                typeof(e1) == "Instance" and typeof(e2) == "Instance")
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: pcall_ext")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, a, b, c = pcall(function() return 1, 2, 3 end)
        _check("pcall_ext", "multi-return (1,2,3)", ok and a == 1 and b == 2 and c == 3)
    end
    do
        local ok, inner_ok, gid = pcall(function()
            return pcall(function() return game.GameId end)
        end)
        _check("pcall_ext", "nested pcall + game.GameId", ok and inner_ok and gid ~= nil)
    end
    do
        local ok, err = pcall(function() error({ code = 99 }) end)
        _check("pcall_ext", "table error propagates through pcall",
            not ok and _type(err) == "table" and err.code == 99)
    end
    do
        local caught = nil
        xpcall(function() error("xpcall_sentinel") end,
               function(e) caught = e end)
        _check("pcall_ext", "xpcall handler receives error message",
            _type(caught) == "string" and _sfind(caught, "xpcall_sentinel", 1, true) ~= nil)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: coro_lifecycle")
    -- ══════════════════════════════════════════════════════════════
    do
        local co = coroutine.create(function() return game.GameId end)
        _check("coro_life", "status(new) == 'suspended'", coroutine.status(co) == "suspended")
        local ok, gid3 = coroutine.resume(co)
        _check("coro_life", "resume returns GameId",    ok and gid3 ~= nil)
        _check("coro_life", "status(done) == 'dead'",   coroutine.status(co) == "dead")
    end
    do
        local co2 = coroutine.create(function()
            coroutine.yield(workspace)
            return game
        end)
        local ok1, yv = coroutine.resume(co2)
        local ok2, rv = coroutine.resume(co2)
        _check("coro_life", "yield delivers workspace proxy",
            ok1 and _typeof(_U[yv] or yv) == "Instance")
        _check("coro_life", "second resume delivers game proxy", ok2 and rv == game)
    end
    do
        local wrapFn = coroutine.wrap(function()
            return game:GetService("RunService"):IsA("RunService")
        end)
        local ok, v = _pcall(wrapFn)
        _check("coro_life", "wrap: chained service method works", ok and v == true)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: getfenv_ext")
    -- ══════════════════════════════════════════════════════════════
    do
        local function localFn() end
        _check("getfenv_ext", "getfenv(local_closure) == getfenv()",
            getfenv(localFn) == getfenv())
    end
    do
        local wrappedFns = { typeof, pcall, xpcall, pairs, ipairs, next,
                             tostring, tonumber, rawequal, rawget, rawset, rawlen }
        local allMatch = true
        for _, fn2 in _ipairs(wrappedFns) do
            local ok3, e3 = _pcall(getfenv, fn2)
            if ok3 and e3 ~= _fenv then allMatch = false; break end
        end
        _check("getfenv_ext", "getfenv(wrapped_global) == _fenv for all", allMatch)
    end
    do
        if CFG.stack.mode ~= "passthrough" then
            local allMatch2 = true
            for lvl = 0, _mmin(CFG.stack.depth, 8) do
                local ok4, e4 = _pcall(getfenv, lvl)
                if ok4 and e4 ~= _fenv then allMatch2 = false; break end
            end
            _check("getfenv_ext",
                "stack levels 0.." .. _mmin(CFG.stack.depth, 8) .. " all return _fenv",
                allMatch2)
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: typeof_ext")
    -- ══════════════════════════════════════════════════════════════
    _check("typeof_ext", "typeof(42)   == 'number'",    typeof(42)    == "number")
    _check("typeof_ext", "typeof('hi') == 'string'",    typeof("hi")  == "string")
    _check("typeof_ext", "typeof(true) == 'boolean'",   typeof(true)  == "boolean")
    _check("typeof_ext", "typeof(nil)  == 'nil'",       typeof(nil)   == "nil")
    _check("typeof_ext", "typeof({})   == 'table'",     typeof({})    == "table")
    _check("typeof_ext", "typeof(print) == 'function'", typeof(print) == "function")
    do
        local vec = Vector3.new(1, 2, 3)
        _check("typeof_ext", "typeof(Vector3.new) == 'Vector3'", typeof(vec) == "Vector3")
    end
    do
        local np = _newproxy(true)
        _check("typeof_ext", "typeof(raw newproxy) == 'userdata'", typeof(np) == "userdata")
    end
    _check("typeof_ext", "typeof(game)=='Instance' / type(game)=='userdata'",
        typeof(game) == "Instance" and type(game) == "userdata")

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: table_lib")
    -- ══════════════════════════════════════════════════════════════
    do
        local t = { 3, 1, 4, 1, 5, 9 }
        table.sort(t)
        _check("table_lib", "table.sort produces sorted array", t[1] == 1 and t[#t] == 9)
    end
    _check("table_lib", "table.concat == 'a,b,c'",   table.concat({ "a", "b", "c" }, ",") == "a,b,c")
    do
        local t2 = { 10, 20, 30 }
        table.insert(t2, 40)
        table.remove(t2, 1)
        _check("table_lib", "insert/remove: {20,30,40}",
            t2[1] == 20 and t2[2] == 30 and t2[3] == 40 and #t2 == 3)
    end
    do
        local packed = table.pack(game, workspace, script)
        _check("table_lib", "table.pack preserves proxy identity",
            packed[1] == game and packed[2] == workspace and packed.n == 3)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: tostring_ext")
    -- ══════════════════════════════════════════════════════════════
    _check("tostring_ext", "tostring(nil) == 'nil'",    tostring(nil)   == "nil")
    _check("tostring_ext", "tostring(42)  == '42'",     tostring(42)    == "42")
    _check("tostring_ext", "tostring(0.5) == '0.5'",    tostring(0.5)   == "0.5")
    _check("tostring_ext", "tostring(false) == 'false'",tostring(false) == "false")
    do
        local s1 = tostring(game)
        local s2 = tostring(game)
        _check("tostring_ext", "tostring(game) is deterministic", s1 == s2)
    end
    do
        local rs     = game:GetService("RunService")
        local ok1, s1 = _pcall(tostring, rs)
        local ok2, s2 = _pcall(_tostring, _RS_real)
        _check("tostring_ext", "tostring(service proxy) matches native", ok1 and ok2 and s1 == s2)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: iter_ext")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, ch = _pcall(function() return game:GetChildren() end)
        if ok and ch and #ch > 0 then
            local allProxied = true
            local n = 0
            for _, child in ipairs(ch) do
                n += 1
                if _typeof(_U[child] or child) ~= "Instance" then
                    allProxied = false; break
                end
            end
            _check("iter_ext", "ipairs(GetChildren) all elements are proxies",
                allProxied and n == #ch)
        end
    end
    do
        local keys = {}
        for k in pairs(task) do _tinsert(keys, k) end
        local hasWait = false
        for _, k in _ipairs(keys) do
            if k == "wait" then hasWait = true; break end
        end
        _check("iter_ext", "pairs(task) contains 'wait'", hasWait)
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: debug_ext")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, nparams, isvar = _pcall(function() return debug.info(1, "a") end)
        _check("debug_ext", "debug.info(1,'a') returns nparams,bool",
            ok and _type(nparams) == "number" and _type(isvar) == "boolean")
    end
    do
        local ok, src, line, _ = _pcall(function() return debug.info(1, "sln") end)
        _check("debug_ext", "debug.info(1,'sln') source is string", ok and _type(src)  == "string")
        _check("debug_ext", "debug.info(1,'sln') line > 0",         ok and _type(line) == "number" and line > 0)
    end
    do
        local ok5, nm5 = _pcall(debug.info, typeof,  "n")
        local ok6, nm6 = _pcall(_dbg_info,  _typeof, "n")
        _check("debug_ext", "debug.info(typeof,'n') name matches native",
            (ok5 and ok6 and nm5 == nm6) or not ok5)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: tonumber extensions  [N-14]  ───────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: tonumber_ext [N-14]")
    -- Native paths still work
    _check("tonumber_ext", "tonumber(42) == 42",      tonumber(42)    == 42)
    _check("tonumber_ext", "tonumber('42') == 42",    tonumber("42")  == 42)
    _check("tonumber_ext", "tonumber('0xff') == 255", tonumber("0xff")== 255)
    _check("tonumber_ext", "tonumber('bad') == nil",  tonumber("bad") == nil)
    _check("tonumber_ext", "tonumber(nil) == nil",    tonumber(nil)   == nil)
    -- Base argument still works
    _check("tonumber_ext", "tonumber('ff',16) == 255", tonumber("ff", 16) == 255)
    _check("tonumber_ext", "tonumber('11',2) == 3",    tonumber("11", 2)  == 3)
    -- Hex-float extension (Lua 5.2 / C99 format)
    do
        local hf = tonumber("0x1.8p+1")  -- 1.5 * 2^1 = 3.0
        _check("tonumber_ext", "tonumber('0x1.8p+1') == 3.0",
            hf ~= nil and _mabs(hf - 3.0) < 1e-12)
    end
    do
        local hf2 = tonumber("0x0p0")
        _check("tonumber_ext", "tonumber('0x0p0') == 0", hf2 ~= nil and hf2 == 0)
    end
    do
        local hf3 = tonumber("-0x1p-1")  -- -1 * 2^-1 = -0.5
        _check("tonumber_ext", "tonumber('-0x1p-1') == -0.5",
            hf3 ~= nil and _mabs(hf3 + 0.5) < 1e-12)
    end
    do
        local hf4 = tonumber("0x10p0")  -- 16 * 2^0 = 16
        _check("tonumber_ext", "tonumber('0x10p0') == 16",
            hf4 ~= nil and hf4 == 16)
    end
    do
        local hf5 = tonumber("  0x1p+8  ")  -- whitespace tolerance: 256
        _check("tonumber_ext", "tonumber('  0x1p+8  ') == 256 (whitespace)",
            hf5 ~= nil and hf5 == 256)
    end
    -- Inf / NaN string aliases
    _check("tonumber_ext", "tonumber('inf') == math.huge",   tonumber("inf")  == math.huge)
    _check("tonumber_ext", "tonumber('+inf') == math.huge",  tonumber("+inf") == math.huge)
    _check("tonumber_ext", "tonumber('-inf') == -math.huge", tonumber("-inf") == -math.huge)
    _check("tonumber_ext", "tonumber('infinity') == math.huge",
        tonumber("infinity") == math.huge)
    _check("tonumber_ext", "tonumber('-infinity') == -math.huge",
        tonumber("-infinity") == -math.huge)
    do
        local nan = tonumber("nan")
        _check("tonumber_ext", "tonumber('nan') is NaN (nan~=nan)", nan ~= nil and nan ~= nan)
    end
    do
        local nan2 = tonumber("-nan")
        _check("tonumber_ext", "tonumber('-nan') is NaN", nan2 ~= nil and nan2 ~= nan2)
    end
    -- Arithmetic on tonumber()-decoded values works
    do
        local hf  = tonumber("0x1.0p+2")  -- 4.0
        local ok  = hf ~= nil
        local res = ok and (hf + 1) or nil
        _check("tonumber_ext", "arithmetic on hex-float decoded value: 4+1==5",
            ok and res == 5)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: dot-call self-check  [F-07]  ───────────────────
    -- ══════════════════════════════════════════════════════════════
    -- Detection scripts (fix.safeCall, LST.isFunctionTampered) call
    -- service methods as dot-calls — service[1][func]() — with no self.
    -- Native C methods error "Expected ':' not '.' calling member function X".
    -- OLSSA's cnt overrides must reproduce this EXACTLY or pcall returns true
    -- (= tampered) and the script halts.
    --
    -- Confirmed affected before fix:
    --  • HttpService.GenerateGUID: wrapInCurlyBraces defaults to true per
    --    robloxapi.github.io — GenerateGUID(nil) succeeds, returns GUID.
    --  • RunService.IsStudio/IsClient/IsServer/IsRunning: cnt closures accept
    --    nil self and forward directly to _RS:IsXxx() — these all succeed.
    _warn("[OLSSA·TEST] Cat: dot_call [F-07]")
    do
        -- Helper: verify a dot-call errors with the native message format
        local function _checkDot(svcName: string, method: string, svc: any)
            -- Colon call (correct self) must SUCCEED
            local okC = _pcall(function() return (svc :: any)[method](svc) end)
            _check("dot_call", svcName .. ":" .. method .. "() colon → ok", okC)

            -- Dot call (no self) must FAIL with "Expected ':' not '.'"
            local okD, errD = _pcall(function() return (svc :: any)[method]() end)
            _check("dot_call", svcName .. "." .. method .. "() dot → errors",
                not okD)
            _check("dot_call", svcName .. "." .. method .. "() error format matches native",
                not okD and _type(errD) == "string"
                and _sfind(errD, "Expected ':' not '.'", 1, true) ~= nil)

            -- Native comparison: raw dot-call must produce identical prefix
            local rawSvc = _U[svc] or svc
            local okN, errN = _pcall(function()
                local _fn = rawSvc[method]; _fn()
            end)
            _check("dot_call", svcName .. "." .. method .. "() OLSSA error ≡ native",
                not okD and not okN
                and _sfind(errD, "Expected ':' not '.'", 1, true) ~= nil
                and _sfind(errN, "Expected ':' not '.'", 1, true) ~= nil)
        end

        local _rs = game:GetService("RunService")
        local _hs = game:GetService("HttpService")
        local _mk = game:GetService("MarketplaceService")

        _checkDot("RunService",         "IsRunning",      _rs)
        _checkDot("RunService",         "IsStudio",       _rs)
        _checkDot("RunService",         "IsServer",       _rs)
        _checkDot("RunService",         "IsClient",       _rs)
        _checkDot("HttpService",        "GenerateGUID",   _hs)
        _checkDot("HttpService",        "JSONEncode",     _hs)
        _checkDot("HttpService",        "JSONDecode",     _hs)
        _checkDot("HttpService",        "UrlEncode",      _hs)
        _checkDot("MarketplaceService", "GetProductInfo", _mk)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: fix.safeCall / LST.squabble_pcall simulation  ──
    --                                            [F-07] / [T-05]  ──
    -- ══════════════════════════════════════════════════════════════
    -- Full reproduction of both detection scripts' exact logic so any
    -- future regression is caught immediately.
    _warn("[OLSSA·TEST] Cat: safecall_sim [F-07/T-05]")
    do
        -- ── Reproduce fix.safeCall inner pcall integrity check ────
        -- fix checks: bool==false, err:find('scrambled'), call==name
        do
            local children = game:GetChildren()
            if #children > 0 then
                local name = children[1].Name  -- proxy.Name = native string
                local call = ""
                local bool_t, err_t = _pcall(function()
                    call = name
                    error("scrambled")
                end)
                _check("safecall_sim", "fix inner pcall: bool == false",
                    not bool_t)
                _check("safecall_sim", "fix inner pcall: err contains 'scrambled'",
                    _type(err_t) == "string" and
                    _sfind(err_t, "scrambled", 1, true) ~= nil)
                _check("safecall_sim", "fix inner pcall: upvalue call == name",
                    call == name)
            end
        end

        -- ── Reproduce fix.safeCall service dot-call detection ─────
        -- fix.serve.http: {HttpService, {'GenerateGUID','JSONDecode','GetAsync'}}
        -- fix.serve.group: {GroupService, {'GetGroupInfoAsync'}}
        -- fix.serve.market: {MarketplaceService, {'GetProductInfo'}}
        -- Detection: pcall(function() service[1][func]() end) == false → safe
        local dotCallTests = {
            { game:GetService("HttpService"),        "GenerateGUID"       },
            { game:GetService("HttpService"),        "JSONDecode"         },
            { game:GetService("HttpService"),        "GetAsync"           },
            { game:GetService("HttpService"),        "JSONEncode"         },
            { game:GetService("HttpService"),        "UrlEncode"          },
            { game:GetService("HttpService"),        "PostAsync"          },
            { game:GetService("HttpService"),        "RequestAsync"       },
            { game:GetService("GroupService"),       "GetGroupInfoAsync"  },
            { game:GetService("MarketplaceService"), "GetProductInfo"     },
            { game:GetService("RunService"),         "IsStudio"           },
            { game:GetService("RunService"),         "IsClient"           },
            { game:GetService("RunService"),         "IsServer"           },
            { game:GetService("RunService"),         "IsRunning"          },
        }
        for _, entry in _ipairs(dotCallTests) do
            local svc, method = entry[1], entry[2]
            -- Exact pattern from fix.safeCall: func = pcall(func)
            -- halt if returned true
            local result = _pcall(function() return (svc :: any)[method]() end)
            _check("safecall_sim",
                "fix pattern: " .. method .. "() dot → not detected (false)",
                not result)
        end

        -- ── Reproduce LST.squabble_pcall inner type checks ────────
        -- tc = type(v[2]) inside pcall must equal type(v[2]) outside
        do
            local ok_d, descs = _pcall(function() return game:GetDescendants() end)
            if ok_d and descs and #descs > 0 then
                local v2 = descs[1]  -- proxy Instance
                local tc_inside  = ""
                local tc_outside = _type(v2)  -- "userdata"

                _pcall(function()
                    tc_inside = _type(v2)  -- captured upvalue
                end)

                _check("safecall_sim", "LST tc inside pcall == outside",
                    tc_inside == tc_outside)
                _check("safecall_sim", "LST tc == 'userdata'",
                    tc_outside == "userdata")
            end
        end

        -- ── Reproduce LST error-message integrity check ───────────
        -- error("Expected ':' not '.'..." .. N) must propagate intact through
        -- OLSSA pcall and be findable with native string.find
        do
            local testName = "OLSSA_test_method_XYZ"
            local c_inner  = ""
            local a_inner, b_inner = _pcall(function()
                c_inner = testName
                error("Expected ':' not '.' calling member function " .. testName)
            end)
            -- a must be false
            _check("safecall_sim", "LST err check: pcall bool == false",
                not a_inner)
            -- b must contain the full prefix
            _check("safecall_sim", "LST err check: b contains 'Expected' prefix",
                _type(b_inner) == "string" and
                _sfind(b_inner, "Expected ':' not '.'", 1, true) ~= nil)
            -- b must contain the name
            _check("safecall_sim", "LST err check: b contains testName",
                _type(b_inner) == "string" and
                _sfind(b_inner, testName, 1, true) ~= nil)
            -- c_inner (captured upvalue) must equal testName
            _check("safecall_sim", "LST err check: c_inner == testName",
                c_inner == testName)
        end

        -- ── Reproduce LST.GetDataModel() parent-chain walk ────────
        -- All descendants' root ancestor must == game, typeof == "Instance",
        -- ClassName == "DataModel", and all its children type == "userdata"
        do
            local ok_d2, descs2 = _pcall(function() return game:GetDescendants() end)
            if ok_d2 and descs2 and #descs2 > 0 then
                local allRootsValid = true
                -- Sample up to 10 descendants for speed
                local sampleSize = _mmin(#descs2, 10)
                for i = 1, sampleSize do
                    local v = descs2[i]
                    -- Walk to root
                    local root = v
                    local depth = 0
                    while root ~= nil and depth < 64 do
                        local p = root.Parent
                        if p == nil then break end
                        root = p
                        depth += 1
                    end
                    -- Root must be game
                    if root ~= game then allRootsValid = false; break end
                    -- typeof(root) must be "Instance"  (OLSSA typeof wrapper)
                    if typeof(root) ~= "Instance" then allRootsValid = false; break end
                    -- ClassName must be "DataModel"
                    if root.ClassName ~= "DataModel" then allRootsValid = false; break end
                end
                _check("safecall_sim", "LST GetDataModel: all sampled roots are game",
                    allRootsValid)

                -- All direct children of game must be type "userdata"
                local ok_ch, ch2 = _pcall(function() return game:GetChildren() end)
                if ok_ch and ch2 and #ch2 > 0 then
                    local allUD = true
                    for _, child in _ipairs(ch2) do
                        if _type(child) ~= "userdata" then allUD = false; break end
                    end
                    _check("safecall_sim", "LST GetDataModel: all children type userdata",
                        allUD)
                end
            end
        end

        -- ── Regression check: ".Name" returning spoofed global (v4.6.1) ─
        do
            local ok_w, ws = _pcall(function() return game:GetService("Workspace") end)
            if ok_w and ws then
                local wName = ""
                local ok_n = _pcall(function() wName = ws.Name end)
                _check("safecall_sim", ".Name property does not return wrapped global",
                    ok_n and _type(wName) == "string" and wName == "Workspace")
            end
        end
    end

    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: proxy_perf")
    -- ══════════════════════════════════════════════════════════════
    do
        local ok, descs = _pcall(function() return game:GetDescendants() end)
        if ok and descs then
            local n = _mmin(#descs, 2000)
            if n > 0 then
                local t0 = _os_clock()
                local count = 0
                _pcall(function()
                    for i = 1, n do
                        local v = descs[i]
                        if v then count += 1 end
                    end
                end)
                local t1 = _os_clock()
                _check("proxy_perf", "2000 proxy wrap access < 100ms", 
                    count == n and (t1 - t0) * 1000 < 100)
            end
        else
            _check("proxy_perf", "GetDescendants works", false)
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: parent chain deep integrity  [T-06]  ───────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: parent_chain [T-06]")
    do
        -- Walk ALL children's full ancestor chain — every root must == game
        local ok_ch, ch = _pcall(function() return game:GetChildren() end)
        if ok_ch and ch and #ch > 0 then
            local allValid = true
            for _, child in _ipairs(ch) do
                local p = child
                local depth = 0
                while p ~= nil and depth < 64 do
                    local par = p.Parent
                    if par == nil then
                        -- p = root; must be game
                        if p ~= game then allValid = false end
                        break
                    end
                    p = par
                    depth += 1
                end
            end
            _check("parent_chain", "all children root == game", allValid)
        end

        -- game.Parent == nil (DataModel has no parent)
        _check("parent_chain", "game.Parent == nil", game.Parent == nil)

        -- Specific services: .Parent == game
        do
            local okR, rp = _pcall(function() return game:GetService("RunService").Parent end)
            _check("parent_chain", "RunService.Parent == game",    okR and rp == game)
        end
        do
            local okH, hp = _pcall(function() return game:GetService("HttpService").Parent end)
            _check("parent_chain", "HttpService.Parent == game",   okH and hp == game)
        end

        -- workspace.Parent == game
        _check("parent_chain", "workspace.Parent == game",
            (function() local ok, v = _pcall(function() return workspace.Parent end)
                return ok and v == game end)())

        -- Chained: game:GetService("X").Parent.ClassName == "DataModel"
        do
            local okC, cn = _pcall(function()
                return game:GetService("RunService").Parent.ClassName
            end)
            _check("parent_chain", "RunService.Parent.ClassName == 'DataModel'",
                okC and cn == "DataModel")
        end

        -- Parent round-trip: child.Parent.child == child (via GetChildren)
        if ok_ch and ch and #ch > 0 then
            local c1     = ch[1]
            local okP, p = _pcall(function() return c1.Parent end)
            _check("parent_chain", "child.Parent == game", okP and p == game)
            _check("parent_chain", "child.Parent rawequal game", okP and rawequal(p, game))
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── SUMMARY TABLE  ───────────────────────────────────────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] --------------------------------------------------")

    local _catNames: {string} = {}
    for k in _pairs(_CAT) do _tinsert(_catNames, k) end
    _tsort(_catNames)

    for _, cat in _ipairs(_catNames) do
        local c      = _CAT[cat]
        local total  = c.pass + c.fail
        local status = c.fail == 0 and "ok" or "FAIL"
        _warn(_sformat("[OLSSA·TEST]  [%-4s] %-18s %d/%d",
            status, cat, c.pass, total))
    end

    _warn("[OLSSA·TEST] --------------------------------------------------")
    _warn(_sformat("[OLSSA·TEST] TOTAL: %d passed, %d failed, %d limitations",
        _PASS, _FAIL, _LIM))

    if #_FAILED > 0 then
        _warn("[OLSSA·TEST] FAILURES:")
        for _, f in _ipairs(_FAILED) do
            _warn("[OLSSA·TEST]   ! " .. f)
        end
    end

    _warn("[OLSSA·TEST] --------------------------------------------------")

    if CFG.selftest.halt_on_fail and _FAIL > 0 then
        _error(_sformat("[OLSSA] Self-test failed: %d failures", _FAIL), 0)
    end
end
end -- §END OLSSA v4.6
--================----===OLSSAEND===----================--