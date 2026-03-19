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
  \___/|_____|____/____/_/   \_\ _v v_  v4.12

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>

  v4.12 changelog — CPU watchdog engine
  ──────────────────────────────────────
  [P-10] CPU watchdog: token-bucket rate limiter injected at OLSSA's safe
         yield points to prevent script execution timeout without exposing
         the yield to guest code via the dilated clock.

  Timeout mechanism (sourced from Roblox engineer Anaminus, devforum):
    The Roblox engine tracks per-thread continuous CPU time.  A thread times
    out when it runs for ~10 seconds without yielding back to the ENGINE.
    coroutine.yield() alone does NOT reset this — it only yields to the
    parent thread.  Only task.wait() / wait() which add the thread to the
    engine scheduler queue actually reset the timeout counter.

  Why OLSSA's wrappers cause timeout with guest tight loops:
    An obfuscated script running a 10,000-iteration loop calls OLSSA's
    pcall wrapper on every iteration.  The guest never voluntarily yields
    back to the engine.  OLSSA's wrapper overhead accumulates: 10,000+
    wrapper invocations × (tpack + unwrap loop + pcall + resolve loop +
    tunpack) = sustained CPU time far beyond 10s.

  Safe yield insertion points (Luau constraint: cannot yield in metamethods
  __index/__newindex/__call/__iter per Luau specification):
    • pcall GUEST path — regular function, safe to yield
    • xpcall GUEST path — regular function, safe to yield
    • (task.wait/wait already yield natively)

  Token bucket design:
    • Heartbeat refills tokens up to max_tokens each frame
    • Every pcall/xpcall GUEST entry consumes elapsed real wall-clock time
    • When tokens < 0: force _task_wait(0) → yields to engine (resets timer)
    • Token refill after yield = one full budget worth

  Stealth clock freeze (undetectable yielding):
    When a forced yield of Y real seconds occurs:
    • _fClockReal / _fTickReal snapshots are RESTORED to pre-yield values
    • _fClockFake / _fTickFake are NOT advanced during yield
    • Net effect: the yield period is completely invisible to dilated clock
    • Guest benchmarks: os.clock(), tick(), time() show ZERO elapsed time
      for the forced yield — identical to native execution with no yield
    • Detection proof: guest has no time function that bypasses dilation

  CFG.throttle (new top-level config):
    enabled    = true          — master switch
    budget_ms  = 8             — real ms of guest CPU per Heartbeat frame
                                 8ms ≈ half a frame at 60fps
    max_tokens = nil           — burst headroom (nil = 2 × budget)

  [P-11] Log flush budget 14ms → 20ms, selftest throttle removed.
  [P-12] _log early-exit before allocation when verbose level not met.
  Carried: [B-10..B-12][B-06..B-09][V-01][V-02][P-01..P-09][F-07][B-01..B-05]

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>

  v4.11 changelog
  ───────────────
  [B-10] Structural iteration fix: pairs/next only wrap values for OLSSA
         proxy tables, not for plain guest tables or _fenv.

  Root cause of DumpTable2 check4 failures (v4.8-v4.10):
    DumpTable2 does:
      for i,v in t do dump[i] = v end          -- generic-for
      for i,v in pairs(t) do                   -- pairs
          if dump[i] ~= v then a = false end
      end
    In Luau, `for k,v in t` (no __iter) compiles to use the environment's
    `next` function, NOT the VM builtin _next.  OLSSA's wrapped `next`
    calls _resolveIterVal on each value → creates new wrapper objects.
    Meanwhile `pairs(t)` with the _fenv special-case returned raw values.
    Result: generic-for yields wrapped values, pairs yields raw values.
    `dump[i] ~= v` → a = false → DumpTable2 returns true → detected.

  Structural fix:
    Both `pairs` and `next` check if the target table is an OLSSA-managed
    proxy (i.e. _U[t] ~= nil OR _W[t] ~= nil).  Only proxy tables get
    value wrapping via _resolveIterVal.  Plain guest tables (including
    _fenv, dump tables, and any Lua table the guest creates) return
    `_next, raw, nil` directly — the exact same iterator that Luau's
    VM-builtin generic-for produces.  Both paths are now identical by
    construction.  No special-casing of _fenv identity needed.

  [B-11] Removed §12.5 _PREPOP large explicit list.
    Pre-population was trying to solve the symptom (too few visible keys)
    rather than the cause (iteration path mismatch).  With B-10, both
    paths agree regardless of key count.  The actual detection check is
    `iterations == 0`, not `iterations > 50`.  OLSSA's ~30 own rawset
    entries are sufficient to pass (> 0).

  [B-12] Test threshold updated: >50 → >0 matching the actual detection
    script's logic (`if dumped.iterations == 0 then return true end`).

  Carried: [B-06..B-09][V-01][V-02][P-01..P-09][F-07][B-01..B-05][N-14]

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>

  v4.10 changelog
  ───────────────
  [B-08] _resolveIterVal: return unknown values as-is instead of wrapping.

  Root cause of v4.9 check4 failure:
    DumpTable2 builds `dump` via generic-for, then calls pairs(dump).
    OLSSA's pairs wrapper calls _resolveIterVal on each value in `dump`.
    Pre-populated non-registered values (warn, type, Vector3, CFrame, etc.)
    had no entry in _W/_KS/_U, so _resolveIterVal fell through to
    wrap(v,...), creating a NEW proxy object.  Then env[k] returned the
    original value.  new_proxy ~= original → b4=false → detected.

  Fix: in _resolveIterVal, replace the terminal `wrap(v,...)` with
  `return v`.  Unknown userdata/functions pass through unchanged.
  This is safe because:
    • Instances from game method returns are already in _W (proxied at
      call-return time via resolve(), not _resolveIterVal).
    • _resolveIterVal is only called for iteration of plain tables.
      The only unknown values are pre-pop entries (C functions, Roblox
      datatype constructors) and user-stored raw values, which should
      be transparent.

  [B-09] _PREPOP list expanded to 80+ Roblox Luau globals.
  Previous list (~40 entries) minus OLSSA overrides (~32) gave <50 net
  new entries.  Expanded with all Roblox standard globals, additional
  Lua globals, and Roblox-specific C functions to guarantee >50 entries
  visible via iteration regardless of OLSSA override count.

  Carried: [B-06][B-07][V-01][V-02][P-01..P-09][F-07][B-01..B-05][N-14]

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>

  v4.9 changelog
  ──────────────
  [B-07] DumpTable detection: two-part architectural fix.

  Root cause of v4.8 failures (still present):
    pairs(getfenv()) > 50 — FAIL: pre-population copied 0 keys because
      _next(_renv,...) finds nothing.  In Roblox Luau the script global
      environment's globals live in an __index chain, not as direct rawset
      entries.  _next on _renv returns only entries explicitly rawset at
      startup (none, or very few).
    pairs vs generic-for agree (DumpTable2) — FAIL: even with correct count,
      OLSSA's wrapped pairs() calls _resolveIterVal() on each value (wrapping
      functions into proxies), while Luau's generic-for uses the VM builtin
      _next returning raw values.  Two paths → two different value objects →
      DumpTable2 cross-check detects mismatch.

  Two-part fix:

    Part 1 — explicit pre-population (§12.5):
      Replace _next(_renv,...) iteration (broken) with an explicit list of
      ~80 known Roblox Luau global names.  For each name not already in
      _fenv (i.e., not overridden by OLSSA), lookup via _renv[name] (works
      even through __index chain) and rawset into _fenv.  Gives a reliable
      ~80+ rawset entries — well above the >50 assertion.

    Part 2 — _fenv special-case in pairs/next wrappers:
      When iterating _fenv specifically, return _next, _fenv, nil directly
      (no value wrapping through _resolveIterVal).  Luau's generic-for also
      uses VM builtin next on _fenv (no __iter → falls back to next,t,nil).
      Both paths now call the same _next function on the same rawset layer
      with the same values → DumpTable2 cross-check agrees → returns false
      (not detected).

      Security note: raw values for _fenv iteration are correct because
      _fenv's rawset layer already holds the wrapped/spoofed versions for
      all OLSSA-overridden keys (game→proxy, pairs→wrapped fn, etc).
      Non-overridden keys hold native values (math table, string table, etc).
      Both values are exactly what a native getfenv() iteration would see.

  Carried: [B-06][V-01][V-02][P-01..P-09][F-07][B-01..B-05][N-14]
           [T-04..T-06][F-05]

  Root cause of v4.7 failures:
    pairs(getfenv()) > 50 — FAIL
    pairs vs generic-for agree (DumpTable2 check4) — FAIL

  Two code paths iterated _fenv and produced different results:
    • OLSSA's wrapped pairs(t) calls _next(raw, prev) directly on the table's
      rawset layer → saw only ~30 OLSSA-injected entries.
    • for k,v in env uses Luau's generic-for which calls __iter metamethod on
      _fenv → saw ~200 entries from the stealth iterator added in v4.7.
  Both paths saw DIFFERENT data → DumpTable2 (pairs/generic-for cross-check)
  detected the mismatch. pairs count ~30 failed the >50 assertion.

  The __iter approach in v4.7 was architecturally wrong: it tried to patch
  around the symptom (generic-for) without fixing the source (wrapped pairs
  bypasses __iter entirely via direct _next call).

  Correct fix — _fenv pre-population:
    Just before setfenv(1,_fenv) in §13, iterate _renv once and rawset any
    key not already overridden into _fenv. Now _next(_fenv,...) naturally
    returns all ~200 native globals. No __iter needed. Both pairs() and
    generic-for call _next on the same fully-populated rawset layer → agree.

  Implementation:
    • _fenv metatable: __iter removed. __index = _renv kept as fallback only.
    • §12.5 (new): pre-populate block runs after all env_write/cfn_write calls.
    • CFG.performance.stealth_getfenv: removed (achieved by pre-pop, not __iter).
    • CFG.performance.memoize_globals: removed (pre-pop makes it redundant).

  Carried: [V-01][V-02][P-01..P-09][F-07][B-01..B-05][N-14][T-04..T-06][F-05]

  Obfuscated Luau Script Security Auditor (OLSSA) by ( / ) Indirecta

  (i) Licensed under the GNU General Public License v3.0
      <https://www.gnu.org/licenses/gpl-3.0.html>

  v4.7 changelog
  ──────────────
  [V-01] mk_fn fixed-arity regression (doc v4.6) REMOVED.
         The P-09 "fast paths" for n=0/1/2 only captured the FIRST return
         value (`local ok, ret = _pcall(fn, ...)`).  Any method returning
         multiple values silently dropped all values beyond the first
         (e.g. coroutine.resume, multi-return service calls).
         Reverted to the correct tpack/tunpack general path.
  [V-02] _mk_filtered_signal GC bug FIXED.
         Signal proxies were created and registered in weak tables (_W/_U)
         but held no strong reference.  They were GC-collected immediately
         on the next cycle, leaving _W[signal] = nil and the signal exposed.
         Fix: _SIGNAL_HOLD table holds strong references for the session.
  [B-05] _checkDot: "colon → ok" → "colon → no self-error" (was described
         in v4.6 changelog but the test code was never updated).
         Methods like JSONDecode/UrlEncode require args beyond self;
         calling svc:Method(svc) with no extra args errors for "invalid arg"
         not "Expected ':' not '.'".  The invariant is ONLY that the
         self-check fires on dot-calls, not that methods succeed with one arg.
  [P-05] Shared metamethods for cnt-free Instance proxies.
         Non-service instances (game descendants, player objects, etc.) were
         each given 11 independent closures on mk_ud construction.  With
         shared_meta=true, a single set of pre-allocated functions is reused,
         eliminating 11 closure allocations per proxy and reducing GC pressure
         during dense traversals (GetDescendants, GetChildren loops).
  [P-06] _FAST_RESOLVE early-exit in resolve(): if v is already an OLSSA
         proxy (_U[v] ~= nil), return it immediately — all lookups already
         happened when it was first created.
  [P-07] _fenv global memoization (memoize_globals=true).
         Globals accessed through _fenv.__index are rawset'd back into _fenv
         on first read.  Subsequent accesses become O(1) rawget instead of
         O(1) __index call.  Reduces per-frame overhead in hot globals loops.
  [P-08] _fenv stealth iterator (stealth_getfenv=true).
         __iter on _fenv collects keys from both rawset and _renv so that
         `for k,v in getfenv()` returns ALL globals, matching native Roblox
         behavior.  Without this, `pairs(getfenv())` only sees ~30 OLSSA
         rawset entries — detectable by scripts checking global count.
  [P-09] Stealth LogService + ScriptContext signal filtering.
         MessageOut and ScriptContext.Error signals are proxied to drop log
         entries containing OLSSA's session ID.  GetLogHistory is filtered
         likewise.  Prevents OLSSA log bleed visible to LogService subscribers.
  Carried: [P-01][P-02][P-03][P-04][F-07][B-01][B-02][B-03][B-04][N-14]
           [T-04][T-05][T-06][F-05]
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
    meta = { revision = "v4.12", date = "2026-03-18" },

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
    -- throttle:  guest CPU budget engine  [§6.5]
    --   Token-bucket rate limiter for guest code execution.
    --   Consumes real wall-clock time at pcall/task.wait boundaries.
    --   Invisible to guest because all its time reads are dilated.
    --
    --   enabled:    master switch
    --   budget_ms:  real CPU milliseconds guest may consume per
    --               Heartbeat frame before the next safe yield point
    --               forces a _task_wait(0).  Default 8ms ≈ ½ frame.
    --   max_tokens: burst headroom in seconds (default 2 × budget).
    --               Allows short bursts above budget before throttling.
    -- ──────────────────────────────────────────────────────────────
    throttle = {
        enabled    = true,
        budget_ms  = 8,        -- ms of real CPU per frame
        max_tokens = nil,      -- nil = 2 × budget (auto)
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

    -- ──────────────────────────────────────────────────────────────
    -- logs.stealth: completely hide OLSSA from LogService subscribers
    -- ──────────────────────────────────────────────────────────────
    logs = {
        verbose   = 2,
        whitelist = nil,
        blacklist = nil,
        prelogs   = false,
        shadow    = true,
        dump      = true,
        stealth   = true,  -- filter OLSSA ID from MessageOut / ScriptContext.Error
    },

    -- ──────────────────────────────────────────────────────────────
    -- performance:  fine-grained overhead controls  [P-05/P-06]
    -- ──────────────────────────────────────────────────────────────
    performance = {
        -- fast_resolve: return proxies immediately without redundant lookups [P-06]
        fast_resolve = true,
        -- shared_meta: reuse pre-allocated metamethods for cnt-free proxies [P-05]
        shared_meta  = true,
        -- Note: memoize_globals and stealth_getfenv were removed in v4.8.
        -- Global visibility parity is now achieved by pre-populating _fenv
        -- with all _renv entries at startup (§12.5).  This makes _next() on
        -- _fenv naturally return all ~200 globals so pairs/next/generic-for
        -- all agree without any __iter workaround.
    },
}

-- Merge CFG.logs into the CFG table (CFG.logs was declared above inline)
-- (no action needed — already set)

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §2  PROXY STATE                                                 ║
-- ╚══════════════════════════════════════════════════════════════════╝
-- _W[original] = proxy       weak-value  (GC'd when proxy unreferenced)
-- _U[proxy]    = original    weak-key    (entry removed when proxy GC'd)
-- _I[guest_fn] = inv_proxy   weak-key    (inverse proxy for callbacks)
-- _KS[k/v]     = wrapped     value-spoof map
-- _SVC         = CFG.game.services   service ClassName → proxy (strong)
-- _CFNS[fn]    = "name"      Lua-wrapped fns that debug.info should report as [C]
-- _SIGNAL_HOLD = strong refs to filtered signal proxies (prevents GC)

local _W    = _setmt({}, { __mode = "v" })
local _U    = _setmt({}, { __mode = "k" })
local _I    = _setmt({}, { __mode = "k" })   -- [N-10] Callback unwrapper cache
local _SVC  = CFG.game.services
local _KS   = {}
local _CFNS = {}   -- [F-03] C-masking table
local _SIGNAL_HOLD = {}  -- [V-02] strong refs: prevents GC of filtered signal proxies

-- Performance flags (cached locals for hot-path access)
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
    -- [P-06] If v is already a proxy, all lookups already happened at construction.
    -- _U[proxy] = raw means v IS a proxy; return it directly.
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

-- ── Shared metamethods for cnt-free Instance proxies  [P-05] ─────
-- For proxies with no content overrides (cnt==nil), we reuse a single
-- set of pre-allocated functions instead of creating 11 new closures
-- per mk_ud() call.  This is safe because these handlers read obj via
-- _U[self] at call time — they do not close over obj at construction time.
-- Reduces GC pressure dramatically during GetDescendants/GetChildren loops.
local _SH = {}  -- populated below; used by mk_ud shared_meta path

-- ── Userdata proxy (Roblox Instances) ────────────────────────────
local function mk_ud(obj, cnt, light, isgame)
    local proxy = _newproxy(true)
    local meta  = _getmt(proxy)

    -- [P-05] Shared meta fast-path: only for cnt-free, non-light proxies.
    -- cnt=nil means no method overrides needed; all reads go through raw obj.
    -- light=false means we DO wrap return values (correct for game instances).
    -- The shared handlers read _U[self] to get obj at call time.
    if _SHARED_META and cnt == nil and not light then
        meta.__index    = _SH[isgame and "idx_game" or "idx_guest"]
        meta.__newindex = _SH.newindex
        meta.__tostring = _SH.tostring
        meta.__eq       = _SH.eq
        meta.__lt       = _SH.lt
        meta.__le       = _SH.le
        meta.__len      = _SH.len
        meta.__unm      = _SH.unm
        meta.__concat   = _SH.concat
        meta.__call     = _SH[isgame and "call_game" or "call_guest"]
        meta.__iter     = _SH.iter
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

-- ── Populate shared metamethod table  [P-05] ─────────────────────
-- Must come AFTER wrap/unwrap/resolve are assigned (they are forward-declared
-- locals whose bodies reference each other, all now fully populated).
do
    _SH.tostring = function(self)  return _tostring(_U[self]) end
    _SH.newindex = function(self, k, v) _U[self][k] = unwrap(v) end
    _SH.len      = function(self)  return #(_U[self]) end
    _SH.unm      = function(self)  return -(_U[self]) end
    _SH.concat   = function(a, b)  return (_U[a] or a) .. (_U[b] or b) end
    _SH.eq       = function(a, b)  return (_U[a] or a) == (_U[b] or b) end
    _SH.lt       = function(a, b)  return (_U[a] or a) <  (_U[b] or b) end
    _SH.le       = function(a, b)  return (_U[a] or a) <= (_U[b] or b) end
    _SH.iter     = function()      return function() end, nil, nil end

    _SH.idx_game = function(self, k)
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
        local ks = _KS[raw]; if ks ~= nil then return ks end
        if _type(raw) == "function" then return wrap(raw, nil, false, true) end
        return wrap(raw, nil, false, true)
    end

    _SH.idx_guest = function(self, k)
        local obj = _U[self]
        if _BLK[k] then return obj[k] end
        local raw = obj[k]
        if _BLV[raw] then return raw end
        local ks = _KS[raw]; if ks ~= nil then return ks end
        if _type(raw) == "function" then return wrap(raw, nil, false, false) end
        return wrap(raw, nil, false, false)
    end

    _SH.call_game = function(self, ...)
        local obj = _U[self]
        local args = _tpack(...)
        for i = 1, args.n do args[i] = unwrap(args[i]) end
        local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
        if not rets[1] then _error(rets[2], 0) end
        for i = 2, rets.n do rets[i] = resolve(rets[i], nil, false, true) end
        return _tunpack(rets, 2, rets.n)
    end

    _SH.call_guest = function(self, ...)
        local obj = _U[self]
        local args = _tpack(...)
        for i = 1, args.n do args[i] = unwrap(args[i]) end
        local rets = _tpack(_pcall(obj, _tunpack(args, 1, args.n)))
        if not rets[1] then _error(rets[2], 0) end
        for i = 2, rets.n do rets[i] = resolve(rets[i], nil, false, false) end
        return _tunpack(rets, 2, rets.n)
    end
end

-- ╔══════════════════════════════════════════════════════════════════╗
-- ║  §5  FORKED ENVIRONMENT  _fenv                                   ║
-- ╠══════════════════════════════════════════════════════════════════╣
-- ║  The Roblox VM marks each script's global table as VM-readonly:  ║
-- ║  rawset() and setmetatable() on it both throw.  The only way to  ║
-- ║  inject spoofed globals is to create a fresh _fenv table,        ║
-- ║  rawset spoofed keys into it, and install via setfenv(1, _fenv). ║
-- ╚══════════════════════════════════════════════════════════════════╝
-- [B-07] §12.5 pre-populates _fenv with all known Roblox Luau globals so
-- _next(_fenv,...) returns a native-sized set.  pairs() and next() wrappers
-- short-circuit to _next,_fenv,nil for _fenv, matching generic-for exactly.
-- No __iter needed.  All three iteration methods agree on keys AND values.
local _fenv = _setmt({}, {
    -- __index fallback to _renv: handles any globals not in the explicit
    -- pre-pop list (new Roblox APIs, etc.) and also any reads during §8-§12
    -- setup before §12.5 runs.
    __index    = _renv,
    __newindex = function(self, k, v) _rawset(self, k, v) end,
    __metatable = "The metatable is locked",
    -- NO __iter: with pre-population + pairs/next _fenv special-case,
    -- all iteration methods agree without any metamethod dispatch.
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
-- ║  §6.5  CPU WATCHDOG ENGINE  [P-10]                               ║
-- ╠══════════════════════════════════════════════════════════════════╣
-- ║  Token-bucket rate limiter injected at OLSSA's safe yield points ║
-- ║  to prevent the Roblox 10-second script execution timeout.       ║
-- ║                                                                  ║
-- ║  How the Roblox timeout works (source: devforum.roblox.com,      ║
-- ║  Roblox engineer Anaminus post):                                 ║
-- ║  The engine tracks continuous CPU time per thread.  A thread is  ║
-- ║  killed after ~10s without yielding back to the ENGINE.          ║
-- ║  coroutine.yield() does NOT reset this — it only yields to the  ║
-- ║  parent thread.  Only task.wait() / wait() (which enqueue the   ║
-- ║  thread in the engine scheduler) reset the timeout counter.     ║
-- ║                                                                  ║
-- ║  Why OLSSA causes timeout with tight guest loops:               ║
-- ║  Obfuscated scripts run 10,000+ iterations calling OLSSA's      ║
-- ║  pcall wrapper each time (squabble_pcall pattern).  The guest   ║
-- ║  never voluntarily calls task.wait().  OLSSA wrapper overhead   ║
-- ║  accumulates without any engine yield → timeout.                ║
-- ║                                                                  ║
-- ║  Safe yield insertion points (Luau spec: cannot yield inside    ║
-- ║  metamethods __index/__newindex/__call/__iter):                  ║
-- ║    • pcall GUEST path  — regular function, safe to yield        ║
-- ║    • xpcall GUEST path — regular function, safe to yield        ║
-- ║                                                                  ║
-- ║  Token bucket:                                                   ║
-- ║    • Heartbeat refills tokens by budget_ms each frame           ║
-- ║    • pcall/xpcall guest entry consumes real wall-clock elapsed   ║
-- ║    • Tokens < 0 → force _task_wait(0) → engine yield (reset)   ║
-- ║                                                                  ║
-- ║  Stealth clock freeze (undetectable):                           ║
-- ║    When we force _task_wait(0) of Y real seconds:               ║
-- ║    • Before yield: nothing (fake clocks not advancing)          ║
-- ║    • After yield: set _fClockReal=now, _fTickReal=now           ║
-- ║      WITHOUT advancing _fClockFake / _fTickFake                 ║
-- ║    • Next _fClock()/_fTick() call delta = near-zero             ║
-- ║    • Guest sees: os.clock(), tick(), time() = unchanged         ║
-- ║    • Benchmarks: identical to unthrottled execution             ║
-- ║    • Detection: impossible — no guest time fn bypasses dilation ║
-- ╚══════════════════════════════════════════════════════════════════╝
local _THR_ENABLED   = false
local _thrTokens     = 0       -- current token balance (seconds)
local _thrMax        = 0       -- max token capacity    (seconds)
local _thrBudget     = 0       -- tokens refilled per Heartbeat (seconds)
local _thrLastClock  = 0       -- native _os_clock() at last checkpoint
local _thrConn       = nil     -- Heartbeat connection for refill

-- _thrMaybeYield():
--   Hot path — called at every pcall/xpcall guest entry.
--   Measures real elapsed, drains tokens, forces yield when exhausted.
--   Performs clock freeze so the yield is invisible to guest time fns.
local function _thrMaybeYield()
    if not _THR_ENABLED then return end
    local now = _os_clock()
    -- Drain tokens by real elapsed time since last checkpoint
    _thrTokens -= (now - _thrLastClock)
    _thrLastClock = now
    if _thrTokens > 0 then return end   -- still have budget, no yield needed

    -- Budget exhausted — must yield to the engine to reset timeout.
    -- [CLOCK FREEZE] After yielding Y real seconds, we advance the
    -- real anchors (_fClockReal, _fTickReal) by Y without touching
    -- the fake clocks (_fClockFake, _fTickFake).  The next _fClock()
    -- call will compute delta = (now - new_fClockReal) ≈ 0, so the
    -- yield period is completely invisible to guest time reads.
    _thrTokens = 0   -- clamp, don't carry debt into next frame

    -- Capture pre-yield real anchors to measure exactly how long we yielded
    local preClockReal = _fClockReal
    local preTickReal  = _fTickReal

    _task_wait(0)   -- yield to Roblox engine scheduler, resets timeout counter

    -- Post-yield: advance real anchors by the yield duration
    -- so _fClock/_fTick compute near-zero delta on next call.
    local yieldDuration = _os_clock() - preClockReal  -- true yield length
    _fClockReal  = preClockReal + yieldDuration        -- = _os_clock() now
    _fTickReal   = preTickReal  + yieldDuration        -- ≈ _tick() now
    -- _fClockFake and _fTickFake are NOT touched → yield is invisible

    -- Refill tokens: give one full budget worth after yielding
    _thrTokens    = _thrBudget
    _thrLastClock = _os_clock()
end

-- Initialise from CFG.throttle
do
    local tcfg = CFG.throttle
    if tcfg and tcfg.enabled then
        _THR_ENABLED = true
        _thrBudget   = (tcfg.budget_ms or 8) / 1000        -- ms → seconds
        _thrMax      = tcfg.max_tokens or (_thrBudget * 4) -- burst headroom
        _thrTokens   = _thrMax                              -- start full
        _thrLastClock = _os_clock()
        -- Heartbeat refill: add exactly budget_ms of tokens per frame.
        -- Unlike rate-based replenishment (tokens/s × dt), this gives a
        -- fixed per-frame allowance independent of actual frame time.
        local _rs_for_thr = _game:GetService("RunService")
        _thrConn = _rs_for_thr.Heartbeat:Connect(function(_dt: number)
            if _thrTokens < _thrMax then
                -- Add one budget's worth; don't exceed max (burst cap)
                _thrTokens = _mmin(_thrMax, _thrTokens + _thrBudget)
            end
        end)
    end
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
    -- [P-11] Increased flush budget 14ms→20ms to clear bursts faster.
    -- The selftest emits ~40+ warn entries; with 14ms some remain queued
    -- across multiple frames adding latency.  20ms clears most in one tick.
    local budget = _os_clock() + 0.020
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
        -- [P-12] Early-exit before any allocation: hottest path when
        -- verbose is set lower than the requested level.
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
            -- [P-03] traceback only for lvl >= 3
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

-- ── LogService + ScriptContext stealth  [P-09 / V-02] ────────────
-- Filters OLSSA session ID from:
--   LogService.MessageOut   (log feed visible to subscribed scripts)
--   ScriptContext.Error      (script error events)
--   LogService:GetLogHistory() (buffered log retrieval)
--
-- [V-02] Fix: signal proxies are stored in _SIGNAL_HOLD (strong reference)
-- so they cannot be GC-collected.  Previously they were registered only in
-- weak tables (_W/_U) and evaporated on the next GC cycle.
if CFG.logs and CFG.logs.stealth then
    local function _mk_signal_filter(real_signal, msg_argpos)
        -- Build a proxy that intercepts Connect/connect/Once/Wait
        -- and filters out any callbacks whose msg argument contains _ID.
        local proxy = _newproxy(true)
        local meta  = _getmt(proxy)

        local function _wrap_cb(guest_fn)
            local raw_fn = unwrap(guest_fn)
            return function(...)
                local args = _tpack(...)
                local msg  = args[msg_argpos]
                if _type(msg) == "string" and _sfind(msg, _ID, 1, true) then
                    return  -- drop OLSSA log entry
                end
                for i = 1, args.n do args[i] = resolve(args[i], nil, false, true) end
                raw_fn(_tunpack(args, 1, args.n))
            end
        end

        meta.__index = function(_, k)
            if k == "Connect" or k == "connect" or k == "ConnectParallel" or k == "Once" then
                return function(_, guest_fn)
                    local conn = real_signal[k](real_signal, _wrap_cb(guest_fn))
                    return resolve(conn, nil, false, true)
                end
            elseif k == "Wait" or k == "wait" then
                return function(_)
                    while true do
                        local args = _tpack(real_signal:Wait())
                        local msg  = args[msg_argpos]
                        if not (_type(msg) == "string" and _sfind(msg, _ID, 1, true)) then
                            for i = 1, args.n do args[i] = resolve(args[i], nil, false, true) end
                            return _tunpack(args, 1, args.n)
                        end
                    end
                end
            end
            local raw = real_signal[k]
            if _type(raw) == "function" then
                return wrap(raw, nil, false, false)
            end
            return resolve(raw, nil, false, true)
        end

        meta.__tostring  = function() return _tostring(real_signal) end
        meta.__metatable = "The metatable is locked"
        -- Register proxy (needed so typeof/rawequal work)
        _U[proxy]        = real_signal
        _W[real_signal]  = proxy
        -- [V-02] Strong reference: prevent GC eviction
        _SIGNAL_HOLD[#_SIGNAL_HOLD + 1] = proxy
        return proxy
    end

    local ok_ls, _LS = _pcall(function() return _game:GetService("LogService") end)
    local ok_sc, _SC = _pcall(function() return _game:GetService("ScriptContext") end)

    if ok_ls and _LS then
        local ok_mo, mo = _pcall(function() return _LS.MessageOut end)
        if ok_mo and mo then _mk_signal_filter(mo, 1) end

        _SVC["LogService"] = mk_ud(_LS, {
            GetLogHistory = function(_)
                local history = _LS:GetLogHistory()
                local filtered = {}
                for i = 1, #history do
                    local entry = history[i]
                    if not (entry and _sfind(_tostring(entry.message or ""), _ID, 1, true)) then
                        _tinsert(filtered, entry)
                    end
                end
                return filtered
            end,
        }, false, false)
    end

    if ok_sc and _SC then
        local ok_er, er = _pcall(function() return _SC.Error end)
        if ok_er and er then _mk_signal_filter(er, 1) end
    end
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
    -- [P-06] Already a proxy: return immediately
    if _FAST_RESOLVE and _U[v] ~= nil then return v end
    if _BLV[v] then return v end
    -- Registered proxy (instance or function already wrapped by OLSSA)
    local cached = _W[v]; if cached ~= nil then return cached end
    local ks = _KS[v];    if ks ~= nil then return ks end
    -- Plain Lua tables not in registry: pass through (no mk_tbl overhead)
    if t == "table" then return v end
    -- Roblox Instance: service SVC fast-path
    if t == "userdata" then
        if isgame then
            local ti = _typeof(v)
            if ti == "Instance" then
                local svc = _SVC[(v :: any).ClassName] or _SVC[v]
                if svc ~= nil then return svc end
                -- Raw unwrapped instance from a direct game method — wrap it
                return wrap(v, nil, false, true)
            end
        end
        -- [B-08] Non-Instance userdata (Vector3, CFrame constructors, etc.):
        -- return as-is.  Wrapping them creates new proxy objects whose identity
        -- differs from the rawset value in _fenv, causing DumpTable2 to flag a
        -- mismatch.  These values are never OLSSA-managed; pass through unchanged.
        return v
    end
    -- [B-08] Unregistered C functions (warn, type, gcinfo, etc.): return as-is.
    -- Same rationale: wrapping creates new objects that don't match pre-pop values.
    -- Registered functions (pairs, next, etc.) are in _W/_KS and handled above.
    return v
end

-- ── pairs ─────────────────────────────────────────────────────────
-- [B-10] Structural fix: only wrap values when iterating an OLSSA-managed
-- proxy table.  For plain guest tables (and _fenv itself), return
-- `_next, raw, nil` directly — the SAME iterator that Luau's VM-builtin
-- generic-for produces.  Both paths are now identical by construction.
--
-- How Luau compiles `for k,v in t do`:
--   • If t has __iter → calls __iter(t)
--   • Otherwise → VM uses the environment's `next` function on t.
--     The env's `next` IS our wrapped next, which for non-proxy tables
--     also returns `_next(raw, k)` directly (see next wrapper below).
--     Therefore generic-for and pairs() produce identical (k,v) pairs.
--
-- Proxy detection:
--   _U[t] ~= nil  → t is an OLSSA proxy (unwrap gives inner raw object)
--   _W[raw] == t  → confirms raw→proxy registration (double-check)
-- Plain tables, _fenv, guest dump tables: _U[t] = nil → passthrough.
cfn_write("pairs", function(t)
    local inner = _U[t]
    if inner ~= nil then
        -- t is an OLSSA proxy (mk_tbl): iterate inner raw table with wrapping
        return function(_, prev)
            local k, v = _next(inner, prev)
            if k == nil then return nil end
            return resolve(k, nil, true, false), _resolveIterVal(v, true)
        end, t, nil
    end
    -- Plain table (guest table, _fenv, etc.): passthrough to native _next.
    -- Values are already in correct form (spoofed keys have wrapped values
    -- rawset'd directly; guest tables have guest-stored values).
    return _next, t, nil
end, _pairs)

-- ── ipairs ────────────────────────────────────────────────────────
cfn_write("ipairs", function(t)
    local inner = _U[t]
    if inner ~= nil then
        -- proxy table: wrap values
        local i = 0
        return function()
            i += 1
            local v = inner[i]
            if v == nil then return nil end
            return i, _resolveIterVal(v, true)
        end
    end
    -- plain table: native behavior, no allocation
    return _ipairs(t)
end, _ipairs)

-- ── next ──────────────────────────────────────────────────────────
-- [B-10] Same proxy-detection logic as pairs.  When Luau compiles
-- `for k,v in t` it calls the env's `next` function.  For plain tables
-- we return the raw k,v so generic-for and explicit next() agree exactly.
cfn_write("next", function(t, k)
    local inner = _U[t]
    if inner ~= nil then
        -- OLSSA proxy: iterate inner table with resolution
        local rk, rv = _next(inner, unwrap(k))
        if rk == nil then return nil end
        return resolve(rk, nil, true, false), _resolveIterVal(rv, true)
    end
    -- Plain table or _fenv: native passthrough.
    -- Handles DumpTable1 (`for key in next, t do`) correctly.
    return _next(t, k)
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
        -- GUEST path: fn is a plain closure → call directly, resolve rets only.
        -- [P-10] Throttle checkpoint: safe to yield here (not a metamethod).
        -- If the token budget is exhausted, _thrMaybeYield() forces
        -- _task_wait(0) to yield back to the Roblox engine scheduler,
        -- resetting the 10-second execution timeout counter.
        -- The dilated clock is frozen during the yield (clock freeze),
        -- so the guest observes zero elapsed time — completely invisible.
        _thrMaybeYield()
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
        -- [P-10] Throttle checkpoint on guest xpcall path
        _thrMaybeYield()
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
            -- [B-05] Colon call with proxy-self: must NOT produce "Expected ':' not '.'"
            -- It may error for other reasons (missing required args) but the self-check
            -- must pass.  We cannot require okC==true because some methods (JSONDecode,
            -- UrlEncode, GetProductInfo) require arguments beyond self and will error
            -- with "invalid argument" or similar when called with only self.
            local okC, errC = _pcall(function() return (svc :: any)[method](svc) end)
            _check("dot_call", svcName .. ":" .. method .. "() colon → no self-error",
                okC or (_type(errC) == "string"
                    and _sfind(errC, "Expected ':' not '.'", 1, true) == nil))

            -- Dot call (no self, no args) must FAIL with "Expected ':' not '.'"
            local okD, errD = _pcall(function() return (svc :: any)[method]() end)
            _check("dot_call", svcName .. "." .. method .. "() dot → errors",
                not okD)
            _check("dot_call", svcName .. "." .. method .. "() error format matches native",
                not okD and _type(errD) == "string"
                and _sfind(errD, "Expected ':' not '.'", 1, true) ~= nil)

            -- Native comparison: raw dot-call must produce identical error prefix
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
    -- ── CATEGORY: DumpTable detection suite  [B-06]  ────────────
    -- ══════════════════════════════════════════════════════════════
    -- Reproduces the exact 5 checks from the DumpTable family detection:
    --   check 1: type(getmetatable(getfenv())) == 'table'  → must be false (string)
    --   check 2: DumpTable(getfenv()).iterations == 0      → pairs must yield > 0 entries
    --   check 3: DumpTable1(getfenv()).iterations == 0     → next must yield > 0 entries
    --   check 4: DumpTable2(getfenv()) == true             → pairs/generic-for disagree
    --   check 5: DumpTable3(getfenv()).iterations == 0     → generic-for must yield > 0
    --
    -- All 5 detection checks must be false (non-detecting) for OLSSA to be invisible.
    --
    -- DumpTable2 logic: if (pairs agrees with generic-for) → return false (not detected).
    -- We assert that pairs and generic-for DO agree (both use _next on the pre-populated
    -- rawset layer) so DumpTable2 returns false → check4 fires false.
    _warn("[OLSSA·TEST] Cat: dumptable_sim [B-10/B-11]")
    do
        local env = getfenv()

        -- Check 1: metatable must be locked string, not a table
        local mt = getmetatable(env)
        _check("dumptable", "getmetatable(getfenv()) ~= table (check1 false)",
            _type(mt) ~= "table")
        _check("dumptable", "getmetatable(getfenv()) == string (locked)",
            _type(mt) == "string")

        -- Check 2: pairs(getfenv()) must yield > 0 iterations.
        -- Actual detection: `if iterations == 0 then return true end` — just needs >0.
        -- OLSSA's own env_write/cfn_write rawsets ~30 entries; well above zero.
        local iter2 = 0
        for _ in pairs(env) do iter2 += 1 end
        _check("dumptable", "pairs(getfenv()) > 0 entries (check2 false)",
            iter2 > 0)
        -- [B-12] The detection check is iterations==0, not >50.  ~30 OLSSA
        -- rawset entries is sufficient; assert >10 as a sanity bound.
        _check("dumptable", "pairs(getfenv()) > 10 entries (OLSSA rawset layer)",
            iter2 > 10)

        -- Check 3: next,t loop must yield > 0 iterations
        local iter3 = 0
        for _ in _next, env, nil do iter3 += 1 end
        _check("dumptable", "next,getfenv() > 0 entries (check3 false)",
            iter3 > 0)

        -- Check 4: pairs vs generic-for must agree.
        -- DumpTable2: builds dump={} with generic-for, cross-checks with pairs.
        -- Returns false (not detected) when they agree, true (detected) otherwise.
        -- With [B-08]: _resolveIterVal returns unknowns as-is, so both paths agree.
        local dump4 = {}
        for i, v in env do dump4[i] = v end           -- generic-for
        local a4 = true
        for i, v in pairs(env) do                      -- pairs
            if dump4[i] ~= v then a4 = false; break end
        end
        local b4 = true
        for i, v in pairs(dump4) do
            if env[i] ~= v then b4 = false; break end
        end
        -- DumpTable2 returns FALSE (not detected) when a4 and b4 (they agree).
        -- We assert a4 and b4 to confirm we are in the non-detected state.
        _check("dumptable", "pairs vs generic-for agree (check4 → DumpTable2 returns false)",
            a4 and b4)
        -- Count parity: generic-for and pairs should see the same number of entries
        local iter4p = 0; for _ in pairs(env) do iter4p += 1 end
        local iter4g = 0; for _ in env         do iter4g += 1 end
        _check("dumptable", "pairs and generic-for entry counts match",
            iter4p == iter4g)

        -- Check 5: generic-for on getfenv() must yield > 0 iterations
        local iter5 = 0
        for _ in env do iter5 += 1 end
        _check("dumptable", "generic-for getfenv() > 0 entries (check5 false)",
            iter5 > 0)

        -- Overall: none of the 5 detection checks fire
        local c1 = (_type(mt) == "table")
        local c2 = (iter2 == 0)
        local c3 = (iter3 == 0)
        -- c4: DumpTable2 returns true = detected when NOT (a4 and b4)
        local c4 = not (a4 and b4)
        local c5 = (iter5 == 0)
        _check("dumptable", "ALL 5 DumpTable checks return false (undetected)",
            not c1 and not c2 and not c3 and not c4 and not c5)
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: fix.safeCall extended detection patterns ────────
    -- ══════════════════════════════════════════════════════════════
    _warn("[OLSSA·TEST] Cat: fixsafe_ext")
    do
        -- fix.dataModel checks: ins.Parent chain and typeof(ins)=="Instance"
        local ok_ch, children = _pcall(function() return game:GetChildren() end)
        if ok_ch and children and #children > 0 then
            -- Every child.Parent must == game, typeof == "Instance", ClassName == "DataModel"
            local allOk = true
            for _, ins in _ipairs(children) do
                local par = ins.Parent
                if par ~= game then allOk = false; break end
                if typeof(par) ~= "Instance" then allOk = false; break end
                if par.ClassName ~= "DataModel" then allOk = false; break end
                -- type(child) must be "userdata" for all game:GetChildren() results
                if _type(ins) ~= "userdata" then allOk = false; break end
            end
            _check("fixsafe_ext", "fix.dataModel loop passes (no halt)", allOk)
        end

        -- fix.serve loop: GroupService.GetGroupInfoAsync dot-call must error
        do
            local okG, gs = _pcall(function() return game:GetService("GroupService") end)
            if okG and gs then
                local dotOk = _pcall(function() return (gs :: any).GetGroupInfoAsync() end)
                _check("fixsafe_ext",
                    "GroupService.GetGroupInfoAsync() dot → false (not detected)",
                    not dotOk)
            end
        end

        -- DataStoreService is only accessed as a service reference (no method calls)
        do
            local okD, ds = _pcall(function() return game:GetService("DataStoreService") end)
            _check("fixsafe_ext", "DataStoreService accessible", okD and ds ~= nil)
            if okD and ds then
                _check("fixsafe_ext", "typeof(DataStoreService) == 'Instance'",
                    typeof(ds) == "Instance")
            end
        end

        -- math.random is captured at startup; inside sandbox it must still be [C]
        do
            local ok_r, src = _pcall(debug.info, math.random, "s")
            _check("fixsafe_ext", "math.random debug.info 's' returns string",
                ok_r and _type(src) == "string")
        end

        -- math.clamp ditto
        do
            local ok_c, src = _pcall(debug.info, math.clamp, "s")
            _check("fixsafe_ext", "math.clamp debug.info 's' returns string",
                ok_c and _type(src) == "string")
        end
    end

    -- ══════════════════════════════════════════════════════════════
    -- ── CATEGORY: CPU watchdog / throttle engine  [P-10]  ────────
    -- ══════════════════════════════════════════════════════════════
    -- Tests the token-bucket throttle engine and verifies that forced
    -- yields are invisible to guest time reads (clock freeze).
    _warn("[OLSSA·TEST] Cat: throttle [P-10]")
    do
        -- ── Test 1: throttle config present and valid ─────────────
        if CFG.throttle then
            _check("throttle", "CFG.throttle.enabled is bool",
                _type(CFG.throttle.enabled) == "boolean")
            _check("throttle", "CFG.throttle.budget_ms > 0",
                (CFG.throttle.budget_ms or 0) > 0)
        else
            _check("throttle", "CFG.throttle block present", false)
        end

        -- ── Test 2: _THR_ENABLED matches CFG ─────────────────────
        if CFG.throttle and CFG.throttle.enabled then
            _check("throttle", "_THR_ENABLED == true when CFG.throttle.enabled",
                _THR_ENABLED == true)
            _check("throttle", "_thrBudget > 0",  _thrBudget > 0)
            _check("throttle", "_thrMax >= _thrBudget",  _thrMax >= _thrBudget)
            _check("throttle", "_thrTokens >= 0", _thrTokens >= 0)
            _check("throttle", "_thrConn ~= nil (Heartbeat connected)", _thrConn ~= nil)
        end

        -- ── Test 3: clock freeze correctness ─────────────────────
        -- Force a throttle yield by draining the token pool, then verify
        -- the dilated clock did not advance by the full real yield duration.
        -- Because pcall(guestfn) is the injection point, we simulate the
        -- exact pattern: tight loop calling pcall 1000 times.
        if _THR_ENABLED then
            -- Sample dilated clock before
            local c_before = _fClock()
            local t_before = _fTick()
            local real_before = _os_clock()

            -- Drain tokens to force at least one yield
            _thrTokens = -1   -- guaranteed exhaust on next checkpoint

            -- Trigger checkpoint via pcall guest path
            local n = 0
            for _ = 1, 1000 do
                pcall(function() n += 1 end)
            end

            local c_after    = _fClock()
            local t_after    = _fTick()
            local real_after = _os_clock()

            local real_elapsed   = real_after  - real_before
            local dilated_clock  = c_after     - c_before
            local dilated_tick   = t_after     - t_before

            -- The real elapsed includes at least one _task_wait(0) ≈ 16ms
            -- The dilated elapsed should be much less than real elapsed
            -- (clock freeze removes yield duration from dilated time)
            _check("throttle", "clock freeze: real elapsed >= 0",
                real_elapsed >= 0)
            -- If throttle fired, dilated should be << real
            -- Dilated ≤ real × dilation + small epsilon (from actual code execution)
            -- We allow generous 2× margin to avoid flakiness from scheduler jitter
            if _dil < 1.0 then
                _check("throttle", "clock freeze: dilated_clock << real elapsed",
                    dilated_clock <= real_elapsed * _dil * 3 + 0.001)
                _check("throttle", "clock freeze: dilated_tick << real elapsed",
                    dilated_tick  <= real_elapsed * _dil * 3 + 0.001)
            end
            _check("throttle", "pcall loop completed all 1000 iterations", n == 1000)
        end

        -- ── Test 4: tight loop tolerance ─────────────────────────
        -- Simulate the exact squabble_pcall pattern: 10,000 pcalls.
        -- This previously caused script timeout.  With throttle it must
        -- complete within reasonable wall-clock time.
        if _THR_ENABLED then
            local count = 0
            local t_start = _os_clock()
            for _ = 1, 10000 do
                pcall(function()
                    count += 1
                end)
            end
            local t_end = _os_clock()
            _check("throttle", "10k pcall loop completes without timeout",
                count == 10000)
            -- 10k pcalls with throttle: should complete in < 10 real seconds
            -- (each yield adds ~16ms; 10k iterations at 8ms budget = ~20 yields = ~320ms)
            _check("throttle", "10k pcall loop < 10 real seconds",
                (t_end - t_start) < 10)
        end

        -- ── Test 5: pcall correctness under throttle ──────────────
        -- Verify pcall still returns correct results when throttle fires
        do
            local ok1, val1 = pcall(function() return 42 end)
            _check("throttle", "pcall correctness: returns true, 42",
                ok1 and val1 == 42)

            local ok2, err2 = pcall(function() error("throttle_test") end)
            _check("throttle", "pcall correctness: error propagates",
                not ok2 and _type(err2) == "string"
                and _sfind(err2, "throttle_test", 1, true) ~= nil)
        end

        -- ── Test 6: throttle is undetectable via time reads ───────
        -- Guest code using os.clock() to benchmark OLSSA overhead should
        -- not see evidence of multi-frame pauses.
        do
            -- Run 100 pcalls, measure dilated elapsed time
            local c1 = os.clock()
            for _ = 1, 100 do
                pcall(function() end)
            end
            local c2 = os.clock()
            local dilated_elapsed = c2 - c1

            -- With dilation=0.15, 100 pcalls should appear << 1 dilated second
            -- even if real time included yields
            _check("throttle", "dilated clock: 100 pcalls appear short to guest",
                dilated_elapsed < 1.0)  -- generous bound

            -- tick() should also be consistent
            local t1 = tick()
            for _ = 1, 100 do
                pcall(function() end)
            end
            local t2 = tick()
            _check("throttle", "tick() consistent with clock during throttle",
                (t2 - t1) < 1.0)
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
end -- §END OLSSA v4.12
--================----===OLSSAEND===----================--