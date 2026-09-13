#!/usr/bin/env python3
"""Built-in YARA rules collection for AEGIS malware detection."""

YARA_RULES = {
    "ransomware": [
        {"name": "WannaCry", "rule": 'rule WannaCry { meta: description = "WannaCry ransomware" author = "AEGIS" strings: $s1 = "WNcry@2ol7" $s2 = "mssecsvc.exe" $s3 = ".WNCRY" $s4 = "tasksche.exe" $mz = { 4D 5A } condition: $mz at 0 and 2 of ($s*) }'},
        {"name": "LockBit3", "rule": 'rule LockBit3 { meta: description = "LockBit 3.0 ransomware" strings: $s1 = "lockbit" nocase $s2 = ".lockbit" $s3 = "Restore-My-Files.txt" $s4 = { 89 45 FC 8B 45 FC 83 C0 01 } condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "BlackCat_ALPHV", "rule": 'rule BlackCat { meta: description = "BlackCat/ALPHV ransomware" strings: $s1 = "access-token" $s2 = "--access-token" $s3 = "esxcli" $s4 = "vscsi" $r1 = /--paths\s+/ condition: uint16(0) == 0x5A4D and 2 of them }'},
        {"name": "Conti", "rule": 'rule Conti { meta: description = "Conti ransomware" strings: $s1 = "CONTI" $s2 = "readme.txt" $s3 = "vssadmin delete shadows" $s4 = "bcdedit /set" condition: uint16(0) == 0x5A4D and 3 of ($s*) }'},
        {"name": "REvil_Sodinokibi", "rule": 'rule REvil { meta: description = "REvil/Sodinokibi ransomware" strings: $s1 = "sodinokibi" nocase $s2 = "expand 32-byte k" $s3 = "-nolan" $s4 = "mpsvc.dll" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Ryuk", "rule": 'rule Ryuk { meta: description = "Ryuk ransomware" strings: $s1 = "RyukReadMe" $s2 = "HERMES" $s3 = ".RYK" $s4 = "cmd.exe /c" $s5 = "vssadmin" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "DarkSide", "rule": 'rule DarkSide { meta: description = "DarkSide ransomware" strings: $s1 = "darkside" nocase $s2 = "README" $s3 = "esxcli vm process" $s4 = { 45 78 70 61 6E 64 20 33 32 } condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Maze", "rule": 'rule Maze { meta: description = "Maze ransomware" strings: $s1 = "DECRYPT-FILES.txt" $s2 = "ChaCha" $s3 = { 0F B6 C0 89 45 FC } $s4 = "maze" nocase condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Clop", "rule": 'rule Clop { meta: description = "Cl0p ransomware" strings: $s1 = ".Clop" $s2 = "ClopReadMe.txt" $s3 = "Dont Worry" $s4 = "CLOP" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Hive", "rule": 'rule Hive { meta: description = "Hive ransomware" strings: $s1 = ".hive" $s2 = "HOW_TO_DECRYPT" $s3 = "login" $s4 = ".onion" condition: uint16(0) == 0x5A4D and 3 of ($s*) }'},
        {"name": "Royal", "rule": 'rule Royal { meta: description = "Royal ransomware" strings: $s1 = ".royal" $s2 = "README.TXT" $s3 = "If you" $s4 = "restore" condition: uint16(0) == 0x5A4D and 3 of ($s*) }'},
        {"name": "Akira", "rule": 'rule Akira { meta: description = "Akira ransomware" strings: $s1 = ".akira" $s2 = "akira_readme.txt" $s3 = "powershell" $s4 = "vssadmin" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Play", "rule": 'rule Play { meta: description = "Play ransomware" strings: $s1 = ".play" $s2 = "ReadMe" $s3 = "wevtutil" $s4 = "diskshadow" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "BlackBasta", "rule": 'rule BlackBasta { meta: description = "Black Basta ransomware" strings: $s1 = "readme.txt" $s2 = ".basta" $s3 = "vssadmin delete" $s4 = "bcdedit" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Medusa", "rule": 'rule MedusaRansom { meta: description = "Medusa ransomware" strings: $s1 = ".MEDUSA" $s2 = "!!!READ_ME_MEDUSA" $s3 = "powershell" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Phobos", "rule": 'rule Phobos { meta: description = "Phobos ransomware" strings: $s1 = ".phobos" $s2 = ".eking" $s3 = "info.txt" $s4 = "info.hta" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
    ],
    "rat": [
        {"name": "CobaltStrike_Beacon", "rule": 'rule CobaltStrike_Beacon { meta: description = "Cobalt Strike Beacon payload" strings: $s1 = "%s (admin)" $s2 = "%s as %s\\\\%s" $s3 = "beacon.dll" $s4 = "ReflectiveLoader" $x1 = { 69 68 69 68 69 6B } condition: uint16(0) == 0x5A4D and (2 of ($s*) or $x1) }'},
        {"name": "Meterpreter", "rule": 'rule Meterpreter { meta: description = "Metasploit Meterpreter" strings: $s1 = "metsrv" $s2 = "stdapi" $s3 = "ReflectiveDLLInject" $s4 = "ext_server" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "njRAT", "rule": 'rule njRAT { meta: description = "njRAT remote access trojan" strings: $s1 = "njRAT" nocase $s2 = "get_Ession" $s3 = "|NJlog|" $s4 = "netsh firewall" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "AsyncRAT", "rule": 'rule AsyncRAT { meta: description = "AsyncRAT" strings: $s1 = "AsyncClient" $s2 = "Pastebin" $s3 = "Anti_Analysis" $s4 = "get_SslClient" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "QuasarRAT", "rule": 'rule QuasarRAT { meta: description = "Quasar RAT" strings: $s1 = "QuasarClient" $s2 = "HandlePacket" $s3 = "StreamCodec" $s4 = "GetOperatingSystem" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Sliver", "rule": 'rule Sliver_Implant { meta: description = "Sliver C2 implant" strings: $s1 = "sliverpb" $s2 = "StartBeaconLoop" $s3 = "GetActiveC2" $go = "Go build" condition: uint16(0) == 0x5A4D and ($go and 1 of ($s*)) }'},
        {"name": "Havoc", "rule": 'rule Havoc_Demon { meta: description = "Havoc C2 Demon agent" strings: $s1 = "Demon" $s2 = "TRANSPORT_HTTP" $s3 = "DemonConfig" condition: 2 of ($s*) }'},
        {"name": "Remcos", "rule": 'rule Remcos { meta: description = "Remcos RAT" strings: $s1 = "Remcos" $s2 = "BreakingSecurity" $s3 = "licence" $s4 = "Mutex" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "DarkComet", "rule": 'rule DarkComet { meta: description = "DarkComet RAT" strings: $s1 = "DarkComet" $s2 = "DCRATMUTEX" $s3 = "#BOT#" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "BruteRatel", "rule": 'rule BruteRatel { meta: description = "Brute Ratel C4 badger" strings: $s1 = "badger_" $s2 = "brc4" $s3 = "DarkVortex" condition: 2 of ($s*) }'},
    ],
    "webshell": [
        {"name": "PHP_Webshell_Generic", "rule": 'rule PHP_Webshell { meta: description = "Generic PHP webshell" strings: $s1 = "system($_" $s2 = "exec($_" $s3 = "passthru($_" $s4 = "shell_exec($_" $s5 = "eval(base64_decode" $s6 = "assert(base64_decode" $s7 = "preg_replace.*e.*$_" condition: any of ($s*) }'},
        {"name": "ASP_Webshell", "rule": 'rule ASP_Webshell { meta: description = "ASP/ASPX webshell" strings: $s1 = "cmd.exe" $s2 = "Process.Start" $s3 = "eval(Request" $s4 = "Execute(Request" $s5 = "CreateObject" condition: 2 of ($s*) }'},
        {"name": "JSP_Webshell", "rule": 'rule JSP_Webshell { meta: description = "JSP webshell" strings: $s1 = "Runtime.getRuntime().exec" $s2 = "ProcessBuilder" $s3 = "request.getParameter" condition: 2 of ($s*) }'},
        {"name": "China_Chopper", "rule": 'rule ChinaChopper { meta: description = "China Chopper webshell" strings: $s1 = "eval(Request" ascii wide $s2 = "eval($_POST" $s3 = { 65 76 61 6C 28 } $s4 = "caidao" condition: 2 of ($s*) }'},
        {"name": "C99_Shell", "rule": 'rule C99Shell { meta: description = "C99 webshell" strings: $s1 = "c99shell" $s2 = "c99_" $s3 = "Safe_Mode" $s4 = "FilesMan" condition: 2 of ($s*) }'},
        {"name": "WSO_Shell", "rule": 'rule WSOShell { meta: description = "WSO webshell" strings: $s1 = "WSO " $s2 = "FilesMan" $s3 = "Sec. Info" $s4 = "wso_" condition: 2 of ($s*) }'},
        {"name": "B374K", "rule": 'rule B374K { meta: description = "b374k webshell" strings: $s1 = "b374k" nocase $s2 = "mini shell" nocase $s3 = "eval(gzinflate" condition: 2 of ($s*) }'},
        {"name": "Godzilla_Shell", "rule": 'rule GodzillaShell { meta: description = "Godzilla webshell" strings: $s1 = "GodzillaShell" $s2 = "xc" $s3 = "pass=" $s4 = "base64_decode" condition: 2 of ($s*) }'},
        {"name": "Weevely", "rule": 'rule Weevely { meta: description = "Weevely webshell" strings: $s1 = "weevely" $s2 = "str_replace" $s3 = "base64_decode" $s4 = "create_function" condition: 3 of ($s*) }'},
    ],
    "credential_stealer": [
        {"name": "Mimikatz", "rule": 'rule Mimikatz { meta: description = "Mimikatz credential dumper" strings: $s1 = "sekurlsa" wide ascii $s2 = "kerberos" wide ascii $s3 = "wdigest" wide ascii $s4 = "gentilkiwi" $s5 = "mimikatz" wide ascii nocase condition: uint16(0) == 0x5A4D and 3 of ($s*) }'},
        {"name": "LaZagne", "rule": 'rule LaZagne { meta: description = "LaZagne credential recovery" strings: $s1 = "lazagne" nocase $s2 = "softwares" $s3 = "browsers" $s4 = "wifi" condition: uint16(0) == 0x5A4D and 3 of ($s*) }'},
        {"name": "Rubeus", "rule": 'rule Rubeus { meta: description = "Rubeus Kerberos abuse tool" strings: $s1 = "Rubeus" $s2 = "kerberoast" $s3 = "asreproast" $s4 = "tgtdeleg" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "SharpHound", "rule": 'rule SharpHound { meta: description = "BloodHound SharpHound collector" strings: $s1 = "SharpHound" $s2 = "BloodHound" $s3 = "CollectionMethod" $s4 = "JsonExport" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Emotet", "rule": 'rule Emotet { meta: description = "Emotet banking trojan/loader" strings: $s1 = { 8D 44 24 ?? 50 68 ?? ?? ?? ?? FF 15 } $s2 = "InternetOpenA" $s3 = "WinHttpOpen" condition: uint16(0) == 0x5A4D and ($s1 and 1 of ($s2, $s3)) }'},
    ],
    "cryptominer": [
        {"name": "XMRig", "rule": 'rule XMRig { meta: description = "XMRig cryptocurrency miner" strings: $s1 = "xmrig" nocase $s2 = "stratum+tcp" $s3 = "pool.minexmr" $s4 = "randomx" $s5 = "cryptonight" condition: 2 of ($s*) }'},
        {"name": "Generic_Miner", "rule": 'rule Generic_Miner { meta: description = "Generic cryptocurrency miner" strings: $s1 = "stratum+tcp://" $s2 = "mining.subscribe" $s3 = "mining.authorize" $s4 = "getwork" $s5 = "hashrate" condition: 2 of ($s*) }'},
        {"name": "CoinHive", "rule": 'rule CoinHive { meta: description = "CoinHive browser miner" strings: $s1 = "coinhive" nocase $s2 = "CoinHive.Anonymous" $s3 = "authedmine" condition: any of ($s*) }'},
    ],
    "rootkit": [
        {"name": "LoJax_UEFI", "rule": 'rule LoJax { meta: description = "LoJax UEFI rootkit (APT28)" strings: $s1 = "rpcnetp" $s2 = "autoche" $s3 = { 55 8B EC 83 EC 10 } condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Necurs", "rule": 'rule Necurs { meta: description = "Necurs rootkit" strings: $s1 = "\\\\Device\\\\" $s2 = "DeviceIoControl" $s3 = "NtLoadDriver" condition: uint16(0) == 0x5A4D and all of ($s*) }'},
        {"name": "CosmicStrand", "rule": 'rule CosmicStrand { meta: description = "CosmicStrand UEFI firmware rootkit" strings: $s1 = { 55 8B EC 56 57 8B 7D 08 } $s2 = "hook" $s3 = "driver" condition: all of them }'},
    ],
    "loader_dropper": [
        {"name": "IcedID", "rule": 'rule IcedID { meta: description = "IcedID/BokBot banking trojan" strings: $s1 = "gzip" $s2 = "Content-Type" $s3 = { E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 } condition: uint16(0) == 0x5A4D and all of them }'},
        {"name": "QakBot", "rule": 'rule QakBot { meta: description = "QakBot/QBot banking trojan" strings: $s1 = "qbot" nocase $s2 = "stager" $s3 = "C:\\\\Users" $s4 = "spx99" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "BazarLoader", "rule": 'rule BazarLoader { meta: description = "BazarLoader/BazarBackdoor" strings: $s1 = "bazar" nocase $s2 = ".bazar" $s3 = { 48 89 5C 24 08 48 89 6C 24 10 } condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "Trickbot", "rule": 'rule Trickbot { meta: description = "TrickBot modular trojan" strings: $s1 = "moduleconfig" $s2 = "trickbot" nocase $s3 = "injectDll" $s4 = "mcconf" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
        {"name": "SunBurst", "rule": 'rule SUNBURST { meta: description = "SolarWinds SUNBURST backdoor" strings: $s1 = "OrionImprovementBusinessLayer" $s2 = "SolarWinds.Orion" $s3 = "avsvmcloud.com" condition: uint16(0) == 0x5A4D and 2 of ($s*) }'},
    ],
}

def get_all_rules():
    """Return all rules as a list of dicts."""
    all_rules = []
    for category, rules in YARA_RULES.items():
        for r in rules:
            all_rules.append({"category": category, "name": r["name"], "rule": r["rule"]})
    return all_rules

def get_rules_by_category(category):
    """Return rules for a specific category."""
    return YARA_RULES.get(category, [])

def search_rules(query):
    """Search rules by name or content."""
    q = query.lower()
    results = []
    for category, rules in YARA_RULES.items():
        for r in rules:
            if q in r["name"].lower() or q in r["rule"].lower():
                results.append({"category": category, "name": r["name"], "rule": r["rule"]})
    return results

def get_stats():
    total = sum(len(rules) for rules in YARA_RULES.values())
    by_cat = {k: len(v) for k, v in YARA_RULES.items()}
    return {"total": total, "by_category": by_cat}

if __name__ == "__main__":
    stats = get_stats()
    print(f"AEGIS YARA Rules: {stats['total']} rules across {len(YARA_RULES)} categories")
    for cat, count in stats["by_category"].items():
        print(f"  {cat}: {count} rules")
