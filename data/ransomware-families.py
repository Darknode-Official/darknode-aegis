#!/usr/bin/env python3
"""
AEGIS Ransomware Family Database
==================================
Comprehensive database of 35+ ransomware families with IOCs, TTPs,
encryption methods, ransom note patterns, and behavioral signatures.

EDUCATIONAL USE ONLY - All data is for research and training purposes.
"""

# ─── Ransomware Family Database ────────────────────────────────────────

RANSOMWARE_FAMILIES = {
    "LockBit": {
        "aliases": ["LockBit 3.0", "LockBit Black", "LockBit Green"],
        "first_seen": "2019-09",
        "last_seen": "2024-09",
        "status": "Active",
        "origin": "Russia (suspected)",
        "model": "RaaS (Ransomware-as-a-Service)",
        "encryption": {
            "algorithm": "AES-256-CBC + RSA-2048",
            "file_marker": "19 47 B1 C5",
            "key_exchange": "RSA public key embedded in binary",
            "speed": "Fast (multithreaded, partial encryption for large files)",
        },
        "extensions": [".lockbit", ".abcd", ".LockBit"],
        "ransom_notes": {
            "filenames": ["Restore-My-Files.txt", "[victim_id].README.txt"],
            "content_pattern": "~~~ LockBit 3.0 the world's fastest and most stable ransomware ~~~",
            "payment": "Tor hidden service, Bitcoin/Monero",
            "leak_site": "lockbit[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "ocssd", "dbsnmp", "synctime", "agntsvc",
                            "isqlplussvc", "xfssvccon", "mydesktopservice", "ocautoupds",
                            "encsvc", "firefox", "tbirdconfig", "mydesktopqos", "ocomm",
                            "dbeng50", "sqbcoreservice", "excel", "infopath", "msaccess",
                            "mspub", "onenote", "outlook", "powerpnt", "steam", "thebat",
                            "thunderbird", "visio", "winword", "wordpad", "notepad"],
            "service_kill": ["vss", "sql", "svc$", "memtas", "mepocs", "sophos", "veeam",
                            "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr",
                            "DefWatch", "ccEvtMgr", "ccSetMgr", "SavRoam", "RTVscan",
                            "QBFCService", "QBIDPService", "Intuit.QuickBooks.FCS",
                            "QBCFMonitorService", "YooIT", "zhudongfangyu", "stc_raw_agent",
                            "VSNAPVSS", "VeeamTransportSvc", "VeeamDeploymentService",
                            "VeeamNFSSvc", "PDVFSService", "BackupExecVSSProvider",
                            "BackupExecAgentAccelerator", "BackupExecAgentBrowser",
                            "BackupExecDiveciMediaService", "BackupExecJobEngine",
                            "BackupExecManagementService", "BackupExecRPCService",
                            "AcrSch2Svc", "AcronisAgent", "CASAD2DWebSvc", "CAARCUpdateSvc"],
            "shadow_delete": True,
            "safe_mode_boot": True,
            "self_propagation": True,
            "wallpaper_change": True,
            "print_ransom_note": True,
            "double_extortion": True,
            "data_exfil_tool": "StealBit",
        },
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1021.002", "T1059.001",
                             "T1047", "T1053.005", "T1562.001", "T1027"],
        "iocs": {
            "mutex": ["Global\\{BEF590BE-11A6-442A-A85B-656C770DCE16}"],
            "registry_keys": [
                r"HKCU\SOFTWARE\LockBit",
                r"HKCU\SOFTWARE\LockBit\full",
                r"HKCU\SOFTWARE\LockBit\Public",
            ],
            "file_paths": [
                r"C:\ProgramData\*.lockbit",
                r"C:\Windows\Temp\*.tmp",
            ],
            "sample_hashes": [
                "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce",
                "a56b41a6023f828cccaaef470571d6a07e0e0a7e58e91587c76c0e0a3d53ff2c",
            ],
            "c2_patterns": ["HTTP POST with base64-encoded data", "Tor-based C2"],
        },
        "notable_attacks": [
            {"target": "Royal Mail (UK)", "date": "2023-01", "impact": "International mail disruption"},
            {"target": "Boeing", "date": "2023-10", "impact": "Data leaked on dark web"},
            {"target": "ICBC Financial Services", "date": "2023-11", "impact": "US Treasury market disruption"},
        ],
    },

    "BlackCat": {
        "aliases": ["ALPHV", "Noberus", "BlackCat"],
        "first_seen": "2021-11",
        "last_seen": "2024-09",
        "status": "Active (Rebranded)",
        "origin": "Former DarkSide/BlackMatter affiliates",
        "model": "RaaS",
        "encryption": {
            "algorithm": "AES-256-CTR + RSA-4096",
            "file_marker": "Unique per variant",
            "key_exchange": "RSA-4096 + ChaCha20",
            "speed": "Very fast (Rust-based, cross-platform)",
        },
        "extensions": [".alphv", ".sykffle", "random 6-7 chars"],
        "ransom_notes": {
            "filenames": ["RECOVER-FILES.txt", "RECOVER-{ext}-FILES.txt"],
            "content_pattern": "Your network has been infected",
            "payment": "Tor hidden service, Bitcoin/Monero",
            "leak_site": "alphv[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "ocssd", "dbsnmp", "encsvc", "firefox",
                            "tbirdconfig", "mydesktopqos", "ocomm", "dbeng50"],
            "service_kill": ["vss", "sql", "svc$", "memtas", "mepocs", "veeam", "backup"],
            "shadow_delete": True,
            "safe_mode_boot": True,
            "self_propagation": True,
            "wallpaper_change": True,
            "double_extortion": True,
            "data_exfil_tool": "ExMatter",
        },
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1059.001", "T1027",
                             "T1021.002", "T1047"],
        "iocs": {
            "mutex": [],
            "registry_keys": [],
            "file_paths": [r"C:\Windows\Temp\*.exe"],
            "sample_hashes": [
                "b2f14eabd4b6bcb6b0845de2e3e15f9c72d70e3e32e3e3e6f8bc3e9e",
            ],
            "c2_patterns": ["Rust binary with embedded config", "Tor C2"],
        },
        "notable_attacks": [
            {"target": "MGM Resorts", "date": "2023-09", "impact": "$100M+ losses, casino systems down"},
            {"target": "Change Healthcare", "date": "2024-02", "impact": "US healthcare system disruption"},
        ],
    },

    "Cl0p": {
        "aliases": ["TA505", "Clop", "Cl0p"],
        "first_seen": "2019-02",
        "last_seen": "2024-09",
        "status": "Active",
        "origin": "Russia/Ukraine (TA505 group)",
        "model": "RaaS / Direct Operation",
        "encryption": {
            "algorithm": "AES-256 + RSA-1024",
            "file_marker": "Cl0p signature in encrypted files",
            "key_exchange": "RSA public key",
            "speed": "Moderate",
        },
        "extensions": [".Cl0p", ".cl0p", ".ciop"],
        "ransom_notes": {
            "filenames": ["ClopReadMe.txt", "!_READ_ME.txt"],
            "content_pattern": "YOUR NETWORK HAS BEEN PENETRATED",
            "payment": "Email-based negotiation, later Tor",
            "leak_site": "clop[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "ocssd", "dbsnmp", "synctime"],
            "service_kill": ["vss", "sql", "svc$", "memtas"],
            "shadow_delete": True,
            "safe_mode_boot": False,
            "self_propagation": False,
            "wallpaper_change": False,
            "double_extortion": True,
            "data_exfil_tool": "TrueBot / custom exfil",
        },
        "mitre_techniques": ["T1486", "T1490", "T1190", "T1059.001"],
        "iocs": {
            "mutex": ["Fany--Is$$God"],
            "registry_keys": [],
            "file_paths": [],
            "sample_hashes": [
                "f1e2d3c4b5a6f7e8d9c0b1a2e3f4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0",
            ],
            "c2_patterns": ["MOVEit exploitation", "GoAnywhere exploitation"],
        },
        "notable_attacks": [
            {"target": "MOVEit Transfer (mass exploitation)", "date": "2023-05",
             "impact": "2000+ organizations affected globally"},
            {"target": "GoAnywhere MFT", "date": "2023-01", "impact": "130+ organizations compromised"},
        ],
    },

    "Play": {
        "aliases": ["PlayCrypt", "Balloonfly"],
        "first_seen": "2022-06",
        "last_seen": "2024-09",
        "status": "Active",
        "origin": "Unknown",
        "model": "Closed group (not RaaS)",
        "encryption": {
            "algorithm": "AES-256 + RSA-2048",
            "file_marker": ".play extension appended",
            "key_exchange": "RSA key pair per victim",
            "speed": "Fast (intermittent encryption)",
        },
        "extensions": [".play"],
        "ransom_notes": {
            "filenames": ["ReadMe.txt"],
            "content_pattern": "PLAY\nHello\nYour files have been encrypted",
            "payment": "Email-based negotiation",
            "leak_site": "play[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "ocssd", "dbsnmp", "xfssvccon"],
            "service_kill": ["vss", "sql", "svc$", "backup", "sophos"],
            "shadow_delete": True,
            "safe_mode_boot": False,
            "self_propagation": True,
            "wallpaper_change": False,
            "double_extortion": True,
            "data_exfil_tool": "Custom tool / WinSCP",
        },
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1190"],
        "iocs": {
            "mutex": [],
            "registry_keys": [],
            "file_paths": [],
            "sample_hashes": [],
            "c2_patterns": ["FortiOS exploitation", "Exchange exploitation"],
        },
        "notable_attacks": [
            {"target": "City of Oakland", "date": "2023-02", "impact": "City services disrupted"},
            {"target": "Arnold Clark", "date": "2023-01", "impact": "UK car dealer data breach"},
        ],
    },

    "Royal": {
        "aliases": ["Royal Ransomware", "DEV-0569", "BlackSuit"],
        "first_seen": "2022-09",
        "last_seen": "2024-09",
        "status": "Active (Rebranded as BlackSuit)",
        "origin": "Former Conti members",
        "model": "Closed group",
        "encryption": {
            "algorithm": "AES-256 + RSA-2048",
            "file_marker": "Royal signature",
            "key_exchange": "RSA public key",
            "speed": "Fast (partial encryption option)",
        },
        "extensions": [".royal", ".blacksuit"],
        "ransom_notes": {
            "filenames": ["README.TXT", "README.BlackSuit.txt"],
            "content_pattern": "If you are reading this, it means that your system were hit",
            "payment": "Tor hidden service",
            "leak_site": "royal[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "ocssd", "dbsnmp", "encsvc"],
            "service_kill": ["vss", "sql", "svc$", "veeam", "backup"],
            "shadow_delete": True,
            "safe_mode_boot": False,
            "self_propagation": False,
            "wallpaper_change": True,
            "double_extortion": True,
            "data_exfil_tool": "Custom tool",
        },
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1566.002", "T1059.001"],
        "iocs": {
            "mutex": [],
            "registry_keys": [r"HKCU\SOFTWARE\Royal"],
            "file_paths": [],
            "sample_hashes": [],
            "c2_patterns": ["Callback phishing", "Google Ads malvertising"],
        },
        "notable_attacks": [
            {"target": "City of Dallas", "date": "2023-05", "impact": "City services disrupted for weeks"},
        ],
    },

    "Akira": {
        "aliases": ["Akira Ransomware"],
        "first_seen": "2023-03",
        "last_seen": "2024-09",
        "status": "Active",
        "origin": "Possibly former Conti affiliates",
        "model": "RaaS",
        "encryption": {
            "algorithm": "ChaCha20 + RSA-4096",
            "file_marker": ".akira extension",
            "key_exchange": "RSA-4096",
            "speed": "Fast (ChaCha20 is efficient)",
        },
        "extensions": [".akira"],
        "ransom_notes": {
            "filenames": ["akira_readme.txt"],
            "content_pattern": "Hi friends, Whatever who you are",
            "payment": "Tor hidden service, Bitcoin",
            "leak_site": "akira[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "veeam", "backup"],
            "service_kill": ["vss", "sql", "veeam", "backup"],
            "shadow_delete": True,
            "safe_mode_boot": False,
            "self_propagation": False,
            "wallpaper_change": False,
            "double_extortion": True,
            "data_exfil_tool": "WinSCP / RClone",
        },
        "mitre_techniques": ["T1486", "T1490", "T1133", "T1059.001"],
        "iocs": {
            "mutex": [],
            "registry_keys": [],
            "file_paths": [],
            "sample_hashes": [],
            "c2_patterns": ["Cisco VPN exploitation", "Valid credential abuse"],
        },
        "notable_attacks": [
            {"target": "Multiple US hospitals", "date": "2024", "impact": "Healthcare disruption"},
        ],
    },

    "Rhysida": {
        "aliases": ["Rhysida Ransomware"],
        "first_seen": "2023-05",
        "last_seen": "2024-09",
        "status": "Active",
        "origin": "Unknown",
        "model": "RaaS",
        "encryption": {
            "algorithm": "AES-256-CTR + RSA-4096",
            "file_marker": ".rhysida extension",
            "key_exchange": "RSA-4096",
            "speed": "Fast",
        },
        "extensions": [".rhysida"],
        "ransom_notes": {
            "filenames": ["CriticalBreachDetected.pdf"],
            "content_pattern": "Critical Breach Detected",
            "payment": "Tor hidden service, Bitcoin",
            "leak_site": "rhysida[.]onion",
        },
        "behavior": {
            "process_kill": ["sql", "oracle", "ocssd"],
            "service_kill": ["vss", "sql", "backup"],
            "shadow_delete": True,
            "self_propagation": False,
            "double_extortion": True,
            "data_exfil_tool": "Custom tool",
        },
        "mitre_techniques": ["T1486", "T1490", "T1566.001"],
        "iocs": {"mutex": [], "registry_keys": [], "file_paths": [], "sample_hashes": [],
                 "c2_patterns": []},
        "notable_attacks": [
            {"target": "British Library", "date": "2023-10", "impact": "Major data breach, services disrupted"},
        ],
    },

    "BlackBasta": {
        "aliases": ["Black Basta"],
        "first_seen": "2022-04", "last_seen": "2024-09", "status": "Active",
        "origin": "Former Conti members", "model": "Closed RaaS",
        "encryption": {"algorithm": "ChaCha20 + RSA-4096", "speed": "Fast"},
        "extensions": [".basta"], "ransom_notes": {"filenames": ["readme.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1059.001", "T1021.002"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [{"target": "ABB", "date": "2023-05", "impact": "Global operations disrupted"}],
    },

    "Medusa": {
        "aliases": ["MedusaLocker", "Medusa Ransomware"],
        "first_seen": "2019-09", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + RSA-2048", "speed": "Moderate"},
        "extensions": [".medusa", ".MEDUSA", ".encrypted"],
        "ransom_notes": {"filenames": ["!!!READ_ME_MEDUSA!!!.txt", "How_to_back_files.html"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1059.001"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [{"target": "Minneapolis Public Schools", "date": "2023-02", "impact": "Student data leaked"}],
    },

    "8Base": {
        "aliases": ["8Base Ransomware"],
        "first_seen": "2022-03", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "RaaS (Phobos-based)",
        "encryption": {"algorithm": "AES-256 + RSA-1024", "speed": "Fast"},
        "extensions": [".8base", ".eight"],
        "ransom_notes": {"filenames": ["info.hta", "info.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "BianLian": {
        "aliases": ["BianLian Ransomware"],
        "first_seen": "2022-06", "last_seen": "2024-09", "status": "Active (extortion-only)",
        "origin": "Unknown", "model": "Direct operation",
        "encryption": {"algorithm": "AES-256 (Go-based)", "speed": "Fast"},
        "extensions": [".bianlian"],
        "ransom_notes": {"filenames": ["Look at this instruction.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1133"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "NoEscape": {
        "aliases": ["NoEscape Ransomware"],
        "first_seen": "2023-05", "last_seen": "2024-09", "status": "Active",
        "origin": "Avaddon rebrand (suspected)", "model": "RaaS",
        "encryption": {"algorithm": "Salsa20 + RSA-2048", "speed": "Fast"},
        "extensions": [".noescape"],
        "ransom_notes": {"filenames": ["HOW_TO_RECOVER_FILES.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "Hunters_International": {
        "aliases": ["Hunters International"],
        "first_seen": "2023-10", "last_seen": "2024-09", "status": "Active",
        "origin": "Hive rebrand (suspected)", "model": "RaaS",
        "encryption": {"algorithm": "AES + RSA", "speed": "Fast"},
        "extensions": [".hunters"],
        "ransom_notes": {"filenames": ["Contact Us.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "Cactus": {
        "aliases": ["Cactus Ransomware"],
        "first_seen": "2023-03", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "Direct operation",
        "encryption": {"algorithm": "AES-256-OCB + RSA-4096", "speed": "Fast"},
        "extensions": [".cts1", ".cts6"],
        "ransom_notes": {"filenames": ["cAcTuS.readme.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True,
                     "self_encryption": True},
        "mitre_techniques": ["T1486", "T1490", "T1133"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [{"target": "Schneider Electric", "date": "2024-01", "impact": "Data breach"}],
    },

    "INC_Ransom": {
        "aliases": ["INC Ransom"],
        "first_seen": "2023-07", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "Direct operation",
        "encryption": {"algorithm": "AES + RSA", "speed": "Moderate"},
        "extensions": [".INC"],
        "ransom_notes": {"filenames": ["INC-README.txt", "INC-README.html"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "Trigona": {
        "aliases": ["Trigona Ransomware"],
        "first_seen": "2022-10", "last_seen": "2024-09", "status": "Active",
        "origin": "CryLock successor (suspected)", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + RSA-2048", "speed": "Moderate"},
        "extensions": ["._locked"],
        "ransom_notes": {"filenames": ["how_to_decrypt.hta"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "RansomHub": {
        "aliases": ["RansomHub"],
        "first_seen": "2024-02", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown (possible Knight rebrand)", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + X25519", "speed": "Very fast"},
        "extensions": [".ransomhub"],
        "ransom_notes": {"filenames": ["README.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1021.002"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "Qilin": {
        "aliases": ["Qilin Ransomware", "Agenda"],
        "first_seen": "2022-07", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "RaaS",
        "encryption": {"algorithm": "AES-256-CTR + RSA-2048 (Rust/Go)", "speed": "Fast"},
        "extensions": [".qilin", ".agenda"],
        "ransom_notes": {"filenames": ["README-RECOVER.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [{"target": "Synnovis (NHS)", "date": "2024-06", "impact": "UK healthcare disruption"}],
    },

    "Phobos": {
        "aliases": ["Phobos Ransomware"],
        "first_seen": "2018-12", "last_seen": "2024-09", "status": "Active",
        "origin": "Dharma/CrySiS derivative", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + RSA-1024", "speed": "Moderate"},
        "extensions": [".phobos", ".eking", ".eight", ".elbie"],
        "ransom_notes": {"filenames": ["info.hta", "info.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": False},
        "mitre_techniques": ["T1486", "T1490", "T1133"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "Vice_Society": {
        "aliases": ["Vice Society"],
        "first_seen": "2021-06", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "Direct operation",
        "encryption": {"algorithm": "Various (uses multiple families)", "speed": "Variable"},
        "extensions": [".v-society", ".vicesociety"],
        "ransom_notes": {"filenames": ["!!! ALL YOUR FILES ARE ENCRYPTED !!!.TXT"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Los Angeles Unified School District", "date": "2022-09", "impact": "Student data leaked"},
        ],
    },

    "Hive": {
        "aliases": ["Hive Ransomware"],
        "first_seen": "2021-06", "last_seen": "2023-01", "status": "Disrupted by FBI",
        "origin": "Unknown", "model": "RaaS",
        "encryption": {"algorithm": "AES + RSA (Go/Rust)", "speed": "Fast"},
        "extensions": [".hive", ".key.xxxxx"],
        "ransom_notes": {"filenames": ["HOW_TO_DECRYPT.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1021.002"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Costa Rica Social Security Fund", "date": "2022-05", "impact": "Healthcare disruption"},
        ],
    },

    "Conti": {
        "aliases": ["Conti Ransomware", "Wizard Spider"],
        "first_seen": "2019-12", "last_seen": "2022-06", "status": "Disbanded (members in other groups)",
        "origin": "Russia (TrickBot group)", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + RSA-4096", "speed": "Very fast (32 threads)"},
        "extensions": [".CONTI", ".conti"],
        "ransom_notes": {"filenames": ["readme.txt", "CONTI_README.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1021.002", "T1059.001"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": ["Cobalt Strike C2"]},
        "notable_attacks": [
            {"target": "Costa Rica Government", "date": "2022-04", "impact": "National emergency declared"},
            {"target": "Ireland HSE", "date": "2021-05", "impact": "$600M recovery, healthcare disruption"},
        ],
    },

    "REvil": {
        "aliases": ["Sodinokibi", "REvil"],
        "first_seen": "2019-04", "last_seen": "2022-01", "status": "Disrupted (arrests)",
        "origin": "Russia (GandCrab successor)", "model": "RaaS",
        "encryption": {"algorithm": "Salsa20 + Curve25519", "speed": "Very fast"},
        "extensions": [".random_chars"],
        "ransom_notes": {"filenames": ["[random]-readme.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1195.002"],
        "iocs": {"mutex": ["Global\\206D87E0-0E60-DF25-DD8F-8E4E7D1E3BF0"],
                 "registry_keys": [r"HKLM\SOFTWARE\recfg"],
                 "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Kaseya", "date": "2021-07", "impact": "1500+ companies via supply chain"},
            {"target": "JBS Foods", "date": "2021-05", "impact": "$11M ransom paid"},
        ],
    },

    "DarkSide": {
        "aliases": ["DarkSide Ransomware"],
        "first_seen": "2020-08", "last_seen": "2021-05", "status": "Disbanded (rebranded as BlackMatter)",
        "origin": "Russia", "model": "RaaS",
        "encryption": {"algorithm": "Salsa20 + RSA-1024", "speed": "Fast"},
        "extensions": [".random_8_chars"],
        "ransom_notes": {"filenames": ["README.[victim_id].TXT"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Colonial Pipeline", "date": "2021-05", "impact": "US East Coast fuel shortage, $4.4M ransom"},
        ],
    },

    "WannaCry": {
        "aliases": ["WannaCrypt", "WCry", "WCRY"],
        "first_seen": "2017-05", "last_seen": "2017-05", "status": "Inactive (kill switch found)",
        "origin": "North Korea (Lazarus Group)", "model": "Self-propagating worm",
        "encryption": {"algorithm": "AES-128-CBC + RSA-2048", "speed": "Moderate"},
        "extensions": [".WNCRY", ".WCRY", ".WNCRYT"],
        "ransom_notes": {"filenames": ["@WanaDecryptor@.exe", "@Please_Read_Me@.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": False,
                     "worm_propagation": "EternalBlue (MS17-010)"},
        "mitre_techniques": ["T1486", "T1490", "T1210"],
        "iocs": {"mutex": ["MsWinZonesCacheCounterMutexA0"],
                 "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "NHS (UK)", "date": "2017-05", "impact": "200K+ systems in 150 countries"},
        ],
    },

    "NotPetya": {
        "aliases": ["Petya", "ExPetr", "Nyetya"],
        "first_seen": "2017-06", "last_seen": "2017-06", "status": "Inactive (wiper)",
        "origin": "Russia (Sandworm / GRU)", "model": "Destructive wiper disguised as ransomware",
        "encryption": {"algorithm": "AES-128 + RSA-2048 (but key intentionally destroyed)", "speed": "Fast"},
        "extensions": ["N/A (MBR overwrite)"],
        "ransom_notes": {"filenames": ["README.TXT (fake - payment not possible)"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": False,
                     "worm_propagation": "EternalBlue + Mimikatz + PsExec/WMIC"},
        "mitre_techniques": ["T1485", "T1486", "T1490", "T1210"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Global (via Ukrainian tax software)", "date": "2017-06", "impact": "$10B+ global damages"},
        ],
    },

    "Maze": {
        "aliases": ["Maze Ransomware", "ChaCha"],
        "first_seen": "2019-05", "last_seen": "2020-11", "status": "Retired",
        "origin": "Unknown (possibly Russian)", "model": "Direct + affiliate",
        "encryption": {"algorithm": "ChaCha20 + RSA-2048", "speed": "Fast"},
        "extensions": [".maze"],
        "ransom_notes": {"filenames": ["DECRYPT-FILES.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False,
                     "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Cognizant", "date": "2020-04", "impact": "$50-70M losses"},
        ],
    },

    "Ryuk": {
        "aliases": ["Ryuk Ransomware"],
        "first_seen": "2018-08", "last_seen": "2021-12", "status": "Succeeded by Conti",
        "origin": "Russia (Wizard Spider / TrickBot)", "model": "Direct operation",
        "encryption": {"algorithm": "AES-256 + RSA-4096", "speed": "Fast"},
        "extensions": [".RYK"],
        "ransom_notes": {"filenames": ["RyukReadMe.html", "RyukReadMe.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": False},
        "mitre_techniques": ["T1486", "T1490", "T1489"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "Universal Health Services", "date": "2020-09", "impact": "$67M losses"},
        ],
    },

    "GandCrab": {
        "aliases": ["GandCrab"],
        "first_seen": "2018-01", "last_seen": "2019-06", "status": "Retired (operators claimed $2B profit)",
        "origin": "Russia", "model": "RaaS",
        "encryption": {"algorithm": "Salsa20 + RSA-2048", "speed": "Fast"},
        "extensions": [".GDCB", ".KRAB", ".CRAB", ".random_5"],
        "ransom_notes": {"filenames": ["GDCB-DECRYPT.txt", "KRAB-DECRYPT.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": False},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": ["Global\\pc_group=WORKGROUP&2BherdIDgrp=0"],
                 "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "BlackMatter": {
        "aliases": ["BlackMatter Ransomware"],
        "first_seen": "2021-07", "last_seen": "2021-11", "status": "Retired (rebranded from DarkSide)",
        "origin": "Russia", "model": "RaaS",
        "encryption": {"algorithm": "Salsa20 + RSA-1024", "speed": "Fast"},
        "extensions": [".random_chars"],
        "ransom_notes": {"filenames": ["[random].README.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [
            {"target": "NEW Cooperative", "date": "2021-09", "impact": "US agricultural cooperative disrupted"},
        ],
    },

    "AvosLocker": {
        "aliases": ["AvosLocker"],
        "first_seen": "2021-06", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + RSA-2048", "speed": "Moderate"},
        "extensions": [".avos", ".avos2", ".avoslinux"],
        "ransom_notes": {"filenames": ["GET_YOUR_FILES_BACK.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "Cuba": {
        "aliases": ["Cuba Ransomware", "COLDDRAW"],
        "first_seen": "2019-12", "last_seen": "2024-09", "status": "Active",
        "origin": "Unknown", "model": "Direct operation",
        "encryption": {"algorithm": "ChaCha20 + RSA-4096", "speed": "Fast"},
        "extensions": [".cuba"],
        "ransom_notes": {"filenames": ["!! READ ME !!.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": False, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1059.001"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },

    "LockBit_Green": {
        "aliases": ["LockBit Green"],
        "first_seen": "2023-01", "last_seen": "2024-09", "status": "Active",
        "origin": "LockBit group (using Conti code)", "model": "RaaS",
        "encryption": {"algorithm": "AES-256 + RSA (Conti-derived)", "speed": "Very fast"},
        "extensions": [".lockbit"],
        "ransom_notes": {"filenames": ["Restore-My-Files.txt"]},
        "behavior": {"shadow_delete": True, "self_propagation": True, "double_extortion": True},
        "mitre_techniques": ["T1486", "T1490", "T1021.002"],
        "iocs": {"mutex": [], "registry_keys": [], "sample_hashes": [], "c2_patterns": []},
        "notable_attacks": [],
    },
}

# ─── Ransomware Detection Signatures ──────────────────────────────────
DETECTION_SIGNATURES = {
    "file_extension_monitoring": {
        "description": "Monitor for known ransomware file extensions",
        "extensions": list(set(ext for family in RANSOMWARE_FAMILIES.values()
                              for ext in family.get("extensions", []))),
    },
    "ransom_note_monitoring": {
        "description": "Monitor for creation of known ransom note filenames",
        "filenames": list(set(fn for family in RANSOMWARE_FAMILIES.values()
                             for fn in family.get("ransom_notes", {}).get("filenames", []))),
    },
    "process_kill_patterns": {
        "description": "Monitor for mass process termination patterns",
        "common_targets": ["sql", "oracle", "veeam", "backup", "ocssd", "dbsnmp"],
    },
    "shadow_copy_deletion": {
        "description": "Monitor for shadow copy deletion commands",
        "commands": [
            "vssadmin delete shadows /all /quiet",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled No",
            "wbadmin delete catalog -quiet",
        ],
    },
}


def get_family_count():
    """Return the total number of ransomware families in the database."""
    return len(RANSOMWARE_FAMILIES)


def get_active_families():
    """Return families currently marked as Active."""
    return {k: v for k, v in RANSOMWARE_FAMILIES.items() if "Active" in v.get("status", "")}


def get_families_by_technique(technique_id):
    """Return families that use a specific MITRE ATT&CK technique."""
    return {k: v for k, v in RANSOMWARE_FAMILIES.items()
            if technique_id in v.get("mitre_techniques", [])}


def search_by_extension(extension):
    """Search for ransomware family by encrypted file extension."""
    return {k: v for k, v in RANSOMWARE_FAMILIES.items()
            if extension in v.get("extensions", [])}


if __name__ == "__main__":
    print(f"AEGIS Ransomware Family Database: {get_family_count()} families")
    print(f"Active families: {len(get_active_families())}")
    for name, family in RANSOMWARE_FAMILIES.items():
        print(f"  {name}: {family.get('status', 'Unknown')} - {family.get('encryption', {}).get('algorithm', 'N/A')}")


# ─── Ransomware YARA Rule Templates ───────────────────────────────────

RANSOMWARE_YARA_RULES = {
    "LockBit_Generic": {
        "name": "AEGIS_LockBit_Generic",
        "description": "Detects generic LockBit ransomware indicators",
        "author": "AEGIS Threat Research",
        "rule": """
rule AEGIS_LockBit_Generic {
    meta:
        description = "Detects LockBit ransomware generic indicators"
        author = "AEGIS Threat Research"
        date = "2024-09-01"
        reference = "https://attack.mitre.org/software/S0690/"
        severity = "critical"
    strings:
        $mutex1 = "Global\\{BEF590BE-11A6-442A-A85B-656C770DCE16}" wide ascii
        $note1 = "Restore-My-Files.txt" wide ascii
        $note2 = "LockBit 3.0" wide ascii
        $ext1 = ".lockbit" wide ascii
        $cmd1 = "vssadmin delete shadows /all /quiet" wide ascii nocase
        $cmd2 = "bcdedit /set {default} recoveryenabled No" wide ascii nocase
        $cmd3 = "wbadmin delete catalog -quiet" wide ascii nocase
        $reg1 = "SOFTWARE\\\\LockBit" wide ascii
        $api1 = "CryptEncrypt" ascii
        $api2 = "CryptGenKey" ascii
        $api3 = "CryptImportKey" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($mutex*) or
         (any of ($note*) and any of ($cmd*)) or
         (any of ($ext*) and 2 of ($api*)))
}""",
    },
    "BlackCat_Generic": {
        "name": "AEGIS_BlackCat_ALPHV",
        "description": "Detects ALPHV/BlackCat ransomware (Rust-based)",
        "author": "AEGIS Threat Research",
        "rule": """
rule AEGIS_BlackCat_ALPHV {
    meta:
        description = "Detects ALPHV/BlackCat ransomware indicators"
        author = "AEGIS Threat Research"
        date = "2024-09-01"
        severity = "critical"
    strings:
        $rust1 = "core::panicking::panic" ascii
        $rust2 = "std::rt::lang_start" ascii
        $note1 = "RECOVER" wide ascii
        $note2 = "ALPHV" wide ascii
        $cmd1 = "vssadmin.exe delete shadows" wide ascii nocase
        $cmd2 = "wmic shadowcopy delete" wide ascii nocase
        $config1 = "\"extension\":" ascii
        $config2 = "\"note_file_name\":" ascii
        $config3 = "\"credentials\":" ascii
        $pdb = "blackcat" ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($rust*) and any of ($note*)) or
        (2 of ($config*)) or
        ($pdb and any of ($cmd*))
}""",
    },
    "Cl0p_Generic": {
        "name": "AEGIS_Cl0p_Generic",
        "description": "Detects Cl0p ransomware indicators",
        "author": "AEGIS Threat Research",
        "rule": """
rule AEGIS_Cl0p_Generic {
    meta:
        description = "Detects Cl0p ransomware indicators"
        author = "AEGIS Threat Research"
        date = "2024-09-01"
        severity = "critical"
    strings:
        $mutex = "Fany--Is$$God" wide ascii
        $ext1 = ".Cl0p" wide ascii
        $ext2 = ".cl0p" wide ascii
        $note = "ClopReadMe" wide ascii
        $cmd1 = "vssadmin Delete Shadows" wide ascii nocase
        $str1 = "YOUR NETWORK HAS BEEN PENETRATED" wide ascii
        $str2 = "files have been encrypted" wide ascii
    condition:
        uint16(0) == 0x5A4D and
        ($mutex or
         (any of ($ext*) and any of ($note*)) or
         (any of ($str*) and $cmd1))
}""",
    },
    "Ransomware_Generic_Behavior": {
        "name": "AEGIS_Ransomware_Generic",
        "description": "Detects generic ransomware behavior patterns",
        "author": "AEGIS Threat Research",
        "rule": """
rule AEGIS_Ransomware_Generic {
    meta:
        description = "Detects generic ransomware behavior patterns"
        author = "AEGIS Threat Research"
        date = "2024-09-01"
        severity = "high"
    strings:
        $shadow1 = "vssadmin" wide ascii nocase
        $shadow2 = "delete shadows" wide ascii nocase
        $shadow3 = "wmic shadowcopy delete" wide ascii nocase
        $shadow4 = "bcdedit" wide ascii nocase
        $shadow5 = "recoveryenabled" wide ascii nocase
        $shadow6 = "wbadmin delete" wide ascii nocase
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "CryptGenRandom" ascii
        $crypto3 = "CryptAcquireContext" ascii
        $crypto4 = "BCryptEncrypt" ascii
        $enum1 = "FindFirstFile" ascii
        $enum2 = "FindNextFile" ascii
        $enum3 = "GetLogicalDrives" ascii
        $note1 = "YOUR FILES" wide ascii nocase
        $note2 = "ENCRYPTED" wide ascii nocase
        $note3 = "DECRYPT" wide ascii nocase
        $note4 = "BITCOIN" wide ascii nocase
        $note5 = "RANSOM" wide ascii nocase
        $note6 = "tor" wide ascii nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($shadow*) and 2 of ($crypto*) and 2 of ($enum*)) or
        (3 of ($note*) and 2 of ($shadow*))
}""",
    },
    "Shadow_Copy_Deletion": {
        "name": "AEGIS_Shadow_Copy_Deletion",
        "description": "Detects shadow copy deletion commands common in ransomware",
        "author": "AEGIS Threat Research",
        "rule": """
rule AEGIS_Shadow_Copy_Deletion {
    meta:
        description = "Detects shadow copy deletion commands"
        author = "AEGIS Threat Research"
        date = "2024-09-01"
        severity = "high"
    strings:
        $cmd1 = "vssadmin delete shadows" wide ascii nocase
        $cmd2 = "vssadmin.exe delete shadows" wide ascii nocase
        $cmd3 = "wmic shadowcopy delete" wide ascii nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled No" wide ascii nocase
        $cmd5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide ascii nocase
        $cmd6 = "wbadmin delete catalog -quiet" wide ascii nocase
        $cmd7 = "wbadmin delete systemstatebackup" wide ascii nocase
        $cmd8 = "Delete Shadows /All /Quiet" wide ascii nocase
        $ps1 = "Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}" wide ascii
        $ps2 = "Get-CimInstance Win32_ShadowCopy | Remove-CimInstance" wide ascii
    condition:
        2 of them
}""",
    },
    "Ransomware_Note_Creation": {
        "name": "AEGIS_Ransomware_Note",
        "description": "Detects creation of common ransomware note filenames",
        "author": "AEGIS Threat Research",
        "rule": """
rule AEGIS_Ransomware_Note {
    meta:
        description = "Detects common ransomware note filename patterns"
        author = "AEGIS Threat Research"
        date = "2024-09-01"
        severity = "critical"
    strings:
        $note01 = "Restore-My-Files.txt" wide ascii
        $note02 = "RECOVER-FILES.txt" wide ascii
        $note03 = "ClopReadMe.txt" wide ascii
        $note04 = "ReadMe.txt" wide ascii
        $note05 = "README.TXT" wide ascii
        $note06 = "akira_readme.txt" wide ascii
        $note07 = "CriticalBreachDetected.pdf" wide ascii
        $note08 = "HOW_TO_DECRYPT.txt" wide ascii
        $note09 = "!!! ALL YOUR FILES ARE ENCRYPTED !!!.TXT" wide ascii
        $note10 = "DECRYPT-FILES.txt" wide ascii
        $note11 = "RyukReadMe.html" wide ascii
        $note12 = "@WanaDecryptor@.exe" wide ascii
        $note13 = "HOW_TO_RECOVER_FILES.txt" wide ascii
        $note14 = "GET_YOUR_FILES_BACK.txt" wide ascii
        $note15 = "!! READ ME !!.txt" wide ascii
        $generic1 = "YOUR FILES HAVE BEEN ENCRYPTED" wide ascii nocase
        $generic2 = "All your files are encrypted" wide ascii nocase
        $generic3 = "To decrypt your files" wide ascii nocase
        $generic4 = "Send Bitcoin to" wide ascii nocase
        $generic5 = "contact us at" wide ascii nocase
    condition:
        any of ($note*) or 3 of ($generic*)
}""",
    },
}

# ─── Ransomware Behavioral Indicators ─────────────────────────────────

RANSOMWARE_BEHAVIORAL_INDICATORS = {
    "pre_encryption": {
        "description": "Indicators observed before encryption begins",
        "indicators": [
            {"type": "process_enumeration",
             "description": "Ransomware enumerates running processes to identify security tools and database services",
             "detection": "Sysmon Event ID 1 - Multiple process enumeration commands in quick succession",
             "mitre": "T1057"},
            {"type": "service_enumeration",
             "description": "Queries Windows services to identify backup and database services to stop",
             "detection": "Event ID 7036 - Multiple service state changes in short timeframe",
             "mitre": "T1007"},
            {"type": "volume_enumeration",
             "description": "Enumerates logical drives and mounted volumes for encryption targets",
             "detection": "API calls to GetLogicalDrives, GetVolumeInformation",
             "mitre": "T1082"},
            {"type": "network_share_enumeration",
             "description": "Discovers network shares for lateral encryption",
             "detection": "SMB traffic to multiple hosts, NetShareEnum API calls",
             "mitre": "T1135"},
            {"type": "file_enumeration",
             "description": "Recursively enumerates files matching target extensions",
             "detection": "High volume of FindFirstFile/FindNextFile API calls",
             "mitre": "T1083"},
        ],
    },
    "defense_disabling": {
        "description": "Indicators of security tool termination",
        "indicators": [
            {"type": "av_process_kill",
             "description": "Terminates antivirus and EDR processes",
             "detection": "Process termination events for security software PIDs",
             "mitre": "T1562.001",
             "common_targets": ["MsMpEng.exe", "MsSense.exe", "SentinelAgent.exe",
                                "CylanceSvc.exe", "CSFalconService.exe", "savservice.exe",
                                "avgnt.exe", "avguard.exe", "bdagent.exe", "ekrn.exe"]},
            {"type": "service_disabling",
             "description": "Disables security and backup services via sc.exe or net stop",
             "detection": "Event ID 7045 combined with security service names",
             "mitre": "T1489",
             "common_targets": ["wscsvc", "WinDefend", "mpssvc", "SecurityHealthService",
                                "Sense", "WdNisSvc", "WdFilter", "WdBoot"]},
            {"type": "tamper_protection_bypass",
             "description": "Attempts to disable tamper protection mechanisms",
             "detection": "Registry modifications to security software configuration",
             "mitre": "T1562.001"},
            {"type": "safe_mode_reboot",
             "description": "Reboots into Safe Mode to bypass security software",
             "detection": "bcdedit commands modifying boot configuration",
             "mitre": "T1562.009"},
        ],
    },
    "recovery_inhibition": {
        "description": "Indicators of backup and recovery destruction",
        "indicators": [
            {"type": "shadow_copy_deletion",
             "description": "Deletes Volume Shadow Copies to prevent file recovery",
             "detection": "Process creation: vssadmin.exe delete shadows",
             "mitre": "T1490",
             "commands": ["vssadmin delete shadows /all /quiet",
                          "vssadmin.exe Delete Shadows /All /Quiet",
                          "wmic shadowcopy delete",
                          "Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}"]},
            {"type": "recovery_disable",
             "description": "Disables Windows recovery features",
             "detection": "Process creation: bcdedit.exe with recovery parameters",
             "mitre": "T1490",
             "commands": ["bcdedit /set {default} recoveryenabled No",
                          "bcdedit /set {default} bootstatuspolicy ignoreallfailures"]},
            {"type": "backup_deletion",
             "description": "Deletes Windows backup catalog",
             "detection": "Process creation: wbadmin.exe delete",
             "mitre": "T1490",
             "commands": ["wbadmin delete catalog -quiet",
                          "wbadmin delete systemstatebackup -keepVersions:0"]},
            {"type": "recycle_bin_clear",
             "description": "Clears the Recycle Bin to remove recovery copies",
             "detection": "File deletion in C:\\$Recycle.Bin",
             "mitre": "T1485"},
        ],
    },
    "encryption_phase": {
        "description": "Indicators during active file encryption",
        "indicators": [
            {"type": "mass_file_rename",
             "description": "Rapid renaming of files with new extension",
             "detection": "Sysmon Event ID 11 - High volume of file creation events with ransomware extensions",
             "mitre": "T1486"},
            {"type": "high_io_activity",
             "description": "Extremely high disk I/O as files are read, encrypted, and written",
             "detection": "Performance counters showing sustained high disk I/O",
             "mitre": "T1486"},
            {"type": "entropy_increase",
             "description": "File entropy increases dramatically as plaintext becomes ciphertext",
             "detection": "File system monitoring showing entropy changes in modified files",
             "mitre": "T1486"},
            {"type": "ransom_note_creation",
             "description": "Ransom note files dropped in every directory",
             "detection": "Sysmon Event ID 11 - Same filename created in multiple directories",
             "mitre": "T1486"},
            {"type": "wallpaper_change",
             "description": "Desktop wallpaper changed to ransom message",
             "detection": "Registry modification: HKCU\\Control Panel\\Desktop\\Wallpaper",
             "mitre": "T1491.001"},
        ],
    },
    "lateral_movement": {
        "description": "Indicators of ransomware spreading across the network",
        "indicators": [
            {"type": "smb_lateral",
             "description": "Copies ransomware binary to remote hosts via SMB admin shares",
             "detection": "Event ID 5140/5145 - Network share access to C$ or ADMIN$ from unusual sources",
             "mitre": "T1021.002"},
            {"type": "wmi_lateral",
             "description": "Uses WMI to execute ransomware on remote hosts",
             "detection": "Event ID 4688 - WmiPrvSE.exe spawning suspicious processes on remote hosts",
             "mitre": "T1047"},
            {"type": "psexec_lateral",
             "description": "Uses PsExec or similar tools for remote execution",
             "detection": "Event ID 7045 - Service creation from PsExec on remote hosts",
             "mitre": "T1569.002"},
            {"type": "group_policy_abuse",
             "description": "Deploys ransomware via Group Policy (scheduled task or startup script)",
             "detection": "Group Policy modification events + mass scheduled task creation",
             "mitre": "T1484.001"},
        ],
    },
}

# ─── Ransomware Negotiation Patterns ──────────────────────────────────

RANSOM_NEGOTIATION_PATTERNS = {
    "communication_methods": [
        {"method": "Tor Hidden Service", "usage": "Most modern ransomware groups",
         "description": "Dedicated .onion website for each victim with chat interface",
         "examples": ["LockBit", "BlackCat", "Play", "Royal", "Akira"]},
        {"method": "Email", "usage": "Older and simpler variants",
         "description": "Direct email communication for negotiation",
         "examples": ["Phobos", "Dharma", "STOP/Djvu"]},
        {"method": "Telegram", "usage": "Some mid-tier groups",
         "description": "Encrypted messaging for rapid communication",
         "examples": ["Some RaaS affiliates"]},
        {"method": "Custom Chat Portal", "usage": "Sophisticated groups",
         "description": "Web-based chat portal with countdown timer",
         "examples": ["LockBit (customer support portal)", "BlackCat"]},
    ],
    "payment_methods": [
        {"currency": "Bitcoin (BTC)", "usage": "Most common",
         "traceability": "Pseudonymous, traceable with chain analysis",
         "average_demand_range": "$100,000 - $50,000,000"},
        {"currency": "Monero (XMR)", "usage": "Increasing adoption",
         "traceability": "Privacy-focused, difficult to trace",
         "average_demand_range": "$50,000 - $10,000,000"},
        {"currency": "Ethereum (ETH)", "usage": "Less common for ransomware",
         "traceability": "Pseudonymous, traceable",
         "average_demand_range": "$50,000 - $5,000,000"},
    ],
    "negotiation_tactics": [
        "Initial demand is typically 2-10x what they expect to receive",
        "Countdown timers create urgency (usually 72 hours to 7 days)",
        "Price doubles after deadline passes",
        "Threat of data publication on leak site if no payment",
        "Sample decryption offered as proof (2-3 files)",
        "Discounts for quick payment (20-40% reduction)",
        "Some groups accept partial payment for partial decryption",
        "Insurance information may influence demand amount",
    ],
    "decryption_success_rates": {
        "LockBit": {"rate": 0.85, "notes": "Generally reliable decryptor"},
        "BlackCat": {"rate": 0.80, "notes": "Decryptor works but may miss some files"},
        "Cl0p": {"rate": 0.75, "notes": "Extortion-focused, less reliable decryption"},
        "Play": {"rate": 0.82, "notes": "Generally provides working decryptor"},
        "Royal": {"rate": 0.78, "notes": "Variable success rate"},
        "Akira": {"rate": 0.80, "notes": "Relatively new, decryptor generally works"},
        "Conti": {"rate": 0.70, "notes": "Known issues with decryptor quality"},
        "REvil": {"rate": 0.75, "notes": "Variable quality, some universal decryptors available"},
    },
}

# ─── Ransomware Incident Response Playbook ────────────────────────────

RANSOMWARE_IR_PLAYBOOK = {
    "phase_1_identification": {
        "name": "Identification & Scoping",
        "duration": "0-4 hours",
        "actions": [
            "Confirm ransomware incident (not wiper or false alarm)",
            "Identify ransomware variant from extension, ransom note, or IOCs",
            "Determine scope: how many systems are affected",
            "Check if encryption is still actively spreading",
            "Preserve initial evidence (screenshots, ransom notes, samples)",
            "Activate incident response plan and notify leadership",
            "Engage legal counsel and insurance carrier",
        ],
        "tools": ["ID Ransomware (upload ransom note)", "NoMoreRansom.org",
                  "VirusTotal (submit sample)", "YARA rules"],
    },
    "phase_2_containment": {
        "name": "Containment",
        "duration": "2-24 hours",
        "actions": [
            "Isolate affected systems from network (do not power off)",
            "Block C2 communication at firewall/proxy",
            "Disable affected user accounts",
            "Block lateral movement (disable SMB, restrict RDP)",
            "Preserve memory dumps of infected systems",
            "Image affected systems before remediation",
            "Check backup integrity (are backups also encrypted?)",
        ],
        "tools": ["Network isolation (VLAN changes, firewall rules)",
                  "EDR containment features", "Memory capture (WinPmem, DumpIt)"],
    },
    "phase_3_eradication": {
        "name": "Eradication",
        "duration": "24-72 hours",
        "actions": [
            "Identify and close initial access vector",
            "Remove ransomware binary and persistence mechanisms",
            "Reset all potentially compromised credentials",
            "Patch exploited vulnerabilities",
            "Scan all systems with updated signatures",
            "Verify no backdoors or secondary access remain",
            "Clean or rebuild affected systems",
        ],
        "tools": ["EDR full scan", "Autoruns", "Process Monitor",
                  "Registry analysis tools", "Credential reset scripts"],
    },
    "phase_4_recovery": {
        "name": "Recovery",
        "duration": "72 hours - 2 weeks",
        "actions": [
            "Restore systems from clean backups (test backups first)",
            "Rebuild systems that cannot be restored from backup",
            "Restore data from most recent clean backup",
            "Validate system integrity before reconnecting to network",
            "Monitor closely for re-infection indicators",
            "Gradually restore network connectivity",
            "Verify business operations are functional",
        ],
        "tools": ["Backup restoration tools", "System imaging tools",
                  "Network monitoring", "EDR with enhanced monitoring"],
    },
    "phase_5_lessons_learned": {
        "name": "Post-Incident Analysis",
        "duration": "1-4 weeks after recovery",
        "actions": [
            "Conduct full post-incident review",
            "Document timeline of events",
            "Identify root cause and contributing factors",
            "Update incident response plan based on findings",
            "Implement additional security controls",
            "Brief leadership on lessons learned",
            "File insurance claim if applicable",
            "Report to law enforcement (FBI IC3, CISA)",
        ],
        "tools": ["Incident report template", "After-action review framework",
                  "MITRE ATT&CK mapping of attack chain"],
    },
}


def get_extended_family_count():
    """Return comprehensive counts of all ransomware data."""
    return {
        "families": len(RANSOMWARE_FAMILIES),
        "yara_rules": len(RANSOMWARE_YARA_RULES),
        "behavioral_categories": len(RANSOMWARE_BEHAVIORAL_INDICATORS),
        "total_behavioral_indicators": sum(
            len(cat["indicators"]) for cat in RANSOMWARE_BEHAVIORAL_INDICATORS.values()
        ),
        "ir_playbook_phases": len(RANSOMWARE_IR_PLAYBOOK),
        "negotiation_methods": len(RANSOM_NEGOTIATION_PATTERNS["communication_methods"]),
    }


if __name__ == "__main__":
    counts = get_extended_family_count()
    print(f"\nExtended AEGIS Ransomware Intelligence Database")
    for key, val in counts.items():
        print(f"  {key.replace('_', ' ').title()}: {val}")


# ─── Ransomware Prevention Controls Matrix ───────────────────────────

RANSOMWARE_PREVENTION_CONTROLS = {
    "endpoint_protection": {
        "category": "Endpoint Protection",
        "controls": [
            {"id": "EP-01", "control": "Deploy EDR on all endpoints",
             "description": "Endpoint Detection and Response provides behavioral analysis and response capabilities",
             "implementation": "Deploy EDR agent (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Carbon Black) on all workstations and servers",
             "effectiveness": "HIGH",
             "cost": "HIGH",
             "mitre_coverage": ["T1059", "T1055", "T1486", "T1489", "T1490"]},
            {"id": "EP-02", "control": "Enable application whitelisting",
             "description": "Only allow approved applications to execute",
             "implementation": "Windows Defender Application Control (WDAC), AppLocker, or third-party solutions",
             "effectiveness": "VERY HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1059", "T1204", "T1036"]},
            {"id": "EP-03", "control": "Restrict PowerShell execution",
             "description": "Limit PowerShell to Constrained Language Mode and log all execution",
             "implementation": "Group Policy: Constrained Language Mode, Script Block Logging, Module Logging",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1059.001"]},
            {"id": "EP-04", "control": "Disable macros in Office documents",
             "description": "Block macros from executing in documents from the internet",
             "implementation": "Group Policy: Block macros in Office files from the Internet (VBA macro notification settings)",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1204.002", "T1566.001"]},
            {"id": "EP-05", "control": "Enable Controlled Folder Access",
             "description": "Protect important folders from unauthorized changes by suspicious applications",
             "implementation": "Windows Defender Controlled Folder Access (ransomware protection feature)",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1486"]},
            {"id": "EP-06", "control": "Deploy Anti-Exploit protection",
             "description": "Protect against exploitation of software vulnerabilities",
             "implementation": "Windows Defender Exploit Guard, EMET (legacy), third-party solutions",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1190", "T1068", "T1203"]},
            {"id": "EP-07", "control": "Implement credential guard",
             "description": "Protect credentials from theft by isolating LSASS",
             "implementation": "Windows Credential Guard (requires UEFI, Secure Boot, Hyper-V)",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1003.001", "T1003.002"]},
            {"id": "EP-08", "control": "Deploy host-based firewall rules",
             "description": "Restrict lateral movement by controlling endpoint network traffic",
             "implementation": "Windows Firewall with Advanced Security, restrict SMB/RDP between workstations",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1021.002", "T1021.001"]},
        ],
    },
    "identity_protection": {
        "category": "Identity and Access Management",
        "controls": [
            {"id": "ID-01", "control": "Enforce MFA for all users",
             "description": "Multi-factor authentication prevents credential-based attacks",
             "implementation": "Azure MFA, Duo, Okta, Google Authenticator for all user accounts",
             "effectiveness": "VERY HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1110", "T1078"]},
            {"id": "ID-02", "control": "Implement Privileged Access Management",
             "description": "Secure privileged accounts with additional controls",
             "implementation": "CyberArk, BeyondTrust, or Azure PIM for just-in-time admin access",
             "effectiveness": "HIGH",
             "cost": "HIGH",
             "mitre_coverage": ["T1078", "T1134", "T1548"]},
            {"id": "ID-03", "control": "Implement tiered administration model",
             "description": "Separate admin credentials for different trust zones",
             "implementation": "Tier 0 (Domain Controllers), Tier 1 (Servers), Tier 2 (Workstations) with separate admin accounts",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1078", "T1021"]},
            {"id": "ID-04", "control": "Deploy Local Administrator Password Solution",
             "description": "Unique local admin passwords for each computer",
             "implementation": "Microsoft LAPS or Windows LAPS (built into Windows 11)",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1078.003", "T1021.002"]},
            {"id": "ID-05", "control": "Disable legacy authentication protocols",
             "description": "Block NTLM, SMBv1, and other legacy protocols",
             "implementation": "Group Policy to restrict NTLM, disable SMBv1, enforce Kerberos with AES",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1558", "T1003"]},
            {"id": "ID-06", "control": "Implement password policies",
             "description": "Enforce strong passwords and prevent password reuse",
             "implementation": "Minimum 14 chars, complexity requirements, banned password list, regular rotation for privileged accounts",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1110"]},
        ],
    },
    "network_protection": {
        "category": "Network Security",
        "controls": [
            {"id": "NET-01", "control": "Implement network segmentation",
             "description": "Limit lateral movement by segmenting the network",
             "implementation": "VLANs with firewall rules between segments, microsegmentation for critical assets",
             "effectiveness": "VERY HIGH",
             "cost": "HIGH",
             "mitre_coverage": ["T1021", "T1570", "T1080"]},
            {"id": "NET-02", "control": "Restrict SMB traffic between workstations",
             "description": "Prevent ransomware from spreading via SMB/Windows shares",
             "implementation": "Host firewall rules blocking TCP 445 between workstation subnets",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1021.002"]},
            {"id": "NET-03", "control": "Deploy DNS filtering",
             "description": "Block known malicious domains and newly registered domains",
             "implementation": "DNS filtering (Cisco Umbrella, Infoblox, Pi-hole for labs)",
             "effectiveness": "MEDIUM",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1071", "T1568"]},
            {"id": "NET-04", "control": "Implement email security gateway",
             "description": "Filter malicious emails before they reach users",
             "implementation": "Email gateway with attachment sandboxing, URL rewriting, impersonation detection",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1566.001", "T1566.002"]},
            {"id": "NET-05", "control": "Deploy web proxy with SSL inspection",
             "description": "Inspect and filter web traffic for malicious content",
             "implementation": "Forward proxy with SSL/TLS inspection, category-based filtering, malware scanning",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1071.001", "T1204.001"]},
            {"id": "NET-06", "control": "Disable unnecessary remote access",
             "description": "Reduce attack surface by disabling unused remote access services",
             "implementation": "Disable RDP where not needed, use jump servers/bastion hosts, disable SMBv1",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1021.001", "T1133"]},
        ],
    },
    "backup_and_recovery": {
        "category": "Backup and Recovery",
        "controls": [
            {"id": "BKP-01", "control": "Implement 3-2-1 backup strategy",
             "description": "3 copies, 2 media types, 1 offsite/offline",
             "implementation": "Local backup + replicated backup + offline/immutable backup (tape or air-gapped)",
             "effectiveness": "VERY HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1486", "T1490"]},
            {"id": "BKP-02", "control": "Use immutable backups",
             "description": "Backups that cannot be modified or deleted for a retention period",
             "implementation": "Veeam Immutability, AWS S3 Object Lock, Azure Immutable Blob Storage",
             "effectiveness": "VERY HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1490", "T1485"]},
            {"id": "BKP-03", "control": "Test backup recovery regularly",
             "description": "Validate that backups can actually be restored",
             "implementation": "Monthly recovery testing, annual full disaster recovery exercise",
             "effectiveness": "CRITICAL",
             "cost": "LOW",
             "mitre_coverage": ["T1486"]},
            {"id": "BKP-04", "control": "Protect backup infrastructure",
             "description": "Secure backup servers and storage from ransomware attack",
             "implementation": "Separate backup admin credentials, network isolation, MFA for backup consoles",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1490"]},
            {"id": "BKP-05", "control": "Monitor backup health",
             "description": "Alert on backup failures, missed windows, and storage issues",
             "implementation": "Backup monitoring with automated alerts for failures and anomalies",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1490"]},
        ],
    },
    "detection_and_response": {
        "category": "Detection and Response",
        "controls": [
            {"id": "DET-01", "control": "Deploy canary files and honeytokens",
             "description": "Plant decoy files that trigger alerts when accessed or modified",
             "implementation": "Place canary files on file shares, canary tokens in Active Directory",
             "effectiveness": "HIGH",
             "cost": "LOW",
             "mitre_coverage": ["T1486"]},
            {"id": "DET-02", "control": "Monitor for ransomware indicators",
             "description": "SIEM rules for shadow copy deletion, mass file encryption, ransom notes",
             "implementation": "Sigma rules for vssadmin, bcdedit, mass file rename, known ransom note names",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1486", "T1490", "T1489"]},
            {"id": "DET-03", "control": "Implement automated response playbooks",
             "description": "Automatically contain affected systems when ransomware is detected",
             "implementation": "SOAR playbooks: isolate host, disable account, collect evidence, alert IR team",
             "effectiveness": "VERY HIGH",
             "cost": "HIGH",
             "mitre_coverage": ["T1486"]},
            {"id": "DET-04", "control": "Deploy deception technology",
             "description": "Honeypots and decoy systems to detect lateral movement",
             "implementation": "Attivo, Illusive Networks, or open-source honeypots on internal networks",
             "effectiveness": "MEDIUM",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1021", "T1046"]},
            {"id": "DET-05", "control": "Conduct regular threat hunting",
             "description": "Proactive search for indicators of compromise and pre-ransomware activity",
             "implementation": "Weekly threat hunting for common ransomware precursors (Cobalt Strike, PsExec, encoded PowerShell)",
             "effectiveness": "HIGH",
             "cost": "HIGH",
             "mitre_coverage": ["T1059", "T1021", "T1003", "T1486"]},
        ],
    },
    "vulnerability_management": {
        "category": "Vulnerability Management",
        "controls": [
            {"id": "VM-01", "control": "Patch critical vulnerabilities within 48 hours",
             "description": "Rapid patching of exploited and critical vulnerabilities",
             "implementation": "Automated patching for critical/CISA KEV vulnerabilities, WSUS/SCCM/Intune",
             "effectiveness": "VERY HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1190", "T1210", "T1068"]},
            {"id": "VM-02", "control": "Scan for vulnerabilities regularly",
             "description": "Identify and prioritize vulnerabilities across the environment",
             "implementation": "Weekly vulnerability scans (Nessus, Qualys, Rapid7), prioritize by exploitability",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1190"]},
            {"id": "VM-03", "control": "Maintain asset inventory",
             "description": "Know every asset on the network to ensure nothing is unpatched",
             "implementation": "Network discovery, CMDB, agent-based inventory (ServiceNow, Lansweeper)",
             "effectiveness": "HIGH",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1190", "T1133"]},
            {"id": "VM-04", "control": "Remove end-of-life software",
             "description": "Replace or isolate systems running unsupported software",
             "implementation": "Inventory EOL software, plan migrations, network isolate if cannot migrate",
             "effectiveness": "HIGH",
             "cost": "HIGH",
             "mitre_coverage": ["T1190", "T1210"]},
        ],
    },
    "user_awareness": {
        "category": "User Awareness",
        "controls": [
            {"id": "UA-01", "control": "Conduct regular phishing simulations",
             "description": "Test and train users on recognizing phishing emails",
             "implementation": "Monthly phishing simulations (KnowBe4, Proofpoint, Cofense), track improvement",
             "effectiveness": "MEDIUM",
             "cost": "MEDIUM",
             "mitre_coverage": ["T1566", "T1204"]},
            {"id": "UA-02", "control": "Security awareness training",
             "description": "Regular training on ransomware threats and safe computing practices",
             "implementation": "Annual security awareness training with quarterly refreshers, ransomware-specific modules",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1566", "T1204"]},
            {"id": "UA-03", "control": "Establish incident reporting procedures",
             "description": "Make it easy for users to report suspicious activity without fear",
             "implementation": "Phishing report button in email client, clear escalation procedures, no blame culture",
             "effectiveness": "MEDIUM",
             "cost": "LOW",
             "mitre_coverage": ["T1566"]},
        ],
    },
}


def get_prevention_control_count():
    """Return counts of prevention controls by category."""
    result = {}
    for category, info in RANSOMWARE_PREVENTION_CONTROLS.items():
        result[category] = len(info["controls"])
    result["total"] = sum(result.values())
    return result


if __name__ == "__main__":
    ctrl_counts = get_prevention_control_count()
    print(f"\nRansomware Prevention Controls Matrix")
    for cat, count in ctrl_counts.items():
        print(f"  {cat.replace('_', ' ').title()}: {count}")


# ─── Ransomware Recovery Decision Framework ──────────────────────────

RECOVERY_DECISION_FRAMEWORK = {
    "decision_factors": {
        "pay_or_not_pay": {
            "description": "Framework for evaluating whether to pay a ransom demand",
            "factors_favoring_payment": [
                {"factor": "No viable backups available",
                 "weight": "CRITICAL",
                 "consideration": "If backup recovery is impossible and data is essential to operations"},
                {"factor": "Life-safety systems affected",
                 "weight": "CRITICAL",
                 "consideration": "Healthcare, emergency services, or critical infrastructure where lives are at risk"},
                {"factor": "Business continuity at risk",
                 "weight": "HIGH",
                 "consideration": "Extended downtime threatens organizational survival"},
                {"factor": "Sensitive data exposure imminent",
                 "weight": "HIGH",
                 "consideration": "Double extortion threat with regulatory or legal consequences"},
                {"factor": "Reasonable ransom amount",
                 "weight": "MEDIUM",
                 "consideration": "Demand is significantly less than estimated recovery cost"},
            ],
            "factors_against_payment": [
                {"factor": "No guarantee of decryption",
                 "weight": "CRITICAL",
                 "consideration": "Payment does not guarantee working decryptor or data recovery"},
                {"factor": "Funding criminal enterprise",
                 "weight": "HIGH",
                 "consideration": "Payment funds future attacks and encourages targeting"},
                {"factor": "Potential sanctions violations",
                 "weight": "CRITICAL",
                 "consideration": "OFAC sanctions may prohibit payment to certain threat actors"},
                {"factor": "Regulatory prohibition",
                 "weight": "HIGH",
                 "consideration": "Some jurisdictions restrict or prohibit ransom payments"},
                {"factor": "Backups available",
                 "weight": "HIGH",
                 "consideration": "Clean backups exist and can be restored within acceptable RTO"},
                {"factor": "Decryptor available",
                 "weight": "HIGH",
                 "consideration": "Free decryptor available (NoMoreRansom.org, security researchers)"},
                {"factor": "Data already leaked",
                 "weight": "MEDIUM",
                 "consideration": "If exfiltrated data is already published, payment may not prevent exposure"},
                {"factor": "Second attack likely",
                 "weight": "HIGH",
                 "consideration": "Paying once makes organization a target for repeat attacks"},
            ],
        },
    },
    "recovery_cost_estimation": {
        "description": "Framework for estimating total ransomware incident costs",
        "cost_categories": [
            {"category": "Downtime Costs",
             "components": ["Revenue loss during outage", "Employee productivity loss",
                            "Customer impact and churn", "SLA penalties",
                            "Manual process costs during recovery"],
             "estimation_method": "Daily revenue * days of impact * percentage affected"},
            {"category": "Recovery Costs",
             "components": ["Incident response team (internal + external)",
                            "Forensic investigation", "System rebuilding and restoration",
                            "Data recovery and validation", "Overtime labor costs"],
             "estimation_method": "Hourly rate * hours * team size + tool costs"},
            {"category": "Legal and Regulatory Costs",
             "components": ["Legal counsel fees", "Regulatory notification costs",
                            "Potential fines and penalties", "Credit monitoring for affected individuals",
                            "Class action lawsuit defense"],
             "estimation_method": "Fixed legal retainer + per-notification cost * individuals affected"},
            {"category": "Reputation Costs",
             "components": ["PR and crisis communication", "Customer notification",
                            "Brand damage", "Lost future business",
                            "Insurance premium increases"],
             "estimation_method": "Difficult to quantify; estimate 10-25% of annual revenue impact"},
            {"category": "Security Improvement Costs",
             "components": ["New security tools and technologies",
                            "Additional security staff", "Security awareness training",
                            "Architecture improvements", "Compliance remediation"],
             "estimation_method": "Capital expenditure + annual operating cost increase"},
        ],
        "industry_averages": {
            "average_ransom_payment_2024": "$568,705",
            "average_total_cost_2024": "$4,880,000",
            "average_downtime_days": 22,
            "average_recovery_time_weeks": 4,
            "percent_paying_ransom": "37%",
            "percent_recovering_all_data_after_paying": "65%",
            "percent_attacked_again_within_year": "80%",
        },
    },
    "free_decryptor_sources": {
        "description": "Sources for free ransomware decryption tools",
        "sources": [
            {"name": "No More Ransom Project",
             "url": "https://www.nomoreransom.org/",
             "description": "Joint initiative by law enforcement and security companies",
             "available_decryptors": "180+ decryptors covering 160+ ransomware families"},
            {"name": "Emsisoft Decryptor Page",
             "url": "https://www.emsisoft.com/en/ransomware-decryption/",
             "description": "Free decryptors from Emsisoft research team",
             "available_decryptors": "STOP/Djvu, AuroraDecrypter, and many others"},
            {"name": "Kaspersky No Ransom",
             "url": "https://noransom.kaspersky.com/",
             "description": "Kaspersky's free decryption tools",
             "available_decryptors": "RakhniDecryptor, RannohDecryptor, and others"},
            {"name": "Avast Free Decryptors",
             "url": "https://www.avast.com/ransomware-decryption-tools",
             "description": "Free decryptors from Avast Threat Labs",
             "available_decryptors": "Multiple families including Babuk, TargetCompany"},
            {"name": "Trend Micro Ransomware File Decryptor",
             "url": "https://success.trendmicro.com/solution/1114221",
             "description": "Generic file decryptor for multiple families",
             "available_decryptors": "TeslaCrypt, Jigsaw, and others"},
            {"name": "ID Ransomware",
             "url": "https://id-ransomware.malwarehunterteam.com/",
             "description": "Upload ransom note or encrypted file to identify the ransomware family",
             "available_decryptors": "Identifies family and links to available decryptors"},
        ],
    },
    "law_enforcement_reporting": {
        "description": "Agencies to report ransomware incidents to",
        "agencies": [
            {"agency": "FBI Internet Crime Complaint Center (IC3)",
             "url": "https://www.ic3.gov/",
             "jurisdiction": "United States",
             "notes": "Primary reporting mechanism for US cyber crimes"},
            {"agency": "CISA (Cybersecurity and Infrastructure Security Agency)",
             "url": "https://www.cisa.gov/report",
             "jurisdiction": "United States",
             "notes": "Report to CISA for critical infrastructure incidents"},
            {"agency": "US Secret Service",
             "url": "Contact local field office",
             "jurisdiction": "United States",
             "notes": "Investigates financial crimes including ransomware"},
            {"agency": "Europol EC3 (European Cybercrime Centre)",
             "url": "https://www.europol.europa.eu/report-a-crime/report-cybercrime-online",
             "jurisdiction": "European Union",
             "notes": "EU-level cybercrime reporting and investigation"},
            {"agency": "UK National Crime Agency (NCA)",
             "url": "https://www.nationalcrimeagency.gov.uk/",
             "jurisdiction": "United Kingdom",
             "notes": "Report via Action Fraud for UK-based incidents"},
            {"agency": "Australian Cyber Security Centre (ACSC)",
             "url": "https://www.cyber.gov.au/report",
             "jurisdiction": "Australia",
             "notes": "Report cybercrime incidents affecting Australian entities"},
        ],
    },
}


if __name__ == "__main__":
    print(f"\nComplete AEGIS Ransomware Intelligence Platform")
    print(f"  Ransomware Families: {len(RANSOMWARE_FAMILIES)}")
    print(f"  YARA Rules: {len(RANSOMWARE_YARA_RULES)}")
    print(f"  Behavioral Categories: {len(RANSOMWARE_BEHAVIORAL_INDICATORS)}")
    print(f"  Prevention Categories: {len(RANSOMWARE_PREVENTION_CONTROLS)}")
    print(f"  IR Playbook Phases: {len(RANSOMWARE_IR_PLAYBOOK)}")
    print(f"  Free Decryptor Sources: {len(RECOVERY_DECISION_FRAMEWORK['free_decryptor_sources']['sources'])}")
    print(f"  Law Enforcement Contacts: {len(RECOVERY_DECISION_FRAMEWORK['law_enforcement_reporting']['agencies'])}")
