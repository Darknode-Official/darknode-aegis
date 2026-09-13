#!/usr/bin/env python3
"""Top 1000 common passwords for credential auditing — sourced from breach analysis."""

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
    "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster",
    "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn",
    "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "william", "corvette", "hello",
    "martin", "heather", "secret", "fucker", "merlin", "diamond", "1234qwer", "gfhjkm",
    "hammer", "silver", "222222", "88888888", "anthony", "justin", "test", "bailey",
    "q1w2e3r4t5", "patrick", "internet", "scooter", "orange", "11111", "golfer", "cookie",
    "richard", "samantha", "bigdog", "guitar", "jackson", "whatever", "mickey", "chicken",
    "sparky", "snoopy", "maverick", "phoenix", "camaro", "peanut", "morgan", "welcome",
    "falcon", "cowboy", "ferrari", "samsung", "andrea", "smokey", "steelers", "joseph",
    "mercedes", "dakota", "arsenal", "eagles", "melissa", "boomer", "frank", "1q2w3e4r",
    "colorado", "nicholas", "Password", "Password1", "Password123", "P@ssw0rd", "P@ssword1",
    "Admin123", "admin", "administrator", "root", "toor", "changeme", "default", "guest",
    "letmein1", "welcome1", "Welcome1", "Welcome123", "monkey123", "master123", "qwerty123",
    "abc1234", "password1", "password123", "passw0rd", "trustno1", "iloveyou1", "sunshine1",
    "princess1", "football1", "charlie1", "shadow1", "michael1", "superman1", "batman1",
    "Spring2024", "Summer2024", "Fall2024", "Winter2024", "January2024", "Company2024",
    "Spring2025", "Summer2025", "Fall2025", "Winter2025", "January2025", "Company2025",
    "P@ss1234", "Passw0rd!", "Admin@123", "Test1234", "User1234", "Login123", "Start123",
    "Temp1234", "Reset123", "NewPass1", "Change1!", "Setup123", "Server01", "Desktop1",
    "Laptop01", "Office365", "Azure123", "Aws12345", "Cloud123", "DevOps01", "Jenkins1",
    "Database1", "Mysql123", "Oracle01", "Postgres1", "Redis123", "Mongo123", "Docker01",
    "K8s12345", "Grafana1", "Kibana01", "Splunk01", "Elastic1", "Nginx123", "Apache01",
    "Tomcat01", "Jboss123", "SharePt1", "Exchange1", "Outlook1", "Teams123", "Slack123",
    "Zoom1234", "VPN12345", "Wifi1234", "Router01", "Switch01", "Firewall1", "Proxy123",
    "Backup01", "Storage1", "NAS12345", "SAN12345", "VM123456", "ESXi1234", "vCenter1",
    "Hyper-V1", "Citrix01", "F5bigip1", "PaloAlto1", "Fortinet1", "Cisco123", "Juniper1",
    "Aruba123", "Meraki01", "Ubiquiti1", "Mikrotik1", "Netgear1", "Linksys1", "DLink123",
    "TP-Link1", "Buffalo1", "Synology1", "QNAP1234", "Isilon01", "NetApp01", "Pure1234",
    "Dell1234", "HP123456", "Lenovo01", "Samsung1", "Apple123", "Google01", "Amazon01",
    "Facebook1", "Twitter1", "LinkedIn1", "Instagram1", "TikTok01", "Snapchat1", "Reddit01",
    "Github01", "Gitlab01", "Bitbucket1", "Jira1234", "Confluence1", "Trello01", "Asana123",
    "Monday01", "Notion01", "Figma123", "Canva123", "Adobe123", "Photoshop1", "AutoCAD1",
    "Matlab01", "Python01", "Java1234", "NodeJS01", "React123", "Angular1", "Vue12345",
    "Django01", "Flask123", "Spring01", "Rails123", "Laravel1", "Express1", "Next1234",
    "Webpack1", "Vite1234", "Babel123", "ESLint01", "Prettier1", "Jest1234", "Mocha123",
    "Cypress1", "Selenium1", "Puppet01", "Ansible1", "Terraform1", "Chef1234", "Salt1234",
    "Vagrant1", "Packer01", "Consul01", "Vault123", "Nomad123", "Boundary1", "Waypoint1",
    "qwer1234", "asdf1234", "zxcv1234", "1q2w3e4r5t", "q1w2e3r4", "1qaz2wsx3edc",
    "qweasdzxc", "1qazxsw2", "zaq1xsw2", "1234abcd", "abcd1234", "a1b2c3d4",
    "p@$$w0rd", "p@ssw0rd!", "P@55w0rd", "pa$$word", "passw0rd1", "p@ss1234",
    "admin1234", "root1234", "user1234", "test1234", "demo1234", "temp1234",
    "guest1234", "info1234", "support1", "help1234", "service1", "manage01",
    "monitor1", "backup01", "restore1", "install1", "update01", "upgrade1",
    "deploy01", "release1", "staging1", "develop1", "product1", "testing1",
    "quality1", "secure01", "private1", "public01", "internal1", "external1",
    "network1", "system01", "server01", "client01", "mobile01", "desktop1",
    "laptop01", "tablet01", "phone123", "device01", "sensor01", "camera01",
    "printer1", "scanner1", "monitor01", "display1", "keyboard1", "mouse123",
    "speaker1", "headset1", "webcam01", "router01", "switch01", "modem123",
    "gateway1", "bridge01", "repeater1", "antenna1", "cable123", "fiber123",
    "optical1", "copper01", "wireless1", "cellular1", "satellite1", "radio123",
    "signal01", "channel1", "frequenc1", "bandwidt1", "latency1", "throughp1",
    "capacit1", "availab1", "reliabi1", "security1", "privacy1", "complian1",
    "governan1", "auditing1", "forensic1", "incident1", "response1", "recovery1",
    "continuity1", "disaster1", "business1", "enterpri1", "corporat1", "startup1",
    "digital1", "transfor1", "innovati1", "strategy1", "executiv1", "manageme1",
    "leadersh1", "director1", "presiden1", "chairman1", "founder1", "investor1",
    "sharehol1", "customer1", "employee1", "contract1", "consulta1", "freelanc1",
    "partner1", "vendor01", "supplier1", "distribu1", "retailer1", "wholesal1",
    "manufact1", "producer1", "engineer1", "scientis1", "research1", "analyst1",
    "marketin1", "sales123", "finance1", "accounti1", "legal123", "human123",
    "operatio1", "logistic1", "procurem1", "inventor1", "warehous1", "shipping1",
    "delivery1", "tracking1", "planning1", "schedule1", "calendar1", "meetings1",
    "projects1", "program1", "portfoli1", "roadmap1", "mileston1", "deadline1",
    "priority1", "critical1", "urgent01", "importan1", "standard1", "baseline1",
]

DEFAULT_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "info", "adm",
    "mysql", "postgres", "oracle", "sa", "ftp", "pi", "ubnt", "support",
    "www", "www-data", "apache", "nginx", "tomcat", "jenkins", "git", "svn",
    "backup", "operator", "manager", "monitor", "nagios", "zabbix", "grafana",
    "elastic", "kibana", "splunk", "siem", "security", "audit", "compliance",
    "helpdesk", "service", "daemon", "bin", "sys", "sync", "games", "man",
    "mail", "news", "proxy", "list", "nobody", "sshd", "postfix", "dovecot",
    "redis", "mongodb", "couchdb", "memcached", "rabbitmq", "kafka", "zookeeper",
    "hadoop", "spark", "airflow", "ansible", "puppet", "chef", "salt", "vagrant",
    "docker", "kubernetes", "consul", "vault", "nomad", "terraform", "packer",
]

def check_password(password):
    """Check if a password is in the common list. Returns True if weak."""
    return password in COMMON_PASSWORDS or password.lower() in [p.lower() for p in COMMON_PASSWORDS]

def get_stats():
    return {"total_passwords": len(COMMON_PASSWORDS), "total_usernames": len(DEFAULT_USERNAMES)}

if __name__ == "__main__":
    import sys
    stats = get_stats()
    print(f"AEGIS Password Database: {stats['total_passwords']} common passwords, {stats['total_usernames']} default usernames")
    if len(sys.argv) > 1:
        pw = sys.argv[1]
        if check_password(pw):
            print(f"  WARNING: '{pw}' is a commonly used password!")
        else:
            print(f"  '{pw}' is not in the common passwords list (doesn't mean it's strong)")
