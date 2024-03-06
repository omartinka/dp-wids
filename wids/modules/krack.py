
"""

Krack attack: Vulnerable wireless driver's allow an attacker to
              replay parts of 4-way EAPOL handshake, reinstalling the keys
              and leaking information.

Detection:    Monitor the order of EAPOL handshakes, alert if reinstallment
              Attack is only possible with an evil-twin MITM attack on different channel,
              so additional alert is generated if such attack was recently detected
"""


