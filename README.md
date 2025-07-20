## 🛠️ WIFROX – Ferramenta de Pentest Wi-Fi 100% em Python

`WIFROX` é uma ferramenta desenvolvida do zero em **Python puro**, voltada para **fins educacionais, pesquisa em segurança da informação e pentest autorizado**.
Ela oferece funcionalidades essenciais de análise de redes Wi-Fi, como varredura ARP, detecção de dispositivos, ataques de desautenticação Wi-Fi, flood ICMP e ataque de força bruta WPA/WPA2 (via integração com ferramentas externas como `aircrack-ng`).

---

### ⚙️ Funcionalidades

* 📡 **Escaneamento de rede local** via ARP
* 🔎 **Detecção de sistema operacional remoto**
* ⚔️ **Ataque de desautenticação Wi-Fi** (deauth attack)
* 🌐 **Ping flood** com múltiplas threads (ICMP DoS)
* 🔐 **Força bruta WPA/WPA2** com wordlists

> Totalmente desenvolvido em **Python**, utilizando bibliotecas como `scapy`, `subprocess`, `netifaces`, `nmap` e `requests`.

---

### ⚠️ AVISO LEGAL

Este projeto foi desenvolvido **exclusivamente para fins educacionais, testes de laboratório e auditorias de segurança autorizadas**.
**O uso desta ferramenta em redes de terceiros, sem autorização explícita, é ilegal e viola leis como o artigo 154-A do Código Penal Brasileiro.**

O autor **não se responsabiliza** por qualquer uso indevido, dano causado, ou violação de políticas e leis locais decorrentes do uso deste software.

---

### ❌ Proibição de Venda

Este projeto é **gratuito e de código aberto**, e **é expressamente proibida sua venda** sob qualquer forma ou meio.
Você pode estudar, modificar e utilizar o código conforme as licenças aplicáveis, desde que **não o comercialize direta ou indiretamente**.

---

### 📚 Para que serve?

* Para estudantes de segurança aprenderem sobre redes.
* Para analistas realizarem testes **autorizados** de segurança.
* Para criação de ambientes controlados de estudo com Wi-Fi.

---

### 🧪 Requisitos

* Python 3.6+
* Linux (preferencialmente Kali Linux ou Parrot)
* Bibliotecas Python: `scapy`, `nmap`, `netifaces`, `requests`
* Ferramentas externas: `aircrack-ng`, `aireplay-ng`
