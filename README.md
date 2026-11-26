# dpdk-tunnel-router

C + DPDK で動く L2/L3 トンネルルーターです。データプレーン（コア）と、
コマンドをコアへ伝えるクライアントを分離しています。

- **core** (`core/`, C11 + DPDK): EAL / NIC / 論理インタフェース / ブリッジ /
  VLAN / FIB / ARP / NDP / トンネルカプセル化 / 外側フラグメントと再組み立て。
- **routerctl** (`rust/routerctl`, Rust): 設定データベースを持たないコマンド
  クライアント。read / configuration モードを持ち、Unix ソケットで 1 行
  コマンドを送ります。candidate はコアが保持します。
- **tunnel-driver** (`rust/tunnel-driver`, Rust): トンネルドライバーを設計する
  ための安全なライブラリ。C データプレーンから `cdylib` としてロードできます。

```
                      routerctl (Rust, stateless)
                              │  Unix socket: "set ..." / "show ..."
                              ▼
                 ┌──────────────────────────────┐
                 │ core (C + DPDK, main lcore)  │
                 │  command parser / config DB  │
                 │  atomic config + persistence │
                 └──────────────┬───────────────┘
                                │ reader gate: immutable runtime snapshot
             ┌──────────────────┼──────────────────┐
             ▼                  ▼                  ▼
        worker 0           worker 1           worker N     (RSS queues)
        RX → L2/L3 → TX    RX → ...           RX → ...
             │                  │                  │
             └──────────┬───────┴──────────────────┘
                        ▼
             DPDK ports / net_null / NIC
```

## 1. 主な機能

| 機能 | 内容 |
| --- | --- |
| EtherIP (RFC 3378) | `encapsulation etherip6`（外側 IPv6 のみ）と `encapsulation etherip`（外側 IPv4/IPv6）。IP protocol 97、EtherIP version 3 |
| トンネルドライバー | C の小さな vtable と Rust の `TunnelDriver` trait。組み込みドライバーに加え、`--plugin` で Rust 製 `.so` を追加可能 |
| オーバーレイ MTU > アンダーレイ MTU | 外側 IPv4 フラグメント / IPv6 Fragment Header を送信時に生成。受信側でワーカーごとに再組み立て。内側 9000 byte を外側 1500 byte で運べる |
| TCP MSS clamping | `tcp-mss auto / none / N`。SYN/SYN-ACK の MSS オプションを書き換え、TCP チェックサムを再計算 |
| Ethernet ARP / NDP | ARP request/reply、NDP NS/NA、近隣キャッシュ、未解決パケットのキューイング、リンクローカル自動生成 |
| IPv6 autoconf | `address ipv6 autoconf` で RA を受信し、SLAAC アドレスとデフォルトルートを動的にインストール |
| VLAN | `set interfaces ethernet eth0 vlan-id 10 ...` で `eth0.10` を作成。タグ終端、L3、ブリッジメンバーに対応 |
| ブリッジ | MAC 学習、フラッディング、エージング。VLAN 子インタフェースやトンネルをメンバーにできる |
| 静的ルート | IPv4/IPv6 の最長一致FIB。再帰的な next-hop 解決に対応 |
| 並列処理 | DPDK RSS + マルチキュー + ワーカー lcore。パケット処理はロックなし、設定は reader gate 付きの不変スナップショット差し替え |
| Ping | `ping <IPv4/IPv6>` でデータプレーン経由の ICMP echo。FIB / ARP / NDP / VLAN を使用 |
| デバッグキャプチャ | `tcpdump start/stop/status` で pcap を取得。物理 RX/TX、トンネル内側 RX/TX、簡易フィルタ、count/snaplen 対応 |
| 永続化 | 正常に適用された設定だけをコアが原子的に保存。クライアントは設定ファイルを書かない |

## 2. ビルド

必要なもの:

- Linux x86_64、C11 コンパイラ、GNU make、pkg-config
- DPDK 23.11 以降（このリポジトリは DPDK 24.11 で確認）
- Rust stable（外部 crate は不要。`cargo` が PATH にない場合は
  `CARGO_REAL=/path/to/cargo make`）

```sh
make            # C core, Rust library, routerctl
make test       # unit tests + live net_null smoke test
```

成果物:

- `build/core/dpdk-tunnel-router`
- `build/rust/release/routerctl`
- `build/rust/release/libtunnel_driver.so`（Rust トンネルドライバープラグイン）

DPDK が標準外の場所にある場合:

```sh
export PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig
make DPDK_CFLAGS="$(pkg-config --cflags libdpdk)" \
     DPDK_LIBS="$(pkg-config --libs libdpdk)"
```

## 3. まず NIC なしで動かす

DPDK の `net_null` PMD を使います。root も hugepage も不要です。

```sh
./scripts/run-netnull.sh
# 別端末
./scripts/routerctl show status
./scripts/routerctl show interfaces
```

`run/running.conf` と `run/ctl.sock` が作られます。終了は Ctrl-C です。

手動で起動する場合:

```sh
mkdir -p run
XDG_RUNTIME_DIR=$PWD/run ./build/core/dpdk-tunnel-router \
  --no-huge --no-pci --vdev=net_null0 -l 0-1 -m 512 -- \
  --workers 1 --config run/running.conf --ctl-sock run/ctl.sock
```

`--` より前が EAL、後ろがアプリのオプションです。`--workers N` には
メイン lcore に加えて N 個のワーカー lcore が必要です（例: `-l 0-3` と
`--workers 3`）。

## 4. 実 NIC で動かす

```sh
sudo modprobe vfio-pci
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:00:06.0 0000:00:07.0
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

sudo ./build/core/dpdk-tunnel-router \
  -l 0-3 -a 0000:00:06.0 -a 0000:00:07.0 -- \
  --workers 3 \
  --config config/example.conf \
  --ctl-sock /run/dpdk-tunnel-router.sock
```

DPDK のポートは起動時にすべて初期化されます。Ethernet インタフェースが
1 つもない設定（初回起動やコメントだけの設定ファイル）では、`eth0`, `eth1`, …
が DPDK port 0, 1, … に自動で割り当てられます。既に Ethernet インタフェースが
ある場合は、保存された `set interfaces ethernet <name> port <id>` に従います。
自動作成時は起動ログに `auto-port: eth0 = DPDK port 0` のように表示されます。
`eth<N>` という名前は DPDK port N に自動対応するため、次のコマンドだけでも
インタフェースを作成できます。

```sh
./scripts/routerctl set interfaces ethernet eth0 address 192.0.2.1/24
```

> DPDK は NIC をカーネルから取り上げます。Linux の `ip link` には論理
> インタフェースは現れません。`routerctl show interfaces` で確認してください。

### 4.1 DPDK ポートの初期化に失敗する場合

次のようなログは、EAL が PCI デバイスを見つけたものの、DPDK がそのデバイスを
初期化できなかったことを示します。

```text
eth_virtio_pci_init(): Failed to init PCI device
EAL: Requested device 0000:06:13.0 cannot be used
...
dpdk-tunnel-router: 0 ports
```

確認と復旧:

```sh
# 1. 古い DPDK プロセスがデバイスを掴んでいないか
sudo pgrep -af dpdk-tunnel-router
sudo pkill -f dpdk-tunnel-router
sudo lsof /dev/vfio/* 2>/dev/null || true

# 2. デバイスのドライバを確認
sudo dpdk-devbind.py --status
lspci -k -s 0000:06:13.0

# 3. カーネルドライバ (virtio-pci) から vfio-pci へ戻す
sudo modprobe vfio-pci
sudo dpdk-devbind.py --bind=vfio-pci 0000:06:13.0 0000:06:14.0

# 4. IOMMU が無い環境では no-IOMMU を許可する
cat /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
sudo sh -c 'echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode'

# 5. 再起動
sudo ./run.sh
```

`enable_unsafe_noiommu_mode` は IOMMU なしで VFIO を使うための設定で、
セキュリティ上の制約があります。可能なら IOMMU を有効化してください。

ポートが 1 つも取れない場合、コアは設定変更だけ可能な制御プレーンとして起動
できます。

コア起動オプション（`--` の後）に `--allow-no-ports` を追加してください。
`run.sh` を使う場合は、その行に追記します。

## 5. コマンド

`routerctl` には **read モード**と **configuration モード**があります。
設定の実体（candidate / running）はコアが保持し、CLI はコマンドを送るだけです。

### 5.1 モード

```sh
./scripts/routerctl
router> show status
router> configure
router(config)> set interfaces ethernet eth0 address 192.0.2.1/24
router(config)> set interfaces tunnel tun0 remote 2001:db8:1::2
router(config)> show configuration        # candidate を表示
router(config)> commit                    # running に反映
router(config)> save                      # 設定ファイルへ保存
router(config)> exit
router> show interfaces                   # running を表示
```

対話モードでは上下キーでコマンド履歴、左右キー / Home / End でカーソル移動、
Backspace / Delete で編集できます。Ctrl-L で画面クリア、Ctrl-C で入力中の
行をキャンセル、Ctrl-D で終了します。履歴は CLI セッション内で保持されます。

- **read モード** (`router>`): `show` / `help` / `configure` / `exit`。
  `set` / `delete` / `commit` / `save` / `discard` は拒否されます。
- **configuration モード** (`router(config)>`): `set` / `delete` / `del` で
  candidate を編集します。
  - `commit`: candidate を検証し、running のデータプレーンへ反映
  - `save`: 現在の running を `--config` のファイルへ原子的に保存
  - `read` / `exit` / `end` で read モードへ戻ります。
- `discard` / `rollback` で candidate を running に戻します。
- 未 commit の candidate、または commit 後未 save の running がある状態で
  `exit` / `end` / `quit` / `read` すると拒否されます。
  `commit` と `save` を済ませるか、`discard` してから抜けてください。
- configuration モードの `show configuration` / `show interfaces` は
  candidate を表示します。`show running-config` は現在の running を表示します。
  `show routes` / `neighbors` / `bridge` / `statistics` などの運用表示は
  running のデータプレーンを参照します。
- candidate は制御セッション（Unix ソケット接続）ごとにコアが保持します。
  切断すると未保存の candidate は破棄されます。
- コア起動時に `--no-persist` を指定した場合、`commit` は running に反映しますが
  `save` は利用できません。
- 別セッションが先に `commit` した場合、古い candidate の `commit` は競合として
  拒否されます。`discard` してから編集し直してください。`save` は現在の
  running を保存するため、別セッションの commit 結果を保存できます。

### 5.2 ワンショット / バッチ

読み取り専用のワンショット:

```sh
./scripts/routerctl show status
./scripts/routerctl show interfaces
```

`set` / `delete` / `del` をワンショットで渡した場合は、互換性のため
「configure → 編集 → commit → save → exit」を 1 トランザクションとして実行します。

```sh
./scripts/routerctl set interfaces ethernet eth0 address 192.0.2.1/24
```

ファイルは 1 つの candidate トランザクションとして適用されます。途中の
コマンドが失敗した場合は discard され、running と設定ファイルは変わりません。

```sh
./scripts/routerctl --file config/example.conf
```

### 5.3 パケットキャプチャ (tcpdump)

read モード・configuration モードのどちらからでも、デバッグ用の pcap
キャプチャを開始できます。`tcpdump` と `capture` は同じコマンドです。

```text
tcpdump start [interface <name>|any] -w <file>
              [-d rx|tx|both] [-s <64..16384>] [-c <count>]
              [filter <expression>]
tcpdump stop
tcpdump status

# start は省略可能（tcpdump 風）
tcpdump -i <name|any> -w <file> [-d ...] [-s ...] [-c ...] [filter ...]
```

例:

```sh
# 物理ポート eth0 の RX/TX を 100 パケット取得
./scripts/routerctl tcpdump start interface eth0 -w /tmp/eth0.pcap -c 100

# トンネル tun0 の内側フレームだけを取得
./scripts/routerctl tcpdump start interface tun0 -w /tmp/tun0.pcap -d both

# TCP 443 のみ
./scripts/routerctl tcpdump start interface any -w /tmp/tcp443.pcap \
  filter "tcp port 443"

./scripts/routerctl tcpdump status
./scripts/routerctl tcpdump stop
```

- pcap は Ethernet (DLT_EN10MB) 形式です。`tcpdump -r` / Wireshark で読めます。
- 取得点:
  - 物理インタフェースの RX: 受信直後（VLAN タグを含む）
  - VLAN 子インタフェース (`eth0.10`): タグを外した後のフレーム
  - トンネルインタフェースの RX: 外側をデカプセルした後の内側 Ethernet
  - トンネルインタフェースの TX: カプセル化前の内側 Ethernet
  - 物理インタフェースの TX: カプセル化・外側フラグメント後の実際の送信フレーム
  - `any` は上記すべて（トンネルでは外側と内側の両方）を取得します。
- フィルタは次の語を空白区切りで AND します。`and` は省略可能です。
  - `ip`, `ip6`, `arp`
  - `tcp`, `udp`, `icmp`, `icmp6`
  - `host ADDR`, `src host ADDR`, `dst host ADDR`
  - `port N`, `src port N`, `dst port N`
  - `vlan ID`
  - `ether host MAC`
  - `or` は未対応です。`filter` は行の最後に置いてください。
- `count` に達すると自動停止します。`stop` で明示停止もできます。
- パケットはワーカーからリングバッファ経由で main lcore がファイルへ書きます。
  ディスク I/O はデータプレーンのワーカーをブロックしません。
- `-w` の相対パスは `routerctl` を実行したディレクトリ基準で絶対パスに変換されます。
  pcap を書き込むのはコアプロセスなので、コアの実行ユーザーが書き込めるパスを指定してください。
- キャプチャ中にリングがあふれた場合は `drops` に計上されます。

### 5.4 ping

データプレーン経由で ICMP echo request を送信します。通常の FIB、ARP/NDP、
VLAN、トンネルのアンダーレイ経路が使われます。

```sh
./scripts/routerctl ping 192.0.2.1
./scripts/routerctl ping 2001:db8::1 count 2
./scripts/routerctl ping 198.51.100.2 count 3 interface eth1
./scripts/routerctl ping fe80::1 interface eth0
```

```text
ping <IPv4|IPv6> [count N] [timeout MS] [size BYTES]
     [source ADDR] [interface IF]

count      1..64 (default 4)
timeout    100..10000 ms per reply (default 1000)
size       8..1400 ICMP payload bytes (default 56)
source     local source address
interface  Ethernet/VLAN egress
```

`interface` は link-local IPv6 や、FIB を使わず特定ポートへ送る場合に指定します。
ping は running（commit 済み）の FIB / インタフェースを使います。

`show neighbors` は ARP/NDP エントリに加えて、ブリッジの L2 MAC テーブルも
表示します。

```text
IPv4 neighbors:
eth0  192.0.2.2  lladdr aa:bb:cc:dd:ee:ff reachable age 120ms pending 0

MAC table (bridge forwarding):
bridge br0  mac aa:bb:cc:dd:ee:ff  port eth0  age 120ms
```

### 5.5 設定コマンド

```text
set interfaces tunnel <Tunnel name> remote <IPv4 / IPv6>
set interfaces tunnel <Tunnel name> local-address <IPv4 / IPv6>
set interfaces tunnel <Tunnel name> local-interface <IF name>
set interfaces tunnel <Tunnel name> mtu <mtu>
set interfaces tunnel <Tunnel name> encapsulation <etherip6 / etherip>
set interfaces tunnel <Tunnel name> tcp-mss <auto / none / N>
set interfaces tunnel <Tunnel name> address <prefix / ipv6 autoconf>

set interfaces ethernet <ethernet name> port <DPDK port ID>   # 拡張
set interfaces ethernet <ethernet name> address <prefix / ipv6 autoconf>
set interfaces ethernet <ethernet name> mtu <mtu>
set interfaces ethernet <ethernet name> vlan-id <VLAN ID> address <prefix|ipv6 autoconf>
set interfaces ethernet <ethernet name> vlan-id <VLAN ID> mtu <mtu>
set interfaces ethernet <ethernet name>.<VLAN ID> address <prefix|ipv6 autoconf>  # alias

set interfaces bridge <Bridge name> children <Interface name>
set interfaces bridge <Bridge name> mtu <mtu>

set protocols static route <IPv4/IPv6 prefix> via <same-family next-hop>
```

補足:

- `set interfaces ethernet eth0 ...` のように `eth<N>` を指定すると、未作成でも
  DPDK port N に自動で割り当てて作成します。任意名を使う場合は
  `set interfaces ethernet <name> port <id>` で明示してください。
- `address` は CIDR を受け付けます。ホストビットは保持されます
  （`192.0.2.1/24` はそのまま。FIB に入る connected route は
  `192.0.2.0/24`）。
- `ipv6 autoconf` は RA の Prefix Information Option（A フラグ）から
  SLAAC アドレスを作り、RA 送信元へのデフォルトルートを入れます。
  VLAN 子でも同じで、タグ付き RA を受信すると VLAN に SLAAC アドレスと
  デフォルトルートをインストールします。
- `vlan-id` は `<ethernet>.<vid>` という VLAN 子インタフェースを作ります。
  子は `set interfaces ethernet eth0.10 ...` のように直接指定することもできます。
- VLAN 子でも IPv4/IPv6 の静的アドレスと `address ipv6 autoconf` が使えます。
  VLAN タグ付きの RA を受信すると、その VLAN に SLAAC アドレスと
  デフォルトルートをインストールします。
- ブリッジの children は L2 インタフェース（Ethernet / VLAN / Tunnel）です。
  L3 アドレスを持つインタフェースはブリッジメンバーにできません。
- `tcp-mss auto` はアンダーレイ MTU から外側ヘッダーと内側 IP/TCP ヘッダーを
  引いた値にクランプします。`none` で無効、数値で固定です。
- 新規トンネルの `encapsulation` 省略時は `etherip`（IPv4/IPv6 両対応）です。
  コマンドの順序に依存せず `remote` を先に設定できます。
- 静的ルートの next-hop はルートと同じアドレスファミリである必要があります。
  再帰 next-hop も解決します（解決できない場合は FIB に残りますが転送不可）。

削除:

```text
delete interfaces ethernet <name> [vlan-id <vid>] [address <prefix>]
delete interfaces tunnel <name> [address <prefix>]
delete interfaces bridge <name> [children <ifname>]
delete protocols static route <prefix>
```

表示:

```text
show configuration
show interfaces [name]
show routes
show neighbors
show bridge
show statistics
show tunnels
show drivers
show status
show version
help
```

configuration モードの `set` / `delete` は candidate だけを更新します。
`commit` 時に candidate の検証、FIB 構築、データプレーンへの一括反映を
行います。`save` 時に running を設定ファイルへ原子的に更新します
（一時ファイル + `rename()`）。commit 失敗時は running を変更しません。
save 失敗時は running を維持したままエラーを返します。
ワンショットの `set` / `delete` と `--file` は、commit と save までを自動で
1 トランザクションとして実行します。

### 5.6 コンテキストヘルプ

`?` をコマンドの末尾に付けると、その位置で使える構文・現在値・例を表示します。

```text
router> ?
router> set ?
router> set interfaces ?
router> set interfaces ethernet eth1 ?
router> set interfaces ethernet eth1 address ?
router> set interfaces tunnel tun0 ?
router> set protocols static route ?
router> show ?
router> tcpdump ?
router> ping ?
```

`help <path>` でも同じ内容を表示できます。

```text
router> help set interfaces ethernet eth1
```

configuration モードでは candidate の現在値を、read モードでは running の
現在値を表示します。

シェルからワンショットで渡す場合、`?` はシェルのワイルドカードなので
クォートしてください。

```sh
./scripts/routerctl set interfaces ethernet eth1 '?'
./scripts/routerctl '?'
```

## 6. トンネル

### 6.1 EtherIP6 / EtherIP

```sh
# 外側 IPv6、内側 Ethernet、オーバーレイ MTU 9000
routerctl set interfaces tunnel tun0 encapsulation etherip6
routerctl set interfaces tunnel tun0 local-address 2001:db8:1::1
routerctl set interfaces tunnel tun0 remote 2001:db8:1::2
routerctl set interfaces tunnel tun0 local-interface eth0
routerctl set interfaces tunnel tun0 mtu 9000
routerctl set interfaces tunnel tun0 tcp-mss auto
routerctl set interfaces tunnel tun0 address 10.0.0.1/30
```

`local-address` を省略した場合は `local-interface` 上の同じファミリの
アドレスから送信元を選びます。`local-interface` はアンダーレイの出力
インタフェース（Ethernet / VLAN）を固定します。省略時は remote への FIB
ルートで決まります。

反対側は local/remote を入れ替えてください。`etherip6` は外側 IPv6 のみ、
`etherip` は外側 IPv4/IPv6 の両方を受け付けます。

### 6.2 オーバーレイ MTU がアンダーレイ MTU を超える場合

例: 内側 9000 byte、アンダーレイ 1500 byte。

1. トンネルドライバーが外側 IP + EtherIP ヘッダーを付加（約 9042 byte）。
2. アンダーレイ出力インタフェースの MTU を超えるため、IPv4 なら IP
   フラグメント、IPv6 なら Fragment Header を付けて分割。
3. 受信側は IP protocol 97 の外側フラグメントをワーカーごとに再組み立てし、
   完全な外側パケットにしてから EtherIP をデカプセル。
4. 再組み立て後の内側フレームを通常の L2/L3 パスへ渡す。

再組み立ての制限:

- 1 パケット最大 16384 byte（オーバーレイ MTU 9000 + 外側ヘッダーを収容）。
- 断片の重なりは拒否（IPv6 RFC 5722 に合わせて厳格）。
- タイムアウト 10 秒。
- フラグメントは RSS により同じフローが同じワーカーキューに届く前提です。
- 外側 IPv6 の拡張ヘッダーは Fragment Header 直前までのみ対応します。

### 6.3 新しいトンネル種別の追加

C の組み込みドライバーは `struct tr_tnl_driver` の vtable、Rust は
`TunnelDriver` trait を実装します。Rust の `cdylib` を
`--plugin build/rust/release/libtunnel_driver.so` で読み込むと、
`set interfaces tunnel ... encapsulation <name>` で選択できます。

詳しくは [docs/tunnel-drivers.md](docs/tunnel-drivers.md) と
[rust/tunnel-driver/examples/gre.rs](rust/tunnel-driver/examples/gre.rs)
を参照してください。

## 7. ARP / NDP / IPv6 autoconf

- Ethernet / VLAN / Tunnel の各 L3 インタフェースに MAC を割り当てます。
  Ethernet は NIC の MAC、VLAN は親の MAC、Tunnel は名前から生成した
  ローカル管理 MAC です。
- IPv4: ARP request に応答し、送信元を学習します。next-hop が未解決なら
  パケットをキューに積み、ARP request をレート制限付きで送ります。
- IPv6: リンクローカルアドレスを自動生成し、NS に NA で応答します。
  next-hop 未解決時は NS を送り、NA で学習後にキューをフラッシュします。
- `address ipv6 autoconf` のインタフェースは起動時に Router Solicitation を
  送り、RA の prefix / router lifetime を取り込みます。RA の有効期限が
  切れると動的アドレスとデフォルトルートを削除します。
- ルーター自身は RA を送信しません（ホスト側 SLAAC のみ）。

## 8. 並列処理と設定反映

- `--workers N` で N 個のワーカー lcore を起動します。
- 各 DPDK ポートに N 個（PMD の上限まで）の RX/TX キューを作り、RSS で
  フローを分散します。
- 設定は不変の `struct tr_runtime` として構築し、一括差し替え。
  パケット処理は per-worker の reader flag と writer gate だけを使い、
  通常の RX/TX パスでは `rwlock` を取得しません。設定変更時は writer が
  reader の drain を待ってから旧 runtime を解放します。
  `show` や設定コピーなどの制御処理は引き続き `rt_lock` で保護します。
- 近隣キャッシュ・MAC 学習テーブルはバケット単位の spinlock、フラグメント
  再組み立てはワーカーごとの独立コンテキストです。
- 設定変更時は近隣 / MAC テーブルをクリアし、古いバインディングを残しません。
- PMD が RSS を広告しない場合（`virtio-net` など）は、自動的に 1 RX キューへ
  フォールバックし、`port N: RSS unsupported by PMD` を表示します。この場合
  受信処理はワーカー 1 つだけになり、複数ワーカーによる RX 分散はできません。

### 8.1 性能最適化

- RX バースト 64 パケット単位で処理。パケットパスから `rwlock` を排除し、
  per-worker reader flag と writer gate で runtime を差し替え
- VLAN は親スロット + VLAN ID のハッシュで子スロットを直接取得（名前検索なし）
- トンネルは outer remote アドレスのハッシュで候補を絞り込み
- CPU ごとの経路キャッシュ（1024 entries）と近隣キャッシュ（512 entries、
  2 秒 TTL）で FIB トライ / ARP・NDP テーブルのロックを省略
- TX はワーカーごと・ポートごとに最大 32 パケットをバッチし、
  `rte_eth_tx_burst()` を 1 回で発行
- RX バースト内で次の mbuf をプリフェッチ
- コアの C コンパイルを `-O3`（DPDK の `-march=native` と併用）
- 全ポートが対応している場合のみ IPv4 TX checksum offload を有効化
- バインド済みポートだけをポーリングする active port リストと、
  アイドル時の adaptive polling（busy poll → sleep）
- 経路・近隣キャッシュは runtime generation で自動無効化。設定変更後は
  古いエントリを使いません。
- FIB は per-worker 経路キャッシュでヒット時 O(1)。コールドパスはビットトライの
  ままです。`rte_lpm` / `rte_lpm6` への置換は、ルートメタデータ（connected /
  recursive next-hop / route_id）の保持と、EAL なしで動く FIB テストの
  都合から今回は見送りました。
- TX checksum offload は全ポートが `RTE_ETH_TX_OFFLOAD_IPV4_CKSUM` を
  広告する場合のみ有効化します。RX checksum offload は VLAN タグを保持し、
  転送パスで L4 checksum を検証しないため有効化していません。

簡易ベンチマークを実行できます。

```sh
make bench
```

1 ワーカー、ARP 解決済みの IPv4 フォワーディングを 200 万パケット処理する
合成ベンチです。NIC 性能ではなく、エンジンと reader gate/キャッシュ/TX バッチの
効果を確認するためのものです。手元の環境では、最適化前の約 3.0 Mpps から
burst API で約 4.9 Mpps 程度まで改善しました（`taskset` で 1 コア固定、
環境により変動）。single API は実行ごとの変動が大きく、約 3〜4 Mpps でした。

## 9. テスト

```sh
make test
```

- `test_config`: 全コマンドのパース、検証、直列化ラウンドトリップ、削除。
- `test_fib`: connected / static / 再帰 next-hop / IPv6 LPM。
- `test_reasm`: IPv4/IPv6 フラグメントの逆順再組み立て、重なり拒否。
- `test_engine`: ARP、NDP、IPv4 転送、VLAN、ブリッジ、RA/SLAAC、
  データプレーン ping、MAC テーブル表示、9000 byte オーバーレイを 1500 byte
  アンダーレイへ分割して再組み立て、TCP MSS clamping とチェックサム。
- `test_capture`: pcap ヘッダ、count 自動停止、ARP フィルタ、pcap レコード。
- Rust: EtherIP4/6 ラウンドトリップ、C ABI のレイアウトと FFI 呼び出し。
- `scripts/smoke-test.sh`: `net_null` で実プロセスを起動し、`routerctl` の
  read / configuration モード、candidate の commit / save / discard、
  未 commit / 未 save exit の拒否、`--file` トランザクション、pcap キャプチャ、
  ping、show neighbors の MAC テーブル、永続化、再起動、ホット追加、
  Rust プラグインのロードを確認。

### VM で全テストを実行

ホストでビルドしたテストバイナリとランタイムライブラリを initramfs に詰め、
QEMU の VM 内で全テストを実行できます。

```sh
make vm-test
```

- QEMU / cpio / gzip が必要です。
- `/boot/vmlinuz-$(uname -r)` が読めない場合は、同じバージョンの
  `linux-image` パッケージを `apt-get download` してワークスペース内で
  展開します。
- KVM が使えない環境では TCG で起動します。
- QEMU コンソールログは `vmtest/console.log` に残ります。
- VM 内で `test_capture` / `test_config` / `test_engine` / `test_fib` /
  `test_plugin` / `test_reasm`、Rust の 9 テスト、`smoke-test.sh` を
  順に実行し、`VM_TESTS_PASS` を確認します。

## 10. 制限事項

- STP/RSTP はありません。ブリッジにループを作らないでください。
- トンネルは 1 インタフェース 1 ピアです。複数ピアはインタフェースを分けます。
- EtherIP 自体に暗号化・認証はありません。必要なら外側で IPsec を使ってください。
- 外側 IPv6 の拡張ヘッダーは未対応です（Fragment Header のみ処理）。
- ルーター自身は RA / DHCP を配布しません。
- タグ付きフレームを L3 終端する場合は `vlan-id` で VLAN 子インタフェースを
  定義してください。VLAN 子を持たない Ethernet に L3 アドレスを付けて
  タグ付きフレームを受けた場合、応答はタグなしになります。
- `--plugin` で追加したドライバー名を設定に保存した場合、次回起動時も同じ
  `--plugin` を指定してください。プラグインがないと設定検証で起動に失敗します。
- フラグメント再組み立ては 16384 byte までです。
- ローカル生成の ICMP エラー / Echo Reply は入力インタフェースの L2 で
  返します（同じリンク上の送信元を想定）。
- DPDK の NIC 設定（キュー、RSS、MTU 上限）は起動時に決まります。MTU は
  ソフトウェアで強制され、NIC は最大 9600 byte を受信できる設定にします。
- RSS 非対応の virtio-net などでは RX キューが 1 本になるため、`--workers`
  を増やしても受信は並列化されません。RSS 対応 PMD が必要です。
- pcap キャプチャはデバッグ用途です。フィルタは簡易 AND のみ（`or` 非対応）、
  IPv6 拡張ヘッダー内の L4 ポートは解釈しません。高負荷時は `drops` が
  増えることがあります。

## 11. ディレクトリ

```
core/                 C + DPDK データプレーン
  src/config*.c       コマンドパーサ、検証、永続化、表示
  src/engine.c        パケット処理（L2/L3/ARP/NDP/トンネル）
  src/tunnel.c        C トンネルドライバー + プラグインローダ
  src/capture.c       tcpdump 風 pcap キャプチャ
  src/help.c          コンテキストヘルプ
  src/reasm.c         外側フラグメント / 再組み立て
  src/fib.c           IPv4/IPv6 LPM
  tests/
rust/
  tunnel-driver/      Rust トンネルドライバーライブラリ + C ABI
  routerctl/          CLI
config/example.conf
docs/
scripts/
```
