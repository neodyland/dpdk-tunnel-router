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
                                │ rwlock: immutable runtime snapshot
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
| 並列処理 | DPDK RSS + マルチキュー + ワーカー lcore。設定は RCU 風の不変スナップショットを rwlock で切替 |
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
`eth<N>` という名前は DPDK port N に自動対応するため、次のコマンドだけでも
インタフェースを作成できます。

```sh
./scripts/routerctl set interfaces ethernet eth0 address 192.0.2.1/24
```

> DPDK は NIC をカーネルから取り上げます。Linux の `ip link` には論理
> インタフェースは現れません。`routerctl show interfaces` で確認してください。

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
router(config)> save                      # 適用 + 永続化
router(config)> exit
router> show interfaces                   # running を表示
```

- **read モード** (`router>`): `show` / `help` / `configure` / `exit`。
  `set` / `delete` / `save` / `discard` は拒否されます。
- **configuration モード** (`router(config)>`): `set` / `delete` / `del` で
  candidate を編集します。`save` または `commit` で running に適用し、
  `--config` のファイルへ原子的に保存します。`read` / `exit` / `end` で
  read モードへ戻ります。
- `discard` / `rollback` で candidate を running に戻します。
- 未保存の変更がある状態で `exit` / `end` / `quit` すると拒否されます。
  `save` するか `discard` してから抜けてください。
- configuration モードの `show configuration` / `show interfaces` は
  candidate を表示します。`show running-config` は現在の running を表示します。
  `show routes` / `neighbors` / `bridge` / `statistics` などの運用表示は
  running のデータプレーンを参照します。
- candidate は制御セッション（Unix ソケット接続）ごとにコアが保持します。
  切断すると未保存の candidate は破棄されます。
- コア起動時に `--no-persist` を指定した場合、`save` は running の更新だけを
  行い、設定ファイルは書きません。
- 別セッションが先に `save` した場合、古い candidate の `save` は競合として
  拒否されます。`discard` してから編集し直してください。

### 5.2 ワンショット / バッチ

読み取り専用のワンショット:

```sh
./scripts/routerctl show status
./scripts/routerctl show interfaces
```

`set` / `delete` / `del` をワンショットで渡した場合は、互換性のため
「configure → 編集 → save → exit」を 1 トランザクションとして実行します。

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

### 5.4 設定コマンド

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
set interfaces ethernet <ethernet name> vlan-id <VLAN ID> address <prefix>
set interfaces ethernet <ethernet name> vlan-id <VLAN ID> mtu <mtu>

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
- `vlan-id` は `<ethernet>.<vid>` という VLAN 子インタフェースを作ります。
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
`save` / `commit` 時に、candidate の検証、FIB 構築、データプレーンへの
一括反映、設定ファイルの原子的更新（一時ファイル + `rename()`）を行います。
save の途中で失敗した場合は running を旧設定へ戻し、candidate は保持します。
ワンショットの `set` / `delete` と `--file` は、この save までを自動で
1 トランザクションとして実行します。

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
- 設定は不変の `struct tr_runtime` として構築し、rwlock で一括差し替え。
  ワーカーはバースト単位で read lock を保持するため、途中状態を見ません。
- 近隣キャッシュ・MAC 学習テーブルはバケット単位の spinlock、フラグメント
  再組み立てはワーカーごとの独立コンテキストです。
- 設定変更時は近隣 / MAC テーブルをクリアし、古いバインディングを残しません。
- PMD が RSS を広告しない場合（`virtio-net` など）は、自動的に 1 RX キューへ
  フォールバックし、`port N: RSS unsupported by PMD` を表示します。この場合
  受信処理はワーカー 1 つだけになり、複数ワーカーによる RX 分散はできません。

## 9. テスト

```sh
make test
```

- `test_config`: 全コマンドのパース、検証、直列化ラウンドトリップ、削除。
- `test_fib`: connected / static / 再帰 next-hop / IPv6 LPM。
- `test_reasm`: IPv4/IPv6 フラグメントの逆順再組み立て、重なり拒否。
- `test_engine`: ARP、NDP、IPv4 転送、VLAN、ブリッジ、RA/SLAAC、
  9000 byte オーバーレイを 1500 byte アンダーレイへ分割して再組み立て、
  TCP MSS clamping とチェックサム。
- `test_capture`: pcap ヘッダ、count 自動停止、ARP フィルタ、pcap レコード。
- Rust: EtherIP4/6 ラウンドトリップ、C ABI のレイアウトと FFI 呼び出し。
- `scripts/smoke-test.sh`: `net_null` で実プロセスを起動し、`routerctl` の
  read / configuration モード、candidate の save / discard、未保存 exit の
  拒否、`--file` トランザクション、pcap キャプチャ、永続化、再起動、
  ホット追加、Rust プラグインのロードを確認。

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
