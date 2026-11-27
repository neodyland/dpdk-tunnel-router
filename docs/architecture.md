# アーキテクチャ

## 1. コンポーネント

| コンポーネント | 言語 | 役割 |
| --- | --- | --- |
| `dpdk-tunnel-router` | C11 + DPDK | EAL、NIC、パケット処理、FIB、ARP/NDP、トンネル、設定の正本 |
| `routerctl` | Rust | Unix ソケットへ 1 行コマンドを送るだけ。設定状態を持たない |
| `tunnel-driver` | Rust | トンネルドライバー用 trait / frame API / C ABI プラグイン |

```
routerctl ── "set interfaces tunnel ..." ──▶ core (main lcore)
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │ 1. 現行設定をコピー                       │
                       │ 2. パース / 検証 / FIB 構築               │
                       │ 3. 不変 runtime を reader gate で差し替え │
                       │ 4. 成功時だけ設定ファイルを原子的に保存   │
                       └─────────────────────┬─────────────────────┘
                                             │
              worker lcores (lock-free reader gate)
              RX burst → L2/L3 engine → TX burst
```

## 2. 制御プレーン

### 2.1 ソケットプロトコル

`routerctl` は `AF_UNIX / SOCK_STREAM` にコマンド 1 行を書き、次の形式で
応答を受け取ります。

```
OK <body length>\n
<body>
```

失敗時は `ERR <body length>\n<body>` です。本文はエラーメッセージまたは
`show` の出力です。サーバーは最大 8 クライアントを非ブロッキングで扱い、
コマンド実行は main lcore 上で直列化されます。

### 2.2 read モード / configuration モード

制御セッション（Unix ソケット接続）ごとにコアが次を保持します。

```c
struct cli_session {
    bool config_mode;
    bool dirty;
    uint64_t base_revision;
    struct tr_config candidate;
};
```

- **read モード**: `show` / `help` / `configure` / `exit` のみ。
  `set` / `delete` / `commit` / `save` / `discard` はコアが拒否します。
- **configuration モード**: `configure` で running のコピーを candidate として
  取得します。`set` / `delete` / `del` は candidate のコピーに対して適用し、
  成功した場合だけ candidate を差し替えます。running は変更しません。
- `show configuration` / `show interfaces` は configuration モードでは
  candidate、read モードでは running を表示します。
  `show running-config` は常に running です。
- `discard` / `rollback` は running から candidate を作り直します。
- 未 commit (`dirty`) または commit 後未 save のまま `exit` / `end` / `quit`
  すると拒否されます。

### 2.3 commit / save

`commit` は candidate を running に反映し、`save` は running をファイルへ
永続化します。

`commit`:

1. `base_revision` と現在の revision を比較し、別セッションの変更を検出。
2. candidate のコピーに NIC MAC を適用し、`tr_config_validate()`。
3. `tr_engine_apply()` が新しい FIB と runtime を構築。
4. `rt_lock` の write lock 下で writer gate を閉じ、全ワーカーの reader flag
   が下りるのを待って runtime ポインタを差し替え。
5. 成功時に revision を進め、`dirty` を落とす。設定ファイルは変更しない。

`save`:

1. candidate が dirty なら「commit が必要」として拒否。
2. 現在の running を読み出す。
3. `tr_config_save()` が設定ファイルを原子的に更新。
4. 成功時に saved revision を更新。

commit の失敗（検証/FIB/runtime）では running とファイルは変更されません。
save の失敗では running は維持され、再度 `save` できます。
`routerctl` のワンショット `set` / `delete` と `--file` は
configure → commit → save を 1 トランザクションとして実行します。

### 2.4 永続化

設定ファイルは「正規化された `set` コマンド列」です。起動時は次の順で
読み込みます。

1. 設定ファイルをプリスキャンし、`set interfaces ethernet <name> port <id>`
   から物理ポートの名前を先に確保。
2. 設定ファイルが存在しない場合、または Ethernet インタフェースが 1 つも
   無い場合は `eth0`, `eth1`, … を自動作成。既に Ethernet がある場合は
   保存された `port` 割り当てに従う（`eth<N>` はコマンド実行時に自動割り当て）。
3. 全行を `tr_config_apply()` で適用。
4. NIC の MAC を Ethernet にコピーし、VLAN 子へ継承。
5. 最終検証後、runtime を構築。

これにより、削除した Ethernet インタフェースが再起動時に勝手に復活すること
はありません。設定ファイルが存在する場合は、すべての Ethernet に `port`
行が必要です（`show configuration` は常に出力します）。

## 3. ランタイムモデル

```c
struct tr_runtime {
    uint64_t generation;
    struct tr_config cfg;          /* immutable snapshot */
    struct tr_fib fib;
    struct tr_tunnel_rt tunnel[64];
    struct tr_local_addr locals[512]; /* configured + link-local + SLAAC */
};
```

- `cfg` は設定のコピー。ワーカーは reader gate 中の不変スナップショットとして参照。
- `fib` は connected / static / SLAAC ルートを入れた LPM トライ。
- `tunnel` はドライバーポインタ、外側アドレス、local-interface、MTU、
  MSS ポリシーを事前解決したもの。
- `locals` はローカル終端判定用。設定アドレスに加え、全 L3 インタフェースの
  リンクローカルと RA で得た SLAAC アドレスを含む。

### 3.1 FIB

IPv4/IPv6 それぞれ 2 分トライで最長一致を行います。connected route を先に
挿入し、static route は設定された next-hop のまま一度挿入した後、全ルート
挿入後に next-hop を再帰解決します。これにより、より具体的な static route
が別の static route を next-hop に指す構成も扱えます。

### 3.2 並列性

- `--workers N` で N 個のワーカー lcore。
- ポートごとに最大 16 の RX/TX キューを作成し、RSS でフロー分散。
- ワーカーは RX バーストごとに per-worker reader flag を立てる。設定差し替え
  以外ではブロックしない。
- 近隣キャッシュとブリッジ MAC テーブルは 64 バケットの spinlock。
- フラグメント再組み立てはワーカーごとの独立テーブル（ロックなし）。
- 統計はインタフェース×ワーカーの `_Atomic uint64_t`。表示時に合算。

## 4. パケットパス

### 4.1 物理ポート受信

```
rte_eth_rx_burst
  → tr_engine_input(worker, ethernet_slot, mbuf)
      → 802.1Q タグ & eth0.10 が存在: タグを外して VLAN 子を選択
      → 802.1ad + 802.1Q タグ & eth0.100.200 が存在:
        S/C タグを外して Q-in-Q 子を選択
      → bridge member なら bridge_ingress()
      → それ以外は l3_ingress()
```

`bridge_ingress()` は送信元 MAC を学習し、宛先が未知/マルチキャストなら
同じブリッジの他の children へコピーを送ります。既知なら 1 ポートだけに
送ります。トンネルメンバーへの出力はカプセル化、Ethernet/VLAN への出力は
L2 送出です。

### 4.2 L3 入力

1. Ethernet ヘッダ、VLAN、宛先 MAC を確認。
2. ARP は `handle_arp()`。
3. IPv4/IPv6 はローカルアドレス判定。
4. ローカルなら ICMP Echo / NS / NA / RA を処理。
5. 転送なら FIB lookup → TTL/Hop Limit 減算 → next-hop 解決 →
   Ethernet 書き換え → 出力。

next-hop が未解決の場合は、近隣テーブルに mbuf をキューイングし、ARP
request / NDP NS を送ります。解決応答を受けるとキューをフラッシュします。
出力インタフェースがトンネルの場合、フラッシュ時にトンネルカプセル化を
行います。

### 4.3 トンネル送信

```
inner Ethernet
  → mss_clamp_frame()（TCP SYN/SYN-ACK、設定時。受信側は decap 直後にも適用）
  → driver->encap()（外側 IP + EtherIP）
  → underlay next-hop 解決
  → 外側 IP 長 > underlay MTU なら frag4/frag6
  → 各フラグメントに Ethernet を付けて TX
```

アンダーレイの next-hop は、`local-interface` が設定されていればその
インタフェースを優先します。未設定なら remote への FIB ルートで決まります。
送信元アドレスは `local-address`、なければ local-interface 上のアドレス
から選びます。

### 4.4 トンネル受信

```
物理ポート
  → IPv4 proto 97 / IPv6 next-header 97 を検出
  → フラグメントなら reasm4/reasm6 で再組み立て
  → (local, remote, family, ingress) に一致するトンネルを検索
  → driver->decap()
  → 内側 Ethernet を tunnel インタフェースの入力として再投入
      → bridge member なら L2、そうでなければ L3
```

一致条件:

- 外側送信元 = tunnel remote
- `local-address` があれば外側宛先と一致
- なければ ingress が `local-interface` と一致し、外側宛先がその
  インタフェースのローカルアドレス
- `local-interface` が設定されていれば ingress も一致

一致しない IP protocol 97 パケットは転送せず破棄します。

### 4.5 デバッグキャプチャ

`tcpdump start` は pcap ライターを main lcore 側で開き、ワーカーはパケットを
固定長スロット（512 個）へコピーして lock-free リングへ入れるだけです。
main lcore の housekeeping がリングを drain して pcap レコードを書き、
100 ms ごとに flush します。ディスク I/O はワーカーをブロックしません。

タップ位置:

| タップ | 内容 |
| --- | --- |
| 物理 RX | 受信直後の Ethernet フレーム（VLAN タグ含む） |
| VLAN 子 RX/TX | タグを外した論理フレーム（親ではタグ付き） |
| トンネル RX | 外側 IP / EtherIP を外した後の内側 Ethernet |
| トンネル TX | カプセル化前（MSS clamp 後）の内側 Ethernet |
| 物理 TX | カプセル化・外側フラグメント後の送信フレーム |

`interface any` は全タップ、`interface eth0` などはスロット一致でフィルタ
します。フィルタ式はワーカー側で評価し、一致したパケットだけをコピーします。
`snaplen`、`count`、方向は開始時に固定され、停止時にリングを drain して
pcap を close します。

キャプチャの有効判定はパケットごとではなく RX バースト先頭で 1 回だけ行い
ます（性能最適化のため）。そのため開始・停止の反映はバースト境界、つまり
最大で 1 バースト分だけ遅れることがあります。パケット単位のフィルタ式は
従来どおりワーカー側で評価します。

## 5. 外側フラグメント

### 5.1 IPv4

- 元の IP ID を保持。
- DF を落とし、MF / fragment offset を設定。
- ヘッダーチェックサムを再計算。
- 再組み立ては (src, dst, id, proto) をキーに、初回フラグメントの
  IP ヘッダー（オプション含む）を保存。完了時に total length と
  checksum を再計算。

### 5.2 IPv6

- 元の IPv6 ヘッダーの next header を 44 に変更。
- Fragment Header（8 byte）を挿入し、元の next header（97）を保持。
- 再組み立ては unfragmentable part（40 byte）と payload を結合し、
  Fragment Header を外して next header を 97 に戻す。
- 重なりは RFC 5722 に従い破棄。

### 5.3 再組み立てテーブル

- ワーカーごとに 64 エントリ。
- 1 エントリ最大 16384 byte。
- フラグメントは最大 128 個。
- 10 秒でタイムアウト。
- 重複フラグメントは無視、部分重なりは拒否。

RSS がフロー単位でキューを決めるため、同じ (src,dst,id) のフラグメントは
同じワーカーに届きます。

## 6. ARP / NDP

### 6.1 近隣テーブル

- IPv4 / IPv6 で別テーブル。
- キーは (ifindex, address)。
- 状態: INCOMPLETE / REACHABLE / STALE。
- 未解決パケットは最大 8 個キューイング。
- ARP request / NS は 1 秒間隔でレート制限。
- INCOMPLETE は 5 秒、解決済みは 300 秒でエージング。

### 6.2 IPv6 autoconf

`address ipv6 autoconf` のインタフェースでは、受信した RA から

- Prefix Information Option（A フラグ、/64）
- Router Lifetime
- Source Link-Layer Address

を取り出します。SLAAC アドレスは prefix + EUI-64（MAC 由来）で生成し、
connected route と RA 送信元へのデフォルトルートを動的エントリとして
追加します。動的エントリは lifetime 経過後に housekeeping で削除され、
runtime が再構築されます。

起動時には全 autoconf インタフェースから Router Solicitation を 1 回送ります。

## 7. TCP MSS clamping

`tcp-mss` が `auto` の場合:

```
max_mss = underlay_mtu
          - outer_ip_header (20 or 40)
          - tunnel_header (2)
          - inner_ethernet_header (14)
          - inner_ip_header (20 or 40)
          - tcp_header (20)
```

内側 Ethernet ヘッダーを引くのは、EtherIP が内側フレーム全体（Ethernet
ヘッダー込み）をカプセル化するためです。これを忘れると max_mss が 14 byte
大きくなり、クランプ後も外側パケットがアンダーレイ MTU を超えて毎回
フラグメントされます。

固定値の場合はその値。既存 MSS が max 以下なら変更しません。MSS を書き換えた
場合は TCP チェックサムを擬似ヘッダー込みで再計算します。対象は SYN が立って
いる TCP パケットで、IP フラグメントの 2 個目以降と、単一セグメントでない
mbuf は対象外です。

適用位置は 2 箇所です。

| 方向 | 場所 |
| --- | --- |
| トンネルへ入る（カプセル化前） | `tunnel_send()` |
| トンネルから出る（再投入前） | `process_outer()`（decap 直後） |

両方向に適用しないと、例えば 9000 MTU の LAN ホストとトンネル越しのサーバの
間で、サーバが広告した MSS がそのまま LAN ホストに届き、LAN ホストが 9 KB
セグメントを送ってしまいます。アンダーレイはそれを 7 フラグメントに分割する
ことになり、1 つのフラグメント損失で 9 KB の TCP セグメント全体が失われます。

## 8. 起動と終了

1. EAL 初期化（`--` より前）。
2. トンネルドライバー登録、`--plugin` のロード。
3. 設定ファイルのプリスキャン、自動ポート作成、全行適用。
4. mbuf プール作成、engine 作成、runtime 適用。
5. 全 DPDK ポートを最大 9600 byte で初期化・start。
6. Router Solicitation 送信。
7. ワーカー lcore 起動、制御ソケット作成。
8. main lcore は制御ソケットの poll と housekeeping（近隣/MAC/再組み立て/
   RA/SLAAC のエージング）を 100 ms 周期で実行。
9. SIGINT/SIGTERM でワーカー停止、ポート停止、EAL cleanup。

## 9. 失敗時の扱い

- 不正コマンド: クライアントへ ERR、設定は不変。
- 設定保存失敗: 旧 runtime を再適用してロールバックし、ERR。
- 外側フラグメントの異常: 該当パケットを破棄、統計 `reasm_fail`。
- 近隣未解決: ARP/NS を送り、パケットはキュー。あふれた場合は古いものを破棄。
- トンネル未完成（remote / local-interface 不足）: `show tunnels` で down、
  該当トンネルへの出力は破棄。
