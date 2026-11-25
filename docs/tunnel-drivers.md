# トンネルドライバーの設計

トンネル種別は「内側 Ethernet フレームに外側ヘッダーを付ける / 外す」だけの
小さなドライバーです。ルーター本体（FIB、ARP/NDP、MTU、フラグメント、
MSS、ブリッジ）はドライバーに依存しません。

## 1. フレーム契約

ドライバーは連続した 1 つのバッファに対する次のビューを受け取ります。

```c
struct tr_tnl_frame {
    uint8_t *base;  /* buffer start */
    uint32_t cap;   /* buffer capacity */
    uint32_t off;   /* current packet offset */
    uint32_t len;   /* current packet length */
};
```

### カプセル化

`off` は内側 Ethernet の先頭を指します。ドライバーは `off` を外側ヘッダー分
だけ前に戻し、`len` を増やして外側 IP パケットを作ります。

```
before:  [ headroom ][ inner Ethernet ]
                         ^ off, len
after:   [ headroom ][ outer IP ][ EtherIP ][ inner Ethernet ]
                       ^ new off, new len
```

`base` から `off` までがヘッドルームです。DPDK mbuf では
`m->buf_addr` / `m->data_off` がそのまま使われます。ドライバーは自分が使う
すべてのバイト（長さ、チェックサム、TTL/Hop Limit を含む）を書いてください。

### デカプセル化

`off` は外側 IP の先頭を指します。ドライバーは外側 IP とトンネルヘッダーを
検証し、`off` を内側 Ethernet の先頭まで進め、`len` を内側フレーム長に
縮めます。失敗時は非 0 を返します。

### オーバーヘッド

`overhead(ctx, family)` は外側 IP ヘッダー + トンネルヘッダーの固定長を
返します。EtherIP は IPv4: 22、IPv6: 42 です。可変長ヘッダーが必要な場合は
最大値を返し、実際の長さはカプセル化時に `off` を調整して表現できます。

## 2. C のドライバー ABI

`core/src/tunnel.h`:

```c
struct tr_tnl_driver_ops {
    int (*encap)(void *ctx, struct tr_tnl_frame *frame,
                 const struct tr_tnl_flow *flow);
    int (*decap)(void *ctx, struct tr_tnl_frame *frame,
                 const struct tr_tnl_flow *flow);
    uint32_t (*overhead)(void *ctx, uint8_t family);
    void (*destroy)(void *ctx);
};

struct tr_tnl_driver {
    char name[32];
    bool builtin;
    bool ipv6_only;
    void *ctx;
    struct tr_tnl_driver_ops ops;
};
```

`struct tr_tnl_flow` は外側の送信元/宛先（IPv4 は先頭 4 byte）、family
(4/6)、hop limit、DSCP、tunnel_id を持ちます。

### 組み込みドライバーの追加

1. `encap` / `decap` / `overhead` を実装。
2. `tr_tunnel_drivers_init()` の `g_builtins[]` に `struct tr_tnl_driver` を
   追加。
3. 名前を `set interfaces tunnel ... encapsulation <name>` で指定。
4. `tr_config_validate()` は `ipv6_only` と remote/local の family を見て
   自動的に整合性を検証します。

組み込み EtherIP は `core/src/tunnel.c` にあります。

## 3. Rust ライブラリ

`rust/tunnel-driver` は外部 crate に依存しません。

```rust
use tunnel_driver::{DriverRegistry, Frame, OuterFlow};
use std::net::Ipv6Addr;

fn main() {
    let registry = DriverRegistry::with_builtins();

    let inner = vec![0u8; 1500];
    let mut buf = vec![0u8; 2048];
    buf[64..64 + inner.len()].copy_from_slice(&inner);
    let mut frame = Frame::new(&mut buf, 64, inner.len()).unwrap();
    let flow = OuterFlow::new(
        "2001:db8::1".parse::<Ipv6Addr>().unwrap().into(),
        "2001:db8::2".parse::<Ipv6Addr>().unwrap().into(),
    )
    .with_tunnel_id(0x12345);

    let driver = registry.get("etherip6-rs").unwrap();
    driver.encapsulate(&mut frame, &flow).unwrap();
    assert_eq!(frame.offset(), 64 - 42);
    assert_eq!(frame.len(), inner.len() + 42);
}
```

### trait

```rust
pub trait TunnelDriver: Send + Sync {
    fn name(&self) -> &str;
    fn supports_v4(&self) -> bool;
    fn supports_v6(&self) -> bool;
    fn overhead(&self, family: Family) -> usize;
    fn encapsulate(&self, frame: &mut Frame<'_>, flow: &OuterFlow)
        -> Result<(), DriverError>;
    fn decapsulate(&self, frame: &mut Frame<'_>)
        -> Result<DecapInfo, DriverError>;
}
```

`Frame` は境界チェック付きの `prepend` / `advance` / `write_at` を提供します。
`OuterFlow` は `IpAddr` で family を表現し、`v4()` / `v6()` でオクテットを
取り出せます。

新しい種別の例として
[`examples/gre.rs`](../rust/tunnel-driver/examples/gre.rs) を参照してください。
GRE transparent Ethernet bridging（protocol 0x6558）を約 100 行で実装して
います。

### レジストリ

```rust
let mut r = DriverRegistry::new();
r.register(Box::new(MyDriver::new()))?;
let d = r.get("my-driver").unwrap();
```

名前は一意です。`DriverRegistry::with_builtins()` は `etherip6-rs` と
`etherip-rs` を登録します。

## 4. C データプレーンへのロード

Rust クレートは `cdylib` と `staticlib` の両方を生成します。

```sh
make
# build/rust/release/libtunnel_driver.so

./build/core/dpdk-tunnel-router ... -- \
  --plugin build/rust/release/libtunnel_driver.so
```

`core/src/tunnel.c` が `dlopen()` し、次のシンボルを呼びます。

```c
int tunnel_driver_plugin_init(const struct tr_tnl_host_api *api);
```

ホスト API:

```c
struct tr_tnl_host_api {
    uint32_t abi_version;       /* 現在 1 */
    int (*register_driver)(const struct tr_tnl_driver *driver,
                           char *err, unsigned errlen, void *host_arg);
    void *host_arg;
};
```

Rust 側は登録したドライバーごとに `FfiCtx` を確保し、C の vtable に
`encap` / `decap` / `overhead` のコールバックを渡します。C は
`struct tr_tnl_driver` をコピーするため、Rust のコンテキストはプロセスの
生存期間中保持されます。

現在のプラグインは次の 2 つを登録します。

| 名前 | 外側 | 実装 |
| --- | --- | --- |
| `etherip6-rs` | IPv6 のみ | Rust |
| `etherip-rs` | IPv4/IPv6 | Rust |

組み込みの `etherip6` / `etherip` と衝突しないよう `-rs` を付けています。
`show drivers` で一覧を確認できます。プラグインで追加したドライバーを設定に
保存した場合、再起動時にも同じ `--plugin` が必要です。

```sh
routerctl show drivers
routerctl set interfaces tunnel tun9 encapsulation etherip6-rs
```

### C ABI のレイアウト

`core/src/tunnel.h` と `rust/tunnel-driver/src/ffi.rs` は次のレイアウトを
共有します（x86_64、`repr(C)`）。

| struct | サイズ | 内容 |
| --- | --- | --- |
| `tr_tnl_frame` / `TdrFrame` | 24 | base(8), cap(4), off(4), len(4), padding |
| `tr_tnl_flow` / `TdrFlow` | 40 | family(1), src[16], dst[16], hop(1), dscp(1), id(4) |
| `tr_tnl_driver` / `TdrDriver` | 80 | name[32], builtin(1), ipv6_only(1), padding, ctx(8), ops(32) |
| `tr_tnl_host_api` / `TdrHostApi` | 24 | abi(4), padding, register(8), arg(8) |

コールバックの戻り値は 0 が成功、負値が失敗です。Rust 側は panic を
`catch_unwind` で境界内に閉じ込めます（release profile は unwind）。

## 5. ドライバーに任せないこと

以下はコアの責務です。ドライバーは関与しません。

- アンダーレイ MTU を超える外側パケットのフラグメント / 再組み立て
- ARP / NDP / FIB / ブリッジ / VLAN
- TCP MSS clamping
- トンネルインタフェースの MTU 検査
- 並列処理・ロック・統計

これにより、新しいカプセル化は「ヘッダーを付ける / 外す」処理だけに集中
できます。

## 6. テスト

```sh
./scripts/cargo.sh test --workspace
./scripts/cargo.sh build --example gre
```

Rust のテストは EtherIP4/6 のラウンドトリップ、切り詰め検出、C ABI の
サイズと FFI 経由の encap/decap を検証します。C 側は
`test_engine` が実際の mbuf と 9000 byte フレームで EtherIP6 の
カプセル化・分割・再組み立て・デカプセル化を検証します。
