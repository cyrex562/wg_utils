use serde::{Deserialize, Serialize};
use kv::msgpack::Msgpack;
use kv::{Config, Encoding, Error, Manager, Serde, ValueBuf};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Testing {
    a: i32,
    b: String
}

fn run() -> Result<(), Error> {
    let mut mgr = Manager::new();
    let mut cfg = Config::default("/tmp/rust-kv");
    let handle = mgr.open(cfg)?;
    let store = handle.write()?;
    let bucket = store.bucket::<&str, ValueBuf<Msgpack<Testing>>>(None)?;
    let mut txn = store.write_txn()?;
    let t = Testing{a: 123, b: "abc".to_owned()};
    txn.set(
        &bucket,
        "testing",
        Msgpack::to_value_buf(t)?,
    )?;
    txn.commit()?;

    let txn = store.read_txn()?;
    let buf = txn.get(&bucket, "testing")?;
    let v = buf.inner()?;
    println!("{:?}", v.to_serde());
    Ok(())
}