use shared_rust::types::{TradeSignal, TradeSide};
use serde_json;

#[test]
fn trade_signal_roundtrip() {
    let ts = TradeSignal {
        symbol: "ETH-USD".into(),
        side: TradeSide::LONG,
        strength: 0.42,
        timestamp: "2025-08-21T12:00:00Z".into(),
        strategy: "mean_reversion".into(),
        meta: Some(serde_json::json!({"note": "test"})),
    };
    let ser = serde_json::to_string(&ts).unwrap();
    // Ensure enum serialized as expected token
    assert!(ser.contains("\"LONG\""), "serialized JSON: {}", ser);
    let back: TradeSignal = serde_json::from_str(&ser).unwrap();
    assert_eq!(back.side, TradeSide::LONG);
}
