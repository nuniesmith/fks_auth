use serde::{Deserialize, Serialize};

// <types:autogen start>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TradeSignal {
    pub symbol: String,
    pub side: TradeSide,
    pub strength: f64,
    pub timestamp: String,
    pub strategy: String,
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TradeSide {
    LONG,
    SHORT,
}
// <types:autogen end>
