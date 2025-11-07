#!/usr/bin/env python3
"""
Rithmic Integration Test Script
Test the Rithmic service with test data
"""

import asyncio
import sys
import os

# Add the src/python directory to the Python path
sys.path.insert(0, '/home/jordan/fks/src/python')

import pytest
pytest.skip("Skipping rithmic integration test by default (external dependency)", allow_module_level=True)  # type: ignore
from services.rithmic.config import RithmicConfig, DEFAULT_TEST_CONFIG  # noqa: E402
from services.rithmic.service import RithmicService
from services.rithmic.client import RithmicClient
from services.rithmic.data_handler import RithmicDataHandler
from services.rithmic.order_manager import RithmicOrderManager, OrderSide, create_market_order

async def test_rithmic_config():
    """Test Rithmic configuration"""
    print("=== Testing Rithmic Configuration ===")
    
    # Test default test config
    config = DEFAULT_TEST_CONFIG
    print(f"Default test config: {config.environment}")
    print(f"Host: {config.host}")
    print(f"Port: {config.port}")
    print(f"SSL enabled: {config.ssl_enabled}")
    print(f"SSL cert path: {config.ssl_cert_path}")
    print(f"Symbols: {config.symbols}")
    
    # Test config from environment
    env_config = RithmicConfig.from_env()
    print(f"Environment config: {env_config.environment}")
    
    # Test validation
    config.username = "test_user"
    config.password = "test_pass"
    is_valid = config.validate()
    print(f"Config validation: {is_valid}")
    
    print("✓ Configuration test completed\n")

async def test_rithmic_client():
    """Test Rithmic client initialization"""
    print("=== Testing Rithmic Client ===")
    
    config = RithmicConfig(
        environment="test",
        username="test_user",
        password="test_pass",
        symbols=["NQ", "ES"]
    )
    
    client = RithmicClient(config)
    print(f"Client initialized: {client.state}")
    print(f"Client stats: {client.get_stats()}")
    
    # Test message handlers
    async def test_handler(message):
        print(f"Test handler received: {message.msg_type}")
    
    client.add_message_handler("test", test_handler)
    client.add_market_data_handler(test_handler)
    client.add_order_handler(test_handler)
    
    print("✓ Client test completed\n")

async def test_data_handler():
    """Test data handler initialization"""
    print("=== Testing Data Handler ===")
    
    config = RithmicConfig(
        environment="test",
        database_url="sqlite:///test_rithmic.db"
    )
    
    data_handler = RithmicDataHandler(config)
    print(f"Data handler initialized with DB: {data_handler.db_path}")
    print(f"Data handler stats: {data_handler.get_stats()}")
    
    # Test callbacks
    async def test_market_callback(market_data):
        print(f"Market data callback: {market_data.symbol}")
    
    async def test_depth_callback(depth_data):
        print(f"Depth data callback: {depth_data.symbol}")
    
    data_handler.add_market_data_callback(test_market_callback)
    data_handler.add_depth_callback(test_depth_callback)
    
    print("✓ Data handler test completed\n")

async def test_order_manager():
    """Test order manager initialization"""
    print("=== Testing Order Manager ===")
    
    config = RithmicConfig(
        environment="test",
        database_url="sqlite:///test_rithmic.db"
    )
    
    order_manager = RithmicOrderManager(config)
    print(f"Order manager initialized")
    print(f"Order manager stats: {order_manager.get_stats()}")
    
    # Test order creation
    market_order = create_market_order("NQ", OrderSide.BUY, 1)
    print(f"Created market order: {market_order.order_id}")
    print(f"Order dict: {market_order.to_dict()}")
    
    # Test order storage
    await order_manager._store_order(market_order)
    print("✓ Order stored in database")
    
    print("✓ Order manager test completed\n")

async def test_service_integration():
    """Test full service integration"""
    print("=== Testing Service Integration ===")
    
    config = RithmicConfig(
        environment="test",
        username="test_user", 
        password="test_pass",
        symbols=["NQ", "ES"],
        database_url="sqlite:///test_rithmic.db"
    )
    
    service = RithmicService(config)
    print(f"Service initialized for {service.config.environment}")
    print(f"Service stats: {service.get_stats()}")
    
    # Test without actually connecting (since we don't have real credentials)
    print("✓ Service integration test completed\n")

async def test_with_mock_data():
    """Test with mock market data"""
    print("=== Testing with Mock Data ===")
    
    config = RithmicConfig(
        environment="test",
        database_url="sqlite:///test_rithmic.db"
    )
    
    # Test data handler with mock data
    data_handler = RithmicDataHandler(config)
    
    # Create mock market data message
    from services.rithmic.client import RithmicMessage
    from datetime import datetime
    
    mock_message = RithmicMessage(
        msg_type="best_bid_offer",
        data={
            "symbol": "NQ",
            "bid_price": 19500.0,
            "ask_price": 19500.25,
            "last_trade_price": 19500.0,
            "volume": 1000,
            "bid_size": 10,
            "ask_size": 15
        },
        timestamp=datetime.now()
    )
    
    # Process mock data
    await data_handler.handle_market_data(mock_message)
    
    # Check if data was stored
    latest_quote = data_handler.get_latest_quote("NQ")
    if latest_quote:
        print(f"Latest quote for NQ: {latest_quote.bid}/{latest_quote.ask}")
        print(f"Last trade: {latest_quote.last}")
    
    print("✓ Mock data test completed\n")

async def main():
    """Run all tests"""
    print("🚀 Starting Rithmic Integration Tests\n")
    
    try:
        await test_rithmic_config()
        await test_rithmic_client()
        await test_data_handler()
        await test_order_manager()
        await test_service_integration()
        await test_with_mock_data()
        
        print("✅ All tests completed successfully!")
        print("\n📋 Next Steps:")
        print("1. Set up real Rithmic test credentials")
        print("2. Test with actual Rithmic test environment")
        print("3. Implement protobuf message handling")
        print("4. Test market data subscriptions")
        print("5. Test order placement and fills")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
