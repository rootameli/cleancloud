"""
Test Redis health checks and graceful degradation
"""

import asyncio
from app.core.redis_manager import RedisManager


def test_redis_degraded_mode():
    """Test Redis manager in degraded mode (USE_REDIS=false)"""
    redis_manager = RedisManager("redis://localhost:6379/0", use_redis=False)

    async def _run():
        await redis_manager.initialize()
        assert redis_manager.client is None
        health = await redis_manager.is_healthy()
        assert health is False
        result = await redis_manager.set("test_key", "test_value")
        assert result is False
        value = await redis_manager.get("test_key")
        assert value is None
        published = await redis_manager.publish("test_channel", {"test": "data"})
        assert published == 0

    asyncio.run(_run())


def test_redis_enabled_mode_without_server():
    """Test Redis manager with USE_REDIS=true but no Redis server"""
    redis_manager = RedisManager("redis://localhost:9999/0", use_redis=True)  # Wrong port

    async def _run():
        await redis_manager.initialize()
        health = await redis_manager.is_healthy()
        assert health is False
        result = await redis_manager.set("test_key", "test_value")
        assert result is False
        value = await redis_manager.get("test_key")
        assert value is None
        published = await redis_manager.publish("test_channel", {"test": "data"})
        assert published == 0

    asyncio.run(_run())


if __name__ == "__main__":
    test_redis_degraded_mode()
    test_redis_enabled_mode_without_server()
    print("All Redis health tests passed!")
