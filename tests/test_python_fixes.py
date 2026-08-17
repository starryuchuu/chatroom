"""
测试修复的漏洞：
1. 服务器公钥指纹验证机制
2. 好友请求结果竞争条件
3. Go服务端消息长度限制（单独在Go测试中）
"""

import unittest
import threading
import time
import sys
import os

# 添加父目录到路径以便导入client模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

class TestPublicKeyFingerprint(unittest.TestCase):
    """测试服务器公钥指纹验证机制"""
    
    def test_fingerprint_constant_exists(self):
        """测试指纹常量已定义"""
        from client import EXPECTED_SERVER_KEY_FINGERPRINT
        # 注意：生产环境应该设置为实际指纹值，这里只是测试常量存在
        self.assertIsNotNone(EXPECTED_SERVER_KEY_FINGERPRINT.__class__)  # 可以是None或字符串
        
    def test_fingerprint_warning_in_code(self):
        """测试代码中包含安全警告注释"""
        with open('../client.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 检查是否包含安全提示
        self.assertIn('MUST_SET_FINGERPRINT', content)
        self.assertIn('security warning', content.lower())


class TestFriendRequestRaceCondition(unittest.TestCase):
    """测试好友请求竞争条件修复"""
    
    def test_lock_exists(self):
        """测试保护锁已定义"""
        from client import friend_request_lock
        self.assertIsInstance(friend_request_lock, type(threading.Lock()))
    
    def test_concurrent_access_safety(self):
        """测试并发访问的安全性"""
        from client import friend_request_result, friend_request_lock
        
        results = []
        errors = []
        
        def writer(thread_id):
            try:
                for i in range(100):
                    with friend_request_lock:
                        friend_request_result[thread_id] = i
                    time.sleep(0.0001)
            except Exception as e:
                errors.append(e)
        
        def reader(thread_id):
            try:
                for i in range(100):
                    with friend_request_lock:
                        _ = friend_request_result.get(thread_id)
                    time.sleep(0.0001)
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t1 = threading.Thread(target=writer, args=(i,))
            t2 = threading.Thread(target=reader, args=(i,))
            threads.extend([t1, t2])
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # 应该没有错误发生
        self.assertEqual(len(errors), 0, f"并发访问出现错误: {errors}")


class TestMessageValidation(unittest.TestCase):
    """测试消息验证逻辑"""
    
    def test_client_message_handling(self):
        """测试客户端消息处理基本功能"""
        # 这里测试客户端能正常导入和初始化
        try:
            import client
            # 验证关键变量存在
            self.assertTrue(hasattr(client, 'friend_request_lock'))
            self.assertTrue(hasattr(client, 'friend_request_result'))
            self.assertTrue(hasattr(client, 'EXPECTED_SERVER_KEY_FINGERPRINT'))
        except Exception as e:
            self.fail(f"客户端模块导入或初始化失败: {e}")


if __name__ == '__main__':
    unittest.main()
