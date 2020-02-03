from __future__ import unicode_literals
import pytest

from redis import exceptions


multiply_script = """
local value = redis.call('GET', KEYS[1])
value = tonumber(value)
return value * ARGV[1]"""

class TestScripting(object):
    @pytest.fixture(autouse=True)
    def reset_scripts(self, r):
        r.script_flush()

    def test_eval(self, r):
        r.set('a', 2)
        # 2 * 3 == 6
        assert r.eval(multiply_script, 1, 'a', 3) == 6