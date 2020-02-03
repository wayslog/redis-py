from __future__ import unicode_literals
import binascii
import datetime
import pytest
import re
import redis
import time

from redis._compat import (unichr, ascii_letters, iteritems, iterkeys,
                           itervalues, long, basestring)
from redis.client import parse_info
from redis import exceptions

from .conftest import (skip_if_server_version_lt, skip_if_server_version_gte,
                       skip_unless_arch_bits)


def redis_server_time(client):
    return datetime.datetime.fromtimestamp(time.time())


# RESPONSE CALLBACKS
class TestResponseCallbacks(object):
    "Tests for the response callback system"

    def test_response_callbacks(self, r):
        assert r.response_callbacks == redis.Redis.RESPONSE_CALLBACKS
        assert id(r.response_callbacks) != id(redis.Redis.RESPONSE_CALLBACKS)
        r.set_response_callback('GET', lambda x: 'static')
        r['a'] = 'foo'
        assert r['a'] == 'static'

    def test_case_insensitive_command_names(self, r):
        assert r.response_callbacks['del'] == r.response_callbacks['DEL']


class TestRedisCommands(object):

    def test_command_on_invalid_key_type(self, r):
        r.lpush('a', '1')
        with pytest.raises(redis.ResponseError):
            r['a']

    def test_ping(self, r):
        assert r.ping()

    # BASIC KEY COMMANDS
    def test_append(self, r):
        assert r.append('a', 'a1') == 2
        assert r['a'] == b'a1'
        assert r.append('a', 'a2') == 4
        assert r['a'] == b'a1a2'

    @skip_if_server_version_lt('2.6.0')
    def test_bitcount(self, r):
        r.setbit('a', 5, True)
        assert r.bitcount('a') == 1
        r.setbit('a', 6, True)
        assert r.bitcount('a') == 2
        r.setbit('a', 5, False)
        assert r.bitcount('a') == 1
        r.setbit('a', 9, True)
        r.setbit('a', 17, True)
        r.setbit('a', 25, True)
        r.setbit('a', 33, True)
        assert r.bitcount('a') == 5
        assert r.bitcount('a', 0, -1) == 5
        assert r.bitcount('a', 2, 3) == 2
        assert r.bitcount('a', 2, -1) == 3
        assert r.bitcount('a', -2, -1) == 2
        assert r.bitcount('a', 1, 1) == 1

    @skip_if_server_version_lt('2.8.7')
    def test_bitpos(self, r):
        key = 'key:bitpos'
        r.set(key, b'\xff\xf0\x00')
        assert r.bitpos(key, 0) == 12
        assert r.bitpos(key, 0, 2, -1) == 16
        assert r.bitpos(key, 0, -2, -1) == 12
        r.set(key, b'\x00\xff\xf0')
        assert r.bitpos(key, 1, 0) == 8
        assert r.bitpos(key, 1, 1) == 8
        r.set(key, b'\x00\x00\x00')
        assert r.bitpos(key, 1) == -1

    @skip_if_server_version_lt('2.8.7')
    def test_bitpos_wrong_arguments(self, r):
        key = 'key:bitpos:wrong:args'
        r.set(key, b'\xff\xf0\x00')
        with pytest.raises(exceptions.RedisError):
            r.bitpos(key, 0, end=1) == 12
        with pytest.raises(exceptions.RedisError):
            r.bitpos(key, 7) == 12

    def test_decr(self, r):
        assert r.decr('a') == -1
        assert r['a'] == b'-1'
        assert r.decr('a') == -2
        assert r['a'] == b'-2'
        assert r.decr('a', amount=5) == -7
        assert r['a'] == b'-7'

    def test_decrby(self, r):
        assert r.decrby('a', amount=2) == -2
        assert r.decrby('a', amount=3) == -5
        assert r['a'] == b'-5'

    def test_delete(self, r):
        assert r.delete('a') == 0
        r['a'] = 'foo'
        assert r.delete('a') == 1

    def test_delete_with_multiple_keys(self, r):
        r['a'] = 'foo'
        r['b'] = 'bar'
        assert r.delete('a', 'b') == 2
        assert r.get('a') is None
        assert r.get('b') is None

    def test_delitem(self, r):
        r['a'] = 'foo'
        del r['a']
        assert r.get('a') is None

    @skip_if_server_version_lt('4.0.0')
    def test_unlink(self, r):
        assert r.unlink('a') == 0
        r['a'] = 'foo'
        assert r.unlink('a') == 1
        assert r.get('a') is None

    @skip_if_server_version_lt('4.0.0')
    def test_unlink_with_multiple_keys(self, r):
        r['a'] = 'foo'
        r['b'] = 'bar'
        assert r.unlink('a', 'b') == 2
        assert r.get('a') is None
        assert r.get('b') is None

    @skip_if_server_version_lt('2.6.0')
    def test_dump_and_restore(self, r):
        r['a'] = 'foo'
        dumped = r.dump('a')
        del r['a']
        r.restore('a', 0, dumped)
        assert r['a'] == b'foo'

    @skip_if_server_version_lt('3.0.0')
    def test_dump_and_restore_and_replace(self, r):
        r['a'] = 'bar'
        dumped = r.dump('a')
        with pytest.raises(redis.ResponseError):
            r.restore('a', 0, dumped)

        r.restore('a', 0, dumped, replace=True)
        assert r['a'] == b'bar'

    def test_exists(self, r):
        assert r.exists('a') == 0
        r['a'] = 'foo'
        r['b'] = 'bar'
        assert r.exists('a') == 1
        assert r.exists('a', 'b') == 2

    def test_exists_contains(self, r):
        assert 'a' not in r
        r['a'] = 'foo'
        assert 'a' in r

    def test_expire(self, r):
        assert not r.expire('a', 10)
        r['a'] = 'foo'
        assert r.expire('a', 10)
        assert 0 < r.ttl('a') <= 10
        assert r.persist('a')
        assert r.ttl('a') == -1

    def test_expireat_datetime(self, r):
        expire_at = redis_server_time(r) + datetime.timedelta(minutes=1)
        r['a'] = 'foo'
        assert r.expireat('a', expire_at)
        assert 0 < r.ttl('a') <= 61

    def test_expireat_no_key(self, r):
        expire_at = redis_server_time(r) + datetime.timedelta(minutes=1)
        assert not r.expireat('a', expire_at)

    def test_expireat_unixtime(self, r):
        expire_at = redis_server_time(r) + datetime.timedelta(minutes=1)
        r['a'] = 'foo'
        expire_at_seconds = int(time.mktime(expire_at.timetuple()))
        assert r.expireat('a', expire_at_seconds)
        assert 0 < r.ttl('a') <= 61

    def test_get_and_set(self, r):
        # get and set can't be tested independently of each other
        assert r.get('a') is None
        byte_string = b'value'
        integer = 5
        unicode_string = unichr(3456) + 'abcd' + unichr(3421)
        assert r.set('byte_string', byte_string)
        assert r.set('integer', 5)
        assert r.set('unicode_string', unicode_string)
        assert r.get('byte_string') == byte_string
        assert r.get('integer') == str(integer).encode()
        assert r.get('unicode_string').decode('utf-8') == unicode_string

    def test_getitem_and_setitem(self, r):
        r['a'] = 'bar'
        assert r['a'] == b'bar'

    def test_getitem_raises_keyerror_for_missing_key(self, r):
        with pytest.raises(KeyError):
            r['a']

    def test_getitem_does_not_raise_keyerror_for_empty_string(self, r):
        r['a'] = b""
        assert r['a'] == b""

    def test_get_set_bit(self, r):
        # no value
        assert not r.getbit('a', 5)
        # set bit 5
        assert not r.setbit('a', 5, True)
        assert r.getbit('a', 5)
        # unset bit 4
        assert not r.setbit('a', 4, False)
        assert not r.getbit('a', 4)
        # set bit 4
        assert not r.setbit('a', 4, True)
        assert r.getbit('a', 4)
        # set bit 5 again
        assert r.setbit('a', 5, True)
        assert r.getbit('a', 5)

    def test_getrange(self, r):
        r['a'] = 'foo'
        assert r.getrange('a', 0, 0) == b'f'
        assert r.getrange('a', 0, 2) == b'foo'
        assert r.getrange('a', 3, 4) == b''

    def test_getset(self, r):
        assert r.getset('a', 'foo') is None
        assert r.getset('a', 'bar') == b'foo'
        assert r.get('a') == b'bar'

    def test_incr(self, r):
        assert r.incr('a') == 1
        assert r['a'] == b'1'
        assert r.incr('a') == 2
        assert r['a'] == b'2'
        assert r.incr('a', amount=5) == 7
        assert r['a'] == b'7'

    def test_incrby(self, r):
        assert r.incrby('a') == 1
        assert r.incrby('a', 4) == 5
        assert r['a'] == b'5'

    @skip_if_server_version_lt('2.6.0')
    def test_incrbyfloat(self, r):
        assert r.incrbyfloat('a') == 1.0
        assert r['a'] == b'1'
        assert r.incrbyfloat('a', 1.1) == 2.1
        assert float(r['a']) == float(2.1)

    def test_mget(self, r):
        assert r.mget([]) == []
        assert r.mget(['a', 'b']) == [None, None]
        r['a'] = '1'
        r['b'] = '2'
        r['c'] = '3'
        assert r.mget('a', 'other', 'b', 'c') == [b'1', None, b'2', b'3']

    def test_mset(self, r):
        d = {'a': b'1', 'b': b'2', 'c': b'3'}
        assert r.mset(d)
        for k, v in iteritems(d):
            assert r[k] == v

    @skip_if_server_version_lt('2.6.0')
    def test_pexpire(self, r):
        assert not r.pexpire('a', 60000)
        r['a'] = 'foo'
        assert r.pexpire('a', 60000)
        assert 0 < r.pttl('a') <= 60000
        assert r.persist('a')
        assert r.pttl('a') == -1

    @skip_if_server_version_lt('2.6.0')
    def test_pexpireat_datetime(self, r):
        expire_at = redis_server_time(r) + datetime.timedelta(minutes=1)
        r['a'] = 'foo'
        assert r.pexpireat('a', expire_at)
        assert 0 < r.pttl('a') <= 61000

    @skip_if_server_version_lt('2.6.0')
    def test_pexpireat_no_key(self, r):
        expire_at = redis_server_time(r) + datetime.timedelta(minutes=1)
        assert not r.pexpireat('a', expire_at)

    @skip_if_server_version_lt('2.6.0')
    def test_pexpireat_unixtime(self, r):
        expire_at = redis_server_time(r) + datetime.timedelta(minutes=1)
        r['a'] = 'foo'
        expire_at_seconds = int(time.mktime(expire_at.timetuple())) * 1000
        assert r.pexpireat('a', expire_at_seconds)
        assert 0 < r.pttl('a') <= 61000

    @skip_if_server_version_lt('2.6.0')
    def test_psetex(self, r):
        assert r.psetex('a', 1000, 'value')
        assert r['a'] == b'value'
        assert 0 < r.pttl('a') <= 1000

    @skip_if_server_version_lt('2.6.0')
    def test_psetex_timedelta(self, r):
        expire_at = datetime.timedelta(milliseconds=1000)
        assert r.psetex('a', expire_at, 'value')
        assert r['a'] == b'value'
        assert 0 < r.pttl('a') <= 1000

    @skip_if_server_version_lt('2.6.0')
    def test_pttl(self, r):
        assert not r.pexpire('a', 10000)
        r['a'] = '1'
        assert r.pexpire('a', 10000)
        assert 0 < r.pttl('a') <= 10000
        assert r.persist('a')
        assert r.pttl('a') == -1

    @skip_if_server_version_lt('2.8.0')
    def test_pttl_no_key(self, r):
        "PTTL on servers 2.8 and after return -2 when the key doesn't exist"
        assert r.pttl('a') == -2

    @skip_if_server_version_lt('2.6.0')
    def test_set_nx(self, r):
        assert r.set('a', '1', nx=True)
        assert not r.set('a', '2', nx=True)
        assert r['a'] == b'1'

    @skip_if_server_version_lt('2.6.0')
    def test_set_xx(self, r):
        assert not r.set('a', '1', xx=True)
        assert r.get('a') is None
        r['a'] = 'bar'
        assert r.set('a', '2', xx=True)
        assert r.get('a') == b'2'

    @skip_if_server_version_lt('2.6.0')
    def test_set_px(self, r):
        assert r.set('a', '1', px=10000)
        assert r['a'] == b'1'
        assert 0 < r.pttl('a') <= 10000
        assert 0 < r.ttl('a') <= 10

    @skip_if_server_version_lt('2.6.0')
    def test_set_px_timedelta(self, r):
        expire_at = datetime.timedelta(milliseconds=1000)
        assert r.set('a', '1', px=expire_at)
        assert 0 < r.pttl('a') <= 1000
        assert 0 < r.ttl('a') <= 1

    @skip_if_server_version_lt('2.6.0')
    def test_set_ex(self, r):
        assert r.set('a', '1', ex=10)
        assert 0 < r.ttl('a') <= 10

    @skip_if_server_version_lt('2.6.0')
    def test_set_ex_timedelta(self, r):
        expire_at = datetime.timedelta(seconds=60)
        assert r.set('a', '1', ex=expire_at)
        assert 0 < r.ttl('a') <= 60

    @skip_if_server_version_lt('2.6.0')
    def test_set_multipleoptions(self, r):
        r['a'] = 'val'
        assert r.set('a', '1', xx=True, px=10000)
        assert 0 < r.ttl('a') <= 10

    def test_setex(self, r):
        assert r.setex('a', 60, '1')
        assert r['a'] == b'1'
        assert 0 < r.ttl('a') <= 60

    def test_setnx(self, r):
        assert r.setnx('a', '1')
        assert r['a'] == b'1'
        assert not r.setnx('a', '2')
        assert r['a'] == b'1'

    def test_setrange(self, r):
        assert r.setrange('a', 5, 'foo') == 8
        assert r['a'] == b'\0\0\0\0\0foo'
        r['a'] = 'abcdefghijh'
        assert r.setrange('a', 6, '12345') == 11
        assert r['a'] == b'abcdef12345'

    def test_strlen(self, r):
        r['a'] = 'foo'
        assert r.strlen('a') == 3

    def test_substr(self, r):
        r['a'] = '0123456789'
        assert r.substr('a', 0) == b'0123456789'
        assert r.substr('a', 2) == b'23456789'
        assert r.substr('a', 3, 5) == b'345'
        assert r.substr('a', 3, -2) == b'345678'

    def test_ttl(self, r):
        r['a'] = '1'
        assert r.expire('a', 10)
        assert 0 < r.ttl('a') <= 10
        assert r.persist('a')
        assert r.ttl('a') == -1

    @skip_if_server_version_lt('2.8.0')
    def test_ttl_nokey(self, r):
        "TTL on servers 2.8 and after return -2 when the key doesn't exist"
        assert r.ttl('a') == -2

    def test_type(self, r):
        assert r.type('a') == b'none'
        r['a'] = '1'
        assert r.type('a') == b'string'
        del r['a']
        r.lpush('a', '1')
        assert r.type('a') == b'list'
        del r['a']
        r.sadd('a', '1')
        assert r.type('a') == b'set'
        del r['a']
        r.zadd('a', {'1': 1})
        assert r.type('a') == b'zset'

    # LIST COMMANDS
    def test_lindex(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.lindex('a', '0') == b'1'
        assert r.lindex('a', '1') == b'2'
        assert r.lindex('a', '2') == b'3'

    def test_linsert(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.linsert('a', 'after', '2', '2.5') == 4
        assert r.lrange('a', 0, -1) == [b'1', b'2', b'2.5', b'3']
        assert r.linsert('a', 'before', '2', '1.5') == 5
        assert r.lrange('a', 0, -1) == \
            [b'1', b'1.5', b'2', b'2.5', b'3']

    def test_llen(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.llen('a') == 3

    def test_lpop(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.lpop('a') == b'1'
        assert r.lpop('a') == b'2'
        assert r.lpop('a') == b'3'
        assert r.lpop('a') is None

    def test_lpush(self, r):
        assert r.lpush('a', '1') == 1
        assert r.lpush('a', '2') == 2
        assert r.lpush('a', '3', '4') == 4
        assert r.lrange('a', 0, -1) == [b'4', b'3', b'2', b'1']

    def test_lpushx(self, r):
        assert r.lpushx('a', '1') == 0
        assert r.lrange('a', 0, -1) == []
        r.rpush('a', '1', '2', '3')
        assert r.lpushx('a', '4') == 4
        assert r.lrange('a', 0, -1) == [b'4', b'1', b'2', b'3']

    def test_lrange(self, r):
        r.rpush('a', '1', '2', '3', '4', '5')
        assert r.lrange('a', 0, 2) == [b'1', b'2', b'3']
        assert r.lrange('a', 2, 10) == [b'3', b'4', b'5']
        assert r.lrange('a', 0, -1) == [b'1', b'2', b'3', b'4', b'5']

    def test_lrem(self, r):
        r.rpush('a', 'Z', 'b', 'Z', 'Z', 'c', 'Z', 'Z')
        # remove the first 'Z'  item
        assert r.lrem('a', 1, 'Z') == 1
        assert r.lrange('a', 0, -1) == [b'b', b'Z', b'Z', b'c', b'Z', b'Z']
        # remove the last 2 'Z' items
        assert r.lrem('a', -2, 'Z') == 2
        assert r.lrange('a', 0, -1) == [b'b', b'Z', b'Z', b'c']
        # remove all 'Z' items
        assert r.lrem('a', 0, 'Z') == 2
        assert r.lrange('a', 0, -1) == [b'b', b'c']

    def test_lset(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.lrange('a', 0, -1) == [b'1', b'2', b'3']
        assert r.lset('a', 1, '4')
        assert r.lrange('a', 0, 2) == [b'1', b'4', b'3']

    def test_ltrim(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.ltrim('a', 0, 1)
        assert r.lrange('a', 0, -1) == [b'1', b'2']

    def test_rpop(self, r):
        r.rpush('a', '1', '2', '3')
        assert r.rpop('a') == b'3'
        assert r.rpop('a') == b'2'
        assert r.rpop('a') == b'1'
        assert r.rpop('a') is None

    def test_rpush(self, r):
        assert r.rpush('a', '1') == 1
        assert r.rpush('a', '2') == 2
        assert r.rpush('a', '3', '4') == 4
        assert r.lrange('a', 0, -1) == [b'1', b'2', b'3', b'4']

    def test_rpushx(self, r):
        assert r.rpushx('a', 'b') == 0
        assert r.lrange('a', 0, -1) == []
        r.rpush('a', '1', '2', '3')
        assert r.rpushx('a', '4') == 4
        assert r.lrange('a', 0, -1) == [b'1', b'2', b'3', b'4']

    @skip_if_server_version_lt('2.8.0')
    def test_sscan(self, r):
        r.sadd('a', 1, 2, 3)
        cursor, members = r.sscan('a')
        assert cursor == 0
        assert set(members) == {b'1', b'2', b'3'}
        _, members = r.sscan('a', match=b'1')
        assert set(members) == {b'1'}

    @skip_if_server_version_lt('2.8.0')
    def test_sscan_iter(self, r):
        r.sadd('a', 1, 2, 3)
        members = list(r.sscan_iter('a'))
        assert set(members) == {b'1', b'2', b'3'}
        members = list(r.sscan_iter('a', match=b'1'))
        assert set(members) == {b'1'}

    @skip_if_server_version_lt('2.8.0')
    def test_hscan(self, r):
        r.hmset('a', {'a': 1, 'b': 2, 'c': 3})
        cursor, dic = r.hscan('a')
        assert cursor == 0
        assert dic == {b'a': b'1', b'b': b'2', b'c': b'3'}
        _, dic = r.hscan('a', match='a')
        assert dic == {b'a': b'1'}

    @skip_if_server_version_lt('2.8.0')
    def test_hscan_iter(self, r):
        r.hmset('a', {'a': 1, 'b': 2, 'c': 3})
        dic = dict(r.hscan_iter('a'))
        assert dic == {b'a': b'1', b'b': b'2', b'c': b'3'}
        dic = dict(r.hscan_iter('a', match='a'))
        assert dic == {b'a': b'1'}

    @skip_if_server_version_lt('2.8.0')
    def test_zscan(self, r):
        r.zadd('a', {'a': 1, 'b': 2, 'c': 3})
        cursor, pairs = r.zscan('a')
        assert cursor == 0
        assert set(pairs) == {(b'a', 1), (b'b', 2), (b'c', 3)}
        _, pairs = r.zscan('a', match='a')
        assert set(pairs) == {(b'a', 1)}

    @skip_if_server_version_lt('2.8.0')
    def test_zscan_iter(self, r):
        r.zadd('a', {'a': 1, 'b': 2, 'c': 3})
        pairs = list(r.zscan_iter('a'))
        assert set(pairs) == {(b'a', 1), (b'b', 2), (b'c', 3)}
        pairs = list(r.zscan_iter('a', match='a'))
        assert set(pairs) == {(b'a', 1)}

    # SET COMMANDS
    def test_sadd(self, r):
        members = {b'1', b'2', b'3'}
        r.sadd('a', *members)
        assert r.smembers('a') == members

    def test_scard(self, r):
        r.sadd('a', '1', '2', '3')
        assert r.scard('a') == 3

    def test_sismember(self, r):
        r.sadd('a', '1', '2', '3')
        assert r.sismember('a', '1')
        assert r.sismember('a', '2')
        assert r.sismember('a', '3')
        assert not r.sismember('a', '4')

    def test_smembers(self, r):
        r.sadd('a', '1', '2', '3')
        assert r.smembers('a') == {b'1', b'2', b'3'}

    def test_spop(self, r):
        s = [b'1', b'2', b'3']
        r.sadd('a', *s)
        value = r.spop('a')
        assert value in s
        assert r.smembers('a') == set(s) - {value}

    def test_spop_multi_value(self, r):
        s = [b'1', b'2', b'3']
        r.sadd('a', *s)
        values = r.spop('a', 2)
        assert len(values) == 2

        for value in values:
            assert value in s

        assert r.spop('a', 1) == list(set(s) - set(values))

    def test_srandmember(self, r):
        s = [b'1', b'2', b'3']
        r.sadd('a', *s)
        assert r.srandmember('a') in s

    @skip_if_server_version_lt('2.6.0')
    def test_srandmember_multi_value(self, r):
        s = [b'1', b'2', b'3']
        r.sadd('a', *s)
        randoms = r.srandmember('a', number=2)
        assert len(randoms) == 2
        assert set(randoms).intersection(s) == set(randoms)

    def test_srem(self, r):
        r.sadd('a', '1', '2', '3', '4')
        assert r.srem('a', '5') == 0
        assert r.srem('a', '2', '4') == 2
        assert r.smembers('a') == {b'1', b'3'}

    # SORTED SET COMMANDS
    def test_zadd(self, r):
        mapping = {'a1': 1.0, 'a2': 2.0, 'a3': 3.0}
        r.zadd('a', mapping)
        assert r.zrange('a', 0, -1, withscores=True) == \
            [(b'a1', 1.0), (b'a2', 2.0), (b'a3', 3.0)]

        # error cases
        with pytest.raises(exceptions.DataError):
            r.zadd('a', {})

        # cannot use both nx and xx options
        with pytest.raises(exceptions.DataError):
            r.zadd('a', mapping, nx=True, xx=True)

        # cannot use the incr options with more than one value
        with pytest.raises(exceptions.DataError):
            r.zadd('a', mapping, incr=True)

    def test_zadd_nx(self, r):
        assert r.zadd('a', {'a1': 1}) == 1
        assert r.zadd('a', {'a1': 99, 'a2': 2}, nx=True) == 1
        assert r.zrange('a', 0, -1, withscores=True) == \
            [(b'a1', 1.0), (b'a2', 2.0)]

    def test_zadd_xx(self, r):
        assert r.zadd('a', {'a1': 1}) == 1
        assert r.zadd('a', {'a1': 99, 'a2': 2}, xx=True) == 0
        assert r.zrange('a', 0, -1, withscores=True) == \
            [(b'a1', 99.0)]

    def test_zadd_ch(self, r):
        assert r.zadd('a', {'a1': 1}) == 1
        assert r.zadd('a', {'a1': 99, 'a2': 2}, ch=True) == 2
        assert r.zrange('a', 0, -1, withscores=True) == \
            [(b'a2', 2.0), (b'a1', 99.0)]

    def test_zadd_incr(self, r):
        assert r.zadd('a', {'a1': 1}) == 1
        assert r.zadd('a', {'a1': 4.5}, incr=True) == 5.5

    def test_zadd_incr_with_xx(self, r):
        # this asks zadd to incr 'a1' only if it exists, but it clearly
        # doesn't. Redis returns a null value in this case and so should
        # redis-py
        assert r.zadd('a', {'a1': 1}, xx=True, incr=True) is None

    def test_zcard(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zcard('a') == 3

    def test_zcount(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zcount('a', '-inf', '+inf') == 3
        assert r.zcount('a', 1, 2) == 2
        assert r.zcount('a', '(' + str(1), 2) == 1
        assert r.zcount('a', 1, '(' + str(2)) == 1
        assert r.zcount('a', 10, 20) == 0

    def test_zincrby(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zincrby('a', 1, 'a2') == 3.0
        assert r.zincrby('a', 5, 'a3') == 8.0
        assert r.zscore('a', 'a2') == 3.0
        assert r.zscore('a', 'a3') == 8.0

    @skip_if_server_version_lt('2.8.9')
    def test_zlexcount(self, r):
        r.zadd('a', {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0})
        assert r.zlexcount('a', '-', '+') == 7
        assert r.zlexcount('a', '[b', '[f') == 5

    @skip_if_server_version_lt('4.9.0')
    def test_zpopmax(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zpopmax('a') == [(b'a3', 3)]

        # with count
        assert r.zpopmax('a', count=2) == \
            [(b'a2', 2), (b'a1', 1)]

    @skip_if_server_version_lt('4.9.0')
    def test_zpopmin(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zpopmin('a') == [(b'a1', 1)]

        # with count
        assert r.zpopmin('a', count=2) == \
            [(b'a2', 2), (b'a3', 3)]

    @skip_if_server_version_lt('4.9.0')
    def test_bzpopmax(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2})
        r.zadd('b', {'b1': 10, 'b2': 20})
        assert r.bzpopmax(['b', 'a'], timeout=1) == (b'b', b'b2', 20)
        assert r.bzpopmax(['b', 'a'], timeout=1) == (b'b', b'b1', 10)
        assert r.bzpopmax(['b', 'a'], timeout=1) == (b'a', b'a2', 2)
        assert r.bzpopmax(['b', 'a'], timeout=1) == (b'a', b'a1', 1)
        assert r.bzpopmax(['b', 'a'], timeout=1) is None
        r.zadd('c', {'c1': 100})
        assert r.bzpopmax('c', timeout=1) == (b'c', b'c1', 100)

    @skip_if_server_version_lt('4.9.0')
    def test_bzpopmin(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2})
        r.zadd('b', {'b1': 10, 'b2': 20})
        assert r.bzpopmin(['b', 'a'], timeout=1) == (b'b', b'b1', 10)
        assert r.bzpopmin(['b', 'a'], timeout=1) == (b'b', b'b2', 20)
        assert r.bzpopmin(['b', 'a'], timeout=1) == (b'a', b'a1', 1)
        assert r.bzpopmin(['b', 'a'], timeout=1) == (b'a', b'a2', 2)
        assert r.bzpopmin(['b', 'a'], timeout=1) is None
        r.zadd('c', {'c1': 100})
        assert r.bzpopmin('c', timeout=1) == (b'c', b'c1', 100)

    def test_zrange(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zrange('a', 0, 1) == [b'a1', b'a2']
        assert r.zrange('a', 1, 2) == [b'a2', b'a3']

        # withscores
        assert r.zrange('a', 0, 1, withscores=True) == \
            [(b'a1', 1.0), (b'a2', 2.0)]
        assert r.zrange('a', 1, 2, withscores=True) == \
            [(b'a2', 2.0), (b'a3', 3.0)]

        # custom score function
        assert r.zrange('a', 0, 1, withscores=True, score_cast_func=int) == \
            [(b'a1', 1), (b'a2', 2)]

    @skip_if_server_version_lt('2.8.9')
    def test_zrangebylex(self, r):
        r.zadd('a', {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0})
        assert r.zrangebylex('a', '-', '[c') == [b'a', b'b', b'c']
        assert r.zrangebylex('a', '-', '(c') == [b'a', b'b']
        assert r.zrangebylex('a', '[aaa', '(g') == \
            [b'b', b'c', b'd', b'e', b'f']
        assert r.zrangebylex('a', '[f', '+') == [b'f', b'g']
        assert r.zrangebylex('a', '-', '+', start=3, num=2) == [b'd', b'e']

    @skip_if_server_version_lt('2.9.9')
    def test_zrevrangebylex(self, r):
        r.zadd('a', {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0})
        assert r.zrevrangebylex('a', '[c', '-') == [b'c', b'b', b'a']
        assert r.zrevrangebylex('a', '(c', '-') == [b'b', b'a']
        assert r.zrevrangebylex('a', '(g', '[aaa') == \
            [b'f', b'e', b'd', b'c', b'b']
        assert r.zrevrangebylex('a', '+', '[f') == [b'g', b'f']
        assert r.zrevrangebylex('a', '+', '-', start=3, num=2) == \
            [b'd', b'c']

    def test_zrangebyscore(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3, 'a4': 4, 'a5': 5})
        assert r.zrangebyscore('a', 2, 4) == [b'a2', b'a3', b'a4']

        # slicing with start/num
        assert r.zrangebyscore('a', 2, 4, start=1, num=2) == \
            [b'a3', b'a4']

        # withscores
        assert r.zrangebyscore('a', 2, 4, withscores=True) == \
            [(b'a2', 2.0), (b'a3', 3.0), (b'a4', 4.0)]

        # custom score function
        assert r.zrangebyscore('a', 2, 4, withscores=True,
                               score_cast_func=int) == \
            [(b'a2', 2), (b'a3', 3), (b'a4', 4)]

    def test_zrank(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3, 'a4': 4, 'a5': 5})
        assert r.zrank('a', 'a1') == 0
        assert r.zrank('a', 'a2') == 1
        assert r.zrank('a', 'a6') is None

    def test_zrem(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zrem('a', 'a2') == 1
        assert r.zrange('a', 0, -1) == [b'a1', b'a3']
        assert r.zrem('a', 'b') == 0
        assert r.zrange('a', 0, -1) == [b'a1', b'a3']

    def test_zrem_multiple_keys(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zrem('a', 'a1', 'a2') == 2
        assert r.zrange('a', 0, 5) == [b'a3']

    @skip_if_server_version_lt('2.8.9')
    def test_zremrangebylex(self, r):
        r.zadd('a', {'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, 'f': 0, 'g': 0})
        assert r.zremrangebylex('a', '-', '[c') == 3
        assert r.zrange('a', 0, -1) == [b'd', b'e', b'f', b'g']
        assert r.zremrangebylex('a', '[f', '+') == 2
        assert r.zrange('a', 0, -1) == [b'd', b'e']
        assert r.zremrangebylex('a', '[h', '+') == 0
        assert r.zrange('a', 0, -1) == [b'd', b'e']

    def test_zremrangebyrank(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3, 'a4': 4, 'a5': 5})
        assert r.zremrangebyrank('a', 1, 3) == 3
        assert r.zrange('a', 0, 5) == [b'a1', b'a5']

    def test_zremrangebyscore(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3, 'a4': 4, 'a5': 5})
        assert r.zremrangebyscore('a', 2, 4) == 3
        assert r.zrange('a', 0, -1) == [b'a1', b'a5']
        assert r.zremrangebyscore('a', 2, 4) == 0
        assert r.zrange('a', 0, -1) == [b'a1', b'a5']

    def test_zrevrange(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zrevrange('a', 0, 1) == [b'a3', b'a2']
        assert r.zrevrange('a', 1, 2) == [b'a2', b'a1']

        # withscores
        assert r.zrevrange('a', 0, 1, withscores=True) == \
            [(b'a3', 3.0), (b'a2', 2.0)]
        assert r.zrevrange('a', 1, 2, withscores=True) == \
            [(b'a2', 2.0), (b'a1', 1.0)]

        # custom score function
        assert r.zrevrange('a', 0, 1, withscores=True,
                           score_cast_func=int) == \
            [(b'a3', 3.0), (b'a2', 2.0)]

    def test_zrevrangebyscore(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3, 'a4': 4, 'a5': 5})
        assert r.zrevrangebyscore('a', 4, 2) == [b'a4', b'a3', b'a2']

        # slicing with start/num
        assert r.zrevrangebyscore('a', 4, 2, start=1, num=2) == \
            [b'a3', b'a2']

        # withscores
        assert r.zrevrangebyscore('a', 4, 2, withscores=True) == \
            [(b'a4', 4.0), (b'a3', 3.0), (b'a2', 2.0)]

        # custom score function
        assert r.zrevrangebyscore('a', 4, 2, withscores=True,
                                  score_cast_func=int) == \
            [(b'a4', 4), (b'a3', 3), (b'a2', 2)]

    def test_zrevrank(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3, 'a4': 4, 'a5': 5})
        assert r.zrevrank('a', 'a1') == 4
        assert r.zrevrank('a', 'a2') == 3
        assert r.zrevrank('a', 'a6') is None

    def test_zscore(self, r):
        r.zadd('a', {'a1': 1, 'a2': 2, 'a3': 3})
        assert r.zscore('a', 'a1') == 1.0
        assert r.zscore('a', 'a2') == 2.0
        assert r.zscore('a', 'a4') is None

    # HYPERLOGLOG TESTS
    @skip_if_server_version_lt('2.8.9')
    def test_pfadd(self, r):
        members = {b'1', b'2', b'3'}
        assert r.pfadd('a', *members) == 1
        assert r.pfadd('a', *members) == 0
        assert r.pfcount('a') == len(members)

    @skip_if_server_version_lt('2.8.9')
    def test_pfcount(self, r):
        members = {b'1', b'2', b'3'}
        r.pfadd('a', *members)
        assert r.pfcount('a') == len(members)
        members_b = {b'2', b'3', b'4'}
        r.pfadd('b', *members_b)
        assert r.pfcount('b') == len(members_b)
        # assert r.pfcount('a', 'b') == len(members_b.union(members))

    # HASH COMMANDS
    def test_hget_and_hset(self, r):
        r.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert r.hget('a', '1') == b'1'
        assert r.hget('a', '2') == b'2'
        assert r.hget('a', '3') == b'3'

        # field was updated, redis returns 0
        assert r.hset('a', '2', 5) == 0
        assert r.hget('a', '2') == b'5'

        # field is new, redis returns 1
        assert r.hset('a', '4', 4) == 1
        assert r.hget('a', '4') == b'4'

        # key inside of hash that doesn't exist returns null value
        assert r.hget('a', 'b') is None

    def test_hdel(self, r):
        r.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert r.hdel('a', '2') == 1
        assert r.hget('a', '2') is None
        assert r.hdel('a', '1', '3') == 2
        assert r.hlen('a') == 0

    def test_hexists(self, r):
        r.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert r.hexists('a', '1')
        assert not r.hexists('a', '4')

    def test_hgetall(self, r):
        h = {b'a1': b'1', b'a2': b'2', b'a3': b'3'}
        r.hmset('a', h)
        assert r.hgetall('a') == h

    def test_hincrby(self, r):
        assert r.hincrby('a', '1') == 1
        assert r.hincrby('a', '1', amount=2) == 3
        assert r.hincrby('a', '1', amount=-2) == 1

    @skip_if_server_version_lt('2.6.0')
    def test_hincrbyfloat(self, r):
        assert r.hincrbyfloat('a', '1') == 1.0
        assert r.hincrbyfloat('a', '1') == 2.0
        assert r.hincrbyfloat('a', '1', 1.2) == 3.2

    def test_hkeys(self, r):
        h = {b'a1': b'1', b'a2': b'2', b'a3': b'3'}
        r.hmset('a', h)
        local_keys = list(iterkeys(h))
        remote_keys = r.hkeys('a')
        assert (sorted(local_keys) == sorted(remote_keys))

    def test_hlen(self, r):
        r.hmset('a', {'1': 1, '2': 2, '3': 3})
        assert r.hlen('a') == 3

    def test_hmget(self, r):
        assert r.hmset('a', {'a': 1, 'b': 2, 'c': 3})
        assert r.hmget('a', 'a', 'b', 'c') == [b'1', b'2', b'3']

    def test_hmset(self, r):
        h = {b'a': b'1', b'b': b'2', b'c': b'3'}
        assert r.hmset('a', h)
        assert r.hgetall('a') == h

    def test_hsetnx(self, r):
        # Initially set the hash field
        assert r.hsetnx('a', '1', 1)
        assert r.hget('a', '1') == b'1'
        assert not r.hsetnx('a', '1', 2)
        assert r.hget('a', '1') == b'1'

    def test_hvals(self, r):
        h = {b'a1': b'1', b'a2': b'2', b'a3': b'3'}
        r.hmset('a', h)
        local_vals = list(itervalues(h))
        remote_vals = r.hvals('a')
        assert sorted(local_vals) == sorted(remote_vals)

    @skip_if_server_version_lt('3.2.0')
    def test_hstrlen(self, r):
        r.hmset('a', {'1': '22', '2': '333'})
        assert r.hstrlen('a', '1') == 2
        assert r.hstrlen('a', '2') == 3

    # SORT
    def test_sort_basic(self, r):
        r.rpush('a', '3', '2', '1', '4')
        assert r.sort('a') == [b'1', b'2', b'3', b'4']

    def test_sort_limited(self, r):
        r.rpush('a', '3', '2', '1', '4')
        assert r.sort('a', start=1, num=2) == [b'2', b'3']

    def test_sort_groups_string_get(self, r):
        r['user:1'] = 'u1'
        r['user:2'] = 'u2'
        r['user:3'] = 'u3'
        r.rpush('a', '2', '3', '1')
        with pytest.raises(exceptions.DataError):
            r.sort('a', get='user:*', groups=True)

    def test_sort_groups_just_one_get(self, r):
        r['user:1'] = 'u1'
        r['user:2'] = 'u2'
        r['user:3'] = 'u3'
        r.rpush('a', '2', '3', '1')
        with pytest.raises(exceptions.DataError):
            r.sort('a', get=['user:*'], groups=True)

    def test_sort_groups_no_get(self, r):
        r['user:1'] = 'u1'
        r['user:2'] = 'u2'
        r['user:3'] = 'u3'
        r.rpush('a', '2', '3', '1')
        with pytest.raises(exceptions.DataError):
            r.sort('a', groups=True)

    def test_sort_desc(self, r):
        r.rpush('a', '2', '3', '1')
        assert r.sort('a', desc=True) == [b'3', b'2', b'1']

    def test_sort_alpha(self, r):
        r.rpush('a', 'e', 'c', 'b', 'd', 'a')
        assert r.sort('a', alpha=True) == \
            [b'a', b'b', b'c', b'd', b'e']

    def test_sort_issue_924(self, r):
        # Tests for issue https://github.com/andymccurdy/redis-py/issues/924
        r.execute_command('SADD', 'issue#924', 1)
        r.execute_command('SORT', 'issue#924')

    def test_cluster_addslots(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('ADDSLOTS', 1) is True

    def test_cluster_count_failure_reports(self, mock_cluster_resp_int):
        assert isinstance(mock_cluster_resp_int.cluster(
            'COUNT-FAILURE-REPORTS', 'node'), int)

    def test_cluster_countkeysinslot(self, mock_cluster_resp_int):
        assert isinstance(mock_cluster_resp_int.cluster(
            'COUNTKEYSINSLOT', 2), int)

    def test_cluster_delslots(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('DELSLOTS', 1) is True

    def test_cluster_failover(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('FAILOVER', 1) is True

    def test_cluster_forget(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('FORGET', 1) is True

    def test_cluster_info(self, mock_cluster_resp_info):
        assert isinstance(mock_cluster_resp_info.cluster('info'), dict)

    def test_cluster_keyslot(self, mock_cluster_resp_int):
        assert isinstance(mock_cluster_resp_int.cluster(
            'keyslot', 'asdf'), int)

    def test_cluster_meet(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('meet', 'ip', 'port', 1) is True

    def test_cluster_nodes(self, mock_cluster_resp_nodes):
        assert isinstance(mock_cluster_resp_nodes.cluster('nodes'), dict)

    def test_cluster_replicate(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('replicate', 'nodeid') is True

    def test_cluster_reset(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('reset', 'hard') is True

    def test_cluster_saveconfig(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('saveconfig') is True

    def test_cluster_setslot(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.cluster('setslot', 1,
                                            'IMPORTING', 'nodeid') is True

    def test_cluster_slaves(self, mock_cluster_resp_slaves):
        assert isinstance(mock_cluster_resp_slaves.cluster(
            'slaves', 'nodeid'), dict)

    @skip_if_server_version_lt('3.0.0')
    def test_readonly_invalid_cluster_state(self, r):
        with pytest.raises(exceptions.RedisError):
            r.readonly()

    @skip_if_server_version_lt('3.0.0')
    def test_readonly(self, mock_cluster_resp_ok):
        assert mock_cluster_resp_ok.readonly() is True

    # GEO COMMANDS
    @skip_if_server_version_lt('3.2.0')
    def test_geoadd(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        assert r.geoadd('barcelona', *values) == 2
        assert r.zcard('barcelona') == 2

    @skip_if_server_version_lt('3.2.0')
    def test_geoadd_invalid_params(self, r):
        with pytest.raises(exceptions.RedisError):
            r.geoadd('barcelona', *(1, 2))

    @skip_if_server_version_lt('3.2.0')
    def test_geodist(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        assert r.geoadd('barcelona', *values) == 2
        assert r.geodist('barcelona', 'place1', 'place2') == 3067.4157

    @skip_if_server_version_lt('3.2.0')
    def test_geodist_units(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        assert r.geodist('barcelona', 'place1', 'place2', 'km') == 3.0674

    @skip_if_server_version_lt('3.2.0')
    def test_geodist_missing_one_member(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1')
        r.geoadd('barcelona', *values)
        assert r.geodist('barcelona', 'place1', 'missing_member', 'km') is None

    @skip_if_server_version_lt('3.2.0')
    def test_geodist_invalid_units(self, r):
        with pytest.raises(exceptions.RedisError):
            assert r.geodist('x', 'y', 'z', 'inches')

    @skip_if_server_version_lt('3.2.0')
    def test_geohash(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        assert r.geohash('barcelona', 'place1', 'place2', 'place3') ==\
            ['sp3e9yg3kd0', 'sp3e9cbc3t0', None]

    @skip_unless_arch_bits(64)
    @skip_if_server_version_lt('3.2.0')
    def test_geopos(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        # redis uses 52 bits precision, hereby small errors may be introduced.
        assert r.geopos('barcelona', 'place1', 'place2') ==\
            [(2.19093829393386841, 41.43379028184083523),
             (2.18737632036209106, 41.40634178640635099)]

    @skip_if_server_version_lt('4.0.0')
    def test_geopos_no_value(self, r):
        assert r.geopos('barcelona', 'place1', 'place2') == [None, None]

    @skip_if_server_version_lt('3.2.0')
    @skip_if_server_version_gte('4.0.0')
    def test_old_geopos_no_value(self, r):
        assert r.geopos('barcelona', 'place1', 'place2') == []

    @skip_if_server_version_lt('3.2.0')
    def test_georadius(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, b'\x80place2')

        r.geoadd('barcelona', *values)
        assert r.georadius('barcelona', 2.191, 41.433, 1000) == [b'place1']
        assert r.georadius('barcelona', 2.187, 41.406, 1000) == [b'\x80place2']

    @skip_if_server_version_lt('3.2.0')
    def test_georadius_no_values(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        assert r.georadius('barcelona', 1, 2, 1000) == []

    @skip_if_server_version_lt('3.2.0')
    def test_georadius_units(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        assert r.georadius('barcelona', 2.191, 41.433, 1, unit='km') ==\
            [b'place1']

    @skip_unless_arch_bits(64)
    @skip_if_server_version_lt('3.2.0')
    def test_georadius_with(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)

        # test a bunch of combinations to test the parse response
        # function.
        assert r.georadius('barcelona', 2.191, 41.433, 1, unit='km',
                           withdist=True, withcoord=True, withhash=True) ==\
            [[b'place1', 0.0881, 3471609698139488,
              (2.19093829393386841, 41.43379028184083523)]]

        assert r.georadius('barcelona', 2.191, 41.433, 1, unit='km',
                           withdist=True, withcoord=True) ==\
            [[b'place1', 0.0881,
              (2.19093829393386841, 41.43379028184083523)]]

        assert r.georadius('barcelona', 2.191, 41.433, 1, unit='km',
                           withhash=True, withcoord=True) ==\
            [[b'place1', 3471609698139488,
              (2.19093829393386841, 41.43379028184083523)]]

        # test no values.
        assert r.georadius('barcelona', 2, 1, 1, unit='km',
                           withdist=True, withcoord=True, withhash=True) == []

    @skip_if_server_version_lt('3.2.0')
    def test_georadius_count(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        assert r.georadius('barcelona', 2.191, 41.433, 3000, count=1) ==\
            [b'place1']

    @skip_if_server_version_lt('3.2.0')
    def test_georadius_sort(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        assert r.georadius('barcelona', 2.191, 41.433, 3000, sort='ASC') ==\
            [b'place1', b'place2']
        assert r.georadius('barcelona', 2.191, 41.433, 3000, sort='DESC') ==\
            [b'place2', b'place1']

    @skip_unless_arch_bits(64)
    @skip_if_server_version_lt('3.2.0')
    def test_georadius_store_dist(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, 'place2')

        r.geoadd('barcelona', *values)
        r.georadius('barcelona', 2.191, 41.433, 1000,
                    store_dist='places_barcelona')
        # instead of save the geo score, the distance is saved.
        assert r.zscore('places_barcelona', 'place1') == 88.05060698409301

    @skip_unless_arch_bits(64)
    @skip_if_server_version_lt('3.2.0')
    def test_georadiusmember(self, r):
        values = (2.1909389952632, 41.433791470673, 'place1') +\
                 (2.1873744593677, 41.406342043777, b'\x80place2')

        r.geoadd('barcelona', *values)
        assert r.georadiusbymember('barcelona', 'place1', 4000) ==\
            [b'\x80place2', b'place1']
        assert r.georadiusbymember('barcelona', 'place1', 10) == [b'place1']

        assert r.georadiusbymember('barcelona', 'place1', 4000,
                                   withdist=True, withcoord=True,
                                   withhash=True) ==\
            [[b'\x80place2', 3067.4157, 3471609625421029,
                (2.187376320362091, 41.40634178640635)],
             [b'place1', 0.0, 3471609698139488,
                 (2.1909382939338684, 41.433790281840835)]]

    def test_bitfield_operations(self, r):
        # comments show affected bits
        bf = r.bitfield('a')
        resp = (bf
                .set('u8', 8, 255)     # 00000000 11111111
                .get('u8', 0)          # 00000000
                .get('u4', 8)                   # 1111
                .get('u4', 12)                      # 1111
                .get('u4', 13)                       # 111 0
                .execute())
        assert resp == [0, 0, 15, 15, 14]

        # .set() returns the previous value...
        resp = (bf
                .set('u8', 4, 1)           # 0000 0001
                .get('u16', 0)         # 00000000 00011111
                .set('u16', 0, 0)      # 00000000 00000000
                .execute())
        assert resp == [15, 31, 31]

        # incrby adds to the value
        resp = (bf
                .incrby('u8', 8, 254)  # 00000000 11111110
                .incrby('u8', 8, 1)    # 00000000 11111111
                .get('u16', 0)         # 00000000 11111111
                .execute())
        assert resp == [254, 255, 255]

        # Verify overflow protection works as a method:
        r.delete('a')
        resp = (bf
                .set('u8', 8, 254)     # 00000000 11111110
                .overflow('fail')
                .incrby('u8', 8, 2)    # incrby 2 would overflow, None returned
                .incrby('u8', 8, 1)    # 00000000 11111111
                .incrby('u8', 8, 1)    # incrby 1 would overflow, None returned
                .get('u16', 0)         # 00000000 11111111
                .execute())
        assert resp == [0, None, 255, None, 255]

        # Verify overflow protection works as arg to incrby:
        r.delete('a')
        resp = (bf
                .set('u8', 8, 255)           # 00000000 11111111
                .incrby('u8', 8, 1)          # 00000000 00000000  wrap default
                .set('u8', 8, 255)           # 00000000 11111111
                .incrby('u8', 8, 1, 'FAIL')  # 00000000 11111111  fail
                .incrby('u8', 8, 1)          # 00000000 11111111  still fail
                .get('u16', 0)               # 00000000 11111111
                .execute())
        assert resp == [0, 0, 0, None, None, 255]

        # test default default_overflow
        r.delete('a')
        bf = r.bitfield('a', default_overflow='FAIL')
        resp = (bf
                .set('u8', 8, 255)     # 00000000 11111111
                .incrby('u8', 8, 1)    # 00000000 11111111  fail default
                .get('u16', 0)         # 00000000 11111111
                .execute())
        assert resp == [0, None, 255]