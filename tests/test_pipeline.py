from __future__ import unicode_literals
import pytest

import redis
from redis._compat import unichr, unicode


class TestPipeline(object):
    pass

#     def test_pipeline_is_true(self, r):
#         "Ensure pipeline instances are not false-y"
#         with r.pipeline(transaction=False) as pipe:
#             assert pipe

#     def test_pipeline(self, r):
#         with r.pipeline(transaction=False) as pipe:
#             (pipe.set('a', 'a1')
#                  .get('a')
#                  .zadd('z', {'z1': 1})
#                  .zadd('z', {'z2': 4})
#                  .zincrby('z', 1, 'z1')
#                  .zrange('z', 0, 5, withscores=True))
#             assert pipe.execute() == \
#                 [
#                     True,
#                     b'a1',
#                     True,
#                     True,
#                     2.0,
#                     [(b'z1', 2.0), (b'z2', 4)],
#                 ]

#     def test_pipeline_length(self, r):
#         with r.pipeline(transaction=False) as pipe:
#             # Initially empty.
#             assert len(pipe) == 0

#             # Fill 'er up!
#             pipe.set('a', 'a1').set('b', 'b1').set('c', 'c1')
#             assert len(pipe) == 3

#             # Execute calls reset(), so empty once again.
#             pipe.execute()
#             assert len(pipe) == 0

#     def test_pipeline_no_transaction(self, r):
#         with r.pipeline(transaction=False) as pipe:
#             pipe.set('a', 'a1').set('b', 'b1').set('c', 'c1')
#             assert pipe.execute() == [True, True, True]
#             assert r['a'] == b'a1'
#             assert r['b'] == b'b1'
#             assert r['c'] == b'c1'

#     def test_exec_error_in_response(self, r):
#         """
#         an invalid pipeline command at exec time adds the exception instance
#         to the list of returned values
#         """
#         r['c'] = 'a'
#         with r.pipeline(transaction=False) as pipe:
#             pipe.set('a', 1).set('b', 2).lpush('c', 3).set('d', 4)
#             result = pipe.execute(raise_on_error=False)

#             assert result[0]
#             assert r['a'] == b'1'
#             assert result[1]
#             assert r['b'] == b'2'

#             # we can't lpush to a key that's a string value, so this should
#             # be a ResponseError exception
#             assert isinstance(result[2], redis.ResponseError)
#             assert r['c'] == b'a'

#             # since this isn't a transaction, the other commands after the
#             # error are still executed
#             assert result[3]
#             assert r['d'] == b'4'

#             # make sure the pipe was restored to a working state
#             assert pipe.set('z', 'zzz').execute() == [True]
#             assert r['z'] == b'zzz'

#     def test_exec_error_raised(self, r):
#         r['c'] = 'a'
#         with r.pipeline(transaction=False) as pipe:
#             pipe.set('a', 1).set('b', 2).lpush('c', 3).set('d', 4)
#             with pytest.raises(redis.ResponseError) as ex:
#                 pipe.execute()
#             assert unicode(ex.value).startswith('Command # 3 (LPUSH c 3) of '
#                                                 'pipeline caused error: ')

#             # make sure the pipe was restored to a working state
#             assert pipe.set('z', 'zzz').execute() == [True]
#             assert r['z'] == b'zzz'

#     def test_transaction_with_empty_error_command(self, r):
#         """
#         Commands with custom EMPTY_ERROR functionality return their default
#         values in the pipeline no matter the raise_on_error preference
#         """
#         for error_switch in (True, False):
#             with r.pipeline(transaction=False) as pipe:
#                 pipe.set('a', 1).mget([]).set('c', 3)
#                 result = pipe.execute(raise_on_error=error_switch)

#                 assert result[0]
#                 assert result[1] == []
#                 assert result[2]

#     def test_pipeline_with_empty_error_command(self, r):
#         """
#         Commands with custom EMPTY_ERROR functionality return their default
#         values in the pipeline no matter the raise_on_error preference
#         """
#         for error_switch in (True, False):
#             with r.pipeline(transaction=False) as pipe:
#                 pipe.set('a', 1).mget([]).set('c', 3)
#                 result = pipe.execute(raise_on_error=error_switch)

#                 assert result[0]
#                 assert result[1] == []
#                 assert result[2]

#     def test_parse_error_raised(self, r):
#         with r.pipeline(transaction=False) as pipe:
#             # the zrem is invalid because we don't pass any keys to it
#             pipe.set('a', 1).zrem('b').set('b', 2)
#             with pytest.raises(redis.ResponseError) as ex:
#                 pipe.execute()

#             assert unicode(ex.value).startswith('Command # 2 (ZREM b) of '
#                                                 'pipeline caused error: ')

#             # make sure the pipe was restored to a working state
#             assert pipe.set('z', 'zzz').execute() == [True]
#             assert r['z'] == b'zzz'