import pytest
import redis
import toml
from mock import Mock

from distutils.version import StrictVersion


REDIS_INFO = {}
BACKEND_INSTANCES = {}

default_redis_url = "redis://localhost:6379"

def pytest_addoption(parser):
    parser.addoption('--redis-url', default=default_redis_url,
                     action="store",
                     help="Redis connection string,"
                          " defaults to `%(default)s`")


def _get_info(redis_url):
    client = redis.Redis.from_url(redis_url)
    client.connection_pool.disconnect()
    return {
        "redis_version": "4.0.9",
        "arch_bits": "64",
    }


def load_aster_standalone_instances(cluster):
    return [ ":".join([x.split(":")[0], x.split(":")[1]]) for x in cluster['servers'] ]


def load_aster_cluster_instances(cluster):
    for server in cluster['servers']:
        client = redis.Redis.from_url("redis://%s" % (server,))
        response = client.execute_command("CLUSTER SLOTS")
        client.connection_pool.disconnect()
        instance_lists = [ "%s:%s" % (x[2][0].decode("utf-8"), x[2][1]) for x in response]
        return instance_lists

def load_aster_instances():
    t = toml.load("default.toml")
    all_instances = []

    for cluster in t["clusters"]:
        if cluster['cache_type'] == 'redis':
            all_instances += load_aster_standalone_instances(cluster)
        elif cluster['cache_type'] == 'redis_cluster':
            all_instances += load_aster_cluster_instances(cluster)
    
    for server in all_instances:
        client = redis.Redis.from_url("redis://%s" % (server,))
        BACKEND_INSTANCES[server] = client

def pytest_sessionstart(session):
    redis_url = session.config.getoption("--redis-url")
    info = _get_info(redis_url)
    version = info["redis_version"]
    arch_bits = info["arch_bits"]
    REDIS_INFO["version"] = version
    REDIS_INFO["arch_bits"] = arch_bits
    load_aster_instances()


def skip_if_server_version_lt(min_version):
    redis_version = REDIS_INFO["version"]
    check = StrictVersion(redis_version) < StrictVersion(min_version)
    return pytest.mark.skipif(
        check,
        reason="Redis version required >= {}".format(min_version))


def skip_if_server_version_gte(min_version):
    redis_version = REDIS_INFO["version"]
    check = StrictVersion(redis_version) >= StrictVersion(min_version)
    return pytest.mark.skipif(
        check,
        reason="Redis version required < {}".format(min_version))


def skip_unless_arch_bits(arch_bits):
    return pytest.mark.skipif(REDIS_INFO["arch_bits"] != arch_bits,
                              reason="server is not {}-bit".format(arch_bits))


def _get_client(cls, request, single_connection_client=True, **kwargs):
    redis_url = request.config.getoption("--redis-url")
    client = cls.from_url(redis_url, **kwargs)
    if single_connection_client:
        client = client.client()

    if request:
        def teardown():
            for (_server, inst) in BACKEND_INSTANCES.items():
                try:
                    inst.flushdb()
                except redis.ConnectionError:
                    # handle cases where a test disconnected a client
                    # just manually retry the flushdb
                    inst.flushdb()
        request.addfinalizer(teardown)
    return client


@pytest.fixture()
def r(request):
    return _get_client(redis.Redis, request)


@pytest.fixture()
def r2(request):
    "A second client for tests that need multiple"
    return _get_client(redis.Redis, request)


def _gen_cluster_mock_resp(r, response):
    connection = Mock()
    connection.read_response.return_value = response
    r.connection = connection
    return r


@pytest.fixture()
def mock_cluster_resp_ok(request, **kwargs):
    r = _get_client(redis.Redis, request, **kwargs)
    return _gen_cluster_mock_resp(r, 'OK')


@pytest.fixture()
def mock_cluster_resp_int(request, **kwargs):
    r = _get_client(redis.Redis, request, **kwargs)
    return _gen_cluster_mock_resp(r, '2')


@pytest.fixture()
def mock_cluster_resp_info(request, **kwargs):
    r = _get_client(redis.Redis, request, **kwargs)
    response = ('cluster_state:ok\r\ncluster_slots_assigned:16384\r\n'
                'cluster_slots_ok:16384\r\ncluster_slots_pfail:0\r\n'
                'cluster_slots_fail:0\r\ncluster_known_nodes:7\r\n'
                'cluster_size:3\r\ncluster_current_epoch:7\r\n'
                'cluster_my_epoch:2\r\ncluster_stats_messages_sent:170262\r\n'
                'cluster_stats_messages_received:105653\r\n')
    return _gen_cluster_mock_resp(r, response)


@pytest.fixture()
def mock_cluster_resp_nodes(request, **kwargs):
    r = _get_client(redis.Redis, request, **kwargs)
    response = ('c8253bae761cb1ecb2b61857d85dfe455a0fec8b 172.17.0.7:7006 '
                'slave aa90da731f673a99617dfe930306549a09f83a6b 0 '
                '1447836263059 5 connected\n'
                '9bd595fe4821a0e8d6b99d70faa660638a7612b3 172.17.0.7:7008 '
                'master - 0 1447836264065 0 connected\n'
                'aa90da731f673a99617dfe930306549a09f83a6b 172.17.0.7:7003 '
                'myself,master - 0 0 2 connected 5461-10922\n'
                '1df047e5a594f945d82fc140be97a1452bcbf93e 172.17.0.7:7007 '
                'slave 19efe5a631f3296fdf21a5441680f893e8cc96ec 0 '
                '1447836262556 3 connected\n'
                '4ad9a12e63e8f0207025eeba2354bcf4c85e5b22 172.17.0.7:7005 '
                'master - 0 1447836262555 7 connected 0-5460\n'
                '19efe5a631f3296fdf21a5441680f893e8cc96ec 172.17.0.7:7004 '
                'master - 0 1447836263562 3 connected 10923-16383\n'
                'fbb23ed8cfa23f17eaf27ff7d0c410492a1093d6 172.17.0.7:7002 '
                'master,fail - 1447829446956 1447829444948 1 disconnected\n'
                )
    return _gen_cluster_mock_resp(r, response)


@pytest.fixture()
def mock_cluster_resp_slaves(request, **kwargs):
    r = _get_client(redis.Redis, request, **kwargs)
    response = ("['1df047e5a594f945d82fc140be97a1452bcbf93e 172.17.0.7:7007 "
                "slave 19efe5a631f3296fdf21a5441680f893e8cc96ec 0 "
                "1447836789290 3 connected']")
    return _gen_cluster_mock_resp(r, response)
