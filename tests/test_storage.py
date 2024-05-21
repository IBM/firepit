import ast
import csv

from collections import Counter
from decimal import Decimal

import pytest
import ujson

from firepit.exceptions import UnknownViewname
from firepit.query import Aggregation
from firepit.query import Column
from firepit.query import Group
from firepit.query import Join
from firepit.query import Limit
from firepit.query import Query
from firepit.query import Order
from firepit.query import Projection
from firepit.query import Table

from .helpers import tmp_storage


def test_local(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', fake_bundle_file)
    assert 'url' in store.tables()
    assert 'url' in store.types()
    assert not store._is_sql_view('url')

    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    assert 'urls' in store.views()
    assert 'urls' not in store.types()
    assert store._is_sql_view('urls')
    urls = store.values('url:value', 'urls')
    print(urls)
    assert len(urls) == 14
    assert 'http://www8.example.com/page/176' in urls
    assert 'http://www27.example.com/page/64' not in urls

    store.delete()


def test_in_memory(fake_bundle_file, tmpdir):
    with open(fake_bundle_file, 'r') as fp:
        bundle = ujson.loads(fp.read())

    store = tmp_storage(tmpdir)
    store.cache('q1', bundle)

    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls = store.values('url:value', 'urls')
    print(urls)
    assert len(urls) == 14
    assert 'http://www8.example.com/page/176' in urls
    assert 'http://www27.example.com/page/64' not in urls

    store.delete()


def test_basic(fake_bundle_file, fake_csv_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('urls', 'url', 'q1', "[ipv4-addr:value ISSUBSET '192.168.0.0/16']")
    urls = store.values('url:value', 'urls')
    print(urls)
    assert len(urls) == 31
    assert 'http://www27.example.com/page/64' in urls
    assert store.count('urls') == 31

    urls1 = store.lookup('urls', limit=5)
    assert len(urls1) == 5
    urls2 = store.lookup('urls', limit=5, offset=2, cols="value")
    assert len(urls2) == 5
    assert len(urls2[1].keys()) == 1

    store.assign('sorted', 'urls', op='sort', by='value')
    urls = store.values('url:value', 'sorted')
    print('sorted:', urls)
    assert len(urls) == 31
    assert urls[0] == 'http://www11.example.com/page/108'

    # Now try to change urls, even though sorted is defined using it
    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls = store.values('url:value', 'urls')
    print('reused:', urls)
    assert len(urls) == 14
    sorted_urls = store.values('url:value', 'sorted')
    print('sorted:', sorted_urls)
    assert len(sorted_urls) == 14  # Also changes...weird

    store.extract('a_ips', 'ipv4-addr', 'q1', "[ipv4-addr:value LIKE '10.%']")
    a_ips = store.values('ipv4-addr:value', 'a_ips')
    print(a_ips)
    print('nunique =', len(set(a_ips)))
    assert len(a_ips) == 10  # There are only 10 unique IPs in the bundle
    assert '10.0.0.141' in a_ips

    store.extract('users', 'user-account', 'q1', "[ipv4-addr:value LIKE '10.%']")
    users = store.values('user-account:account_login', 'users')
    print(users)
    assert len(users) == 14  # There are only 14 unique usernames in the bundle
    counter = Counter(users)
    assert counter['henry'] == 1
    assert counter['isabel'] == 1
    by = 'user-account:account_login'
    store.assign('grouped_users', 'users', op='group', by=by)
    cols = store.columns('grouped_users')
    _, _, by = by.rpartition(':')
    assert f'unique_{by}' not in cols
    grouped_users = store.lookup('grouped_users')
    print(grouped_users)
    henry = next((item for item in grouped_users if item['account_login'] == 'henry'), None)
    assert henry
    isabel = next((item for item in grouped_users if item['account_login'] == 'isabel'), None)
    assert isabel

    with open(fake_csv_file, newline='') as fp:
        reader = csv.DictReader(fp)
        def infer_type(value):
            try:
                return ast.literal_eval(value)
            except Exception:
                return value
        data = [{key: infer_type(val) for key, val in row.items()} for row in reader]
        res = store.load('test_procs', data)
        assert res == 'process'
    rows = store.lookup('test_procs')
    assert len(rows) == 5
    assert isinstance(rows[0]['pid'], int) or isinstance(rows[0]['pid'], Decimal)
    ids = [row['id'] for row in rows]
    assert 'process--41eb677f-0335-49da-98b8-375e22f8c94e_0' in ids
    assert 'process--0bb2e61f-8c88-415d-bb7a-bcffc991c38e_0' in ids
    assert rows[1]['binary_ref.parent_directory_ref.path'] == 'C:\\Windows\\System32'
    assert rows[2]['parent_ref.command_line'] == 'C:\\windows\\system32\\cmd.exe /c "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v caldera /f"'

    ips = ['10.0.0.1', '10.0.0.2']
    res = store.load('test_ips', ips, sco_type='ipv4-addr')
    assert res == 'ipv4-addr'
    rows = store.lookup('test_ips')
    assert len(rows) == 2
    for row in rows:
        assert row['type'] == 'ipv4-addr'
        assert row['value'] in ips

    store.delete()
    store = tmp_storage(tmpdir)
    assert len(store.tables()) <= 2  # could be pre-populated with observed-data and identity


def test_join(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    store.extract('local_ips', 'ipv4-addr', 'q1', "[ipv4-addr:value LIKE '%']")

    res = store.load('test_ips', [
        {
            'type': 'ipv4-addr',
            'value': '10.0.0.201',
            'risk': 'high',
        },
        {
            'type': 'ipv4-addr',
            'value': '10.0.0.214',
            'risk': 'high',
        }
    ])

    store.join('marked', 'local_ips', 'value', 'test_ips', 'value')
    rows = store.lookup('marked')
    assert 'value' in rows[0]
    assert 'risk' in rows[0]
    for row in rows:
        if row['value'] in ['10.0.0.201', '10.0.0.214']:
            assert row['risk'] == 'high'
        else:
            assert row['risk'] is None


@pytest.mark.parametrize(
    'sco_type, prop, op, value, expected, unexpected', [
        ('url', 'value', 'LIKE', '%example.com/page/1%', 'http://www26.example.com/page/176', 'http://www67.example.com/page/264'),
        ('url', 'value', 'MATCHES', '^.*example.com/page/1[0-9]*$', 'http://www26.example.com/page/176', 'http://www67.example.com/page/264'),
        ('ipv4-addr', 'value', 'ISSUBSET', '10.0.0.0/8', '10.0.0.141', '192.168.212.97'),
        ('ipv4-addr', 'value', '=', '10.0.0.141', '10.0.0.141', '192.168.212.97'),
        ('network-traffic', 'dst_port', '<=', 1024, 22, 3128),
        ('user-account', 'account_login', 'IN', ('alice', 'bob', 'carol'), 'bob', 'david'),
        ('network-traffic', 'dst_ref.value', 'ISSUBSET', '10.0.0.0/25', '10.0.0.73', '10.0.0.197'),
    ]
)
def test_ops(fake_bundle_file, tmpdir, sco_type, prop, op, value, expected, unexpected):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    if isinstance(value, str):
        value = f"'{value}'"
    store.extract('data', sco_type, 'q1', f"[{sco_type}:{prop} {op} {value}]")
    data = store.values(f"{sco_type}:{prop}", 'data')
    assert expected in data
    assert unexpected not in data

    # Try the negation when appropriate
    if op in ['IN', 'LIKE', 'MATCHES', 'ISSUBSET', 'ISSUPERSET']:
        store.extract('data', sco_type, 'q1', f"[{sco_type}:{prop} NOT {op} {value}]")
        data = store.values(f"{sco_type}:{prop}", 'data')
        assert unexpected in data
        assert expected not in data


def test_grouping(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")
    store.assign('conns', 'conns', op='group', by='src_ref.value')  # Deprecated
    srcs = store.values('src_ref.value', 'conns')
    assert srcs

    groups = store.lookup('conns')
    assert groups
    assert 'unique_dst_port' in groups[0].keys()


def test_grouping_dst_port(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")
    store.assign('conns', 'conns', op='group', by='dst_port')  # Deprecated
    srcs = store.values('dst_port', 'conns')
    assert srcs

    groups = store.lookup('conns')
    assert groups
    assert 'dst_port' in groups[0].keys()


def test_extract(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")
    store.assign('conns', 'conns', op='group', by='src_ref.value')
    srcs = store.values('src_ref.value', 'conns')
    assert srcs

    groups = store.lookup('conns')
    assert groups
    assert 'unique_dst_port' in groups[0].keys()


def test_schema(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    schema = store.schema('url')
    print(schema)
    columns = [i['name'] for i in schema]
    assert 'id' in columns
    assert 'value' in columns


def test_filter(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    store.filter('urls', 'url', 'urls', "[url:value = 'http://www20.example.com/page/19']")
    urls = store.values('url:value', 'urls')
    assert len(urls) == 1
    assert 'http://www20.example.com/page/19' == urls[0]
    views = store.views()
    assert len(views) == 1
    assert views[0] == 'urls'


def test_filter2(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    store.extract('ssh_conns', 'network-traffic', 'q1', "[network-traffic:dst_port = 22]")
    store.filter('ssh_ips', 'ipv4-addr', 'ssh_conns', "[network-traffic:dst_port = 22]")
    ssh_conns = store.lookup('ssh_conns')
    assert len(ssh_conns) == 29
    ssh_ips = store.lookup('ssh_ips')
    assert len(ssh_ips) == 29 # BUG?: * 2
    views = store.views()
    assert len(views) == 2


def test_reassign(fake_bundle_file, fake_csv_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls = store.lookup('urls')
    assert len(urls) == 14
    #print(ujson.dumps(urls, indent=4))

    # Simulate running some analytics to enrich these
    for url in urls:
        url['x_enrich'] = 1

    # Now reload into the same var
    store.reassign('urls', urls)
    rows = store.lookup('urls')
    print(ujson.dumps(rows, indent=4))
    assert len(rows) == len(urls)
    assert rows[0]['x_enrich'] == 1

    # Make sure original var length isn't modified
    urls = store.lookup('urls')
    assert len(urls) == 14

    # Original var's objects should have been updated
    assert urls[0]['x_enrich'] == 1


def test_reassign_after_grouping(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")
    assert 'conns' not in store.tables()
    assert 'conns' not in store.types()
    assert 'conns' in store.views()
    store.assign('grouped_conns', 'conns', op='group', by='src_ref.value')
    assert 'grouped_conns' in store.views()
    grouped_conns = store.lookup('grouped_conns')

    # Simulate running some analytics to enrich these
    for grp in grouped_conns:
        grp['x_enrich'] = 1

    # Now reload into the same var
    store.reassign('grouped_conns', grouped_conns)
    rows = store.lookup('grouped_conns')
    #print(ujson.dumps(rows, indent=4))
    assert len(rows) == len(grouped_conns)
    assert rows[0]['x_enrich'] == 1

    # Now it's a table!!!
    assert 'grouped_conns' in store.tables()
    assert 'grouped_conns' in store.views()
    assert 'grouped_conns' not in store.types()

    # Can we still work with it?
    store.assign('x_conns', 'grouped_conns', op='sort', by='src_ref.value')
    rows = store.lookup('x_conns')
    #print(ujson.dumps(rows, indent=4))
    assert len(rows) == len(grouped_conns)

    # Can we reassign to that name?
    store.assign('grouped_conns', 'grouped_conns', op='sort', by='src_ref.value')
    print('PC: tables:', store.tables())
    print('PC: types:', store.types())
    print('PC: views:', store.views())
    assert 'grouped_conns' not in store.tables()  # Now it's a SQL view again!
    assert 'grouped_conns' not in store.types()
    assert 'grouped_conns' in store.views()
    rows = store.lookup('grouped_conns')
    print(ujson.dumps(rows, indent=4))
    assert len(rows) == len(grouped_conns)


# With the normalized DB, can we still enrich IPs in network-traffic?
def test_reassign_enriched_refs(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    # Grab some network traffic
    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port = 22]")
    conns = store.lookup('conns')

    # Grab the dest addrs from those same connections
    store.extract('dests', 'ipv4-addr', 'q1', "[network-traffic:dst_port = 22]")

    # Simulate running some analytics to enrich these
    for conn in conns:
        conn['dst_ref.x_enrich'] = 1

    # Now reload into the same var
    store.reassign('conns', conns)
    rows = store.lookup('conns')
    assert len(rows) == len(conns)

    # Check dests for enrichment
    dests = store.lookup('dests')
    print(ujson.dumps(dests, indent=4))
    for dest in dests:
        assert 'x_enrich' in dest
        if dest['value'].startswith('10.'):
            assert dest['x_enrich'] == 1


def test_reassign_with_dependents(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls = store.lookup('urls')
    assert len(urls) == 14

    # Create new view based on this one
    qry = store.timestamped('urls', run=False)
    store.assign_query('ts_urls', qry)

    # Simulate running some analytics to enrich these
    for url in urls:
        url['x_enrich'] = 1

    # Now reload into the same var
    store.reassign('urls', urls)
    rows = store.lookup('urls')
    print(ujson.dumps(rows, indent=4))
    assert len(rows) == len(urls)
    assert rows[0]['x_enrich'] == 1

    # Make sure original var length isn't modified
    urls = store.lookup('urls')
    assert len(urls) == 14

    # Original var's objects should have been updated
    assert urls[0]['x_enrich'] == 1

    # Check dependent view
    ts_urls = store.lookup('ts_urls')
    print(ujson.dumps(ts_urls, indent=4))
    assert ts_urls[0]['x_enrich'] == 1
    assert "first_observed" in ts_urls[0]


def test_appdata(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    store.extract('ssh_conns', 'network-traffic', 'q1', "[network-traffic:dst_port = 22]")
    data = {'foo': 99}
    store.set_appdata('ssh_conns', ujson.dumps(data))
    result = ujson.loads(store.get_appdata('ssh_conns'))
    assert data['foo'] == result['foo']
    assert len(result) == len(data)

    store2 = tmp_storage(tmpdir, clear=False)
    result = ujson.loads(store2.get_appdata('ssh_conns'))
    assert data['foo'] == result['foo']
    assert len(result) == len(data)


def test_viewdata(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    store.extract('ssh_conns', 'network-traffic', 'q1', "[network-traffic:dst_port = 22]")
    ssh_data = {'foo': 99}
    store.set_appdata('ssh_conns', ujson.dumps(ssh_data))
    store.extract('dns_conns', 'network-traffic', 'q1', "[network-traffic:dst_port = 53]")
    dns_data = {'bar': 98}
    store.set_appdata('dns_conns', ujson.dumps(dns_data))

    results = store.get_view_data(['ssh_conns', 'dns_conns'])
    assert len(results) == 2
    for result in results:
        if result['name'] == 'ssh_conns':
            assert ssh_data == ujson.loads(result['appdata'])
        else:
            assert dns_data == ujson.loads(result['appdata'])


def test_duplicate(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)

    # Query once
    store.cache('q1', [fake_bundle_file])
    store.extract('urls1', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls1 = store.values('url:value', 'urls1')

    # Now query again - not reasonable, but simulates getting duplicate IDs from different sources
    store.cache('q2', [fake_bundle_file])
    store.extract('urls2', 'url', 'q2', "[url:value LIKE '%page/1%']")
    urls2 = store.values('url:value', 'urls2')

    assert len(urls1) == len(urls2)


def test_sort_same_name(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    store.extract('urls', 'url', 'q1', "[ipv4-addr:value ISSUBSET '192.168.0.0/16']")
    urls1 = store.values('url:value', 'urls')
    print(urls1)
    assert len(urls1) == 31
    store.assign('urls', 'urls', op='sort', by='value')
    urls2 = store.values('url:value', 'urls')
    print(urls2)
    assert len(urls2) == 31
    assert set(urls1) == set(urls2)


def test_merge(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)

    store.cache('test-bundle', [fake_bundle_file])
    all_urls = set(store.values('url:value', 'url'))

    store.extract('urls1', 'url', 'test-bundle', "[url:value LIKE '%page/1%']")
    urls1 = set(store.values('url:value', 'urls1'))

    store.extract('urls2', 'url', 'test-bundle', "[url:value NOT LIKE '%page/1%']")
    urls2 = set(store.values('url:value', 'urls2'))

    assert urls1 | urls2 == all_urls

    store.merge('merged', ['urls1', 'urls2'])
    merged = set(store.values('url:value', 'merged'))
    assert merged == all_urls


def test_change_type(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    # Create a var `foo` of type url
    store.extract('foo', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls = store.values('url:value', 'foo')
    print(urls)
    assert len(urls) == 14

    # Create a var `sorted_foo` of type url that depends on `foo`
    store.assign('sorted_foo', 'foo', op='sort', by='value')

    store.extract('foo', 'ipv4-addr', 'q1', "[ipv4-addr:value ISSUBSET '192.168.0.0/16']")


def test_remove(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', fake_bundle_file)

    store.extract('urls1', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls1 = store.lookup('urls1')
    assert len(urls1) == 14

    store.extract('urls2', 'url', 'q1', "[url:value LIKE '%page/2%']")
    urls2 = store.lookup('urls2')
    assert len(urls2)

    store.remove_view('urls1')
    with pytest.raises(UnknownViewname):
        store.lookup('urls1')

    urls2 = store.lookup('urls2')
    assert len(urls2)


def test_rename(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', fake_bundle_file)

    store.extract('urls1', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls1 = store.lookup('urls1')
    assert len(urls1) == 14

    store.rename_view('urls1', 'urls2')
    with pytest.raises(UnknownViewname):
        store.lookup('urls1')

    urls2 = store.lookup('urls2')
    assert len(urls2) == 14


@pytest.mark.parametrize(
    'names', [
        (['urls1']),
        (['urls2']),
        (['urls1', 'urls2']),
    ]
)
def test_remove_after_merge(fake_bundle_file, tmpdir, names):
    store = tmp_storage(tmpdir)

    store.cache('test-bundle', [fake_bundle_file])
    all_urls = set(store.values('url:value', 'url'))

    store.extract('urls1', 'url', 'test-bundle', "[url:value LIKE '%page/1%']")
    urls1 = set(store.values('url:value', 'urls1'))

    store.extract('urls2', 'url', 'test-bundle', "[url:value NOT LIKE '%page/1%']")
    urls2 = set(store.values('url:value', 'urls2'))

    assert urls1 | urls2 == all_urls

    store.merge('merged', ['urls1', 'urls2'])

    # Remove the views we merged
    for name in names:
        store.remove_view(name)

    merged = set(store.values('url:value', 'merged'))
    assert merged == all_urls


def test_port_zero(fake_bundle_file_2, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file_2])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")

    # sort by src_port and make sure port 0 comes first
    store.assign('sconns', 'conns', op='sort', by='src_port')
    conns = store.lookup('sconns')
    assert conns[0]['src_port'] == 0
    assert conns[0]['id'] == 'network-traffic--637791d8-c981-5a1e-9714-f0c4cfcb736b'
    assert conns[0]['start'] == '2020-06-30T19:25:09.447726Z'


def test_duplicate_identity(fake_bundle_list, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', fake_bundle_list)
    assert store.count('identity') == 1


def test_clobber_viewname(fake_bundle_file_2, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file_2])

    store.extract('conns1', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")
    store.extract('conns2', 'network-traffic', 'q1', "[network-traffic:dst_port > 1024]")
    store.rename_view('conns2', 'conns1')  # Clobber conns1

    # conns2 should be no more:
    with pytest.raises(UnknownViewname):
        store.lookup('conns2')


def test_three_ips(one_event_bundle, tmpdir):
    """A single Observation SDO can contain any arbitrary number and type
    of SCOs.  In the case that one type appears multiple times,
    firepit will attempt to mark one as the "primary", or most
    significant, instance by setting an "x_firepit_rank" attribute to 1.

    A common case is `ipv4-addr`: if you have a `network-traffic`
    object, then you usally have 2 `ipv4-addr` (or `ipv6-addr`)
    objects.  In that case, firepit will (arbitrarily) pick the object
    referenced as the `src_ref` to be the "primary".

    This test case involves 1 Observation with 3 IP addresses.  One is
    `src_ref`, one is `dst_ref`, and third is...well, ask the QRadar
    people, I guess.

    """
    store = tmp_storage(tmpdir)
    store.cache('q1', [one_event_bundle])

    results = store._query(('SELECT value FROM "ipv4-addr" i'
                            ' JOIN __contains c on i.id = c.target_ref'
                            ' WHERE c."x_firepit_rank" IS NOT NULL'))
    rows = results.fetchall()
    assert len(rows) == 1  # There can be only 1!!!
    assert rows[0]['value'] == '10.95.79.130'


def test_finish(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', fake_bundle_file, defer_index=True)
    store.finish()  # No effect with sqlite3
    store.extract('urls', 'url', 'q1', "[url:value LIKE '%page/1%']")
    urls = store.values('url:value', 'urls')
    assert len(urls) == 14
    assert 'http://www8.example.com/page/176' in urls
    assert 'http://www27.example.com/page/64' not in urls
    store.delete()


def test_grouping_multi_auto(fake_bundle_file, tmpdir):
    # Same test as test_grouping but uses assign_query instead of assign
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port < 1024]")
    query = Query()
    query.append(Table('conns'))
    #query.append(Group(['src_ref.value']))
    query.append(Join('ipv4-addr', 'src_ref', '=', 'id'))
    query.append(Group([Column('value', alias='src_ref.value')]))
    store.assign_query('conns', query)
    srcs = store.values('src_ref.value', 'conns')
    assert srcs

    groups = store.lookup('conns')
    assert groups
    assert 'unique_dst_port' in groups[0].keys()


def test_grouping_multi_agg_1(fake_bundle_file, tmpdir):
    # Same test as test_grouping but uses assign_query instead of assign
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port > 0]")
    query = Query([
        Table('conns'),
        #Group(['src_ref.value']),
        Join('ipv4-addr', 'src_ref', '=', 'id'),
        Group([Column('value', alias='src_ref.value')]),
        #Aggregation([('SUM', 'number_observed', 'total')]),
        #Aggregation([('SUM', Column('number_observed', table='conns'), 'total')]),
        Aggregation([('COUNT', 'src_port', 'total')]),
        Order([('total', Order.DESC)]),
        Limit(10)
    ])
    store.assign_query('grp_conns', query)

    groups = store.lookup('grp_conns')
    print(groups)
    assert groups
    assert 'total' in groups[0].keys()
    assert len(groups) == 10
    expected = [
        ('192.168.90.122', 6),
        ('192.168.160.194', 4),
        ('192.168.57.49', 4),
        ('192.168.70.186', 4),
        ('192.168.104.15', 3),
        ('192.168.132.245', 3),
        ('192.168.152.147', 3),
        ('192.168.156.235', 3),
        ('192.168.203.101', 3),
        ('192.168.0.175', 2),
    ]
    for i, values in enumerate(expected):
        # The order of addrs when count is a tie is not guaranteed
        # assert groups[i]['src_ref.value'] == values[0]
        assert groups[i]['total'] == values[1]


def test_assign_query_1(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('conns', 'network-traffic', 'q1', "[network-traffic:dst_port > 0]")
    query = Query([
        Table('conns'),
        Join('ipv4-addr', 'src_ref', '=', 'id', alias='src'),
        Join('ipv4-addr', 'dst_ref', '=', 'id', alias='dst', lhs='conns'),
        Projection([
            Column('value', table='src', alias='src_ref.value'),
            'src_port',
            Column('value', table='dst', alias='dst_ref.value'),
            'dst_port',
            'protocols',
        ]),
        Order([('src_ref.value', Order.DESC)]),
    ])
    store.assign_query('conns', query)
    srcs = store.values('src_ref.value', 'conns')
    assert srcs[0] > srcs[-1]
    assert srcs == sorted(srcs, reverse=True)


def test_number_observed(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('users', 'user-account', 'q1', "[ipv4-addr:value LIKE '10.%']")
    assert isinstance(store.number_observed('users', 'account_login'), int)
    assert store.number_observed('users', 'account_login') == 100
    assert store.number_observed('users', 'account_login', 'henry') == 2
    assert store.number_observed('users', 'account_login', 'isabel') == 12


def test_timestamped(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])

    store.extract('users', 'user-account', 'q1', "[ipv4-addr:value LIKE '10.%']")
    accounts = store.timestamped('users')
    assert len(accounts) == 100
    assert 'first_observed' in accounts[0].keys()
    assert 'account_login' in accounts[0].keys()
    assert 'user_id' in accounts[0].keys()
    assert 'id' in accounts[0].keys()
    logins = store.timestamped('users', 'account_login')
    assert len(logins) == 100
    assert set(logins[0].keys()) == {'first_observed', 'account_login'}
    henry = store.timestamped('users', 'account_login', 'henry')
    assert len(henry) == len([i for i in logins if i['account_login'] == 'henry'])
    isabel = store.timestamped('users', 'account_login', 'isabel')
    assert len(isabel) == len([i for i in logins if i['account_login'] == 'isabel'])

def test_value_counts(fake_bundle_file, tmpdir):
    store = tmp_storage(tmpdir)
    store.cache('q1', [fake_bundle_file])
    data = store.value_counts('user-account', 'account_login')
    print(data)
    henry = [i for i in data if i['account_login'] == 'henry'][0]
    assert henry['count'] == 2
    isabel = [i for i in data if i['account_login'] == 'isabel'][0]
    assert isabel['count'] == 12


def test_extract_outside_pattern(fake_bundle_file, tmpdir):
    """
    Conjunction using properties "outside" the returned entity type inside parens caused issues
    https://github.com/opencybersecurityalliance/firepit/issues/124
    """
    with open(fake_bundle_file, 'r') as fp:
        bundle = ujson.loads(fp.read())

    store = tmp_storage(tmpdir)
    store.cache('q1', bundle)

    store.extract('nt', 'network-traffic', 'q1', "[(url:value LIKE '%page/1%' AND x-oca-asset:hostName LIKE 'pc%')]")
