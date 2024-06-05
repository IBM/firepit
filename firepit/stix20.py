import os
from collections import defaultdict
from lark import Lark, Transformer, v_args

from firepit.props import parse_prop


def get_grammar():
    pth = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "paramstix.lark")
    return open(pth, "r").read()


def stix2sql(pattern, sco_type, dialect='sqlite3'):
    grammar = get_grammar()
    return Lark(grammar,
                parser="lalr",
                transformer=_TranslateTree(sco_type, dialect)).parse(pattern)


def _convert_op(sco_type, prop, op, rhs, dialect):
    orig_op = op
    neg, _, op = op.rpartition(' ')
    if op == 'ISSUBSET':
        #TODO: ipv6-addr
        if sco_type == 'ipv4-addr' or prop in ['src_ref.value',
                                               'dst_ref.value']:
            return f'{neg} (in_subnet("{prop}", {rhs}))'
        else:
            raise ValueError(
                f'{orig_op} not supported for SCO type {sco_type}')
    elif op == 'ISSUPERSET':  # When would anyone use ISSUPERSET?
        #TODO: ipv6-addr
        if sco_type == 'ipv4-addr' or prop in ['src_ref.value',
                                               'dst_ref.value']:
            return f'{neg} (in_subnet({rhs}, "{prop}"))'  # FIXME!
        else:
            raise ValueError(
                f'{orig_op} not supported for SCO type {sco_type}')
    elif prop.endswith('payload_bin'):
        if op == 'MATCHES':
            return f'{neg} match_bin(CAST({rhs} AS TEXT), "{prop}")'
        elif op == 'LIKE':
            return f'{neg} like_bin(CAST({rhs} AS TEXT), "{prop}")'
    elif op == 'MATCHES':
        op = '~' if dialect == 'postgresql' else 'MATCH'
        return f'{neg} "{prop}" {op} {rhs}'
    prop, chunk, subprop = prop.partition('[*]')
    if chunk:
        if op == '!=':
            neg = 'NOT'
        op = 'LIKE'
        rhs = rhs.strip("'")
        if subprop:
            subprop = subprop.lstrip('.')
            rhs = f"'%\"{subprop}\":\"{rhs}\"%'"
        else:
            rhs = f"'%{rhs}%'"
    if dialect == 'postgresql' and op == 'LIKE':
        rhs = rhs.replace("\\", r"\\")  # PostgreSQL uses \ for escape with LIKE only!
    return f'"{prop}" {neg} {op} {rhs}'


def comp2sql(sco_type, prop, op, value, dialect):
    result = ''
    links = parse_prop(sco_type, prop)
    for link in reversed(links):
        if link[0] == 'node':
            from_type = link[1] or sco_type
            result = _convert_op(from_type, link[2], op, value, dialect)
        elif link[0] == 'rel':
            _, from_type, ref_name, to_type = link
            if ref_name.endswith('_refs'):
                # Handle reflists
                tmp = (f'"id" IN (SELECT "id" FROM "{from_type}" JOIN "__reflist" AS "r"'
                       f' ON "{from_type}"."id" = "r"."source_ref" AND "r"."ref_name" = \'{ref_name}\''
                       f' AND "r"."target_ref"')
                end = ')'
            else:
                tmp = f'"{ref_name}"'
                end = ''
            result = f' {tmp} IN (SELECT "id" FROM "{to_type}" WHERE {result}){end}'

    return result


def path2sql(sco_type, path):
    result = ''
    links = parse_prop(sco_type, path)
    for link in reversed(links):
        if link[0] == 'node':
            pass
        elif link[0] == 'rel':
            result = f'"{link[2]}" IN (SELECT "id" FROM "{link[3]}" WHERE {result})'
    return result


@v_args(inline=True)
class _TranslateTree(Transformer):
    """Transformer to convert relevant parts of STIX pattern to WHERE clause"""

    def __init__(self, sco_type, dialect):
        self.sco_type = sco_type
        self.dialect = dialect

    def _make_comp(self, lhs, op, rhs):
        sco_type, _, prop = lhs.partition(':')

        # Ignore object paths that don't match table type
        if self.sco_type == sco_type:
            return comp2sql(sco_type, prop, op, rhs, self.dialect)
        return ''

    def _make_exp(self, lhs, op, rhs):
        return op.join(filter(None, [lhs, rhs]))

    def disj(self, lhs, rhs):
        return self._make_exp(lhs, ' OR ', rhs)

    def conj(self, lhs, rhs):
        return self._make_exp(lhs, ' AND ', rhs)

    def obs_disj(self, lhs, rhs):
        return self.disj(lhs, rhs)

    def obs_conj(self, lhs, rhs):
        return self.conj(lhs, rhs)

    def comp_grp(self, exp):
        return f'({exp})' if exp else None

    def simple_comp_exp(self, lhs, op, rhs):
        return self._make_comp(lhs, op, rhs)

    def comp_disj(self, lhs, rhs):
        return self.disj(lhs, rhs)

    def comp_conj(self, lhs, rhs):
        return self.conj(lhs, rhs)

    def op(self, value):
        return f'{value}'

    def quoted_str(self, value):
        # Adapt the string literal from STIX escapes to SQL escapes
        value = value.replace(r'\\', '\\')  # Convert double backslash to single
        value = value.replace(r"\'", "''")  # Convert escape from backslash to apostrophe
        return f"'{value}'"

    def lit_list(self, *args):
        return "(" + ','.join(args) + ")"

    def start(self, exp, qualifier):
        # For now, drop the qualifier.  Assume the query handled it.
        return f'{exp}' if exp else None

    def object_path(self, sco_type, prop):
        return f'{sco_type}:{prop}'


def summarize_pattern(pattern):
    grammar = get_grammar()
    paths = Lark(grammar,
                 parser="lalr",
                 transformer=_SummarizePattern()).parse(pattern)
    result = defaultdict(set)
    for path in paths:
        sco_type, _, prop = path.partition(':')
        result[sco_type].add(prop)
    return result


@v_args(inline=True)
class _SummarizePattern(Transformer):
    def obs_disj(self, lhs, rhs):
        return lhs | rhs

    def obs_conj(self, lhs, rhs):
        return lhs & rhs

    def comp_grp(self, exp):
        return exp

    def simple_comp_exp(self, lhs, _op, _rhs):
        return {lhs}

    def comp_disj(self, lhs, rhs):
        return lhs | rhs

    def comp_conj(self, lhs, rhs):
        return lhs | rhs  # Still want union here

    # None of these actually matter
    def op(self, _op):
        return None

    def quoted_str(self, _value):
        return None

    def lit_list(self, *args):
        return None

    def start(self, exp, _qualifier):
        return exp

    def object_path(self, sco_type, prop):
        return f'{sco_type}:{prop}'
