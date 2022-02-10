"""Utilities for generating SQL while avoiding SQL injection vulns"""

from firepit.validate import validate_name
from firepit.validate import validate_path

import re

COMP_OPS = ['=', '<>', '!=', '<', '>', '<=', '>=', 'LIKE', 'IN', 'IS', 'IS NOT']
PRED_OPS = ['AND', 'OR']
JOIN_TYPES = ['INNER', 'OUTER', 'LEFT OUTER', 'CROSS']
AGG_FUNCS = ['COUNT', 'SUM', 'MIN', 'MAX', 'AVG', 'NUNIQUE']


def _validate_column_name(name):
    if name != '*':
        validate_path(name)  # This is for STIX object paths, not column names...


def _validate_column(col):
    if isinstance(col, str):
        _validate_column_name(col)
    elif isinstance(col, Column):
        _validate_column_name(col.name)
        if col.table:
            validate_name(col.table)
        if col.alias:
            validate_path(col.alias)


class InvalidComparisonOperator(Exception):
    pass


class InvalidPredicateOperator(Exception):
    pass


class InvalidJoinOperator(Exception):
    pass


class InvalidAggregateFunction(Exception):
    pass


class InvalidQuery(Exception):
    pass


def _quote(obj):
    """Double-quote an SQL identifier if necessary"""
    if isinstance(obj, str):
        if obj == '*':
            return obj
        return f'"{obj}"'
    return str(obj)


class Column:
    """SQL Column name"""

    def __init__(self, name, table=None, alias=None):
        _validate_column_name(name)
        if table:
            validate_name(table)
        if alias:
            validate_path(alias)
        self.name = name
        self.table = table
        self.alias = alias

    def __str__(self):
        if self.table:
            result = f'"{self.table}".{_quote(self.name)}'
        else:
            result = f'{_quote(self.name)}'
        if self.alias:
            result = f'{result} AS "{self.alias}"'
        return result

    def endswith(self, s):
        return str(self).endswith(s)


class CoalescedColumn:
    """First non-null column from a list - used after a JOIN"""

    def __init__(self, names, alias):
        for name in names:
            _validate_column_name(name)
        validate_path(alias)
        self.names = names
        self.alias = alias

    def __str__(self):
        result = ', '.join([name for name in self.names])
        result = f'COALESCE({result}) AS "{self.alias}"'
        return result


class Predicate:
    """Simple row value predicate"""

    def __init__(self, lhs, op, rhs):
        if op not in COMP_OPS:
            raise InvalidComparisonOperator(op)
        if rhs is None:
            rhs = 'NULL'
        if lhs.endswith('[*]'):  # STIX list property
            lhs = lhs[:-3]
            if rhs.lower() != 'null':
                rhs = f"%{rhs}%"  # wrap with SQL wildcards since list is encoded as string
                if op == '=':
                    op = 'LIKE'
                elif op == '!=':
                    op = 'NOT LIKE'
        if isinstance(lhs, str):
            validate_path(lhs)
        self.lhs = lhs
        self.op = op
        self.rhs = rhs
        if self.rhs in ['null', 'NULL']:
            self.values = ()
            if op not in ['=', '!=', '<>', 'IS', 'IS NOT']:
                raise InvalidComparisonOperator(op)  # Maybe need different exception here?
        elif isinstance(self.rhs, (list, tuple)):
            self.values = tuple(self.rhs)
        elif isinstance(self.rhs, Column):
            self.values = tuple()
        else:
            self.values = (self.rhs, )

    def render(self, placeholder):
        if self.rhs in ['null', 'NULL']:
            if self.op in ['!=', '<>']:
                text = f'({_quote(self.lhs)} IS NOT NULL)'
            elif self.op == '=':
                text = f'({_quote(self.lhs)} IS NULL)'
            else:
                raise InvalidComparisonOperator(self.op)
        elif isinstance(self.rhs, Column):
            text = f'({_quote(self.lhs)} {self.op} {_quote(self.rhs)})'
        elif self.op == 'IN':
            phs = ', '.join([placeholder] * len(self.rhs))
            text = f'({_quote(self.lhs)} {self.op} ({phs}))'
        else:
            text = f'({_quote(self.lhs)} {self.op} {placeholder})'
        return text


class Filter:
    """Alternative SQL WHERE clause"""

    OR = ' OR '
    AND = ' AND '

    def __init__(self, preds, op=AND):
        self.preds = preds
        self.op = op
        self.values = ()
        for pred in self.preds:
            self.values += pred.values

    def render(self, placeholder):
        pred_list = []
        for pred in self.preds:
            pred_list.append(pred.render(placeholder))
        result = self.op.join(pred_list)
        if self.op == Filter.OR:
            return f'({result})'
        return result


class Order:
    """SQL ORDER BY clause"""

    ASC = 'ASC'
    DESC = 'DESC'

    def __init__(self, cols):
        self.cols = []
        for col in cols:
            if isinstance(col, tuple):
                validate_path(col[0])
                self.cols.append(col)
            elif isinstance(col, str):
                validate_path(col)
                self.cols.append((col, Order.ASC))

    def render(self, placeholder):
        col_list = []
        for col in self.cols:
            col_list.append(f'"{col[0]}" {col[1]}')
        return ', '.join(col_list)


class Projection:
    """SQL SELECT (really projection - pick column subset) clause"""
    def __init__(self, cols):
        for col in cols:
            _validate_column(col)
        self.cols = cols

    def render(self, placeholder):
        return ', '.join([_quote(col) for col in self.cols])


class Table:
    """SQL Table selection"""

    def __init__(self, name):
        validate_name(name)
        self.name = name

    def render(self, placeholder):
        return self.name


class Group:
    """SQL GROUP clause"""

    def __init__(self, cols):
        for col in cols:
            _validate_column(col)
        self.cols = cols

    def render(self, placeholder):
        cols = []
        for col in self.cols:
            if isinstance(col, Column):  # Again, nasty hacks
                if col.table:
                    cols.append(f'{col.table}"."{col.name}')
                else:
                    cols.append(col.name)
            else:
                cols.append(col)
        return ', '.join([_quote(col) for col in cols])


class Aggregation:
    """Aggregate rows"""

    def __init__(self, aggs):
        self.aggs = []
        for agg in aggs:
            if isinstance(agg, tuple):
                if len(agg) == 3:
                    func, col, alias = agg
                elif len(agg) == 2:
                    func, col = agg
                    alias = None
                if func.upper() not in AGG_FUNCS:
                    raise InvalidAggregateFunction(func)
                if col is not None and col != '*':
                    _validate_column(col)
                self.aggs.append((func, col, alias))
            else:
                raise TypeError('expected aggregation tuple but received ' + str(type(agg)))
        self.group_cols = []  # Filled in by Query

    def render(self, placeholder):
        exprs = [_quote(col) for col in self.group_cols]
        for agg in self.aggs:
            mod = ''
            func, col, alias = agg
            if func.upper() == 'NUNIQUE':
                func = 'COUNT'
                mod = 'DISTINCT '
            if not col:
                col = '*'
            if col == '*':
                expr = f'{func}({mod}{col})'  # No quotes for *
            else:
                expr = f'{func}({mod}"{col}")'
            if not alias:
                alias = func.lower()
            expr += f' AS "{alias}"'
            exprs.append(expr)
        return ', '.join(exprs)


class Offset:
    """SQL row offset"""

    def __init__(self, num):
        self.num = int(num)

    def render(self, placeholder):
        return str(self.num)


class Limit:
    """SQL row count"""

    def __init__(self, num):
        self.num = int(num)

    def render(self, placeholder):
        return str(self.num)


class Count:
    """Count the rows in a result set"""

    def __init__(self):
        pass

    def render(self, placeholder):
        return 'COUNT(*) AS "count"'


class Unique:
    """Reduce the rows in a result set to unique tuples"""

    def __init__(self):
        pass

    def render(self, placeholder):
        return 'SELECT DISTINCT *'


class CountUnique:
    """Unique count of the rows in a result set"""

    def __init__(self, cols=None):
        for col in cols or []:
            _validate_column(col)
        self.cols = cols

    def render(self, placeholder):
        if self.cols:
            cols = ', '.join([f'"{col}"' for col in self.cols])
            return f'COUNT(DISTINCT {cols}) AS "count"'
        return 'COUNT(*) AS "count"'


class Join:
    """Join 2 tables"""

    def __init__(self, name,
                 left_col=None, op=None, right_col=None,
                 preds=None,
                 how='INNER', alias=None, lhs=None):
        """
        Use *either* `left_col`, `op`, and `right_col` or `preds`
        """
        validate_name(name)
        if all((left_col, op, right_col)):
            _validate_column(left_col)
            _validate_column(right_col)
        if alias:
            validate_name(alias)
        if lhs:
            validate_name(name)
        if how.upper() not in JOIN_TYPES:
            raise InvalidJoinOperator(how)
        self.prev_name = lhs  # If none, filled in by Query
        self.name = name
        self.left_col = left_col
        self.op = op
        self.right_col = right_col
        self.how = how
        self.alias = alias
        self.values = tuple()
        self.preds = preds
        if preds:
            for pred in self.preds:
                self.values += pred.values

    def __repr__(self):
        return f'Join({self.name}, {self.left_col}, {self.op}, {self.right_col}, {self.how}, {self.alias}, {self.prev_name})'

    def __eq__(self, rhs):
        return (
            self.prev_name == rhs.prev_name and
            self.name == rhs.name and
            self.left_col == rhs.left_col and
            self.op == rhs.op and
            self.right_col == rhs.right_col and
            self.how == rhs.how and
            self.alias == rhs.alias)

    def render(self, placeholder):
        # Assume there's a FROM before this?
        target = f'"{self.name}"'
        table = target
        if self.alias:
            target += f' AS "{self.alias}"'
            table = f'"{self.alias}"'
        if self.left_col:
            cond = (f'"{self.prev_name}"."{self.left_col}"'
                    f' {self.op} {table}."{self.right_col}"')
        else:
            pred_list = []
            for pred in self.preds:
                tmp = pred.render(placeholder)
                pred_list.append(tmp)
            cond = ' AND '.join(pred_list)
        return f'{self.how.upper()} JOIN {target} ON {cond}'


class Query:
    def __init__(self, arg=None):
        self.stages = []
        self.tables = []  # Treat like a stack
        if isinstance(arg, str):
            self.append(Table(arg))
        elif isinstance(arg, list):
            for stage in arg:
                self.append(stage)

    def last_stage(self):
        return self.stages[-1] if self.stages else None

    def append(self, stage):
        if isinstance(stage, Aggregation):
            # If there's already a Projection, that's an error
            for prev in self.stages:
                if isinstance(prev, Projection):
                    raise InvalidQuery('cannot have Aggregation after Projection')
            if self.stages:
                last = self.last_stage()
                if isinstance(last, Group):
                    stage.group_cols = last.cols  # Copy grouped columns
        elif isinstance(stage, Join):
            # Need to look back and grab previous table name
            last = self.last_stage()
            if isinstance(last, Join):
                if last == stage:
                    return  # It's redundant
            if isinstance(last, (Table, Join)):  #TODO: use table stack
                if not stage.prev_name:
                    stage.prev_name = last.name
            else:
                raise InvalidQuery('Join must follow Table or Join')
        elif isinstance(stage, Count):
            # See if we can combine with previous stages
            last = self.last_stage()
            if isinstance(last, Unique):
                self.stages.pop(-1)
                cols = None
                if self.stages:
                    last = self.last_stage()
                    if isinstance(last, Projection):
                        proj = self.stages.pop(-1)
                        cols = proj.cols
                stage = CountUnique(cols)
        elif isinstance(stage, CountUnique):
            # See if we can combine with previous stages
            last = self.last_stage()
            if isinstance(last, Projection):
                self.stages.pop(-1)
                stage.cols = last.cols
        elif isinstance(stage, Table):
            self.tables.append(stage.name)
        self.stages.append(stage)

    def extend(self, stages):
        for stage in stages:
            self.append(stage)

    def render(self, placeholder):
        if not self.tables:
            raise InvalidQuery("no table")  #TODO: better message
        query = ''
        values = ()
        prev = None  # TODO: Probably need state machine here
        for stage in self.stages:
            text = stage.render(placeholder)
            if isinstance(stage, Table):
                query = f'FROM "{text}"'
            elif isinstance(stage, Projection):
                query = f'SELECT {text} {query}'
            elif isinstance(stage, Filter):
                values += stage.values
                if isinstance(prev, Aggregation):
                    keyword = 'HAVING'
                elif isinstance(prev, Filter):
                    keyword = 'AND'
                else:
                    keyword = 'WHERE'
                query = f'{query} {keyword} {text}'
            elif isinstance(stage, Group):
                query = f'{query} GROUP BY {text}'
            elif isinstance(stage, Aggregation):
                query = f'SELECT {text} {query}'
            elif isinstance(stage, Order):
                query = f'{query} ORDER BY {text}'
            elif isinstance(stage, Limit):
                query = f'{query} LIMIT {text}'
            elif isinstance(stage, Offset):
                query = f'{query} OFFSET {text}'
            elif isinstance(stage, Count):
                if isinstance(prev, Unique):
                    # Should have already been combined, so we should never hit this
                    query = f'SELECT {text} FROM ({query}) AS tmp'
                else:
                    query = f'SELECT {text} {query}'
            elif isinstance(stage, Unique):
                if query.startswith('SELECT '):
                    query = re.sub(r'^SELECT ', 'SELECT DISTINCT ', query)
                else:
                    query = f'SELECT DISTINCT * {query}'
            elif isinstance(stage, Join):
                values += stage.values
                query = f'{query} {text}'
            elif isinstance(stage, CountUnique):
                if stage.cols:
                    query = f'SELECT {text} {query}'
                else:
                    query = f'SELECT {text} FROM (SELECT DISTINCT * {query}) AS tmp'
            prev = stage
        # If there's no projection...
        if not query.startswith('SELECT'):  # Hacky
            query = 'SELECT * ' + query
        return query, values
