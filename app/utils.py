import logging
import re
from typing import Optional, Union
import operator

import requests
import pycountry
from django.db.models import Q
from rest_framework import exceptions, status
from rest_framework.views import exception_handler

errors_logger = logging.getLogger('errors_log')

mappings = {
    ' eq ': ' = ',
    ' ne ': ' != ',
    ' gt ': ' > ',
    ' lt ': ' < ',
    ' gte ': ' >= ',
    ' lte ': ' <= ',
}

filter_mappings = {
    'eq': 'exact',
    'ne': 'exact',  # use as ~Q()
}

models_filter_fields = {
    'USER': ('username', 'role', 'country', 'first_name', 'last_name'),
    'MEAL': ('title', 'calories', 'type', 'public', 'created_date')
}

AND, OR = 'AND', 'OR'


def get_calories_from_api(food=''):
    url = 'https://trackapi.nutritionix.com/v2/natural/nutrients'
    payload = {'query': food}
    headers = {'x-app-id': '5ea661b2', 'x-app-key': '47dfe4088b3f3c20bf6df76f7130e986', 'x-remote-user-id': '0'}
    response = requests.post(url, data=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        try:
            calories = data['foods'][0]['nf_calories']
        except KeyError as e:
            calories = 0
    else:
        calories = 0

    return calories


def get_country(country_code=''):
    if not isinstance(country_code, str):
        country = None
    else:
        country = pycountry.countries.get(alpha_3=country_code.upper())
    return country


def check_required_params(required_params, request_data):
    m = map(lambda x: x in request_data and request_data.get(x), required_params)
    if not all(m):
        exc = exceptions.APIException(f'request must contain {required_params}')
        exc.status_code = status.HTTP_400_BAD_REQUEST
        raise exc


def check_optional_params(optional_params, request_data):
    m = map(lambda x: x in request_data and request_data.get(x), optional_params)
    if not any(m):
        exc = exceptions.APIException(f'request must contain at least on of {optional_params} parameters')
        exc.status_code = status.HTTP_400_BAD_REQUEST
        raise exc


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first, to get the standard error response.
    response = exception_handler(exc, context)

    # Now add the HTTP status code to the response.
    if response is not None:
        details = dict()
        details['details'] = list()
        for data in response.data.values():
            if isinstance(data, (list, tuple)):
                for d in data:
                    details['details'].append(d)
            else:
                details['details'].append(data)
        response.data = details

    errors_logger.error('Error', exc_info=exc)

    return response


def filter_query_convert(query):
    if query and isinstance(query, str):
        pattern_drop = re.compile(r"drop\s+table\s*\w*")
        pattern_alter = re.compile(r"alter\s+table\s+\w+")
        pattern_delete = re.compile(r"delete\s+from\s+\w+")
        pattern_update = re.compile(r"update\s+\w+\s+set\s+\w+")
        pattern_insert = re.compile(r"insert\s+into\s+\w+")
        pattern_select = re.compile(r"select\s+\w+\s+from\s+")
        query_lower = query.lower()
        if '--' in query_lower or '/*' in query_lower or \
                pattern_drop.match(query_lower) or pattern_alter.match(query_lower) or \
                pattern_update.match(query_lower) or pattern_insert.match(query_lower) or \
                pattern_delete.match(query_lower) or pattern_select.match(query_lower):
            return None
        for expression, operation in mappings.items():
            query = query.replace(expression, operation)

    return query


def string_to_q(s: str, model: str) -> Optional[Q]:
    s_list = s.split(' ', 2)
    if s_list[0] not in models_filter_fields[model]:
        return None
    s_list[1] = s_list[1].lower()
    q_params = {f'{s_list[0]}__{filter_mappings[s_list[1]] if s_list[1] in filter_mappings else s_list[1]}': s_list[2]}
    q = Q(**q_params)
    if s_list[1] == 'ne':
        q = ~q
    return q


def filter_query_to_q(query: str, model: str) -> Optional[list]:
    q_list = []
    stack = []
    query = query.strip()
    query_upper = query.upper()
    recursive = False
    for i, c in enumerate(query):
        if c == '(':
            if len(stack) > 0:
                recursive = True
            stack.append(i)
            continue
        if c == ')':
            if len(stack) == 0:
                # wrong formatted query parenthesis
                q_list = None
                break
            else:
                start = stack.pop()
                if recursive:
                    if len(stack) == 0:
                        q_l = filter_query_to_q(query[start + 1: i], model)
                        if q_l:
                            q_list.append(q_l)
                        recursive = False
                else:
                    q = string_to_q(query[start + 1: i], model)
                    q_list.append(q)

                    if AND in query_upper[i + 1: i + 6]:
                        operation = AND
                    elif OR in query_upper[i + 1: i + 6]:
                        operation = OR
                    else:
                        operation = ''

                    #operation = ('AND' if 'AND' in query_upper[i + 1: i + 6] else 'OR' if 'OR' in query_upper[i + 1: i + 6] else '')

                    if operation in (AND, OR):
                        q_list.append(operation)
                    else:
                        break
                        # finish end of query
    i = 0
    while len(q_list) > 1 and i <= len(q_list) - 1:
        # first execute AND operations
        q = q_list[i]
        if isinstance(q, str):
            if q == AND:
                if isinstance(q_list[i-1], Q) and isinstance(q_list[i+1], Q):
                    q_list[i-1:i+2] = [operator.and_(q_list[i-1], q_list[i+1])]
                    i = 0
                    continue
        i += 1

    i = 0
    while len(q_list) > 1 and i <= len(q_list) - 1:
        # then execute OR operations
        q = q_list[i]
        if isinstance(q, str):
            if q == OR:
                if isinstance(q_list[i - 1], Q) and isinstance(q_list[i + 1], Q):
                    q_list[i - 1:i + 2] = [operator.or_(q_list[i - 1], q_list[i + 1])]
                    i = 0
                    continue
        i += 1

    return q_list[0]
