import logging
import re
from typing import Optional
import operator
from datetime import datetime

import requests
import pycountry

from django.db.models import Q, Model, fields
from rest_framework import exceptions, status
from rest_framework.views import exception_handler

errors_logger = logging.getLogger('errors_log')

supported_operations = {
    'eq', 'ieq', 'ne', 'ine', 'gt', 'gte', 'lt', 'lte', 'in', 'range', 'isnull', 'date'
}

lookup_mappings = {
    'eq': 'exact',
    'ieq': 'iexact',
    'ne': 'exact',  # use as ~Q()
    'ine': 'iexact',  # use as ~Q()
}

models_remote_fields = {
    'USER': (),
    'MEAL': ('country', ),
    'FAVOURITEMEAL': ('country', 'calories', 'type', 'title', )
}

models_foreign_keys_of_remote_fields = {
    'USER': {},
    'MEAL': {
        'country': 'owner'
    },
    'FAVOURITEMEAL': {
        'country': 'user',
        'calories': 'meal',
        'type': 'meal',
        'title': 'meal'
    },
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
        except KeyError:
            calories = 0

        if not isinstance(calories, (float, int)):
            calories = 0

        calories = max(0, calories)
    else:
        calories = 0

    return calories


def get_country(country_code: str = ''):
    if not isinstance(country_code, str):
        country = None
    else:
        country = pycountry.countries.get(alpha_3=country_code.upper())
    return country


def check_required_params(required_params, request_data):
    # allow 0 (zero) but not allow '' (empty string)
    m = map(lambda x: x in request_data and request_data.get(x) is not None and len(str(request_data.get(x))), required_params)
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
        if isinstance(response.data, dict):
            for data in response.data.values():
                if isinstance(data, (list, tuple)):
                    for d in data:
                        details['details'].append(d)
                else:
                    details['details'].append(data)
        elif isinstance(response.data, (list, tuple)):
            for data in response.data:
                if isinstance(data, (list, tuple)):
                    for d in data:
                        details['details'].append(d)
                else:
                    details['details'].append(data)
        response.data = details

    errors_logger.error('Error', exc_info=exc)

    return response


def model_fields_to_list(model: Model) -> list:
    if model._meta.model_name.upper() == 'USER':
        fields_list = ['id', 'username', 'first_name', 'last_name', 'last_name', 'role', 'country']
    else:
        fields_list = [field.attname for field in model._meta.fields]
    return fields_list


def string_to_datetime_or_int(s: str or int) -> Optional[datetime or str]:
    '''
    Parse string to datetime,

    supported formats: ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d.%m.%Y', '%d.%m.%Y %H:%M:%S', %d/%m/%Y', '%d/%m/%Y %H:%M:%S']

    :param s: string to parse
    :return: datetime
    '''
    if not s:
        return None

    for fmt in ("'%Y-%m-%d'", "'%Y-%m-%d %H:%M:%S'", "'%d.%m.%Y'", "'%d.%m.%Y %H:%M:%S'", "'%d/%m/%Y'", "'%d/%m/%Y %H:%M:%S'"):
        try:
            return datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            pass

    return s


def string_to_bool(s: str) -> Optional[bool or str]:
    '''
    Parse string to boolean,

    :param s: string to parse
    :return: boolean
    '''
    if not s:
        return None

    s = True if s.lower() == 'true' else False if s.lower() == 'false' else s

    return s


def string_to_list(s: str) -> Optional[list or str]:
    '''
    Parse string to tuple,

    :param s: string to parse
    :return: list
    '''
    if not s:
        return None

    s = s[1:-1]  # remove [] brackets
    result_list = []
    for item in s.split(','):
        if item:
            result_list.append(item.strip())
    return result_list


def string_to_q(s: str, model: Model) -> Optional[Q]:
    # s must be in the form: field_name operation value.
    # Ex: "date eq '2016-05-01'", "calories gt 40", "calories range [30, 60]" and so on
    s = s.strip()
    s_list = s.split(' ', 2)
    if len(s_list) != 3:
        return None

    field_name = s_list[0].lower()
    original_field_name = field_name
    operation_original = s_list[1].lower()
    value = s_list[2].strip()
    if operation_original not in supported_operations:
        return None

    operation = lookup_mappings[operation_original] if operation_original in lookup_mappings else operation_original

    model_fields = model_fields_to_list(type(model)())

    if field_name not in model_fields:
        model_name = model._meta.model_name.upper()
        try:
            if field_name in models_remote_fields[model_name]:
                # ForeignKey field
                remote_model = model._meta.get_field(models_foreign_keys_of_remote_fields[model_name][field_name]).remote_field.model()
                if field_name not in model_fields_to_list(remote_model):
                    return None
                else:
                    model = remote_model
                    field_name = f'{models_foreign_keys_of_remote_fields[model_name][field_name]}__{field_name}'
            else:
                return None
        except (KeyError, AttributeError, TypeError):
            return None

    if operation not in model._meta.get_field(original_field_name).get_lookups():
        return None

    if operation in ('isnull',):
        value = string_to_bool(value)
        if not isinstance(value, bool):
            return None
    elif operation in ('in', 'range'):
        value = string_to_list(value)
        if value:
            if operation == 'range' and len(value) != 2:
                return None
        else:
            return None

        if isinstance(model._meta.get_field(original_field_name), (fields.DateTimeField, fields.DateField)):
            new_value_list = []
            for v in value:
                v = string_to_datetime_or_int(v)
                if not v:
                    return None
                new_value_list.append(v)
            value = new_value_list

    else:
        if isinstance(model._meta.get_field(original_field_name), (fields.DateTimeField, fields.DateField)):
            value = string_to_datetime_or_int(value)
            if not value:
                return None

    q_params = {f'{field_name}__{operation}': value}

    q = Q(**q_params)
    if operation_original in ('ne', 'ine'):
        q = ~q
    return q


def filter_query_to_q(query: str, model: Model) -> Optional[Q]:
    q_list = []
    result_q_object = None
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
                        q_l = filter_query_to_q(query[start + 1: i], type(model)())
                        if q_l:
                            q_list.append(q_l)
                        else:
                            q_list = None
                            break
                        recursive = False
                    else:
                        continue
                else:
                    q = string_to_q(query[start + 1: i], type(model)())
                    if q:
                        q_list.append(q)
                    else:
                        q_list = None
                        break

                next_operation = query_upper[i + 1: i + 5].strip()
                if next_operation in (AND, OR, ''):
                    operation = next_operation
                else:
                    q_list = None
                    break

                if operation in (AND, OR):
                    q_list.append(operation)
                else:
                    break
                    # finish end of query
    if q_list:
        i = 0
        while len(q_list) > 1 and i <= len(q_list) - 1:
            # first execute AND operations
            q = q_list[i]
            if isinstance(q, str):
                if q == AND:
                    try:
                        if isinstance(q_list[i-1], Q) and isinstance(q_list[i+1], Q):
                            q_list[i-1:i+2] = [operator.and_(q_list[i-1], q_list[i+1])]
                            i = 0
                            continue
                    except IndexError:
                        return None
            i += 1

        i = 0
        while len(q_list) > 1 and i <= len(q_list) - 1:
            # then execute OR operations
            q = q_list[i]
            if isinstance(q, str):
                if q == OR:
                    try:
                        if isinstance(q_list[i - 1], Q) and isinstance(q_list[i + 1], Q):
                            q_list[i - 1:i + 2] = [operator.or_(q_list[i - 1], q_list[i + 1])]
                            i = 0
                            continue
                    except IndexError:
                        return None
            i += 1

        result_q_object = q_list[0]
    else:
        if isinstance(q_list, list):
            result_q_object = string_to_q(query, type(model)())

    return result_q_object
