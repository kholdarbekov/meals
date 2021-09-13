import requests
import pycountry
from rest_framework import exceptions, status
from rest_framework.views import exception_handler


mappings = {
    ' eq ': ' = ',
    ' ne ': ' != ',
    ' gt ': ' > ',
    ' lt ': ' < ',
    ' gte ': ' >= ',
    ' lte ': ' <= ',
}


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

    return response


def filter_query_convert(query):
    if query and isinstance(query, str):
        for expression, operation in mappings.items():
            query = query.replace(expression, operation)

    return query
