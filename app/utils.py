import requests
import pycountry


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
