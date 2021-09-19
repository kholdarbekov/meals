from django.test import TestCase
from ..utils import *
from ..models import Meal


class UtilsTest(TestCase):

    def test_get_calories_from_api(self):
        self.assertEqual(get_calories_from_api('potato'), 160.89)
        self.assertEqual(get_calories_from_api('Not Found meal'), 0)

    def test_get_country(self):
        country = get_country('UZB')
        self.assertEqual(country.name, 'Uzbekistan')

        country2 = get_country('WWW')
        self.assertIsNone(country2)

    def test_check_required_params(self):
        required_params = ('a', 'b', 'c')
        request_data = {'a': 1}
        with self.assertRaises(exceptions.ValidationError):
            check_required_params(required_params, request_data)

        required_params2 = ('a', 'b', 'c')
        request_data2 = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
        self.assertIsNone(check_required_params(required_params2, request_data2))

    def test_check_optional_params(self):
        optional_params = ('a', 'b', 'c')
        request_data = {'d': 1}
        with self.assertRaises(exceptions.ValidationError):
            check_optional_params(optional_params, request_data)

        optional_params2 = ('a', 'b', 'c')
        request_data2 = {'a': 1, 'd': 2}
        self.assertIsNone(check_optional_params(optional_params2, request_data2))

    def test_model_fields_to_list(self):
        meal_fields_from_function = model_fields_to_list(Meal())
        actual_meal_fields = [field.attname for field in Meal()._meta.fields]

        for field in actual_meal_fields:
            self.assertIn(field, meal_fields_from_function)

        for field in meal_fields_from_function:
            self.assertIn(field, actual_meal_fields)

    def test_string_to_bool(self):
        self.assertTrue(string_to_bool('True'))
        self.assertFalse(string_to_bool('False'))
        self.assertIsNone(string_to_bool(''))
        self.assertEqual(string_to_bool('another'), 'another')

    def test_string_to_list(self):
        self.assertListEqual(string_to_list('[1,2,3]'), ['1', '2', '3'])
        self.assertIsNone(string_to_list(''))
        self.assertIsNone(string_to_list('[1,2'))
        self.assertListEqual(string_to_list('[]'), [])
        self.assertListEqual(string_to_list('[,]'), [])

    def test_string_to_q(self):
        self.assertEqual(string_to_q('calories gt 20', Meal()), Q(calories__gt='20'))

    def test_filter_query_to_q(self):
        q = filter_query_to_q("(created_date eq '2021-09-20') AND ((calories gt 20) OR (calories lt 10))", Meal())
        q_or = operator.or_(Q(calories__gt='20'), Q(calories__lt='10'))
        q_and = operator.and_(Q(created_date__exact=datetime(2021, 9, 20)), q_or)
        self.assertEqual(q, q_and)
