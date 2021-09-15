from django.test import TestCase
from ..models import User, Meal, FavouriteMeal


class UserTest(TestCase):
    """ Test module for User model """

    @classmethod
    def setUpTestData(cls):
        User.objects.create_user(username='test_user1', password='password1234567', country='UZB', role=User.REGULAR_USER)

    def test_user_authenticate(self):
        # unit test
        usr1 = User.objects.get(username='test_user1')
        result = usr1.check_password('password1234567')
        self.assertTrue(result)

    def test_user_check_info(self):
        # unit test
        usr1 = User.objects.get(username='test_user1')
        self.assertEqual(usr1.role, User.REGULAR_USER)
        self.assertEqual(usr1.country, 'UZB')

    def test_user_create_superuser(self):
        # unit test
        superuser1 = User.objects.create_superuser(username='admin', password='password1234567', country='UZB')
        self.assertEqual(superuser1.role, User.ADMIN)
        self.assertEqual(superuser1.country, 'UZB')
        self.assertTrue(superuser1.is_superuser)
        self.assertTrue(superuser1.is_staff)

    def test_create_user_blank_values(self):
        # unit test
        with self.assertRaises(ValueError):
            _ = User.objects.create_user(username='', password='password1234567', country='UZB')

        with self.assertRaises(ValueError):
            _ = User.objects.create_user(username='user1', password='password1234567', country='')

        with self.assertRaises(ValueError):
            _ = User.objects.create_user(username='user1', password='', country='UZB')

        with self.assertRaises(ValueError):
            _ = User.objects.create_user(username='', password='', country='')


class MealTest(TestCase):
    """ Test module for Meal model """

    @classmethod
    def setUpTestData(cls):
        u1 = User.objects.create_user(username='test_user1', password='password1234567', country='UZB', role=User.REGULAR_USER)
        Meal.objects.create(title='Sandwich', calories=100, type=Meal.LUNCH, owner=u1, public=True)

    def test_meal_title_and_calories(self):
        # unit test
        meal = Meal.objects.get(title='Sandwich')
        self.assertEqual(str(meal), 'Sandwich')
        self.assertEqual(meal.calories, 100)

    def test_meal_owner(self):
        # unit test
        meal = Meal.objects.get(title='Sandwich')
        u1 = User.objects.get(username='test_user1')
        self.assertEqual(meal.owner, u1)


class FavouriteMealTest(TestCase):
    """ Test module for FavouriteMeal model """

    @classmethod
    def setUpTestData(cls):
        u1 = User.objects.create_user(username='test_user1', password='password1234567', country='UZB', role=User.REGULAR_USER)
        m1 = Meal.objects.create(title='Sandwich', calories=100, type=Meal.LUNCH, owner=u1, public=True)
        FavouriteMeal.objects.create(meal=m1, user=u1)

    def test_favourite(self):
        # unit test
        u1 = User.objects.get(username='test_user1')
        m1 = Meal.objects.get(title='Sandwich')
        self.assertTrue(u1.favourites.filter(meal=m1))

    def test_string_method(self):
        # unit test
        f1 = FavouriteMeal.objects.last()
        self.assertEqual(str(f1), 'test_user1 favorites Sandwich')
