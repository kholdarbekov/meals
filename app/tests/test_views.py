from django.core.exceptions import ObjectDoesNotExist
from rest_framework.test import APITestCase, APIClient
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.urls import reverse

from ..models import User
from ..serializers import UserSerializer

api_admin_client = APIClient()
api_moderator_client = APIClient()
api_regular_client = APIClient()


class UserTest(APITestCase):

    @classmethod
    def setUpTestData(cls):
        u_admin = User.objects.create_superuser(username='admin', password='password1234567', country='UZB', role=User.ADMIN)
        u_moderator = User.objects.create_superuser(username='moderator', password='password1234567', country='UZB', role=User.MODERATOR)
        u_regular = User.objects.create_superuser(username='regular', password='password1234567', country='UZB', role=User.REGULAR_USER)

        token, created = Token.objects.get_or_create(user=u_admin)
        api_admin_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        token, created = Token.objects.get_or_create(user=u_moderator)
        api_moderator_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        token, created = Token.objects.get_or_create(user=u_regular)
        api_regular_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        User.objects.create_user(username='test_user1', password='password1234567', country='UZB', role=User.REGULAR_USER)
        User.objects.create_user(username='test_user2', password='password1234567', country='UZB', role=User.REGULAR_USER)
        User.objects.create_user(username='test_user3', password='password1234567', country='UZB', role=User.REGULAR_USER)
        User.objects.create_user(username='test_user4', password='password1234567', country='UZB', role=User.REGULAR_USER)

    def test_login(self):
        # e2e test
        response = api_regular_client.post(reverse('user_login'), data={'username': 'test_user1', 'password': 'password1234567'}, format='json')

        user = User.objects.get(username='test_user1')
        token, created = Token.objects.get_or_create(user=user)
        self.assertEqual(response.data['token'], token.key)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_register(self):
        # e2e test
        response = api_regular_client.post(reverse('user_register'),
                                           data={'username': 'test_user5',
                                                 'password': 'password1234567',
                                                 'country': 'UZB',
                                                 'role': '1',
                                                 'first_name': 'fname',
                                                 'last_name': 'lname'},
                                           format='json')

        user = User.objects.get(username='test_user5')
        self.assertIsNotNone(response.data['token'])
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_update(self):
        # e2e test
        response = api_regular_client.put(reverse('user_update'),
                                          data={
                                              'first_name': 'new name',
                                              'last_name': 'new last name'},
                                          format='json')

        user = User.objects.get(username='regular')
        serializer = UserSerializer(user, many=False)
        self.assertEqual(serializer.data, response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete(self):
        # e2e test
        response = api_moderator_client.delete(reverse('user_delete'), data={'username': 'test_user4'}, format='json')
        with self.assertRaises(ObjectDoesNotExist):
            _ = User.objects.get(username='test_user4')

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_get_all_users(self):
        # e2e test
        response = api_moderator_client.get(reverse('users_list'), format='json')
        users = User.objects.filter(role=User.REGULAR_USER)
        serializer = UserSerializer(users, many=True)
        self.assertEqual(response.data['results'], serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
