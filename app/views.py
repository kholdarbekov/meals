import logging
import operator

from django.core.exceptions import ObjectDoesNotExist
from django.db import models, DatabaseError

from rest_framework import generics, status, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .serializers import UserSerializer, UserRegisterSerializer, UserUpdateSerializer, UserPasswordUpdateSerializer, UserDetailsSerializer, \
    MealListSerializer, MealCreateSerializer, MealUpdateSerializer, \
    FavouriteMealCreateSerializer, FavouriteMealListSerializer, FavouriteMealUpdateSerializer
from .models import User, Meal, FavouriteMeal
from .utils import check_required_params, check_optional_params, filter_query_to_q, supported_operations
from .permissions import IsAdminOrModeratorUser, IsAdminOrRegularUser


logger = logging.getLogger('app_log')


class ModelsDetailsView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        models_details = {}
        for model in (Meal(), FavouriteMeal()):
            model_name = model._meta.model_name.upper()
            models_details[model_name] = {}
            for field in (field.attname for field in model._meta.fields):
                models_details[model_name][field] = []
                for lookup in model._meta.get_field(field).get_lookups():
                    if lookup == 'exact':
                        lookup = ['eq', 'ne']
                    elif lookup == 'iexact':
                        lookup = ['ieq', 'ine']

                    if isinstance(lookup, str):
                        if lookup in supported_operations:
                            models_details[model_name][field].append(lookup)
                    elif isinstance(lookup, list):
                        models_details[model_name][field].extend(lookup)

        models_details['USER'] = {
            'id': ["eq", "ne", "ieq", "ine", "gt", "gte", "lt", "lte", "in", "range", "isnull"],
            'username': ["eq", "ne", "ieq", "ine", "gt", "gte", "lt", "lte", "in", "range", "isnull"],
            'first_name': ["eq", "ne", "ieq", "ine", "gt", "gte", "lt", "lte", "in", "range", "isnull"],
            'last_name': ["eq", "ne", "ieq", "ine", "gt", "gte", "lt", "lte", "in", "range", "isnull"],
            'role': ["eq", "ne", "ieq", "ine", "gt", "gte", "lt", "lte", "in", "range", "isnull"],
            'country': ["eq", "ne", "ieq", "ine", "gt", "gte", "lt", "lte", "in", "range", "isnull"],
        }

        return Response(models_details)


class UserView(generics.GenericAPIView):

    def get_object(self):
        error_message = list()
        user = None
        try:
            if self.request.user.role != User.REGULAR_USER:
                username = self.request.data['username']
                user = User.objects.get(username=username, is_superuser=False, is_staff=False)
            else:
                user = self.request.user
                self.request.data['username'] = user.username
        except KeyError as key:
            error_message.append('{param} is not sent'.format(param=key))
        except ObjectDoesNotExist:
            error_message.append('User not found')
        except Exception as e:
            error_message.extend(e.args)

        if error_message:
            exc = exceptions.ValidationError(*error_message)
            raise exc

        return user


class MealView(generics.GenericAPIView):

    def get_object(self):
        error_message = list()
        meal = None
        try:
            meal_id = self.request.data['id']
            meal = Meal.objects.get(id=meal_id)
            if self.request.user.role == User.REGULAR_USER:
                if meal.owner != self.request.user:
                    error_message.append(f'Meal with id={meal_id} does not belong to you')

        except KeyError as key:
            error_message.append('{param} is not sent'.format(param=key))
        except ObjectDoesNotExist:
            error_message.append('Meal not found')
        except Exception as e:
            error_message.extend(e.args)

        if error_message:
            exc = exceptions.ValidationError(*error_message)
            raise exc

        return meal


class UserLoginView(ObtainAuthToken):
    permission_classes = [AllowAny, ]

    def post(self, request, *args, **kwargs):
        logger.info(f'UserLoginView: request.data={request.data}')
        required_params = ('username', 'password')
        check_required_params(required_params, request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        return Response({'token': token.key, 'role': user.role})


class UsersListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminOrModeratorUser]

    def get_queryset(self):
        list_errors = list()
        users = None

        roles = [User.REGULAR_USER]
        if self.request.user.role == User.ADMIN:
            roles += [User.MODERATOR, User.ADMIN]

        if self.request.data.get('query'):
            q = filter_query_to_q(self.request.data.get('query'), User())
            logger.info(f'UsersListView: user={self.request.user}, query={self.request.data.get("query")}, q={q}')
            if q:
                try:
                    users = User.objects.filter(q)
                except (TypeError, ValueError, DatabaseError):
                    list_errors.append('Error while executing query. Please check your input')
            else:
                list_errors.append('filter query is invalid')

            if list_errors:
                exc = exceptions.ValidationError(*list_errors)
                raise exc
        else:
            users = User.objects.all()

        if users:
            users = users.filter(role__in=roles)
            if not self.request.user.is_superuser:
                users = users.filter(is_superuser=False, is_staff=False)
        else:
            users = User.objects.none()

        return users


class UserDetailsView(UserView, generics.RetrieveAPIView):
    serializer_class = UserDetailsSerializer
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        logger.info(f'UserRetrieveView: user={request.user}, request.data={request.data}')
        if request.user.role != User.REGULAR_USER:
            required_params = ('username',)
            check_required_params(required_params, request.data)

        return super(UserDetailsView, self).get(request, *args, **kwargs)


class UserRegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny, ]

    def post(self, request, *args, **kwargs):
        logger.info(f'UserRegisterView: request.data={request.data}, request.user={request.user}')
        required_params = ('username', 'password', 'country')
        if request.user.is_authenticated:
            if request.user.role == User.ADMIN:
                required_params = ('username', 'password', 'country', 'role')
        check_required_params(required_params, request.data)
        return super(UserRegisterView, self).post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        kwargs = {'role': User.REGULAR_USER}
        if request.user.is_authenticated:
            if request.user.role == User.ADMIN:
                kwargs['role'] = request.data['role']
        self.perform_create(serializer, **kwargs)
        headers = self.get_success_headers(serializer.data)
        user = serializer.instance
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'role': user.role}, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer, **kwargs):
        serializer.save(**kwargs)


class UserUpdateView(UserView, generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        logger.info(f'UserUpdateView: user={request.user}, request.data={request.data}')
        if request.user.role != User.REGULAR_USER:
            required_params = ('username',)
            check_required_params(required_params, request.data)

        if request.user.role != User.ADMIN:
            try:
                # Only Admin can change user's role
                request.data.pop('role', None)
            except AttributeError:
                pass

        optional_params = ('first_name', 'last_name', 'country',)
        check_optional_params(optional_params, request.data)
        return super(UserUpdateView, self).put(request, *args, **kwargs)


class UserPasswordUpdateView(UserView, generics.UpdateAPIView):
    serializer_class = UserPasswordUpdateSerializer
    permission_classes = [IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        logger.info(f'UserPasswordUpdateView: user={request.user}, request.data={request.data}')
        if request.user.role != User.REGULAR_USER:
            required_params = ('username', 'password_old', 'password_new')
        else:
            required_params = ('password_old', 'password_new')
        check_required_params(required_params, request.data)
        return super(UserPasswordUpdateView, self).put(request, *args, **kwargs)


class UserDeleteView(UserView, generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, ]

    def delete(self, request, *args, **kwargs):
        logger.info(f'UserDeleteView: user={request.user}, request.data={request.data}')
        if request.user.role != User.REGULAR_USER:
            required_params = ('username',)
            check_required_params(required_params, request.data)
        return super(UserDeleteView, self).delete(request, *args, **kwargs)


class MealListView(generics.ListAPIView):
    serializer_class = MealListSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def get_queryset(self):
        list_errors = list()
        meals = None
        if self.request.data.get('query'):
            q = filter_query_to_q(self.request.data.get('query'), Meal())
            logger.info(f'MealListView: user={self.request.user}, query={self.request.data.get("query")}, q={q}')
            if q:
                try:
                    meals = Meal.objects.filter(q)
                except (TypeError, ValueError, DatabaseError):
                    list_errors.append('Error while executing query. Please check your input')

            else:
                list_errors.append('filter query is invalid')

            if list_errors:
                exc = exceptions.ValidationError(*list_errors)
                raise exc

        else:
            meals = Meal.objects.all()

        if meals:
            if self.request.user.role == User.REGULAR_USER:
                q_public_meals = models.Q(public=True)
                q_own_private_meals = models.Q(public=False, owner=self.request.user)
                q_meals = operator.or_(q_public_meals, q_own_private_meals)
                meals = meals.filter(q_meals)
        else:
            meals = Meal.objects.none()
        return meals


class MealCreateView(generics.CreateAPIView):
    serializer_class = MealCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def post(self, request, *args, **kwargs):
        logger.info(f'MealCreateView: user={request.user}, request.data={request.data}')
        required_params = ('title', 'type')
        check_required_params(required_params, request.data)
        if request.data.get('calories'):
            if float(request.data['calories']) < 0:
                raise exceptions.ValidationError('calories must be positive')
        return super(MealCreateView, self).post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        kwargs = {'owner': request.user}
        if request.user.role == User.ADMIN and request.data.get('user'):
            try:
                user = User.objects.get(username=request.data['user'], is_superuser=False, is_staff=False)
                kwargs['owner'] = user
            except ObjectDoesNotExist:
                exc = exceptions.ValidationError(f'User not found with username={request.data["user"]}')
                raise exc
        self.perform_create(serializer, **kwargs)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer, **kwargs):
        serializer.save(**kwargs)


class MealUpdateView(MealView, generics.UpdateAPIView):
    serializer_class = MealUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def put(self, request, *args, **kwargs):
        logger.info(f'MealUpdateView: user={request.user}, request.data={request.data}')
        required_params = ('id',)
        check_required_params(required_params, request.data)
        if request.data.get('calories'):
            if float(request.data['calories']) < 0:
                raise exceptions.ValidationError('calories must be positive')
        return super(MealUpdateView, self).put(request, *args, **kwargs)


class MealDeleteView(MealView, generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def delete(self, request, *args, **kwargs):
        logger.info(f'MealDeleteView: user={request.user}, request.data={request.data}')
        required_params = ('id',)
        check_required_params(required_params, request.data)
        return super(MealDeleteView, self).delete(request, *args, **kwargs)


class FavouriteMealCreateView(generics.CreateAPIView):
    serializer_class = FavouriteMealCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def post(self, request, *args, **kwargs):
        logger.info(f'FavouriteMealCreateView: user={request.user}, request.data={request.data}')
        if request.user.role != User.REGULAR_USER:
            required_params = ('user', 'meal')
        else:
            required_params = ('meal', )
        check_required_params(required_params, request.data)
        return super(FavouriteMealCreateView, self).post(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        error_message = list()
        meal = None
        user = None
        try:
            if request.user.role != User.REGULAR_USER:
                username = request.data['user']
                user = User.objects.get(username=username, is_superuser=False, is_staff=False)
            else:
                user = request.user
                request.data['user'] = user.username
        except ObjectDoesNotExist:
            error_message.append('User Not found')

        try:
            meal_id = request.data['meal']
            meal = Meal.objects.get(id=meal_id)
            if meal.owner != user:
                if not meal.public:
                    error_message.append('Meal is not public')
        except ObjectDoesNotExist:
            error_message.append('Meal Not found')

        if user:
            if user.favourites.filter(meal=meal):
                error_message.append('Meal is already in favourite list of this user')

        if error_message:
            exc = exceptions.ValidationError(*error_message)
            raise exc

        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        except Exception as e:
            return Response(data=e.args, status=status.HTTP_400_BAD_REQUEST)


class FavouriteMealDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def get_object(self):
        logger.info(f'FavouriteMealDeleteView: user={self.request.user}, request.data={self.request.data}')
        error_message = list()
        favourite = None
        try:
            favourite_id = self.request.data['id']
            favourite = FavouriteMeal.objects.get(id=favourite_id)
            if self.request.user.role == User.REGULAR_USER:
                if favourite.user != self.request.user:
                    error_message.append('Favourite does not belong to you')
        except KeyError as key:
            error_message.append('parameter {key} is not sent'.format(key=key))
        except ObjectDoesNotExist:
            error_message.append('Favourite not found')
        except Exception as e:
            error_message.extend(e.args)

        if error_message:
            exc = exceptions.ValidationError(*error_message)
            raise exc

        return favourite


class FavouriteMealListView(generics.ListAPIView):
    serializer_class = FavouriteMealListSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def get_queryset(self):
        list_errors = list()
        favourites = None
        if self.request.data.get('query'):
            q = filter_query_to_q(self.request.data.get('query'), FavouriteMeal())
            logger.info(f'FavouriteMealListView: user={self.request.user}, query={self.request.data.get("query")}, q={q}')
            if q:
                try:
                    favourites = FavouriteMeal.objects.filter(q)
                except (TypeError, ValueError, DatabaseError):
                    list_errors.append('Error while executing query. Please check your input')
            else:
                list_errors.append('filter query is invalid')

            if list_errors:
                exc = exceptions.ValidationError(*list_errors)
                raise exc
        else:
            favourites = FavouriteMeal.objects.all()

        if favourites:
            if self.request.user.role == User.REGULAR_USER:
                favourites = favourites.filter(user=self.request.user)
        else:
            favourites = FavouriteMeal.objects.none()

        return favourites


class FavouriteMealUpdateView(generics.UpdateAPIView):
    serializer_class = FavouriteMealUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularUser]

    def put(self, request, *args, **kwargs):
        logger.info(f'FavouriteMealUpdateView: user={request.user}, request.data={request.data}')
        if request.user.role != User.REGULAR_USER:
            required_params = ('id', 'user', 'new_meal_id')
        else:
            required_params = ('id', 'new_meal_id')
        check_required_params(required_params, request.data)
        return super(FavouriteMealUpdateView, self).put(request, *args, **kwargs)

    def get_object(self):
        error_message = list()
        favourite = None
        meal = None
        user = None

        try:
            favourite_id = self.request.data['id']
            favourite = FavouriteMeal.objects.get(id=favourite_id)
            if self.request.user.role == User.REGULAR_USER:
                if favourite.user != self.request.user:
                    error_message.append('Favourite does not belong to you')
        except ObjectDoesNotExist:
            error_message.append('Favourite not found')
        except Exception as e:
            error_message.extend(e.args)

        try:
            meal_id = self.request.data['new_meal_id']
            meal = Meal.objects.get(id=meal_id)
            if self.request.user.role == User.REGULAR_USER:
                if meal.owner != self.request.user:
                    if not meal.public:
                        error_message.append('Meal is not public')
        except ObjectDoesNotExist:
            error_message.append('Meal not found')
        except Exception as e:
            error_message.extend(e.args)

        try:
            if self.request.user.role != User.REGULAR_USER:
                username = self.request.data['user']
                user = User.objects.get(username=username, is_superuser=False, is_staff=False)
            else:
                user = self.request.user
        except ObjectDoesNotExist:
            error_message.append('User not found')

        try:
            f = FavouriteMeal.objects.get(user=user, meal=meal)
            if f:
                error_message.append('Meal is already in favourite list of this user')
        except ObjectDoesNotExist:
            pass

        if error_message:
            exc = exceptions.ValidationError(*error_message)
            raise exc

        return favourite
