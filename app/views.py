import logging

from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError

from rest_framework import generics, status, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .serializers import UserSerializer, UserRegisterSerializer, UserUpdateSerializer, UserPasswordUpdateSerializer, \
    MealListSerializer, MealCreateSerializer, MealUpdateSerializer, \
    FavouriteMealCreateSerializer, FavouriteMealListSerializer, FavouriteMealUpdateSerializer
from .models import User, Meal, FavouriteMeal
from .utils import check_required_params, check_optional_params, filter_query_convert
from .permissions import IsAdminOrModeratorRoleUser, IsAdminOrRegularRoleUser


logger = logging.getLogger('app_log')


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
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
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
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
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
    permission_classes = [IsAuthenticated, IsAdminOrModeratorRoleUser]

    def get_queryset(self):
        roles = [User.REGULAR_USER]
        if self.request.user.role == User.ADMIN:
            roles += [User.MODERATOR, User.ADMIN]

        query = filter_query_convert(self.request.data.get('query'))

        if query:
            select = "SELECT * FROM users WHERE " + str(query)
        else:
            select = "SELECT * FROM users WHERE 1=1 "

        select += f" AND role in {tuple(roles) if len(roles) > 1 else f'({roles[0]})'}"

        if not self.request.user.is_superuser:
            select += " AND is_superuser = False AND is_staff = False"

        logger.info(f'UsersListView: user={self.request.user}, select={select}')

        try:
            users = User.objects.raw(select)
            _ = bool(users)
        except DatabaseError as exc:
            exc = exceptions.APIException(exc.args[0])
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc
        return users


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
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def get_queryset(self):

        query = filter_query_convert(self.request.data.get('query'))
        if query:
            select = f"SELECT meals.* FROM meals, users WHERE meals.owner_id=users.id AND " + str(query)
        else:
            select = f"SELECT meals.* FROM meals, users WHERE meals.owner_id=users.id"

        if self.request.user.role == User.REGULAR_USER:
            select += " AND (meals.public=True OR (meals.public=False AND meals.owner_id={}))".format(self.request.user.id)

        logger.info(f'MealListView: user={self.request.user}, select={select}')

        try:
            meals = Meal.objects.raw(select)
            _ = bool(meals)
            return meals
        except DatabaseError as exc:
            exc = exceptions.APIException(exc.args[0])
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc


class MealCreateView(generics.CreateAPIView):
    serializer_class = MealCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def post(self, request, *args, **kwargs):
        logger.info(f'MealCreateView: user={request.user}, request.data={request.data}')
        required_params = ('title', 'type')
        check_required_params(required_params, request.data)
        return super(MealCreateView, self).post(request, *args, **kwargs)


class MealUpdateView(MealView, generics.UpdateAPIView):
    serializer_class = MealUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def put(self, request, *args, **kwargs):
        logger.info(f'MealUpdateView: user={request.user}, request.data={request.data}')
        required_params = ('id',)
        check_required_params(required_params, request.data)
        return super(MealUpdateView, self).put(request, *args, **kwargs)


class MealDeleteView(MealView, generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def delete(self, request, *args, **kwargs):
        logger.info(f'MealDeleteView: user={request.user}, request.data={request.data}')
        required_params = ('id',)
        check_required_params(required_params, request.data)
        return super(MealDeleteView, self).delete(request, *args, **kwargs)


class FavouriteMealCreateView(generics.CreateAPIView):
    serializer_class = FavouriteMealCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

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
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
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
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

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
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc

        return favourite


class FavouriteMealListView(generics.ListAPIView):
    serializer_class = FavouriteMealListSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def get_queryset(self):
        query = filter_query_convert(self.request.data.get('query'))
        if query:
            select = """SELECT favourites.* 
                        FROM favourites, meals, users 
                        WHERE meals.id=favourites.meal_id 
                        AND users.id=favourites.user_id
                        AND """ + str(query)
            if self.request.user.role == User.REGULAR_USER:
                select += f" AND favourites.user_id={self.request.user.id}"
        else:
            select = """SELECT favourites.* 
                        FROM favourites, meals, users 
                        WHERE meals.id=favourites.meal_id 
                        AND users.id=favourites.user_id
                        """
            if self.request.user.role == User.REGULAR_USER:
                select += f" AND favourites.user_id={self.request.user.id}"

        logger.info(f'FavouriteMealListView: user={self.request.user}, select={select}')

        try:
            favourites = FavouriteMeal.objects.raw(select)
            _ = bool(favourites)
            return favourites
        except DatabaseError as exc:
            exc = exceptions.APIException(exc.args[0])
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc


class FavouriteMealUpdateView(generics.UpdateAPIView):
    serializer_class = FavouriteMealUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

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
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc

        return favourite
