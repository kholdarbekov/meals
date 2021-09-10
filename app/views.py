from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError
from django.db.models import QuerySet

from django.shortcuts import render
from rest_framework import generics, status, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated

from .serializers import UserSerializer, UserRegisterSerializer, UserUpdateSerializer, UserPasswordUpdateSerializer, \
    MealListSerializer, MealCreateSerializer, MealUpdateSerializer, \
    FavouriteMealCreateSerializer, FavouriteMealListSerializer, FavouriteMealUpdateSerializer
from .models import User, Meal, FavouriteMeal
from .utils import check_required_params, filter_query_convert
from .permissions import IsAdminRoleUser, IsModeratorRoleUser, IsAdminOrModeratorRoleUser, IsAdminOrRegularRoleUser


class UserLoginView(ObtainAuthToken):
    permission_classes = [AllowAny, ]

    def post(self, request, *args, **kwargs):
        required_params = ('username', 'password')
        check_required_params(required_params, request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        return Response({'token': token.key, 'type': user.role})


class UsersListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminOrModeratorRoleUser]

    def get_queryset(self):
        roles = [User.REGULAR_USER]
        if self.request.user.role == User.ADMIN:
            roles += [User.MODERATOR]
        # users = User.objects.filter(role__in=roles)

        query = filter_query_convert(self.request.data.get('query'))

        if query:
            select = f"SELECT * FROM app_user WHERE role in {tuple(roles)} AND " + query
        else:
            select = f"SELECT * FROM app_user WHERE role in {tuple(roles)}"
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

    def create(self, request, *args, **kwargs):
        required_params = ('username', 'password', 'country')
        check_required_params(required_params, request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        user = serializer.instance
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'role': user.role}, status=status.HTTP_201_CREATED, headers=headers)


class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        required_params = ('username',)
        check_required_params(required_params, request.data)
        return super(UserUpdateView, self).put(request, *args, **kwargs)

    def get_object(self):
        error_message = list()
        user = None
        try:
            username = self.request.data['username']
            if self.request.user.role == User.REGULAR_USER:
                if self.request.user.username != username:
                    error_message.append("Can not edit other users' info")
            if not error_message:
                user = User.objects.get(username=username)
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


class UserPasswordUpdateView(generics.UpdateAPIView):
    serializer_class = UserPasswordUpdateSerializer
    permission_classes = [IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        required_params = ('username', 'password_old', 'password_new')
        check_required_params(required_params, request.data)
        return super(UserPasswordUpdateView, self).put(request, *args, **kwargs)

    def get_object(self):
        error_message = list()
        user = None
        try:
            username = self.request.data['username']
            if self.request.user.role == User.REGULAR_USER:
                if self.request.user.username != username:
                    error_message.append("Can not change other users' password")
            if not error_message:
                user = User.objects.get(username=username)
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


class UserDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminOrModeratorRoleUser]

    def delete(self, request, *args, **kwargs):
        required_params = ('username',)
        check_required_params(required_params, request.data)
        return super(UserDeleteView, self).delete(request, *args, **kwargs)

    def get_object(self):
        error_message = list()
        user = None
        try:
            username = self.request.data['username']
            user = User.objects.get(username=username)
        except KeyError:
            error_message.append('parameter id is not sent')
        except ObjectDoesNotExist:
            error_message.append('User not found')
        except Exception as e:
            error_message.extend(e.args)

        if error_message:
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc

        return user


class MealListView(generics.ListAPIView):
    serializer_class = MealListSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def get_queryset(self):
        # meals = Meal.objects.filter(public=True)
        query = filter_query_convert(self.request.data.get('query'))

        if query:
            select = f"SELECT * FROM app_meal WHERE public=1 AND " + query
        else:
            select = f"SELECT * FROM app_meal public=1"
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

    def create(self, request, *args, **kwargs):
        required_params = ('title', 'type')
        check_required_params(required_params, request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class MealUpdateView(generics.UpdateAPIView):
    serializer_class = MealUpdateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def put(self, request, *args, **kwargs):
        required_params = ('id',)
        check_required_params(required_params, request.data)
        return super(MealUpdateView, self).put(request, *args, **kwargs)

    def get_object(self):
        error_message = list()
        meal = None
        try:
            meal_id = self.request.data['id']
            meal = Meal.objects.get(id=meal_id)
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


class MealDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def delete(self, request, *args, **kwargs):
        required_params = ('id',)
        check_required_params(required_params, request.data)
        return super(MealDeleteView, self).delete(request, *args, **kwargs)

    def get_object(self):
        error_message = list()
        meal = None
        try:
            meal_id = self.request.data['id']
            meal = Meal.objects.get(id=meal_id)
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


class FavouriteMealCreateView(generics.CreateAPIView):
    serializer_class = FavouriteMealCreateSerializer
    permission_classes = [IsAuthenticated, IsAdminOrRegularRoleUser]

    def create(self, request, *args, **kwargs):
        error_message = list()

        required_params = ('user', 'meal')
        check_required_params(required_params, request.data)

        meal = None
        user = None
        try:
            username = request.data['user']
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as exc:
            error_message.append('User Not found')

        try:
            meal_id = request.data['meal']
            meal = Meal.objects.get(id=meal_id)
        except ObjectDoesNotExist as exc:
            error_message.append('Meal Not found')

        if user.favourites:
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
        error_message = list()
        favourite = None
        try:
            meal_id = self.request.data['meal_id']
            favourite = FavouriteMeal.objects.filter(user=self.request.user, meal_id=meal_id)
            if not favourite:
                error_message.append('Meal not found in favourite list')
        except KeyError:
            error_message.append('parameter id is not sent')
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
        favourites = None

        '''
        if self.request.user.role == User.REGULAR_USER:
            if self.request.user.favourites:
                favourites = self.request.user.favourites.all()
        elif self.request.user.role == User.ADMIN:
            favourites = FavouriteMeal.objects.all()
        '''

        query = filter_query_convert(self.request.data.get('query'))

        if query:
            select = f"SELECT * FROM app_favouritemeal WHERE " + query
            if self.request.user.role == User.REGULAR_USER:
                select += f" AND user_id={self.request.user.id}"
        else:
            select = f"SELECT * FROM app_favouritemeal"
            if self.request.user.role == User.REGULAR_USER:
                select += f" WHERE user_id={self.request.user.id}"

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

    def get_object(self):
        error_message = list()
        favourite = None
        try:
            favourite_id = self.request.data['id']
            favourite = FavouriteMeal.objects.get(id=favourite_id)
        except KeyError as key:
            error_message.append('{param} is not sent'.format(param=key))
        except ObjectDoesNotExist:
            error_message.append('Favourite Meal not found')
        except Exception as e:
            error_message.extend(e.args)

        try:
            meal_id = self.request.data['meal']
            _ = Meal.objects.get(id=meal_id)
        except ObjectDoesNotExist:
            error_message.append('Meal not found')

        if error_message:
            exc = exceptions.APIException(*error_message)
            exc.status_code = status.HTTP_400_BAD_REQUEST
            raise exc

        return favourite
