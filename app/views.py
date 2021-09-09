from django.core.exceptions import ObjectDoesNotExist

from django.shortcuts import render
from rest_framework import generics, status, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response

from .serializers import UserSerializer, UserRegisterSerializer, UserUpdateSerializer, \
    MealListSerializer, MealCreateSerializer, MealUpdateSerializer, \
    FavoriteMealCreateSerializer, FavoriteMealListSerializer
from .models import User, Meal, FavouriteMeal
from rest_framework.permissions import AllowAny, IsAuthenticated


class UserLoginView(ObtainAuthToken):
    permission_classes = [AllowAny, ]

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        return Response({'token': token.key, 'type': user.role})


class UsersListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, ]

    def get_queryset(self):
        users = User.objects.filter(role=User.REGULAR_USER)
        return users


class UserRegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny, ]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            user = serializer.instance
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, 'type': User.REGULAR_USER}, status=status.HTTP_201_CREATED, headers=headers)
        except Exception as e:
            return Response(data=e.args, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsAuthenticated, ]

    def get_object(self):
        error_message = list()
        user = None
        try:
            username = self.request.data['username']
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
    permission_classes = [IsAuthenticated, ]

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
    permission_classes = [IsAuthenticated, ]

    def get_queryset(self):
        meals = Meal.objects.all()
        return meals


class MealCreateView(generics.CreateAPIView):
    serializer_class = MealCreateSerializer
    permission_classes = [IsAuthenticated, ]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        except Exception as e:
            return Response(data=e.args, status=status.HTTP_400_BAD_REQUEST)


class MealUpdateView(generics.UpdateAPIView):
    serializer_class = MealUpdateSerializer
    permission_classes = [IsAuthenticated, ]

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
    permission_classes = [IsAuthenticated, ]

    def get_object(self):
        error_message = list()
        meal = None
        try:
            meal_id = self.request.data['id']
            meal = Meal.objects.get(id=meal_id)
        except KeyError:
            error_message.append('parameter id is not sent')
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
    serializer_class = FavoriteMealCreateSerializer
    permission_classes = [IsAuthenticated, ]

    def create(self, request, *args, **kwargs):
        error_message = list()
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
    permission_classes = [IsAuthenticated, ]

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
    serializer_class = FavoriteMealListSerializer
    permission_classes = [IsAuthenticated, ]

    def get_queryset(self):
        favourites = None
        if self.request.user.role == User.REGULAR_USER:
            if self.request.user.favourites:
                favourites = self.request.user.favourites.all()
        elif self.request.user.role == User.ADMIN:
            favourites = FavouriteMeal.objects.all()
        return favourites
