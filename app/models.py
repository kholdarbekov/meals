from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models

from django.utils.translation import gettext_lazy as _


class UserManager(BaseUserManager):
    def create_user(self, username, country, password=None, **extra_fields):
        if not username:
            raise ValueError(_('The given username must be set'))
        if not country:
            raise ValueError(_('The given country must be set'))
        # Lookup the real model class from the global app registry so this
        # manager method can be used in migrations. This is fine because
        # managers are by definition working on the real model.
        GlobalUserModel = self.model
        username = GlobalUserModel.normalize_username(username)
        user = self.model(username=username, country=country, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, country, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', User.ADMIN)

        if not extra_fields.get('is_staff'):
            raise ValueError(_('Superuser must have is_staff=True'))
        if not extra_fields.get('is_superuser'):
            raise ValueError(_('Superuser must have is_superuser=True'))
        return self.create_user(username, country, password, **extra_fields)


class User(AbstractUser):
    REGULAR_USER = 1
    MODERATOR = 2
    ADMIN = 3

    ROLE_CHOICES = (
        (REGULAR_USER, 'Regular User'),
        (MODERATOR, 'Moderator'),
        (ADMIN, 'Admin')
    )
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=ROLE_CHOICES[0][0])
    country = models.CharField(null=False, max_length=3, default='UZB')

    REQUIRED_FIELDS = ['country']

    objects = UserManager()

    def __str__(self):
        return self.username


class Meal(models.Model):
    BREAKFAST = 1
    LUNCH = 2
    DINNER = 3
    SNACK = 4

    MEAL_TYPE_CHOICES = (
        (BREAKFAST, 'Breakfast'),
        (LUNCH, 'Lunch'),
        (DINNER, 'Dinner'),
        (SNACK, 'Snack')
    )
    title = models.CharField(blank=False, null=False, max_length=256)
    type = models.PositiveSmallIntegerField(choices=MEAL_TYPE_CHOICES, default=MEAL_TYPE_CHOICES[0][0])
    calories = models.FloatField(default=0.0, blank=True, null=True)
    owner = models.ForeignKey('User', related_name='meals', on_delete=models.CASCADE)
    public = models.BooleanField(default=False)

    def __str__(self):
        return self.title


class FavouriteMeal(models.Model):
    user = models.ForeignKey('User', related_name='favourites', on_delete=models.CASCADE)
    meal = models.ForeignKey('Meal', related_name='favorited_users', on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user} favorites {self.meal}'
