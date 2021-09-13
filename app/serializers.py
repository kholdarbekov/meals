import pycountry
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ObjectDoesNotExist
from django.core.validators import MinValueValidator

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _

from .models import User, Meal, FavouriteMeal

from .utils import get_calories_from_api, get_country


class MealListSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    owner = serializers.StringRelatedField(many=False, read_only=True)

    class Meta:
        model = Meal
        fields = ['id', 'title', 'type', 'calories', 'owner', 'public']


class MealCreateSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    owner = serializers.StringRelatedField(many=False, read_only=True)
    public = serializers.BooleanField(default=False)

    def create(self, validated_data):
        meal = Meal.objects.create(
            title=validated_data['title'],
            type=validated_data['type'],
            calories=validated_data['calories'],
            owner=validated_data['owner'],
            public=validated_data['public']
        )
        return meal

    def validate(self, attrs):
        meal_type = attrs.get('type')
        if not isinstance(meal_type, int):
            msg = _('Meal type must be integer!')
            raise serializers.ValidationError(msg, code='validation')

        if meal_type not in (Meal.BREAKFAST, Meal.LUNCH, Meal.DINNER, Meal.SNACK):
            msg = _(f'Meal type must be valid choice! Choices are: {Meal.BREAKFAST, Meal.LUNCH, Meal.DINNER, Meal.SNACK}')
            raise serializers.ValidationError(msg, code='validation')

        calories = attrs.get('calories')
        if calories:
            if not isinstance(calories, (int, float)):
                msg = _('Meal calories must be numeric!')
                raise serializers.ValidationError(msg, code='validation')
        else:
            # get calories from API
            calories = get_calories_from_api(attrs.get('title'))

        attrs['calories'] = calories

        try:
            attrs['owner'] = self.context['request'].user
        except (ObjectDoesNotExist, AttributeError, KeyError):
            msg = _('Meal owner not found!')
            raise serializers.ValidationError(msg, code='validation')

        return attrs

    class Meta:
        model = Meal
        fields = ['id', 'title', 'type', 'calories', 'owner', 'public']


class MealUpdateSerializer(serializers.ModelSerializer):
    calories = serializers.FloatField(min_value=0, required=False)
    owner = serializers.StringRelatedField(many=False, read_only=True, required=False)
    type = serializers.IntegerField(min_value=1, required=False)
    title = serializers.CharField(required=False, max_length=256)
    public = serializers.BooleanField(required=False)

    def update(self, instance, validated_data):
        '''
        if not validated_data['title']:
            validated_data['title'] = instance.title
        if not validated_data.get('type'):
            validated_data['type'] = instance.type
        if not validated_data.get('calories'):
            validated_data['calories'] = instance.calories
        if not validated_data.get('public'):
            validated_data['public'] = instance.public
        if not validated_data.get('owner'):
            validated_data['owner'] = instance.owner
        '''
        instance = super().update(instance, validated_data)

        return instance

    def validate(self, attrs):
        calories = attrs.get('calories')
        if calories:
            if not isinstance(calories, (int, float)):
                msg = _('Meal calories must be numeric!')
                raise serializers.ValidationError(msg, code='validation')
        else:
            # get calories from API
            calories = get_calories_from_api(attrs.get('title'))

        attrs['calories'] = calories
        return attrs

    class Meta:
        model = Meal
        fields = ['id', 'title', 'type', 'calories', 'public', 'owner']


class FavouriteMealCreateSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(queryset=User.objects.all(), slug_field='username')
    meal = serializers.SlugRelatedField(queryset=Meal.objects.all(), slug_field='id')

    def validate(self, attrs):
        user = attrs.get('user')
        meal = attrs.get('meal')
        if user.favourites.filter(meal=meal):
            msg = _('Meal is already in favourite list of this user')
            raise serializers.ValidationError(msg, code='validation')
        return attrs

    class Meta:
        model = FavouriteMeal
        fields = ['id', 'user', 'meal']


class FavouriteMealListSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    user = serializers.StringRelatedField(many=False, read_only=True)
    meal = MealListSerializer(many=False, read_only=True)

    class Meta:
        model = FavouriteMeal
        fields = ['id', 'user', 'meal']


class FavouriteMealUpdateSerializer(serializers.ModelSerializer):
    new_meal_id = serializers.SlugRelatedField(queryset=Meal.objects.all(), slug_field='id')

    class Meta:
        model = FavouriteMeal
        fields = ['id', 'new_meal_id']


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'role', 'country']


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
            country=validated_data['country'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            role=User.REGULAR_USER
        )
        return user

    def validate(self, attrs):
        country_code = attrs.get('country')
        country = get_country(country_code)
        if not country:
            msg = _('Country must be valid 3 letter country code')
            raise serializers.ValidationError(msg, code='validation')

        attrs['country'] = country.alpha_3

        if not attrs.get('first_name'):
            attrs['first_name'] = ''
        if not attrs.get('last_name'):
            attrs['last_name'] = ''

        return attrs

    class Meta:
        model = User
        fields = ['username', 'password', 'country', 'first_name', 'last_name']


class UserUpdateSerializer(serializers.ModelSerializer):
    country = serializers.CharField(required=False, error_messages={'blank': 'country may not be blank'})
    first_name = serializers.CharField(required=False, error_messages={'blank': 'first_name may not be blank'})
    last_name = serializers.CharField(required=False, error_messages={'blank': 'last_name may not be blank'})

    def validate(self, attrs):
        country_code = attrs.get('country')
        if country_code:
            country = get_country(country_code)
            if not country:
                msg = _('Country must be valid 3 letter country code')
                raise serializers.ValidationError(msg, code='validation')

            attrs['country'] = country.alpha_3

        return attrs

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'role', 'country']


class UserPasswordUpdateSerializer(serializers.ModelSerializer):
    password_old = serializers.CharField(write_only=True)
    password_new = serializers.CharField(write_only=True)
    username = serializers.CharField(write_only=True)

    def update(self, instance, validated_data):
        instance = super(UserPasswordUpdateSerializer, self).update(instance, validated_data)
        instance.set_password(validated_data['password_new'])
        instance.save()
        return instance

    def validate(self, attrs):
        if attrs.get('password_old'):
            if not self.instance.check_password(attrs.get('password_old')):
                msg = _('provided password is incorrect')
                raise serializers.ValidationError(msg, code='validation')
        if attrs.get('password_old') == attrs.get('password_new'):
            msg = _('old password and new password are same!')
            raise serializers.ValidationError(msg, code='validation')
        if attrs.get('password_new'):
            validate_password(attrs.get('password_new'))

        return attrs

    class Meta:
        model = User
        fields = ['username', 'password_old', 'password_new']
