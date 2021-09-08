from django.urls import path
from .views import UsersListView, UserLoginView, UserRegisterView, UserUpdateView, UserDeleteView, \
    MealListView, MealCreateView, MealUpdateView, MealDeleteView

urlpatterns = [
    path('user/login', UserLoginView.as_view(), name='user_login'),
    path('user/register', UserRegisterView.as_view(), name='user_register'),
    path('user/update', UserUpdateView.as_view(), name='user_update'),
    path('user/delete', UserDeleteView.as_view(), name='user_delete'),
    path('users/', UsersListView.as_view(), name='users_list'),

    path('meals/', MealListView.as_view(), name='meals_list'),
    path('meal/create', MealCreateView.as_view(), name='meal_create'),
    path('meal/update', MealUpdateView.as_view(), name='meal_update'),
    path('meal/delete', MealDeleteView.as_view(), name='meal_delete'),
]
