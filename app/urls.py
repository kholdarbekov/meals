from django.urls import path
from .views import UsersListView, UserLoginView, UserRegisterView, UserUpdateView, UserDeleteView, UserPasswordUpdateView, UserDetailsView, \
    MealListView, MealCreateView, MealUpdateView, MealDeleteView, \
    FavouriteMealCreateView, FavouriteMealDeleteView, FavouriteMealListView, FavouriteMealUpdateView, \
    ModelsDetailsView

urlpatterns = [
    path('user/login/', UserLoginView.as_view(), name='user_login'),
    path('user/register/', UserRegisterView.as_view(), name='user_register'),
    path('user/update/', UserUpdateView.as_view(), name='user_update'),
    path('user/delete/', UserDeleteView.as_view(), name='user_delete'),
    path('user/password-change/', UserPasswordUpdateView.as_view(), name='user_password_change'),
    path('user/details/', UserDetailsView.as_view(), name='user_details'),
    path('users/', UsersListView.as_view(), name='users_list'),

    path('meals/', MealListView.as_view(), name='meals_list'),
    path('meal/create/', MealCreateView.as_view(), name='meal_create'),
    path('meal/update/', MealUpdateView.as_view(), name='meal_update'),
    path('meal/delete/', MealDeleteView.as_view(), name='meal_delete'),

    path('favourite/create/', FavouriteMealCreateView.as_view(), name='favourite_create'),
    path('favourite/delete/', FavouriteMealDeleteView.as_view(), name='favourite_delete'),
    path('favourite/update/', FavouriteMealUpdateView.as_view(), name='favourite_update'),
    path('favourites/', FavouriteMealListView.as_view(), name='favourites_list'),

    path('models-fields-lookups/', ModelsDetailsView.as_view(), name='models_details'),
]
