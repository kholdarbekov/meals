# Introduction

The goal of this project is to provide **Favourite Meal Management** for Users. There are 3 roles with different permission levels. 

Regular user would only be able to CRUD on their owned records, Moderator would be able to CRUD only users, and Admin would be able to CRUD all records and users.

Project is written with Django 3.2 using DRF


### Main features

* Separated dev, test, staging, and production settings

* API calls are authenticated (Token authentication)

* SQLite by default if no env variable is set

* Get calories from Calories API provider (https://www.nutritionix.com) for meal if amount of calories not provided by user

* Meal is either public or private

* User can see the list of all public meals and can pick their favorites by countries

* API provides filter and pagination capabilities for all endpoints that return a list of elements

* Filtering allows using parenthesis for defining operations precedence and use any combination of the available fields. The supported operations are: **or**, **and**, **eq** (equals), **ieq** (case-insensitive equals), **ne** (not equals), **ine** (case-insensitive not equals), **gt** (greater than), **gte** (greater than or equal to), **lt** (lower than), **lte** (lower than or equal to), **in** (is in list[] of specified values), **range** (between specified range [start, end]), **isnull** (is value null, True or False), **date** (in case of datetime field compare only date)

# Usage Notes

User roles are: Regular, Moderator, and Admin with 1, 2, and 3 as numerical representations respectively.

Meal types are: Breakfast, Lunch, Dinner, Snack with 1, 2, 3, and 4 as numerical representations respectively.

### Export environment variables

Before running project execute `enviroment_values.sh`. It contains DJANGO_SECRET_KEY, DATABASE credentials, and DJANGO_SETTINGS_MODULE

    $ ./enviroment_values.sh
    
And then install project dependencies:

    $ pip install -r requirements.txt

Then apply the migrations:

    $ python manage.py migrate

You can now run the development server:

    $ python manage.py runserver
      
### Testing

Run test with coverage `run_tests_with_coverage.sh`

    $ ./run_tests_with_coverage.sh
