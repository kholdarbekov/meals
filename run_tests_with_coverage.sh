#!/usr/bin/env bash
coverage erase
coverage run manage.py test --settings=meals.settings.test
coverage report