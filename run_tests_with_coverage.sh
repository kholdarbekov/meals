#!/usr/bin/env bash
coverage erase
coverage run manage.py test --settings="$DJANGO_SETTINGS_MODULE"
coverage report