# This is an auto-generated Django model module.
# You'll have to do the following manually to clean this up:
#   * Rearrange models' order
#   * Make sure each model has one field with primary_key=True
#   * Make sure each ForeignKey and OneToOneField has `on_delete` set to the desired behavior
#   * Remove `managed = False` lines if you wish to allow Django to create, modify, and delete the table
# Feel free to rename the models, but don't rename db_table values or field names.
from django.db import models


class Access(models.Model):
    id_user = models.ForeignKey('Users', models.DO_NOTHING, db_column='id_user', blank=True, null=True)
    id_lock = models.ForeignKey('Locks', models.DO_NOTHING, db_column='id_lock', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'access'


class Locks(models.Model):
    number = models.CharField(max_length=100, blank=True, null=True)
    preview = models.CharField(max_length=100, blank=True, null=True)
    about = models.CharField(max_length=100, blank=True, null=True)
    token = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'locks'


class Users(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    surname = models.CharField(max_length=100, blank=True, null=True)
    email = models.CharField(unique=True, max_length=100, blank=True, null=True)
    password = models.CharField(max_length=500, blank=True, null=True)
    token = models.CharField(max_length=500, blank=True, null=True)
    is_admin = models.BooleanField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'users'