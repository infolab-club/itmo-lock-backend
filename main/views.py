from django.http.response import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.http import HttpResponse, HttpRequest, JsonResponse
from .models import Users, Access, Locks
import json
import jwt
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from validate_email import validate_email
from django.views.decorators.csrf import csrf_exempt
from myfirst.settings import SECRET_KEY

@csrf_exempt
def registration(request):
    values = json.loads(request.body)
    if 'email' in values.keys() and 'name' in values.keys() and 'surname' in values.keys() and 'password' in values.keys() and validate_email(values['email']):
        token = jwt.encode({
                'email': values['email'],
                'time': str(datetime.utcnow())
            }, key = SECRET_KEY)
        try:
            user = Users(name=values['name'], surname=values['surname'], email=values['email'], password=generate_password_hash(values['password']), token=token, is_admin=False)
            user.save()
            return JsonResponse({
                'token': token
            })
        except:
            return HttpResponseBadRequest("invalid input")
    else:
        return HttpResponseBadRequest("invalid input")


@csrf_exempt
def login(request):
    values = json.loads(request.body)
    if 'email' in values.keys() and 'password' in values.keys():
        user = Users.objects.filter(email=values['email']).first()
        if user == None:
            return HttpResponseBadRequest("Wrong email")
        else:
            if check_password_hash(user.password, values['password']):
                return HttpResponse(json.dumps({"token": user.token}))
            else:
                return HttpResponseBadRequest("Wrong password")
    else:
        return HttpResponseBadRequest("Invalid input")


@csrf_exempt
def add_user(request, id):
    token = request.headers.get('Authorization')
    user = Users.objects.filter(token=token).first()
    lock = Locks.objects.filter(id=id).first()
    if user is None:
        return HttpResponseBadRequest("Unauthorized user")
    else:
        if user.is_admin:
            values = json.loads(request.body)
            user_to_add = Users.objects.filter(id=values['id']).first()
            access = Access(id_user=user_to_add, id_lock=lock)
            access.save()
            try:
                return HttpResponse("Success")
            except:
                return HttpResponseBadRequest("Invalid input")
        else:
            return HttpResponseBadRequest('Permission denied')


@csrf_exempt
def remove_user(request, id):
    token = request.headers.get('Authorization')
    user = Users.objects.filter(token=token).first()
    if user is None:
        return HttpResponseBadRequest("Unauthorized user")
    else:
        if user.is_admin:
            values = json.loads(request.body)
            try:
                Access.objects.filter(id_user=values['id'], id_lock=id).delete()
                return HttpResponse("Success")
            except:
                return HttpResponseBadRequest("Invalid input")
        else:
            return HttpResponseBadRequest("Permission denied")


@csrf_exempt
def get_locks(request):
    token = request.headers.get('Authorization')
    user = Users.objects.filter(token=token).first()
    if user is None:
        return HttpResponseBadRequest("Unauthorized user")
    else:
        if user.is_admin:
            locks = Locks.objects.all()
            locks_list = []
            for i in range(len(locks)):
                locks_list.append({
                    "id": locks[i].id,
                    "number": locks[i].number,
                    "preview": locks[i].preview,
                    "about": locks[i].about
                })
            return JsonResponse({"locks": locks_list})
        else:
            locks_ids = Access.objects.filter(id_user=user.id).all()
            locks = []
            for i in range(len(locks_ids)):
                locks.append(Locks.objects.filter(id=locks_ids[i].id_lock.id).first())
            locks_list = []
            for i in range(len(locks)):
                locks_list.append({
                    "id": locks[i].id,
                    "number": locks[i].number,
                    "preview": locks[i].preview,
                    "about": locks[i].about
                })
            return JsonResponse({"locks": locks_list})


@csrf_exempt
def get_lock_token(request, id):
    token = request.headers.get('Authorization')
    user = Users.objects.filter(token=token).first()
    if user is None:
        return HttpResponseBadRequest("Unauthorized user")
    else:
        if user.is_admin:
            lock = Locks.objects.filter(id=id).first()
            return JsonResponse({
                "token": lock.token,
                "mac": lock.mac
            })
        else:
            access = Access.objects.filter(id_user=user.id, id_lock=id).first()
            if access is None:
                return HttpResponseBadRequest("Permission denied")
            else:
                lock = Locks.objects.filter(id=id).first()
                return JsonResponse({
                    "token": lock.token,
                    "mac": lock.mac
                })


@csrf_exempt
def get_users(request):
    token = request.headers.get('Authorization')
    user = Users.objects.filter(token=token).first()
    if user is None:
        return HttpResponseBadRequest("Unauthorized user")
    else:
        if user.is_admin:
            users = Users.objects.all()
            users_list = []
            for i in range(len(users)):
                accessible_locks_id = []
                accessible_locks = Access.objects.filter(id_user=users[i].id).all()
                for j in range(len(accessible_locks)):
                    accessible_locks_id.append(accessible_locks[j].id_lock.id)
                users_list.append({
                    "id": users[i].id,
                    "name": users[i].name,
                    "surname": users[i].surname,
                    "locks": accessible_locks_id
                })
            return JsonResponse({'users': users_list})
        else:
            return HttpResponseBadRequest("Permission denied")


@csrf_exempt
def get_user(request):
    token = request.headers.get('Authorization')
    user = Users.objects.filter(token=token).first()
    if user is None:
        return HttpResponseBadRequest("Unauthorized user")
    else:
        return JsonResponse({
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'surname': user.surname,
            'is_admin': user.is_admin
        })