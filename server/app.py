#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()
        if 'username' not in json_data or 'password' not in json_data:
            return {'error': 'Username and password are required'}, 400
        
        user = User(username=json_data['username'])
        user.password_hash = bcrypt.generate_password_hash(json_data['password']).decode('utf-8')
        
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        return user.to_dict(), 201
    
class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        
        return {}, 204

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        if 'username' not in json_data or 'password' not in json_data:
            return {'error': 'Username and password are required'}, 400

        user = User.query.filter_by(username=json_data['username']).first()
        if user and bcrypt.check_password_hash(user.password_hash, json_data['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid credentials'}, 401


class Logout(Resource):
     def delete(self):
        if 'user_id' in session:
            session.pop('user_id', None)
        return {}, 204
     
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
