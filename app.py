from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_cors import CORS
import requests
import datetime
import base64
import json
import os
import re
from models import db, Users
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from resources.crud import User, Product, Order, OrderResource, Carts, Payment, CartsResource, ProductResource

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

EMAIL_VALIDATION_API_URL = os.getenv('EMAIL_VALIDATION_API_URL')
EMAIL_VALIDATION_API_KEY = os.getenv('EMAIL_VALIDATION_API_KEY')

db.init_app(app)
migrate = Migrate(app,db)

CORS(app, supports_credentials=True)

api = Api(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.route('/')
def index():
    return 'Welcome to the Momma nut home page!'

def is_real_email(email):
    response = requests.get(f"{EMAIL_VALIDATION_API_URL}?email={email}&api_key={EMAIL_VALIDATION_API_KEY}")
    data = response.json()
    
    if response.status_code == 200 and data.get('data', {}).get('result') == 'deliverable':
        return True
    return False

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_strong_password(password):
    return bool(re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$", password))

class Signup(Resource):
    def post(self):
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        role = data.get('role', 'user')

        if not email and not phone:
            return {'error': 'Email or phone number is required!'}, 400

        if email and not is_valid_email(email):
            return {'error': 'Invalid email format!'}, 400

        if email and Users.query.filter_by(email=email).first():
            return {'error': 'Email already exists!'}, 400

        if phone and Users.query.filter_by(phone=phone).first():
            return {'error': 'Phone number already exists!'}, 400

        if not is_strong_password(password):
            return {'error': 'Password must be at least 8 characters long and contain both letters and numbers.'}, 400

        if password != confirm_password:
            return {'error': 'Passwords do not match!'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(name=name, email=email, phone=phone, password=hashed_password, role=role)

        db.session.add(new_user)
        db.session.commit()

        create_token = create_access_token(identity={'id': new_user.id, 'name': new_user.name, 'email': new_user.email, 'phone': new_user.phone, 'role': new_user.role})

        return {
            'message': 'User created successfully!',
            'create_token': create_token,
            'user': {
                'id': new_user.id,
                'name': new_user.name,
                'email': new_user.email,
                'phone': new_user.phone,
                'role': new_user.role
            }
        }, 201


class Login(Resource):
    def post(self):
        data = request.get_json()
        identifier = data.get('identifier')  # Either email or phone
        password = data.get('password')

        if not identifier or not password:
            return {'error': 'Email/Phone and password are required!'}, 400
        
        if "@" in identifier and identifier.isdigit():
            return {'error': 'Enter EITHER email OR phone, not both!'}, 400

        user = Users.query.filter((Users.email == identifier) | (Users.phone == identifier)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            create_token = create_access_token(identity={'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone, 'role': user.role})
            refresh_token = create_refresh_token(identity={'id': user.id, 'name': user.name, 'email': user.email, 'phone': user.phone, 'role': user.role})

            return {
                'create_token': create_token,
                'refresh_token': refresh_token,
                'role': user.role,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'phone': user.phone,
                    'role': user.role
                }
            }, 200

        return {'error': 'Incorrect email/phone or password, please try again!'}, 401

class DeleteAcc(Resource):
    @jwt_required()
    def delete(self):
        current = get_jwt_identity()
        user_id = current.get('id')
        role = current.get('role')

        data = request.get_json()
        target_user_id = data.get('user_id') if data else user_id

        if role != "admin" and target_user_id != user_id:
            return {'error': 'Unauthorized action!'}, 403

        delete_user = Users.query.get(target_user_id)
        if not delete_user:
            return {'error': 'The user does not exist!'}, 404

        db.session.delete(delete_user)
        db.session.commit()
        return {'message': 'The user was deleted successfully!'}, 200

    
class Refresh(Resource):
    @jwt_required(refresh = True)
    def post(self):
        current_user = get_jwt_identity()
        new_access_token = create_refresh_token(identity = current_user)
        return{'access_token':new_access_token}, 201
    
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(Refresh, '/refresh')
api.add_resource(DeleteAcc, '/delete')

api.add_resource(User, '/users')
api.add_resource(Product, '/products')
api.add_resource(ProductResource, "/product/<int:product_id>")
api.add_resource(Order, '/orders')
api.add_resource(OrderResource, '/orders/<int:order_id>')
api.add_resource(Payment, '/payments') 
api.add_resource(Carts, '/cart') 
api.add_resource(CartsResource, '/cart', '/cart/<int:cart_id>')

if __name__ == '__main__':
    app.run(debug=True)