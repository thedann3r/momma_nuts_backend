from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from models import db, Users, Products
from datetime import datetime, timedelta
# from werkzeug.security import check_password_hash
from flask_bcrypt import Bcrypt
from flask_jwt_extended import jwt_required, get_jwt_identity

app = Flask(__name__)
bcrypt = Bcrypt(app)

class User(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()

        if current_user['role'] == 'admin':
            users = Users.query.all()
            return [{
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone': user.phone,
                'role': user.role
            } for user in users], 200

        # Normal users can only fetch their own profile
        user = Users.query.get(current_user['id'])
        if not user:
            return {'error': 'User not found'}, 404

        return {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'phone': user.phone,
            'role': user.role
        }, 200

    @jwt_required()
    def patch(self):
        current_user = get_jwt_identity()
        user = Users.query.get(current_user['id'])

        if not user:
            return {'error': 'User not found'}, 404

        data = request.get_json()
        new_name = data.get('name')
        new_email = data.get('email')
        new_phone = data.get('phone')
        new_password = data.get('new_password')

        if new_name:
            user.name = new_name
        if new_email:
            existing_email = Users.query.filter(Users.email == new_email, Users.id != current_user['id']).first()
            if existing_email:
                return {'error': 'Email already in use'}, 400
            user.email = new_email
        if new_phone:
            existing_phone = Users.query.filter(Users.phone == new_phone, Users.id != current_user['id']).first()
            if existing_phone:
                return {'error': 'Phone number already in use'}, 400
            user.phone = new_phone

        if new_password and new_password.strip():
            current_password = data.get('current_password')
            if not current_password:
                return {'error': 'Current password is required to change password'}, 400
            if not bcrypt.check_password_hash(user.password, current_password):
                return {'error': 'Incorrect current password'}, 401
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        db.session.commit()
        return {'message': 'Profile updated successfully'}, 200
    
class Product(Resource):
    def get(self):
        products = Products.query.all()
        if not products:
            return {'error' : 'Products not found'}, 404
        return [product.to_dict() for product in products]
    
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()

        # Check if user is admin
        if current_user['role'] != 'admin':
            return {'error': 'The user is forbidden from adding new products!'}, 403

        # Get request data
        data = request.get_json()
        required_fields = {'name', 'description', 'price', 'image'}
        
        # Validate required fields
        if not data or not all(key in data for key in required_fields):
            return {'error': 'Missing required fields!'}, 422

        # Clean input data
        name = data['name'].strip()
        description = data['description'].strip()
        
        # Validate price
        try:
            price = float(data['price'])
        except ValueError:
            return {'error': 'Price must be a valid number'}, 400

        # Ensure price is positive
        if price <= 0:
            return {'error': 'Price must be greater than zero'}, 400

        # Check if product name already exists
        existing_product = Products.query.filter_by(name=name).first()
        if existing_product:
            return {'error': 'A product with this name already exists'}, 400

        # Handle stock (default to 0 if not provided)
        stock = int(data.get('stock', 0))
        if stock < 0:
            return {'error': 'Stock cannot be negative'}, 400

        # Create new product
        new_product = Products(
            name=name,
            description=description,
            price=price,
            image=data['image'],
            stock=stock  # Will be 0 if not provided
        )
        
        # Save to database
        db.session.add(new_product)
        db.session.commit()

        return new_product.to_dict(), 201
    
    @jwt_required()
    def patch(self):
        current_user = get_jwt_identity()

        # Ensure only admins can update products
        if current_user['role'] != 'admin':
            return {'error': 'Only admins can update products!'}, 403

        # Get request data
        data = request.get_json()
        product_id = data.get('id')  # Expecting product ID in the request body
        if not product_id:
            return {'error': 'Product ID is required!'}, 400

        product = Products.query.get(product_id)
        if not product:
            return {'error': 'Product not found!'}, 404

        # Update fields if provided
        if 'name' in data:
            product.name = data['name'].strip()

        if 'description' in data:
            product.description = data['description'].strip()

        if 'price' in data:
            try:
                price = float(data['price'])
                if price <= 0:
                    return {'error': 'Price must be greater than zero!'}, 400
                product.price = price
            except ValueError:
                return {'error': 'Price must be a valid number!'}, 400

        if 'image' in data:
            product.image = data['image']

        if 'stock' in data:
            try:
                stock = int(data['stock'])
                if stock < 0:
                    return {'error': 'Stock cannot be negative!'}, 400
                product.stock = stock
            except ValueError:
                return {'error': 'Stock must be an integer!'}, 400

        db.session.commit()
        return {'message': 'Product updated successfully!'}, 200

    @jwt_required()
    def delete(self):
        current_user = get_jwt_identity()

        # Ensure only admins can delete products
        if current_user['role'] != 'admin':
            return {'error': 'Only admins can delete products!'}, 403

        # Get product ID from request body
        data = request.get_json()
        product_id = data.get('id')
        if not product_id:
            return {'error': 'Product ID is required!'}, 400

        product = Products.query.get(product_id)
        if not product:
            return {'error': 'Product not found!'}, 404

        # Delete product
        db.session.delete(product)
        db.session.commit()
        return {'message': 'Product deleted successfully!'}, 200


