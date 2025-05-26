from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from email_utils import send_order_confirmation_email
from models import db, Users, Products, Orders, Payments, OrderItems, Cart, Comments, Likes
from datetime import datetime, timedelta
# from werkzeug.security import check_password_hash 
from flask_bcrypt import Bcrypt
from flask_jwt_extended import jwt_required, get_jwt_identity

app = Flask(__name__)  
bcrypt = Bcrypt(app)

class MeResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()

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

class User(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()

        if current_user['role'] == 'admin':
            users = Users.query.filter_by(deleted_at=None).all()  # Exclude soft-deleted users
            return [{
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone': user.phone,
                'role': user.role
            } for user in users], 200

        # Normal users can only fetch their own profile
        user = Users.query.filter_by(id=current_user['id'], deleted_at=None).first()
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

        try:
            if new_name and new_name.strip():
                user.name = new_name.strip()

            if new_email and new_email.strip() and new_email != user.email:
                existing_email = Users.query.filter(Users.email == new_email, Users.id != user.id).first()
                if existing_email:
                    return {'error': 'Email already in use'}, 400
                user.email = new_email.strip()

            if new_phone and new_phone.strip() and new_phone != user.phone:
                existing_phone = Users.query.filter(Users.phone == new_phone, Users.id != user.id).first()
                if existing_phone:
                    return {'error': 'Phone number already in use'}, 400
                user.phone = new_phone.strip()

            if new_password and isinstance(new_password, str) and new_password.strip():
                current_password = data.get('current_password')
                if not current_password:
                    return {'error': 'Current password is required to change password'}, 400
                
                if not user.password or not bcrypt.check_password_hash(user.password, current_password):
                    return {'error': 'Incorrect current password'}, 401

                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            db.session.commit()
            return {'message': 'Profile updated successfully'}, 200

        except Exception as e:
            db.session.rollback()  # Rollback in case of any error
            return {'error': f'An error occurred: {str(e)}'}, 500
    
class Product(Resource):
    def get(self):
        products = Products.query.filter_by(deleted_at=None).all()  # Exclude soft-deleted
        if not products:
            return {'error': 'Products not found'}, 404
        return [
            {
                'id': product.id,
                'name': product.name,
                'description': product.description,
                'price': product.price,
                'image': product.image,
                'stock': product.stock
            } for product in products
        ], 200
    
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
        existing_product = Products.query.filter_by(name=name).filter(Products.deleted_at == None).first()
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
    
class ProductResource(Resource):
    @jwt_required()
    def patch(self, product_id):
        current_user = get_jwt_identity()

        # Ensure only admins can update products
        if current_user['role'] != 'admin':
            return {'error': 'Only admins can update products!'}, 403

        # Find the product
        product = Products.query.get(product_id)
        if not product:
            return {'error': 'Product not found!'}, 404

        # Get request data
        data = request.get_json()

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
                product.stock += stock  # ✅ Add new stock to current stock
            except ValueError:
                return {'error': 'Stock must be an integer!'}, 400

        db.session.commit()

        # ✅ Return the updated product instead of just a message
        return {
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'image': product.image,
            'stock': product.stock
        }, 200

    @jwt_required()
    def delete(self, product_id):
        current_user = get_jwt_identity()

        if current_user['role'] != 'admin':
            return {'error': 'Only admins can delete products!'}, 403

        product = Products.query.get(product_id)
        if not product:
            return {'error': 'Product not found!'}, 404

        # Perform soft delete
        product.deleted_at = datetime.utcnow()
        db.session.commit()
        return {'message': 'Product soft deleted successfully!'}, 200

class Order(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()

        if not current_user:
            return {'error': 'Unauthorized. Please log in to place an order.'}, 401

        data = request.get_json()
        if not data or 'items' not in data:
            return {'error': 'Missing required fields!'}, 422

        items = data['items']
        if not isinstance(items, list) or len(items) == 0:
            return {'error': 'At least one product must be included in the order.'}, 400

        total_price = 0
        order_items = []
        product_updates = []

        for item in items:
            product_id = item.get('product_id')
            quantity = item.get('quantity')

            if not product_id or not quantity:
                return {'error': 'Each item must include product_id and quantity'}, 400

            if quantity <= 0:
                return {'error': 'Quantity must be at least 1'}, 400

            product = Products.query.get(product_id)
            if not product:
                return {'error': f'Product with ID {product_id} not found'}, 404

            if product.stock < quantity:
                return {'error': f'Insufficient stock for product {product.name}'}, 400

            total_price += product.price * quantity

            order_items.append(OrderItems(product_id=product_id, quantity=quantity, order_id=None))  
            product_updates.append((product, quantity))  # Store product updates

        # Create new order
        new_order = Orders(
            user_id=current_user['id'],
            total_price=total_price,
            status="pending"
        )
        db.session.add(new_order)
        db.session.commit()  # Ensure order_id is generated

        # Assign order ID to order items and save them
        for order_item in order_items:
            order_item.order_id = new_order.id
            db.session.add(order_item)

        # Deduct stock after order is confirmed
        for product, quantity in product_updates:
            product.stock -= quantity

        db.session.commit()  # Commit all changes

        # Clear cart after successful order creation
        Cart.query.filter_by(user_id=current_user['id']).delete()
        db.session.commit()

        return {
            'message': 'Order placed successfully',
            'order': {
                'id': new_order.id,
                'user_id': new_order.user_id,
                'total_price': new_order.total_price,
                'status': new_order.status,
                'items': [{'product_id': item.product_id, 'quantity': item.quantity} for item in order_items]
            }
        }, 201

    
class OrderResource(Resource):
    @jwt_required()
    def get(self, order_id=None):
        current_user = get_jwt_identity()

        # Admin can view all orders
        if current_user['role'] == 'admin':
            if order_id:
                order = Orders.query.get(order_id)
                if not order:
                    return {'error': 'Order not found'}, 404
                return self.serialize_order(order), 200
            else:
                orders = Orders.query.all()
                return [self.serialize_order(order) for order in orders], 200

        # Regular users can only view their own orders
        else:
            if order_id:
                order = Orders.query.filter_by(id=order_id, user_id=current_user['id']).first()
                if not order:
                    return {'error': 'Order not found'}, 404
                return self.serialize_order(order), 200
            else:
                orders = Orders.query.filter_by(user_id=current_user['id']).all()
                return [self.serialize_order(order) for order in orders], 200

    def serialize_order(self, order):
        return {
            'id': order.id,
            'user_id': order.user_id,
            'total_price': order.total_price,
            'status': order.status,
                'items': [
                {
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'price': item.price,
                    'name': item.product.name,  # Include product name
                    'image': item.product.image  # Include product image
                } for item in order.items
            ]
        }

    @jwt_required()
    def patch(self, order_id):
        current_user = get_jwt_identity()
        
        # Fetch the order
        order = Orders.query.get(order_id)
        if not order:
            return {'error': 'Order not found'}, 404
        
        # Only an admin can cancel a completed order
        if order.status == 'completed' and current_user['role'] != 'admin':
            return {'error': 'Only an admin can cancel a completed order'}, 403
        
        # Restore product stock
        for item in order.items:
            product = Products.query.get(item.product_id)
            if product:
                product.stock += item.quantity

        # Mark order as canceled
        order.status = 'canceled'
        
        # If the order was completed, update payment status
        if order.status == 'completed' and order.payment:
            order.payment.status = "Refund Pending"  # Or "Reversed" if refund is processed instantly

        db.session.commit()

        return {'message': 'Order canceled successfully, payment status updated'}, 200

class Payment(Resource):

    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()

        if current_user['role'] == 'admin':
            payments = Payments.query.all()  # Admins get all payments
        else:
            payments = Payments.query.filter_by(user_id=current_user['id']).all()

        if not payments:
            return {'message': 'No payments found'}, 404

        # Manually serialize the payment without triggering recursion
        payment_list = []
        for payment in payments:
            payment_dict = {
                'id': payment.id,
                'order_id': payment.order_id,
                'user_id': payment.user_id,
                'mpesa_receipt_number': payment.mpesa_receipt_number,
                'phone_number': payment.phone_number,
                'amount': payment.amount,
                'status': payment.status,
                'transaction_date': payment.transaction_date.isoformat() if payment.transaction_date else None,  # Handling datetime conversion
                'checkout_request_id': payment.checkout_request_id,
                'merchant_request_id': payment.merchant_request_id
            }
            payment_list.append(payment_dict)

        return payment_list, 200
    
    # @jwt_required()
    # def post(self):
    #     current_user = get_jwt_identity()
    #     data = request.get_json()

    #     required_fields = {'order_id', 'phone_number', 'mpesa_receipt_number'}
    #     if not data or not all(field in data for field in required_fields):
    #         return {'error': 'Missing required fields!'}, 422

    #     order = Orders.query.get(data['order_id'])

    #     if not order:
    #         return {'error': 'Order not found'}, 404

    #     # Ensure the order belongs to the logged-in user
    #     if order.user_id != current_user['id']:
    #         return {'error': 'Unauthorized to make payment for this order'}, 403

    #     # Check if order is already paid
    #     existing_payment = Payments.query.filter_by(order_id=order.id).first()
    #     if existing_payment:
    #         return {'error': 'Payment already exists for this order'}, 400

    #     # ✅ Fix: Use order.total_price instead of user input for amount
    #     amount = order.total_price  

    #     # Create a new payment
    #     new_payment = Payments(
    #         order_id=order.id,
    #         user_id=current_user['id'],
    #         phone_number=data['phone_number'],
    #         amount=amount,  # ✅ Secure amount
    #         mpesa_receipt_number=data['mpesa_receipt_number'],
    #         transaction_date=datetime.utcnow(),  
    #         status="Completed"
    #     )

    #     db.session.add(new_payment)

    #     # Update order status to completed
    #     order.status = "completed"
        
    #     db.session.commit()

    #     return {
    #         'message': 'Payment successful',
    #         'payment': {
    #             'id': new_payment.id,
    #             'order_id': new_payment.order_id,
    #             'amount': new_payment.amount,
    #             'status': new_payment.status,
    #             'transaction_date': new_payment.transaction_date
    #         }
    #     }, 201
    

class Carts(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'Invalid request format'}, 400

            product_id = data.get('product_id')
            quantity = data.get('quantity', 1)  # Default quantity is 1

            if not product_id:
                return {'error': 'Product ID is required'}, 400

            # Fetch product and validate availability
            product = Products.query.filter_by(id=product_id, deleted_at=None).first()
            if not product:
                return {'error': 'Product not found or has been removed'}, 404

            if product.stock < quantity:
                return {'error': f'Only {product.stock} items available in stock'}, 400

            # Check if item is already in the cart
            cart_item = Cart.query.filter_by(user_id=current_user['id'], product_id=product_id).first()

            if cart_item:
                new_quantity = cart_item.quantity + quantity
                if new_quantity > product.stock:  # Prevent exceeding stock
                    return {'error': f'Only {product.stock} items available in stock'}, 400
                cart_item.quantity = new_quantity
            else:
                cart_item = Cart(user_id=current_user['id'], product_id=product_id, quantity=quantity)
                db.session.add(cart_item)

            # Reduce stock after adding to cart
            # product.stock -= quantity

            db.session.commit()

            return {
                'message': 'Product added to cart successfully',
                'cart_item': {
                    'id': cart_item.id,
                    'product_id': cart_item.product_id,
                    'quantity': cart_item.quantity
                }
            }, 201

        except Exception as e:
            db.session.rollback()
            return {'error': 'An error occurred', 'details': str(e)}, 500

    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()

        cart_items = Cart.query.filter_by(user_id=current_user['id']).all()

        if not cart_items:
            return {'message': 'Cart is empty'}, 200

        serialized_cart = []
        for item in cart_items:
            serialized_cart.append({
                'id': item.id,
                'product_id': item.product_id,
                'quantity': item.quantity,
                'product_name': item.product.name,
                'product_image': item.product.image,
                'price': item.product.price,
                # optional: add subtotal per item
                'subtotal': round(item.product.price * item.quantity, 2)
            })

        return serialized_cart, 200

class CartsResource(Resource):
    @jwt_required()
    def delete(self, cart_id=None):
        current_user = get_jwt_identity()

        if cart_id is not None:  # Deleting a single cart item
            cart_item = Cart.query.filter_by(id=cart_id, user_id=current_user['id']).first()
            if not cart_item:
                return {'error': 'Cart item not found'}, 404

            try:
                db.session.delete(cart_item)
                db.session.commit()
                return {'message': 'Item removed from cart successfully'}, 200
            except Exception as e:
                db.session.rollback()
                return {'error': 'Failed to remove item', 'details': str(e)}, 500

        # If no cart_id is provided, clear all cart items for the user
        user_cart_items = Cart.query.filter_by(user_id=current_user['id']).all()
        if not user_cart_items:
            return {'message': 'Cart is already empty'}, 200

        try:
            Cart.query.filter_by(user_id=current_user['id']).delete()
            db.session.commit()
            return {'message': 'Cart cleared successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': 'Failed to clear cart', 'details': str(e)}, 500



class Checkout(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        user_id = current_user['id']

        cart_items = Cart.query.filter_by(user_id=user_id).all()
        if not cart_items:
            return {'error': 'Cart is empty, add items first!'}, 400

        total_price = 0
        order_items_data = []

        # ✅ 1. Create Order (status defaults to 'pending')
        new_order = Orders(user_id=user_id, total_price=0)
        db.session.add(new_order)
        db.session.commit()  # Commit early to get order ID

        for cart_item in cart_items:
            product = Products.query.get(cart_item.product_id)

            if not product:
                return {'error': f'Product with ID {cart_item.product_id} not found!'}, 404

            if product.stock < cart_item.quantity:
                return {'error': f'Not enough stock for {product.name}. Available: {product.stock}'}, 400

            # ✅ 2. Deduct stock
            product.stock -= cart_item.quantity

            # ✅ 3. Calculate total price
            item_total = product.price * cart_item.quantity
            total_price += item_total

            # ✅ 4. Create Order Item
            order_item = OrderItems(
                order_id=new_order.id,
                product_id=product.id,
                quantity=cart_item.quantity,
                price=product.price
            )
            db.session.add(order_item)

            order_items_data.append({
                'product_id': product.id,
                'name': product.name,
                'quantity': cart_item.quantity,
                'price': product.price
            })

        # ✅ 5. Update order total price
        new_order.total_price = total_price

        # ✅ 6. Create Pending Payment Entry
        # new_payment = Payments(
        #     order_id=new_order.id,
        #     user_id=user_id,
        #     phone_number=None,  # Will be updated during payment
        #     amount=total_price,
        #     status="Pending",  # Ensures we track unpaid orders
        #     mpesa_receipt_number=None,
        #     transaction_date=datetime.utcnow()
        # )
        # db.session.add(new_payment)

        # ✅ 7. Clear the cart
        Cart.query.filter_by(user_id=user_id).delete()

        db.session.commit()

        # Send order confirmation email after commit

        if current_user.get('email'):
            send_order_confirmation_email(current_user['email'], new_order.id)

        return {
            'message': 'Order created successfully, proceed to payment.',
            'order_id': new_order.id,
            'total_price': total_price,
            'order_items': order_items_data
        }, 201

class Comment(Resource):
    def get(self):
        comments = Comments.query.filter(Comments.deleted_at.is_(None)).all()
        if not comments:
            return {"error": "Reviews not found"}, 404
        
        return [
            {
                **comment.to_dict(),
                "product": comment.product.to_dict() if comment.product else None
            }
            for comment in comments
        ]
    
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.get_json()

        if "content" not in data or "product_id" not in data:
            return {"error": "Missing 'content' or 'product_id' field"}, 422

        # Block replies here
        if data.get("parent_id") is not None:
            return {"error": "Use /comments/<comment_id>/replies to post replies"}, 400

        # Ensure the product exists
        product = Products.query.filter_by(id=data["product_id"], deleted_at=None).first()
        if not product:
            return {"error": "Product not found or has been deleted"}, 404

        new_comment = Comments(
            content=data["content"],
            user_id=current_user["id"],
            product_id=data["product_id"],  # Set the product_id to associate the comment with a product
            parent_id=None,
            created_at=datetime.utcnow()
        )

        db.session.add(new_comment)
        db.session.commit()

        return {**new_comment.to_dict(), "product": product.to_dict()}, 201

    
class CommentResource(Resource):
    @jwt_required()
    def delete(self, id):
        current_user = get_jwt_identity()

        comment = Comments.query.get(id)

        if not comment or comment.deleted_at is not None:
            return {'message': 'Comment not found!'}, 404

        if current_user['role'] != 'admin' and comment.user_id != current_user['id']:
            return {'error': 'You are not authorized to delete this comment!'}, 403

        comment.deleted_at = datetime.utcnow()
        db.session.commit()
        return {'message': 'Comment deleted successfully!'}, 200
    
    def get(self, id=None, product_id=None):
        if product_id:
            comments = Comments.query.filter_by(product_id=product_id).filter(Comments.deleted_at.is_(None)).all()

            if not comments:
                return {"error": "No comments found for this product"}, 404

            return [
                {
                    **comment.to_dict(),
                    "product": comment.product.to_dict() if comment.product else None
                }
                for comment in comments
            ]

        elif id:
            comment = Comments.query.filter_by(id=id).filter(Comments.deleted_at.is_(None)).first()

            if not comment:
                return {"error": "Comment not found!"}, 404

            return {
                **comment.to_dict(),
                "product": comment.product.to_dict() if comment.product else None
            }

        return {"error": "Invalid request, product_id or id required"}, 400
    
class CommentResourceCount(Resource):
    def get(self, comment_id):
        comment = Comments.query.filter_by(id=comment_id).filter(Comments.deleted_at.is_(None)).first()

        if not comment:
            return {"error": "Comment not found"}, 404

        likes_count = Likes.query.filter_by(comment_id=comment_id).count()

        return {"comment": comment.to_dict(), "likes_count": likes_count}, 200
    
class Reply(Resource):
    
    @jwt_required()
    def post(self, comment_id):
        current_user = get_jwt_identity()
        data = request.get_json()

        # Check if 'content' is in the request body
        if "content" not in data:
            return {"error": "Missing 'content' field"}, 422

        # Get the parent comment
        parent_comment = Comments.query.filter_by(id=comment_id, deleted_at=None).first()
        if not parent_comment:
            return {"error": "Parent comment not found or has been deleted"}, 404

        # Prevent replying to a reply (only root-level comments can have replies)
        if parent_comment.parent_id is not None:
            return {"error": "Cannot reply to a reply"}, 400

        # Create a new reply
        reply = Comments(
            content=data["content"],
            user_id=current_user["id"],
            parent_id=comment_id,
            created_at=datetime.utcnow()
        )

        # Commit to the database
        db.session.add(reply)
        db.session.commit()

        return reply.to_dict(), 201
    
    def get(self, comment_id):
        parent_comment = Comments.query.filter_by(id=comment_id).filter(Comments.deleted_at.is_(None)).first()
        if not parent_comment:
            return {"error": "Parent comment not found"}, 404

        if parent_comment.parent_id is not None:
            return {"error": "Cannot fetch replies of a reply"}, 400

        replies = Comments.query.filter_by(parent_id=comment_id).filter(Comments.deleted_at.is_(None)).all()
        if not replies:
            return {"message": "No replies found for this comment"}, 200

        return [reply.to_dict() for reply in replies], 200
    
class ReplyResource(Resource):
    @jwt_required()
    def delete(self, comment_id, reply_id):
        current_user = get_jwt_identity()

        parent_comment = Comments.query.get(comment_id)
        if not parent_comment or parent_comment.deleted_at is not None:
            return {"error": "Parent comment not found"}, 404

        if parent_comment.parent_id is not None:
            return {"error": "Cannot delete a reply to a reply"}, 400

        reply = Comments.query.get(reply_id)
        if not reply or reply.deleted_at is not None:
            return {"error": "Reply not found"}, 404

        if reply.parent_id is None:
            return {"error": "The provided ID is not a reply"}, 400

        if reply.parent_id != parent_comment.id:
            return {"error": "Reply does not belong to this comment"}, 400

        if reply.user_id != current_user["id"] and current_user["role"] != "admin":
            return {"error": "You are not authorized to delete this reply"}, 403

        # ✅ Soft delete
        reply.deleted_at = datetime.utcnow()
        db.session.commit()

        return {"message": "Reply deleted successfully!"}, 200
    
class LikeResource(Resource):
    @jwt_required()
    def post(self, product_id):
        current_user = get_jwt_identity()

        # ✅ Block likes on soft-deleted products
        product = Products.query.filter_by(id=product_id, deleted_at=None).first()
        if not product:
            return {"error": "Product not found or has been deleted"}, 404

        existing_like = Likes.query.filter_by(user_id=current_user['id'], product_id=product_id).first()
        if existing_like:
            return {"error": "You have already liked this product"}, 400

        like = Likes(user_id=current_user['id'], product_id=product_id)
        db.session.add(like)
        db.session.commit()

        return {"message": "Product liked successfully!"}, 201

    @jwt_required()
    def delete(self, product_id):
        current_user = get_jwt_identity()

        # ✅ Block unliking soft-deleted products
        product = Products.query.filter_by(id=product_id, deleted_at=None).first()
        if not product:
            return {"error": "Product not found or has been deleted"}, 404

        like = Likes.query.filter_by(user_id=current_user['id'], product_id=product_id).first()
        if not like:
            return {"error": "You have not liked this product yet"}, 400

        db.session.delete(like)
        db.session.commit()

        return {"message": "Like removed successfully!"}, 200

    @jwt_required()
    def get(self, product_id):
        current_user = get_jwt_identity()

        existing_like = Likes.query.filter_by(user_id=current_user['id'], product_id=product_id).first()
        liked = True if existing_like else False

        likes_count = Likes.query.filter_by(product_id=product_id).count()

        return {"liked": liked, "likes_count": likes_count}, 200
