from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask_cors import CORS
from flask_mail import Mail, Message
from email_utils import send_welcome_email
import requests
import datetime 
import base64
import json
import os 
import re
from models import db, Orders, Payments, Users
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from resources.crud import User, Product, Order, OrderResource, Carts, Payment, CartsResource, ProductResource, Checkout, Comment, CommentResource, CommentResourceCount, LikeResource, Reply, ReplyResource, MeResource

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

# mpesa integration

consumer_key = os.getenv('CONSUMER_KEY')
consumer_secret = os.getenv('CONSUMER_SECRET')
shortcode = os.getenv('SHORTCODE')
passkey = os.getenv('PASSKEY')
callback_url = "https://0e87-197-248-19-111.ngrok-free.app/mpesa/callback"

@app.route('/mpesa/pay', methods=['POST'])
@jwt_required()
def mpesa_pay():
    current_user = get_jwt_identity()
    data = request.get_json()

    print("Received data:", data)

    phone_number = str(data.get('phone_number') or "").strip()
    if not phone_number:
        return jsonify({'error': 'Phone number is required'}), 400
    order_id = data.get('order_id')

    if not phone_number or not order_id:
        return jsonify({'error': 'Phone number and Order ID are required'}), 400

    # 🛑 Fetch order & validate
    order = db.session.get(Orders, order_id)
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    if order.user_id != current_user['id']:
        return jsonify({'error': 'Unauthorized to pay for this order'}), 403
    if order.status == "completed":
        return jsonify({'error': 'Order is already paid for'}), 400
    
    amount = int(order.total_price)

    if amount != order.total_price:  # ✅ Ensure correct amount
        return jsonify({'error': f'Incorrect amount! Order requires {order.total_price}'}), 400

    # ✅ Use order's total price
    amount = order.total_price  

    access_token = get_access_token()
    if not access_token:
        return jsonify({'error': 'Failed to get Mpesa access token!'}), 500

    timestamp = get_timestamp()
    password = generate_password(shortcode, passkey, timestamp)

    payload = {
        "BusinessShortCode": shortcode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": shortcode,
        "PhoneNumber": phone_number,
        "CallBackURL": callback_url,
        "AccountReference": str(order_id),  # Store order_id in reference
        "TransactionDesc": f"Payment for Order #{order_id}"
    }

    stk_push_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    response = requests.post(stk_push_url, json=payload, headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'})

    if response.status_code == 200:
        response_data = response.json()
        merchant_request_id = response_data.get("MerchantRequestID")
        checkout_request_id = response_data.get("CheckoutRequestID")

        # order.status == "completed"

        fake_receipt = f"FAKE-{merchant_request_id[:6]}"

        # ✅ Store payment in DB with tracking IDs
        new_payment = Payments(
            order_id=order_id,
            user_id=current_user['id'],
            phone_number=phone_number,
            amount=amount,
            status="Completed",
            merchant_request_id=merchant_request_id,
            checkout_request_id=checkout_request_id,
            mpesa_receipt_number=fake_receipt
        )

        db.session.add(new_payment)

        order.status = "completed"

        db.session.commit()

        return jsonify({'message': 'STK push initiated successfully', "data": response_data}), 200

    return jsonify({'error': 'Failed to initiate STK push', 'data': response.json()}), 500
    
@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    data = request.get_json()

    try:
        result_code = data['Body']['stkCallback']['ResultCode']
        result_desc = data['Body']['stkCallback']['ResultDesc']
        checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']  # This is what we use to track payments

        if result_code == 0:  # ✅ Payment was successful
            callback_metadata = data['Body']['stkCallback']['CallbackMetadata']['Item']
            amount = next(item['Value'] for item in callback_metadata if item['Name'] == 'Amount')
            mpesa_receipt_number = next(item['Value'] for item in callback_metadata if item['Name'] == 'MpesaReceiptNumber')
            phone_number = next(item['Value'] for item in callback_metadata if item['Name'] == 'PhoneNumber')

            # ✅ Find payment using checkout_request_id
            payment = Payments.query.filter_by(checkout_request_id=checkout_request_id).first()
            if not payment:
                return jsonify({'error': 'Payment record not found'}), 404

            # ✅ Find the associated order
            order = Orders.query.get(payment.order_id)
            if not order:
                return jsonify({'error': 'Order not found'}), 404

            # ✅ Update payment details
            payment.status = "Completed"
            payment.mpesa_receipt_number = mpesa_receipt_number
            payment.transaction_date = datetime.datetime.utcnow()
            db.session.commit()

            # ✅ Mark order as completed
            order.status = "completed"
            db.session.commit()

            return jsonify({
                'message': 'Payment received successfully!',
                'receipt': mpesa_receipt_number,
                'amount': amount,
                'phone': phone_number
            }), 200

        else:  # ❌ Payment failed
            payment = Payments.query.filter_by(checkout_request_id=checkout_request_id).first()
            if payment:
                payment.status = "Failed"
                db.session.commit()

            return jsonify({'status': 'Failed', 'message': result_desc}), 400

    except KeyError:
        return jsonify({'error': 'Invalid callback data'}), 400

    
def get_access_token():
    url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    response = requests.get(url, auth=(consumer_key, consumer_secret))
    return response.json().get('access_token') if response.status_code == 200 else None

def generate_password(shortcode, passkey, timestamp):
    data_to_encode = f'{shortcode}{passkey}{timestamp}'
    return base64.b64encode(data_to_encode.encode()).decode('utf-8')

def get_timestamp():
    return datetime.datetime.now().strftime('%Y%m%d%H%M%S')


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

# Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # For Gmail
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')  # Use .env or hardcode for now
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')  # Use app password if using Gmail
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

mail = Mail(app)

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

        if email and Users.query.filter(Users.email == email, Users.is_active == True).first():
            return {'error': 'Email already exists!'}, 400

        if phone and Users.query.filter(Users.phone == phone, Users.is_active == True).first():
            return {'error': 'Phone number already exists!'}, 400

        if not is_strong_password(password):
            return {'error': 'Password must be at least 8 characters long and contain both letters and numbers.'}, 400

        if password != confirm_password:
            return {'error': 'Passwords do not match!'}, 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(name=name, email=email, phone=phone, password=hashed_password, role=role)

        db.session.add(new_user)
        db.session.commit()

        # ✅ Send welcome email if email is provided
        if new_user.email:
            send_welcome_email(new_user.email, new_user.name)

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
            return {'error': 'Please use either email or phone number and password!'}, 400

        if "@" in identifier and identifier.isdigit():
            return {'error': 'Enter either email or phone number, not both!'}, 400

        # Only fetch users who are active and not soft deleted
        user = Users.query.filter(
            ((Users.email == identifier) | (Users.phone == identifier)) & 
            (Users.is_active == True) & 
            (Users.deleted_at == None)
        ).first()

        if user and bcrypt.check_password_hash(user.password, password):
            user_data = {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone': user.phone,
                'role': user.role
            }

            return {
                'create_token': create_access_token(identity=user_data),
                'refresh_token': create_refresh_token(identity=user_data),
                'role': user.role,
                'user': user_data
            }, 200

        # return {'error': 'Incorrect email, phone number, password, or account is deactivated!'}, 401
        return {'error': 'Invalid credentials!'}, 401

# from datetime import datetime

class DeleteAcc(Resource):
    @jwt_required()
    def delete(self):
        current = get_jwt_identity()
        user_id = current.get('id')
        role = current.get('role')

        data = request.get_json()
        target_user_id = int(data.get('user_id')) if data and 'user_id' in data else user_id

        if role != "admin" and target_user_id != user_id:
            return {'error': 'Unauthorized action!'}, 403

        delete_user = Users.query.get(target_user_id)
        if not delete_user or not delete_user.is_active:
            return {'error': 'The user does not exist or is already deactivated!'}, 404

        delete_user.is_active = False
        delete_user.deleted_at = datetime.datetime.utcnow()
        delete_user.email = f"deleted_{delete_user.id}_{delete_user.email}"
        delete_user.phone = f"deleted_{delete_user.id}_{delete_user.phone}"

        db.session.commit()

        return {'message': 'The user account has been deactivated successfully!'}, 200
    
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


api.add_resource(MeResource, '/me')
api.add_resource(User, '/users')
api.add_resource(Product, '/products')
api.add_resource(ProductResource, "/products/<int:product_id>")
api.add_resource(Order, '/orders')
api.add_resource(OrderResource, '/orders/<int:order_id>', '/orders')
api.add_resource(Payment, '/payments') 
api.add_resource(Carts, '/cart') 
api.add_resource(CartsResource, '/cart', '/cart/<int:cart_id>')
api.add_resource(Checkout, '/checkout')

api.add_resource(Comment, '/comments')
api.add_resource(CommentResource, '/comments/<int:id>', '/comments/product/<int:product_id>')
api.add_resource(CommentResourceCount, '/comment/<int:comment_id>')
api.add_resource(Reply, '/comments/<int:comment_id>/replies')
api.add_resource(ReplyResource, '/comments/<int:comment_id>/replies/<int:reply_id>')
api.add_resource(LikeResource, '/products/<int:product_id>/likes') 
# api.add_resource(LikeResource, '/comments/<int:comment_id>/likes_count')
# api.add_resource(Reply, '/replies')

if __name__ == '__main__':
    app.run(debug=True)