from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import UniqueConstraint
from flask_marshmallow import Marshmallow
import datetime

db = SQLAlchemy()
ma = Marshmallow()

class Users(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    #relationships
    orders = db.relationship('Orders', back_populates='user', lazy=True, cascade="all, delete-orphan")
    payments = db.relationship('Payments', back_populates='user', lazy=True, cascade="all, delete-orphan")
    cart_items = db.relationship('Cart', back_populates='user', lazy=True, cascade="all, delete-orphan")

    serialize_rules = ('-orders.user', '-payments.user', '-cart_items.user', '-password')

class Products(db.Model, SerializerMixin):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255), nullable=True)  # Store image URLs
    stock = db.Column(db.Integer, default=0)

    #relationships
    order_items = db.relationship('OrderItems', back_populates='product', lazy=True, cascade="all, delete-orphan")
    cart_items = db.relationship('Cart', back_populates='product', lazy=True, cascade="all, delete-orphan")

    serialize_rules = ('-order_items.product', '-cart_items.product')

class Orders(db.Model, SerializerMixin):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, completed, canceled
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    #relationships
    user = db.relationship('Users', back_populates='orders')
    items = db.relationship('OrderItems', back_populates='order', lazy=True, cascade="all, delete-orphan")
    payment = db.relationship('Payments', back_populates='order', uselist=False, cascade="all, delete-orphan")  # One-to-One

    serialize_rules = ('-user.orders', '-items.order', '-payment.order')

class OrderItems(db.Model, SerializerMixin):
    __tablename__ = 'order_items'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    price = db.Column(db.Float, nullable=False)

    #relationships
    order = db.relationship('Orders', back_populates='items')
    product = db.relationship('Products', back_populates='order_items')
    
    serialize_rules = ('-order.items', '-product.order_items')

class Payments(db.Model, SerializerMixin):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mpesa_receipt_number = db.Column(db.String(50), unique=True, nullable=True)
    phone_number = db.Column(db.String(15), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="Pending")  # Possible values: Pending, Completed, Failed
    transaction_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    checkout_request_id = db.Column(db.String(100), unique=True, nullable=True)
    merchant_request_id = db.Column(db.String(100), unique=True, nullable=True)

    #relationships
    order = db.relationship('Orders', back_populates='payment')
    user = db.relationship('Users', back_populates='payments')
    
    serialize_rules = ('-order.payment', '-user.payments')

class Cart(db.Model, SerializerMixin):
    __tablename__ = 'cart'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    added_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    #relationships
    user = db.relationship('Users', back_populates='cart_items')
    product = db.relationship('Products', back_populates='cart_items')
    
    serialize_rules = ('-user.cart_items', '-product.cart_items')

class Currency(db.Model, SerializerMixin):
    __tablename__ = 'currencies'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)  # e.g., "KES", "USD"
    name = db.Column(db.String(50), nullable=False)  # e.g., "Kenyan Shilling"
    exchange_rate = db.Column(db.Float, nullable=False)  # Exchange rate to base currency
    last_updated = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    serialize_rules = ()