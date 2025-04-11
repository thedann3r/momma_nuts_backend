from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import UniqueConstraint
from flask_marshmallow import Marshmallow
from datetime import datetime
# import datetime

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

    orders = db.relationship('Orders', back_populates='user', lazy=True, cascade="all, delete-orphan")
    payments = db.relationship('Payments', back_populates='user', lazy=True, cascade="all, delete-orphan")
    cart_items = db.relationship('Cart', back_populates='user', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comments', back_populates='user', cascade="all, delete")
    likes = db.relationship('Likes', back_populates='user', cascade="all, delete")

    def to_dict(self, include_comments=True, include_likes=True, include_orders=True, include_payments=True):
        data = {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
        }
        if include_comments:
            data["comments"] = [comment.to_dict() for comment in self.comments]
        if include_likes:
            data["likes"] = [like.to_dict() for like in self.likes]
        if include_orders:
            data["orders"] = [order.to_dict() for order in self.orders]
        if include_payments:
            data["payments"] = [payment.to_dict() for payment in self.payments]
        return data

    serialize_rules = ('-orders.user', '-payments.user', '-cart_items.user', '-password', '-comments.user', '-likes.user')

class Products(db.Model, SerializerMixin):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255), nullable=True)
    stock = db.Column(db.Integer, default=0)

    order_items = db.relationship('OrderItems', back_populates='product', lazy=True, cascade="all, delete-orphan")
    cart_items = db.relationship('Cart', back_populates='product', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comments', back_populates='product', cascade="all, delete")

    def to_dict(self, include_comments=True):
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price": self.price,
            "image": self.image,
            "stock": self.stock,
        }
        if include_comments:
            data["comments"] = [comment.to_dict() for comment in self.comments]
        return data

    # serialize_rules = ('-order_items.product', '-cart_items.product')
    serialize_rules = ('-order_items.product', '-cart_items.product', '-order_items.order', '-order_items.order.items', '-order_items.order.user.comments', '-comments.product')

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
    
    serialize_rules = ('-order.items', '-order.payment', '-product.order_items',)

class Payments(db.Model, SerializerMixin):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    mpesa_receipt_number = db.Column(db.String(50), unique=True, nullable=True)
    phone_number = db.Column(db.String(15), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="Pending")  # Possible values: Pending, Completed, Failed
    transaction_date = db.Column(db.DateTime, default=datetime.utcnow)
    checkout_request_id = db.Column(db.String(100), unique=True, nullable=True)
    merchant_request_id = db.Column(db.String(100), unique=True, nullable=True)

    #relationships
    order = db.relationship('Orders', back_populates='payment')
    user = db.relationship('Users', back_populates='payments')

    serialize_rules = ('-order.payment', '-user.payments', '-order.items', '-order.user', '-order.items.product')

    def to_dict(self):
        # Manually convert datetime fields to string (ISO 8601 format)
        serialized_data = {
            'id': self.id,
            'order_id': self.order_id,
            'user_id': self.user_id,
            'mpesa_receipt_number': self.mpesa_receipt_number,
            'phone_number': self.phone_number,
            'amount': self.amount,
            'status': self.status,
            'transaction_date': self.transaction_date.isoformat() if self.transaction_date else None,
            'checkout_request_id': self.checkout_request_id,
            'merchant_request_id': self.merchant_request_id
        }
        
        # Convert related models to dict (order, user)
        serialized_data['order'] = self.order.to_dict() if self.order else None
        serialized_data['user'] = self.user.to_dict() if self.user else None

        return serialized_data

class Cart(db.Model, SerializerMixin):
    __tablename__ = 'cart'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    # added_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    #relationships
    user = db.relationship('Users', back_populates='cart_items')
    product = db.relationship('Products', back_populates='cart_items')
    
    serialize_rules = ('-user.cart_items', '-product.cart_items', '-product.order_items')

class Currency(db.Model, SerializerMixin):
    __tablename__ = 'currencies'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)  # e.g., "KES", "USD"
    name = db.Column(db.String(50), nullable=False)  # e.g., "Kenyan Shilling"
    exchange_rate = db.Column(db.Float, nullable=False)  # Exchange rate to base currency
    last_updated = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    serialize_rules = ()

class Comments(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # This should now work
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("comments.id"), nullable=True)  # For replies

    # Relationships
    user = db.relationship("Users", back_populates="comments")
    replies = db.relationship("Comments", back_populates="parent", cascade="all, delete-orphan")
    parent = db.relationship("Comments", remote_side=[id], back_populates="replies")
    product = db.relationship("Products", back_populates="comments")
    likes = db.relationship("Likes", back_populates="comment", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
            "user": self.user.to_dict(include_comments=False, include_orders=False, include_payments=False) if self.user else None,
            "replies": [reply.to_dict_without_replies() for reply in self.replies] if self.replies else [],
            "product": self.product.to_dict(include_comments=False) if self.product else None,
            "parent_id": self.parent_id,
        }

    # Add this helper to safely serialize a reply without nesting its own replies again:
    def to_dict_without_replies(self):
        return {
            "id": self.id,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
            "user": self.user.to_dict(include_comments=False, include_orders=False, include_payments=False) if self.user else None,
            "product": None,  # Skip product in replies
            "parent_id": self.parent_id,
        }


    # serialize_rules = (
    #     '-user.password',  # Exclude sensitive user data
    #     '-replies.parent_id',  # Exclude the parent_id of replies to prevent recursion
    #     '-user.comments',  # Avoid sending the user's own comments
    #     '-product.comments'
    # )
    serialize_rules = (
        '-user.comments',         # Prevents going from comment → user → user's other comments
        '-product.comments',      # Prevents going from comment → product → other comments on that product
        '-replies.parent',        # Prevents replies from including their parent comment again (avoids nesting recursion)
        '-likes.comment',         # Prevents going from comment → likes → back to comment (recursion loop)
        '-user.password',         # Security: hides the user's password
    )

class Likes(db.Model):
    __tablename__ = 'likes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey("comments.id"), nullable=False)

    user = db.relationship("Users", back_populates="likes")
    comment = db.relationship("Comments", back_populates="likes")

    def to_dict(self):
        return {
            "id": self.id,
            "user": {
                "id": self.user.id,
                "name": self.user.name,
                "email": self.user.email
            },
            "comment": {
                "id": self.comment.id,
                "content": self.comment.content,
                "user_id": self.comment.user_id
            } if self.comment else None
        }

    __table_args__ = (db.UniqueConstraint('user_id', 'comment_id', name='unique_like'),)

    serialize_rules = (
        '-user.password',  # Exclude sensitive user data
        '-comment.likes',  # Avoid serializing all likes on the comment when not needed
        '-comment.user.comments',  # Avoid circular reference to user comments
    )
