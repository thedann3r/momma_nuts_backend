from flask_mail import Message
# from your_flask_app import mail  # import your `mail` instance
# from app import mail

def send_email(to_email, subject, body): 
    try:
        from app import mail  # Import here to avoid circular import
        msg = Message(subject, recipients=[to_email], body=body)
        mail.send(msg)
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")

def send_welcome_email(email, name):
    subject = "Welcome to Momma Nut!"
    body = f"Hello {name},\n\nThank you for signing up for PeanutApp. We’re glad to have you!"
    send_email(email, subject, body)


def send_order_confirmation_email(email, order_id):
    subject = f"Order Confirmation - Order #{order_id}"
    body = f"Hello,\n\nYour order #{order_id} has been successfully placed. Thank you for shopping with PeanutApp!"
    send_email(email, subject, body)

def send_password_reset_email(email, reset_link):
    subject = "Password Reset Request"
    body = f"Hello,\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you didn't request this, please ignore this email."
    send_email(email, subject, body)

# def send_order_confirmation_email(user_email, order_id):
#     subject = f"Order Confirmation - Order #{order_id}"
#     body = f"Hello,\n\nYour order #{order_id} has been successfully placed. Thank you for shopping with PeanutApp!"
#     send_email(user_email, subject, body)

# from models import Orders

# def send_order_confirmation_email(user_email, order_id):
#     order = Orders.query.filter_by(id=order_id).first()

#     if not order:
#         print(f"Order #{order_id} not found.")
#         return

#     # Get product names from order items
#     try:
#         product_names = [item.product.name for item in order.order_items]
#         product_list = ", ".join(product_names)
#     except Exception as e:
#         print(f"Failed to retrieve product names for order #{order_id}: {e}")
#         product_list = "Unavailable"

#     subject = f"Order Confirmation - Order #{order_id}"
#     body = f"""Hello,

# Your order #{order_id} has been successfully placed.
# Products in your order: {product_list}

# Thank you for shopping with PeanutApp!
# """

#     send_email(user_email, subject, body)

# def send_email(to_email, subject, body):
#     try:
#         msg = Message(subject, recipients=[to_email], body=body)
#         mail.send(msg)
#     except Exception as e:
#         print(f"Failed to send email to {to_email}: {e}")
