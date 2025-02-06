from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)  # Inisialisasi SQLAlchemy

migrate = Migrate(app, db)  # Inisialisasi Flask-Migrate

# Model untuk pengguna
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  # Kolom email
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Tambahkan kolom is_admin

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(255), nullable=True)  # Pastikan kolom ini ada
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Order(db.Model):
       id = db.Column(db.Integer, primary_key=True)
       user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
       product_name = db.Column(db.String(150), nullable=False)
       quantity = db.Column(db.Integer, nullable=False)
       price = db.Column(db.Float, nullable=False)
       total = db.Column(db.Float, nullable=False)
       address = db.Column(db.String(255), nullable=False)
    
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/shop")
def shop():
    return render_template("shop.html")

@app.route('/cart')
def cart():
    if 'username' in session:
        user_id = session['user_id']
        cart_items = Cart.query.filter_by(user_id=user_id).all()
        total_items = sum(item.quantity for item in cart_items)  # Hitung total item
        return render_template('cart.html', cart_items=cart_items, total_items=total_items)
    return redirect(url_for('login'))

@app.route("/contact")
def contact():
    return  render_template("contact.html")

@app.route("/testimonial")
def testimonial():
    return  render_template("testimonial.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['username'] = user.username  # Simpan username di session
            session['user_id'] = user.id  # Simpan user_id di session
            session['is_admin'] = user.is_admin  # Simpan status admin di session
            return redirect(url_for('home'))  # Redirect ke halaman home setelah login
        else:
            return render_template("login.html", error="Username atau password salah.")
    return render_template("login.html")

@app.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        is_admin = request.form.get("is_admin") == 'on'  # Menambahkan checkbox untuk admin

        # Cek apakah username atau email sudah ada
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return render_template("sign-up.html", error="Username atau email sudah digunakan.")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, email=email, is_admin=is_admin)  # Menambahkan is_admin
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("sign-up.html")

@app.route("/logout")
def logout():
    session.pop('username', None)  # Hapus username dari session
    return redirect(url_for('home'))

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'username' in session:
        product_name = request.form.get('product_name')
        quantity = request.form.get('quantity')
        price = request.form.get('price')
        image_url = request.form.get('image_url')  # Ambil URL gambar dari form
        user_id = session['user_id']

        new_cart_item = Cart(product_name=product_name, quantity=quantity, price=price, image_url=image_url, user_id=user_id)
        
        db.session.add(new_cart_item)
        db.session.commit()
        return redirect(url_for('shop'))  # Redirect ke halaman shop setelah menambahkan
    return redirect(url_for('login'))  # Redirect ke login jika belum login

@app.route('/confirm-checkout', methods=['GET', 'POST'])
def confirm_checkout():
    if 'username' in session:
        user_id = session['user_id']
        cart_items = Cart.query.filter_by(user_id=user_id).all()

        if request.method == 'POST':
            address = request.form.get('address')

            # Simpan setiap item ke dalam tabel Orders
            for item in cart_items:
                new_order = Order(
                    user_id=user_id,
                    product_name=item.product_name,
                    quantity=item.quantity,
                    price=item.price,
                    total=item.quantity * item.price,
                    address=address
                )
                db.session.add(new_order)

            # Hapus semua item dari keranjang setelah checkout
            for item in cart_items:
                db.session.delete(item)
            db.session.commit()

            return redirect(url_for('thank_you'))

        return render_template('confirm-checkout.html', cart_items=cart_items)
    return redirect(url_for('login'))

@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    if 'username' in session:
        cart_item = Cart.query.get(item_id)
        if cart_item:
            db.session.delete(cart_item)
            db.session.commit()
        return redirect(url_for('cart'))  # Redirect kembali ke halaman cart
    return redirect(url_for('login'))

@app.route('/thank-you')
def thank_you():
    return render_template('thank-you.html')

@app.route('/admin')
def admin_dashboard():
    if 'username' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        if user.is_admin:
            orders = Order.query.all()  # Ambil semua data dari tabel Orders
            return render_template('admin_dashboard.html', orders=orders)  # Kirim data ke template
    return redirect(url_for('login'))  # Redirect ke login jika bukan admin

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Membuat tabel jika belum ada
    
    port = int(os.environ.get('PORT', 8080))  # Ubah default port ke 8080
    app.run(host='0.0.0.0', port=port)  # Hapus debug mode untuk production
