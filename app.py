from sqlalchemy.exc import SQLAlchemyError
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from yaml import full_load
from itsdangerous import URLSafeTimedSerializer as Serializer, SignatureExpired, BadSignature
from os.path import join
from os import getcwd
from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity
from datetime import timedelta


# DB設定檔引入
config_path = join(getcwd(), "config.yaml")
app = Flask(__name__)
app.config.from_file(config_path, load=full_load)
db = SQLAlchemy(app)

# token生成器設定檔引入
s = Serializer(app.config['SECRET_KEY'])

# mail STMP 設定檔引入
mail = Mail(app)

# jwt 設定引入
jwt = JWTManager()
jwt.init_app(app)


class Users(db.Model):
    _id = db.Column('id', db.Integer, primary_key=True, nullable=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(162), nullable=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email


# with app.app_context():
#    db.create_all()


def send_email(token):
    subject = "驗證你的信箱"
    recipient = "recipient@example.com"
    msg = Message(subject=subject,
                  recipients=[recipient],
                  sender=app.config['MAIL_DEFAULT_SENDER'])
    html_content = f"""
        <h1>您好！</h1>
        <p>感謝您註冊我們的服務，請點擊以下連結以完成驗證：</p>
        <a href="http://127.0.0.1:5000/confirm_email/{token}">驗證連結</a>
        <br><br>
        <p>祝好，<br>我們的團隊</p>
        """

    # 構建郵件
    msg.html = html_content

    try:
        # 發送郵件
        mail.send(msg)
        return 'Email sent successfully'
    except Exception as e:
        return f'Failed to send email: {str(e)}'


@app.route("/")
def hello():
    return "Hello, Ugatto!"


@app.route('/register', methods=['GET', 'POST'])
def register():
    # 註冊使用者

    if request.method == 'POST':
        username = request.json.get('username')
        email = request.json.get('email')

        user = Users.query.filter_by(email=email).first()
        # 確認 email 是否已註冊
        if user:
            # email已設定密碼表示已註冊過
            if user.password != None:
                return jsonify({"error": "The account is existed"}), 400

            # email未設定密碼表示尚未驗證信箱
            else:
                user.username = username
                db.session.commit()
                send_email(token)
                return jsonify({"message": "Has send verify mail! Please check your mailbox!"}), 201

        # 生成安全令牌
        token = s.dumps(email, salt='email-confirm')

        # 創建新用戶
        new_user = Users(username=username, email=email)
        db.session.add(new_user)
        db.session.commit()
        send_email(token)

        return jsonify({"message": "Has send verify mail! Please check your mailbox!"}), 201

    return 123


@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    # 確認email

    try:
        # decode token並驗證
        email = s.loads(token, salt='email-confirm', max_age=3600)
        new_token = s.dumps(email, salt='password-setting')

        return jsonify({"message": "Token is valid!", "password_token": new_token}), 200
    except SignatureExpired:
        # token過期處理
        return jsonify({"error": "Token has expired. Please request a new one."}), 400
    except BadSignature:
        # 無效token處理
        return jsonify({"error": "Invalid token. Please check the link."}), 400


@app.route('/reset_password', methods=['POST'])
def reset_password():
    # 新用戶設定密碼

    password_token = request.json.get('password_token')
    password = request.json.get('password')

    try:
        email = s.loads(password_token, salt='password-setting')
        user = Users.query.filter_by(email=email).first()

        # 卻認此帳號是否已完成密碼設定
        if user.password != None:
            return jsonify({"error": "The account is existed"}), 400

        user.password = generate_password_hash(password)
        db.session.commit()

        return {"message": "User set password successfully!"}, 201
    except SignatureExpired:
        # token過期處理
        return jsonify({"error": "Token has expired. Please request a new one."}), 400
    except BadSignature:
        # 無效token處理
        return jsonify({"error": "Invalid token. Please check the link."}), 400


@app.route('/login', methods=['POST'])
def login():
    # 使用者登入

    email = request.json.get('email')
    password = request.json.get('password')

    # 查詢用戶是否存在
    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found!'}), 404

    # 驗證密碼（假設存儲的密碼是哈希值）
    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Incorrect password!'}), 401

    # 登入成功邏輯
    access_token = create_access_token(identity=email,
                                       expires_delta=timedelta(days=1),
                                       additional_claims=None)
    return jsonify({'message': 'Login successful!',
                    'jwt_token': access_token}), 200


@app.route('/jwtTest', methods=['POST'])
@jwt_required()
def jwtTest():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/user/<int:id>', methods=['DELETE'])
def delete_user(id):
    # 刪除使用者

    try:
        # 查找使用者
        user = Users.query.get_or_404(id)

        # 執行刪除
        db.session.delete(user)
        db.session.commit()

        # 返回成功訊息
        return jsonify({"message": "User deleted successfully!"}), 200
    except SQLAlchemyError as e:
        # 捕獲資料庫異常
        db.session.rollback()  # 回滾操作
        return jsonify({"error": "Database error occurred.", "details": str(e)}), 500
    except Exception as e:
        # 捕獲其他異常
        return jsonify({"error": "An unexpected error occurred.", "details": str(e)}), 500
