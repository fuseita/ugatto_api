from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:virgo@127.0.0.1:9020/test'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Users(db.Model):
    _id = db.Column('id', db.Integer, primary_key=True, nullable=True)
    username = db.Column('username', db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password


# with app.app_context():
#    db.create_all()


@app.route("/")
def hello():
    return "Hello, Ugatto!"

# 創建使用者
@app.route('/creatAccount', methods=['POST'])
def creat_account():
    data = request.json
    new_account = Users(
        username=data['username'], password=data['password'], email=data['email'])
    db.session.add(new_account)
    db.session.commit()

    return jsonify({'message': 'user created!', 'id': new_account._id}), 201

# 取得所有使用者
@app.route('/users', methods=['GET'])
def get_all_users():
    users = Users.query.all()
    
    return jsonify([{'id': user._id, 'username': user.username, 'email': user.email, 'password': user.password} for user in users])

# 取得一位使用者 by id
@app.route('/user/<int:id>')
def get_user(id):
    user = Users.query.get_or_404(id)

    return jsonify([{'id': user._id, 'username': user.username, 'email': user.email, 'password': user.password}])

# 更新一位使用者
@app.route('/user/<int:id>', methods=['PUT'])
def update_user(id):
    user = Users.query.get_or_404(id)
    data = request.json
    user.username  = data['username']
    user.email = data['email']
    user.password = data['password']
    db.session.commit()

    return {"message": "User updated successfully!"}, 200

# 刪除一位使用者
@app.route('/user/<int:id>', methods=['DELETE'])
def delete_user(id):
    user = Users.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return {"message": "User deleted successfully!"}, 200