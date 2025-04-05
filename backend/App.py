from flask import Flask, request, jsonify
import pickle
import numpy as np
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Create Flask app
app = Flask(__name__)
CORS(app)  # Allow frontend to talk to backend

# Load the pickled files
with open('movies.pkl', 'rb') as f:
    movies = pickle.load(f)

with open('similarity.pkl', 'rb') as f:
    similarity = pickle.load(f)

# Get movie titles list for searching
movie_list = movies['title'].values

# Function to recommend movies
def recommend(movie_name):
    movie_name = movie_name.lower()
    # Check if movie exists in the list
    if movie_name not in movies['title'].str.lower().values:
        return []

    idx = movies[movies['title'].str.lower() == movie_name].index[0]
    distances = similarity[idx]
    movie_indices = sorted(list(enumerate(distances)), reverse=True, key=lambda x: x[1])[1:11]

    recommended_movies = []
    for i in movie_indices:
        recommended_movies.append(movies.iloc[i[0]]['title'])

    return recommended_movies

# API route to get movie recommendations
@app.route('/recommend', methods=['GET'])
def recommend_movies():
    movie = request.args.get('movie')
    if not movie:
        return jsonify({'error': 'No movie title provided'}), 400

    results = recommend(movie)
    return jsonify({'recommended': results})

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

# Setup DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'  # change this in production

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Create DB
with app.app_context():
    db.create_all()

# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.username)
        return jsonify({'token': access_token}), 200

    return jsonify({'message': 'Invalid credentials'}), 401

# Protected Route
@app.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    current_user = get_jwt_identity()
    return jsonify({'user': current_user}), 200