from flask import Flask, jsonify, request
import os
from models import db, User, Recipe, RecipeIngredient, RecipeStep, Image
from datetime import datetime
from flask_migrate import Migrate
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
import re
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_jwt_extended import create_refresh_token, get_jwt, jwt_required, get_jwt_identity
from sqlalchemy import String, cast, or_


app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000", "https://recipes.dylanastrup.com"]}}, supports_credentials=True)

# --- START OF CORRECTED SECTION ---
# Database Configuration
uri = os.environ.get('DATABASE_URL')
if uri:  # If the DATABASE_URL is set at all...
    # Heroku URLs start with postgres://, but SQLAlchemy needs postgresql://
    # This check is for future compatibility.
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
else: # Otherwise, fall back to SQLite for local development
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    uri = f'sqlite:///{os.path.join(BASE_DIR, "recipes.db")}'

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- END OF CORRECTED SECTION ---

db.init_app(app)
migrate = Migrate(app,db)

# Set up a secret key for signing JWT tokens
app.config['JWT_SECRET_KEY'] = '9a8ab176bee3c41cddf4436bb6e1c41dfc7944bb4ee1dd1eded09372c8f05844'
jwt = JWTManager(app)


# Import models from models folder
from models.User import User
from models.Recipe import Recipe
from models.Ingredient import Ingredient
from models.Measurement import Measurement
from models.RecipeIngredient import RecipeIngredient
from models.RecipeStep import RecipeStep
from models.Tag import Tag
from models.RecipeTag import recipe_tags
from models.Image import Image


from flask_jwt_extended import create_access_token

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  #SMTP server
app.config['MAIL_PORT'] = 587  # Standard port for secure emails
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dylanastrup@gmail.com'  
app.config['MAIL_PASSWORD'] = 'bcob qkhm qwvs ttym' 
app.config['MAIL_DEFAULT_SENDER'] = 'dylanastrup@gmail.com' 

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])

@app.route("/ping")
def ping():
    print("📶 /ping called!")
    return "pong", 200


@app.route('/api/whoami')
@jwt_required()
def whoami():
    print("🔍 Headers received:", dict(request.headers))  # Add this line
    current_user = get_jwt_identity()
    print("🔍 JWT Identity Received:", current_user)
    return jsonify(current_user)



## REGISTER ##

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400
        

    username = data['username']
    email = data['email']
    password = data['password']

    # Validate username (at least 3 characters)
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400

    # Validate email format
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"error": "Invalid email format"}), 400

    # Validate password (at least 8 characters, 1 number, 1 special character)
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    if not re.match(password_regex, password):
        return jsonify({
            "error": "Password must be at least 8 characters long, "
                     "contain at least one number and one special character (@$%*?&)."
        }), 400

    # Check if user already exists
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    # Create new user and hash password using set_password()
    new_user = User(username=username, email=email)
    new_user.set_password(password)  # Hash password before storing

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

## REGISTER OPTIONS ##

@app.route('/api/register', methods=['OPTIONS'])
def register_options():
    origin = request.headers.get('Origin', '')
    if origin in ["http://localhost:3000", "https://recipes.dylanastrup.com"]:
        response = jsonify({"message": "CORS preflight successful"})
        response.headers.add("Access-Control-Allow-Origin", origin)
        response.headers.add("Access-Control-Allow-Credentials", "true")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        return response, 200
    return jsonify({"error": "Unauthorized origin"}), 403



## LOGIN ##


@app.route('/api/login', methods=['OPTIONS', 'POST'])
@cross_origin(origins=["http://localhost:3000", "https://recipes.dylanastrup.com"], supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=str(user.id), additional_claims={"role": user.role}, fresh=True)
        refresh_token = create_refresh_token(identity=str(user.id), additional_claims={"role": user.role})
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200

    return jsonify({"error": "Invalid credentials"}), 401

## FORGOT PASSWORD ##

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No account with this email"}), 400

    # Generate a secure reset token
    token = serializer.dumps(email, salt="password-reset-salt")

    # Create reset URL
    allowed_origins = ["http://localhost:3000", "https://recipes.dylanastrup.com"]
    origin = request.headers.get("Origin", "http://localhost:3000")
    if origin not in allowed_origins:
        return jsonify({"error": "Unauthorised request origin"}), 403
    reset_url = f"{origin}/reset-password/{token}"  

    # Send Email
    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"Click the link to reset your password: {reset_url}"
    mail.send(msg)

    return jsonify({"message": "Password reset email sent"}), 200


## RESET PASSWORD ##

@app.route('/api/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)  # Token expires in 1 hour
    except:
        return jsonify({"error": "Invalid or expired token"}), 400

    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password or len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 400

    # Update password
    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully"}), 200


## HOME ##

@app.route('/api/')
def home():
    return "Welcome to the Recipe Book!"


## API TEST##

@app.route('/api/test', methods=['GET'])
def test_route():
    return jsonify({"message": "This is a test response."})


## GET ALL RECIPES ##

@app.route('/api/recipes', methods=['GET'])
@jwt_required()
def get_recipes():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    user_favorites = {recipe.id for recipe in user.favorite_recipes} # Get a set of favorite recipe IDs
    search = request.args.get('search', '').lower()
    sort_by = request.args.get('sort', '')
    
    query = Recipe.query

    if search:
        # Changed .join() to .outerjoin() to include recipes with no tags
        query = query.outerjoin(Recipe.tags).filter(
            or_(
                Recipe.recipe_name.ilike(f"%{search}%"),
                Recipe.cuisine.ilike(f"%{search}%"),
                Recipe.recipe_description.ilike(f"%{search}%"),
                Tag.tag_name.ilike(f"%{search}%")
            )
        ).distinct()

    sort_options = {
        "recipe_name_asc": Recipe.recipe_name.asc(), "recipe_name_desc": Recipe.recipe_name.desc(),
        "cuisine_asc": Recipe.cuisine.asc(), "cuisine_desc": Recipe.cuisine.desc(),
        "total_time_asc": (Recipe.prep_time + Recipe.cook_time).asc(), "total_time_desc": (Recipe.prep_time + Recipe.cook_time).desc(),
        "difficulty_asc": Recipe.difficulty.asc(), "difficulty_desc": Recipe.difficulty.desc(),
        "servings_asc": Recipe.servings.asc(), "servings_desc": Recipe.servings.desc(),
    }
    if sort_by in sort_options:
        query = query.order_by(sort_options[sort_by])
    else:
        query = query.order_by(Recipe.created_at.desc())
        
    recipes = query.all()
    recipe_list = []
    for recipe in recipes:
        recipe_list.append({
            "id": recipe.id, "recipe_name": recipe.recipe_name, "description": recipe.recipe_description,
            "cuisine": recipe.cuisine, "prep_time": recipe.prep_time, "cook_time": recipe.cook_time,
            "total_time": recipe.prep_time + recipe.cook_time, "servings": recipe.servings,
            "difficulty": recipe.difficulty, "created_at": recipe.created_at,
            "ingredients": [{"ingredient_name": ri.ingredient.ingredient_name, "amount": ri.ingredient_quantity, "measurement_unit": ri.measurement.measurement_name if ri.measurement else None} for ri in recipe.recipe_ingredient],
            "steps": [{"step_number": step.step_number, "instruction": step.step_description} for step in recipe.recipe_step],
            "tags": [tag.tag_name for tag in recipe.tags],
            "images": [img.image_url for img in recipe.image],
            "is_favorited": recipe.id in user_favorites
        })
    return jsonify(recipe_list)



@app.route('/api/recipes', methods=['POST'])
def create_recipe():
    data = request.get_json()
    if not data or "user_id" not in data:
        return jsonify({"error": "Missing required data"}), 400

    try:
        new_recipe = Recipe(
            user_id=data['user_id'],
            recipe_name=data['recipe_name'],
            recipe_description=data['description'],
            cuisine=data['cuisine'],
            prep_time=data['prep_time'],
            cook_time=data['cook_time'],
            servings=data['servings'],
            difficulty=data['difficulty']
        )
        db.session.add(new_recipe)
        db.session.flush()

        for ingredient in data.get('ingredients', []):
            ingredient_name = ingredient.get('ingredient_name')
            measurement_name = ingredient.get('measurement_name')
            quantity = ingredient.get('amount')
            if not ingredient_name or not quantity: continue
            
            existing_ingredient = Ingredient.query.filter_by(ingredient_name=ingredient_name).first()
            if not existing_ingredient:
                existing_ingredient = Ingredient(ingredient_name=ingredient_name)
                db.session.add(existing_ingredient)
                db.session.flush()

            existing_measurement = Measurement.query.filter_by(measurement_name=measurement_name).first()
            if not existing_measurement and measurement_name:
                existing_measurement = Measurement(measurement_name=measurement_name)
                db.session.add(existing_measurement)
                db.session.flush()

            recipe_ingredient = RecipeIngredient(
                recipe_id=new_recipe.id,
                ingredient_id=existing_ingredient.id,
                measurement_id=existing_measurement.id if existing_measurement else None,
                ingredient_quantity=quantity
            )
            db.session.add(recipe_ingredient)

        for step in data.get('steps', []):
            recipe_step = RecipeStep(
                recipe_id=new_recipe.id,
                step_number=step.get('step_number'),
                step_description=step.get('instruction')
            )
            db.session.add(recipe_step)

        for image_url in data.get('images', []):
            if image_url:
                recipe_image = Image(recipe_id=new_recipe.id, image_url=image_url)
                db.session.add(recipe_image)

        tag_names = data.get('tags', [])
        for tag_name_str in tag_names:
            if tag_name_str:
                tag = Tag.query.filter_by(tag_name=tag_name_str).first()
                if not tag:
                    tag = Tag(tag_name=tag_name_str)
                    db.session.add(tag)
                new_recipe.tags.append(tag)

        db.session.commit()
        return jsonify({ "id": new_recipe.id, "message": "Recipe created successfully" }), 201

    except Exception as e:
        db.session.rollback()
        print("Database Error:", str(e))
        return jsonify({"error": "An internal error occurred"}), 500


@app.route('/api/recipes/<int:recipe_id>', methods=['PUT'])
@jwt_required()
def update_recipe(recipe_id):
    current_user_id = get_jwt_identity()
    data = request.get_json()

    recipe_entry = Recipe.query.get(recipe_id)
    if not recipe_entry:
        return jsonify({"error": "Recipe not found"}), 404

    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.role != 'admin' and str(recipe_entry.user_id) != str(current_user_id):
        return jsonify({"error": "Unauthorized to edit this recipe"}), 403

    try:
        recipe_entry.recipe_name = data.get('recipe_name', recipe_entry.recipe_name)
        recipe_entry.recipe_description = data.get('description', recipe_entry.recipe_description)
        recipe_entry.cuisine = data.get('cuisine', recipe_entry.cuisine)
        recipe_entry.prep_time = data.get('prep_time', recipe_entry.prep_time)
        recipe_entry.cook_time = data.get('cook_time', recipe_entry.cook_time)
        recipe_entry.servings = data.get('servings', recipe_entry.servings)
        recipe_entry.difficulty = data.get('difficulty', recipe_entry.difficulty)

        if 'ingredients' in data:
            RecipeIngredient.query.filter_by(recipe_id=recipe_id).delete()
            for ing_data in data.get('ingredients', []):
                ing_name = ing_data.get('ingredient_name')
                if not ing_name: continue
                ing_obj = Ingredient.query.filter_by(ingredient_name=ing_name).first()
                if not ing_obj:
                    ing_obj = Ingredient(ingredient_name=ing_name)
                    db.session.add(ing_obj)
                    db.session.flush()
                meas_obj = None
                meas_name = ing_data.get('measurement_name')
                if meas_name:
                    meas_obj = Measurement.query.filter_by(measurement_name=meas_name).first()
                    if not meas_obj:
                        meas_obj = Measurement(measurement_name=meas_name)
                        db.session.add(meas_obj)
                        db.session.flush()
                new_recipe_ing = RecipeIngredient(recipe_id=recipe_id, ingredient_id=ing_obj.id, measurement_id=meas_obj.id if meas_obj else None, ingredient_quantity=ing_data.get('amount'))
                db.session.add(new_recipe_ing)

        if 'steps' in data:
            RecipeStep.query.filter_by(recipe_id=recipe_id).delete()
            for step_data in data.get('steps', []):
                db.session.add(RecipeStep(recipe_id=recipe_id, step_number=step_data.get('step_number'), step_description=step_data.get('instruction')))

        if 'images' in data:
            Image.query.filter_by(recipe_id=recipe_id).delete()
            for img_url in data.get('images', []):
                if img_url and img_url.strip():
                    db.session.add(Image(recipe_id=recipe_id, image_url=img_url))
        
        if 'tags' in data:
            recipe_entry.tags.clear()
            tag_names = data.get('tags', [])
            for tag_name_str in tag_names:
                if tag_name_str and tag_name_str.strip():
                    tag = Tag.query.filter_by(tag_name=tag_name_str.strip()).first()
                    if not tag:
                        tag = Tag(tag_name=tag_name_str.strip())
                        db.session.add(tag)
                    recipe_entry.tags.append(tag)

        db.session.commit()
        return jsonify({"message": "Recipe updated successfully"}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Update Error: {e}")
        return jsonify({"error": str(e)}), 500

## DELETE RECIPE ##

@app.route('/api/recipes/<int:recipe_id>', methods=['DELETE'])
@jwt_required()
def delete_recipe(recipe_id):
    current_user_id = get_jwt_identity()

    # 1️⃣ Fetch full user object
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # 2️⃣ Find the recipe
    recipe_entry = Recipe.query.get(recipe_id)
    if not recipe_entry:
        return jsonify({"error": "Recipe not found"}), 404

    # 3️⃣ Check permissions
    if user.role != 'admin' and str(recipe_entry.user_id) != str(current_user_id):
        return jsonify({"error": "Unauthorized to delete this recipe"}), 403

    try:
        # 4️⃣ Delete related data first
        RecipeIngredient.query.filter_by(recipe_id=recipe_id).delete()
        RecipeStep.query.filter_by(recipe_id=recipe_id).delete()
        Image.query.filter_by(recipe_id=recipe_id).delete()

        # 5️⃣ Delete the recipe
        db.session.delete(recipe_entry)
        db.session.commit()

        return jsonify({"message": f"Recipe {recipe_id} deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


## GET RECIPE BY ID ##

@app.route('/api/recipes/<int:recipe_id>', methods=['GET'])
@jwt_required()
def get_recipe(recipe_id):
    recipe_entry = Recipe.query.get(recipe_id)  # Fetch recipe by ID

    if not recipe_entry:
        return jsonify({"error": "Recipe not found"}), 404
    
    user = User.query.get(recipe_entry.user_id) if recipe_entry.user_id else None
    username = user.username if user else None

    # Fetch ingredients with measurements
    ingredients_data = []
    for recipe_ingredient in recipe_entry.recipe_ingredient:
        ingredient = recipe_ingredient.ingredient
        measurement = recipe_ingredient.measurement
        ingredients_data.append({
            "ingredient_id": ingredient.id,
            "ingredient_name": ingredient.ingredient_name,
            "amount": recipe_ingredient.ingredient_quantity,
            "measurement_unit": measurement.measurement_name if measurement else None
        })

    # Fetch recipe steps
    steps_data = [
        {"step_number": step.step_number, "instruction": step.step_description}
        for step in recipe_entry.recipe_step
    ]

    # Fetch related tags
    tags_data = [tag.tag_name for tag in recipe_entry.tags]

    # Fetch recipe images
    images_data = [image.image_url for image in recipe_entry.image]

    # Construct response
    return jsonify({
        "id": recipe_entry.id,
        "recipe_name": recipe_entry.recipe_name,
        "description": recipe_entry.recipe_description,
        "prep_time": recipe_entry.prep_time,
        "cook_time": recipe_entry.cook_time,
        "servings": recipe_entry.servings,
        "difficulty": recipe_entry.difficulty,
        "cuisine": recipe_entry.cuisine,
        "user_id": recipe_entry.user_id,
        "username": username,
        "created_at": recipe_entry.created_at,
        "ingredients": ingredients_data,
        "tags": tags_data,
        "steps": steps_data,
        "images": images_data
    })

## TAGS ##

@app.route('/api/tags', methods=['GET'])
def get_tags():
    tags = Tag.query.all()
    tag_list = [tag.tag_name for tag in tags]
    return jsonify(tag_list)


## GET USER ##

@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user = get_jwt_identity()
    if int(current_user) != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    })

## GET USERS RECIPES ##

@app.route('/api/users/<int:user_id>/recipes', methods=['GET'])
@jwt_required()
def get_user_recipes(user_id):
    current_user = get_jwt_identity()
    if int(current_user) != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    recipes = Recipe.query.filter_by(user_id=user_id).all()
    
    recipe_list = [{
        "id": recipe.id,
        "recipe_name": recipe.recipe_name,
        "description": recipe.recipe_description,
        "cuisine": recipe.cuisine,
        "prep_time": recipe.prep_time,
        "cook_time": recipe.cook_time,
        "servings": recipe.servings,
        "difficulty": recipe.difficulty,
        "created_at": recipe.created_at
    } for recipe in recipes]

    return jsonify(recipe_list)


## UPDATE USER PROFILE ##

@app.route('/api/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)

    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    print("🔹 Received Data:", data)

    # Validate and Update Username
     # Check for duplicate username (only if username is changing)
    if "username" in data and data["username"] and data["username"] != user.username:
        existing_user = User.query.filter_by(username=data["username"]).first()
        if existing_user:
            return jsonify({"error": "Username already taken"}), 400
        user.username = data["username"]

    # Check for duplicate email (only if email is changing)
    if "email" in data and data["email"] and data["email"] != user.email:
        existing_email = User.query.filter_by(email=data["email"]).first()
        if existing_email:
            return jsonify({"error": "Email already in use"}), 400
        user.email = data["email"]

    # Validate and Update Password
    if "password" in data and data["password"]:
        new_password = data["password"]

        # Password Strength Requirements
        if len(new_password) < 8:
            return jsonify({"error": "Password must be at least 8 characters long"}), 400
        if not any(char.isdigit() for char in new_password):
            return jsonify({"error": "Password must contain at least one number"}), 400
        if not any(char.isupper() for char in new_password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400

        print("🔹 New Password Received:", new_password)
        user.password_hash = generate_password_hash(new_password)
        print("🔹 Hashed Password:", user.password_hash)

    try:
        db.session.commit()
        print("Profile Updated Successfully!")
        return jsonify({"message": "Profile updated successfully!"})
    except Exception as e:
        db.session.rollback()
        print("Update Error:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
        current_user = get_jwt_identity()

        # Re-issue access token using full identity (which includes id and role)
        claims = get_jwt()
        role = claims.get("role")
        access_token = create_access_token(identity=str(current_user), additional_claims={"role": role}, fresh=False)


        return jsonify(access_token=access_token), 200
    
@app.route('/api/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    current_user = get_jwt_identity()

    # If your token's identity is just the user ID, you'll need to fetch the role
    if isinstance(current_user, str) or isinstance(current_user, int):
        user = User.query.get(current_user)
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin access only"}), 403
    else:
        # If your token uses `identity={"id": user.id, "role": user.role}`
        if current_user.get("role") != "admin":
            return jsonify({"error": "Admin access only"}), 403

    return jsonify({"message": "Welcome to the admin dashboard!"})

@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()

    if isinstance(current_user, str) or isinstance(current_user, int):
        user = User.query.get(current_user)
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin access only"}), 403
    else:
        if current_user.get("role") != "admin":
            return jsonify({"error": "Admin access only"}), 403

    users = User.query.all()

    user_list = [{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "recipe_count": len(user.recipe)  # Requires user.recipe relationship
    } for user in users]

    return jsonify(user_list), 200



@app.route('/api/admin/users/<int:user_id>/role', methods=['PATCH'])
@jwt_required()
def update_user_role(user_id):
    current_user = get_jwt_identity()

    if isinstance(current_user, str) or isinstance(current_user, int):
        user = User.query.get(current_user)
        if not user or user.role != 'admin':
            return jsonify({"error": "Admin access only"}), 403
    else:
        if current_user.get("role") != "admin":
            return jsonify({"error": "Admin access only"}), 403

    data = request.get_json()
    new_role = data.get("role")

    if new_role not in ["admin", "user"]:
        return jsonify({"error": "Invalid role"}), 400

    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    target_user.role = new_role
    db.session.commit()

    return jsonify({"message": f"User {target_user.username} role updated to {new_role}"}), 200

import traceback  # ← ensure this is at the top of your app.py

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    jwt_data = get_jwt()
    if jwt_data.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.username == '[deleted]':
        return jsonify({"error": "Cannot delete the system user"}), 403

    deleted_user = User.query.filter_by(username='[deleted]').first()
    if not deleted_user:
        return jsonify({"error": "'[deleted]' user not found"}), 500

    # Reassign related recipes to [deleted] user
    for recipe in user.recipe:
        recipe.user_id = deleted_user.id

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"User {user.username} deleted"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


## USER FAVORITES ##

@app.route('/api/users/favorites/<int:recipe_id>', methods=['POST'])
@jwt_required()
def add_favorite(recipe_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    recipe = Recipe.query.get(recipe_id)
    if not user or not recipe:
        return jsonify({"error": "User or Recipe not found"}), 404

    user.favorite_recipes.append(recipe)
    db.session.commit()
    return jsonify({"message": "Recipe added to favorites"}), 200

@app.route('/api/users/favorites/<int:recipe_id>', methods=['DELETE'])
@jwt_required()
def remove_favorite(recipe_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    recipe = Recipe.query.get(recipe_id)
    if not user or not recipe:
        return jsonify({"error": "User or Recipe not found"}), 404

    if recipe in user.favorite_recipes:
        user.favorite_recipes.remove(recipe)
        db.session.commit()
    return jsonify({"message": "Recipe removed from favorites"}), 200

@app.route('/api/users/favorites', methods=['GET'])
@jwt_required()
def get_favorites():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    favorite_list = []
    # Loop through the user's favorite recipes
    for recipe in user.favorite_recipes:
        # Construct the full recipe object, similar to get_recipes
        favorite_list.append({
            "id": recipe.id,
            "recipe_name": recipe.recipe_name,
            "description": recipe.recipe_description,
            "cuisine": recipe.cuisine,
            "prep_time": recipe.prep_time,
            "cook_time": recipe.cook_time,
            "servings": recipe.servings,
            "difficulty": recipe.difficulty,
            "created_at": recipe.created_at,
            "user_id": recipe.user_id, # Needed for edit/delete check
            "ingredients": [{"ingredient_name": ri.ingredient.ingredient_name, "amount": ri.ingredient_quantity, "measurement_unit": ri.measurement.measurement_name if ri.measurement else None} for ri in recipe.recipe_ingredient],
            "steps": [{"step_number": step.step_number, "instruction": step.step_description} for step in recipe.recipe_step],
            "tags": [tag.tag_name for tag in recipe.tags],
            "images": [img.image_url for img in recipe.image],
            "is_favorited": True # Since these are favorites, this is always true
        })
    return jsonify(favorite_list)







if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)