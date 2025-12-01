from flask import Flask, jsonify, request
import os
from datetime import datetime
import re
import traceback
import inflect

# Database and models
# ADDED 'Ingredient' back to this list
from models import db, User, Recipe, Ingredient, Measurement, RecipeIngredient, RecipeStep, Image, Tag, recipe_tags, user_favorites
from flask_migrate import Migrate

# Extensions
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token, get_jwt
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import String, cast, or_


app = Flask(__name__)
p = inflect.engine() # Initialize the singularization engine

CORS(app, 
     resources={r"/api/*": {
         "origins": ["http://localhost:3000", "https://recipes.dylanastrup.com"],
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"]
     }}, 
     supports_credentials=True
)

# --- Database Configuration ---
uri = os.environ.get('DATABASE_URL')
if uri:
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    uri = f'sqlite:///{os.path.join(BASE_DIR, "recipes.db")}'

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app,db)

# Set up a secret key for signing JWT tokens
app.config['JWT_SECRET_KEY'] = '9a8ab176bee3c41cddf4436bb6e1c41dfc7944bb4ee1dd1eded09372c8f05844'
jwt = JWTManager(app)

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dylanastrup@gmail.com'  
app.config['MAIL_PASSWORD'] = 'bcob qkhm qwvs ttym' 
app.config['MAIL_DEFAULT_SENDER'] = 'dylanastrup@gmail.com' 

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])


# --- HELPER: MEASUREMENT NORMALIZATION ---
UNIT_MAPPINGS = {
    "tablespoon": "tbsp", "tablespoons": "tbsp", "tbsp": "tbsp", "T": "tbsp",
    "teaspoon": "tsp", "teaspoons": "tsp", "tsp": "tsp", "t": "tsp",
    "cup": "cup", "cups": "cup", "c": "cup",
    "ounce": "oz", "ounces": "oz", "oz": "oz",
    "fluid ounce": "fl oz", "fluid ounces": "fl oz", "fl oz": "fl oz",
    "pound": "lb", "pounds": "lb", "lb": "lb", "lbs": "lb",
    "gram": "g", "grams": "g", "g": "g",
    "kilogram": "kg", "kilograms": "kg", "kg": "kg",
    "liter": "l", "liters": "l", "l": "l",
    "milliliter": "ml", "milliliters": "ml", "ml": "ml",
    "quart": "qt", "quarts": "qt", "qt": "qt",
    "pint": "pt", "pints": "pt", "pt": "pt",
    "gallon": "gal", "gallons": "gal", "gal": "gal",
    "pinch": "pinch", "pinches": "pinch",
    "clove": "clove", "cloves": "clove",
    "slice": "slice", "slices": "slice",
    "can": "can", "cans": "can"
}

def normalize_measurement(unit_name):
    if not unit_name:
        return None
    clean_name = unit_name.lower().strip()
    return UNIT_MAPPINGS.get(clean_name, clean_name)

# --- HELPER: INGREDIENT NORMALIZATION ---
def normalize_ingredient(name):
    if not name:
        return None
    # 1. Lowercase and strip whitespace
    clean = name.lower().strip()
    
    # 2. Singularize (e.g., "carrots" -> "carrot")
    # p.singular_noun returns False if the word is already singular
    singular = p.singular_noun(clean)
    
    if singular:
        return singular
    return clean


# --- API ROUTES ---

@app.route("/ping")
def ping():
    return "pong", 200

@app.route('/api/whoami')
@jwt_required()
def whoami():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user:
        return jsonify({"id": user.id, "username": user.username, "role": user.role})
    return jsonify({"error": "User not found"}), 404


## AUTHENTICATION ROUTES ##

@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json()
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400
        
    username = data['username']
    email = data['email']
    password = data['password']

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters long"}), 400

    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"error": "Invalid email format"}), 400

    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    if not re.match(password_regex, password):
        return jsonify({
            "error": "Password must be at least 8 characters long, "
                     "contain at least one number and one special character (@$%*?&)."
        }), 400

    if User.query.filter_by(email=data['email']).first() or User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "User already exists"}), 400

    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

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

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "No account with this email"}), 400

    token = serializer.dumps(email, salt="password-reset-salt")
    origin = request.headers.get("Origin", "http://localhost:3000")
    reset_url = f"{origin}/reset-password/{token}"  

    msg = Message("Password Reset Request", recipients=[email])
    msg.body = f"Click the link to reset your password: {reset_url}"
    mail.send(msg)

    return jsonify({"message": "Password reset email sent"}), 200


## RESET PASSWORD ##

@app.route('/api/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except:
        return jsonify({"error": "Invalid or expired token"}), 400

    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password or len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 400

    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully"}), 200

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    role = claims.get("role")
    access_token = create_access_token(identity=str(current_user_id), additional_claims={"role": role}, fresh=False)
    return jsonify(access_token=access_token), 200

## RECIPE & TAG ROUTES ##

@app.route('/api/tags', methods=['GET'])
@jwt_required()
def get_tags():
    tags = Tag.query.all()
    tag_list = [tag.tag_name for tag in tags]
    return jsonify(tag_list)

@app.route('/api/recipes', methods=['GET'])
@jwt_required()
def get_recipes():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    user_favorites = {recipe.id for recipe in user.favorite_recipes} if user else set()
    
    search = request.args.get('search', '').lower()
    sort_by = request.args.get('sort', '')
    
    query = Recipe.query

    if search:
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
            "id": recipe.id,
            "recipe_name": recipe.recipe_name,
            "description": recipe.recipe_description,
            "cuisine": recipe.cuisine,
            "prep_time": recipe.prep_time,
            "cook_time": recipe.cook_time,
            "servings": recipe.servings,
            "difficulty": recipe.difficulty,
            "created_at": recipe.created_at,
            "user_id": recipe.user_id,
            "ingredients": [{"ingredient_name": ri.ingredient.ingredient_name, "amount": ri.ingredient_quantity, "measurement_unit": ri.measurement.measurement_name if ri.measurement else None} for ri in recipe.recipe_ingredient],
            "steps": [{"step_number": step.step_number, "instruction": step.step_description} for step in recipe.recipe_step],
            "tags": [tag.tag_name for tag in recipe.tags],
            "images": [img.image_url for img in recipe.image],
            "is_favorited": recipe.id in user_favorites
        })
    return jsonify(recipe_list)


@app.route('/api/recipes', methods=['POST'])
@jwt_required()
def create_recipe():
    data = request.get_json()
    current_user_id = get_jwt_identity()
    if not data: return jsonify({"error": "No data received"}), 400
    try:
        new_recipe = Recipe(
            user_id=current_user_id,
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
            raw_name = ingredient.get('ingredient_name')
            quantity = ingredient.get('amount')
            if not raw_name or not quantity: continue
            
            # --- USE NORMALIZED INGREDIENT NAME ---
            ingredient_name = normalize_ingredient(raw_name)

            existing_ingredient = Ingredient.query.filter_by(ingredient_name=ingredient_name).first()
            if not existing_ingredient:
                existing_ingredient = Ingredient(ingredient_name=ingredient_name)
                db.session.add(existing_ingredient)
                db.session.flush()

            # --- USE NORMALIZED MEASUREMENT ---
            raw_measurement = ingredient.get('measurement_name')
            measurement_name = normalize_measurement(raw_measurement)

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
            db.session.add(RecipeStep(recipe_id=new_recipe.id, step_number=step.get('step_number'), step_description=step.get('instruction')))

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
                raw_name = ing_data.get('ingredient_name')
                if not raw_name: continue
                
                # --- USE NORMALIZED INGREDIENT NAME ---
                ing_name = normalize_ingredient(raw_name)

                ing_obj = Ingredient.query.filter_by(ingredient_name=ing_name).first()
                if not ing_obj:
                    ing_obj = Ingredient(ingredient_name=ing_name)
                    db.session.add(ing_obj)
                    db.session.flush()
                
                # --- USE NORMALIZED MEASUREMENT ---
                raw_measurement = ing_data.get('measurement_name')
                meas_name = normalize_measurement(raw_measurement)

                meas_obj = None
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
    user = User.query.get(current_user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    recipe_entry = Recipe.query.get(recipe_id)
    if not recipe_entry: return jsonify({"error": "Recipe not found"}), 404
    if user.role != 'admin' and str(recipe_entry.user_id) != str(current_user_id):
        return jsonify({"error": "Unauthorized to delete this recipe"}), 403
    try:
        RecipeIngredient.query.filter_by(recipe_id=recipe_id).delete()
        RecipeStep.query.filter_by(recipe_id=recipe_id).delete()
        Image.query.filter_by(recipe_id=recipe_id).delete()
        recipe_entry.tags.clear()
        db.session.delete(recipe_entry)
        db.session.commit()
        return jsonify({"message": f"Recipe {recipe_id} deleted successfully"}), 200
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

    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    is_favorited = False
    if current_user and recipe_entry in current_user.favorite_recipes:
        is_favorited = True

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
        "images": images_data,
        "is_favorited": is_favorited
    })

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

## USER ROUTES ##

@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    if claims.get("role") != 'admin' and str(current_user_id) != str(user_id):
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
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
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

    
## ADMIN ROUTES ##

@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    claims = get_jwt()
    if claims.get("role") != "admin": return jsonify({"error": "Admin access only"}), 403
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username, "email": user.email, "role": user.role, "created_at": user.created_at, "recipe_count": len(user.recipe)} for user in users]
    return jsonify(user_list)

@app.route('/api/admin/users/<int:user_id>/role', methods=['PATCH'])
@jwt_required()
def update_user_role(user_id):
    claims = get_jwt()
    if claims.get("role") != "admin": return jsonify({"error": "Admin access only"}), 403
    data = request.get_json()
    new_role = data.get("role")
    if new_role not in ["admin", "user"]: return jsonify({"error": "Invalid role"}), 400
    target_user = User.query.get(user_id)
    if not target_user: return jsonify({"error": "User not found"}), 404
    target_user.role = new_role
    db.session.commit()
    return jsonify({"message": f"User {target_user.username} role updated to {new_role}"}), 200

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

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)