from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app (single instance)
app = FastAPI(title="Liquor Store Inventory API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
client = MongoClient(MONGODB_URI)
db = client["liquor_store"]
inventory_collection = db["inventory"]
sales_collection = db["sales"]
expenses_collection = db["expenses"]
users_collection = db["users"]

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Pydantic models
class User(BaseModel):
    id_number: str
    name : str
    role : str = "operator" # Default role

class UserInDB(User):
    hashed_password: str
    must_change_password: bool

class PasswordChange(BaseModel):
    new_password: str

class Item(BaseModel):
    id: str  # Custom ID provided by user
    name: str
    category: str
    bottle_size: Optional[str] = None
    quantity: int
    price: float
    cost_price: float
    last_updated: Optional[datetime] = None

class ItemInDB(Item):
    id: str # This is the _id from MongoDB

class Sale(BaseModel):
    item_id: str
    quantity: int
    payment_method: str = "Cash" # New: Default to Cash
    user_id: Optional[str] = None
    timestamp: Optional[datetime] = None

class SaleInDB(Sale):
    id: str

class Expense(BaseModel):
    description: str
    amount: float
    timestamp: Optional[datetime] = None

class ExpenseInDB(Expense):
    id: str


# Helper functions
def item_to_dict(item):
    """Converts a MongoDB item document to a dictionary suitable for API response."""
    return {
        "id": str(item["_id"]), # Use _id as the public 'id'
        "name": item["name"],
        "category": item["category"],
        "bottle_size": item.get("bottle_size"),
        "quantity": item["quantity"],
        "price": item["price"],
        "cost_price": item.get('cost_price'),
        "last_updated": item["last_updated"]
    }

def sale_to_dict(sale):
    """Converts a MongoDB sale document to a dictionary suitable for API response."""
    user = users_collection.find_one({"id_number": sale["user_id"]})
    return {
        "id": str(sale["_id"]), # Convert ObjectId to string
        "item_id": str(sale["item_id"]),
        "quantity": sale["quantity"],
        "payment_method": sale.get("payment_method", "Cash"), # New: Include payment method
        "user_id": str(sale["user_id"]),
        "user_name": user["name"] if user else "Unknown",
        "timestamp": sale["timestamp"]
    }

def expense_to_dict(expense):
    """Converts a MongoDB expense document to a dictionary suitable for API response."""
    return {
        "id": str(expense["_id"]),
        "description": expense["description"],
        "amount": expense["amount"],
        "timestamp": expense["timestamp"]
    }

def verify_password(plain_password, hashed_password):
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Hashes a plain password."""
    return pwd_context.hash(password)

def create_access_token(data: dict):
    """Creates a JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get the current authenticated user."""
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id_number: str = payload.get("sub")
        if id_number is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = users_collection.find_one({"id_number": id_number})
    if user is None:
        raise credentials_exception
    return user

@app.get("/users/me", response_model=User)
async def get_current_user_details(current_user: dict = Depends(get_current_user)):
    """Returns details of the current authenticated user."""
    return {
        "id_number": current_user["id_number"],
        "name": current_user["name"],
        "role": current_user["role"]
    }

def is_admin(user: dict = Depends(get_current_user)):
    """Dependency to check if the current user is an admin."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

@app.get("/users/count")
async def get_user_count():
    """Returns the total number of users in the database."""
    count = users_collection.count_documents({})
    return {"count": count}

@app.post("/register")
async def register(user: User, current_user: dict = Depends(get_current_user)):
    """Registers a new user (operator). Only admins can register users after the first admin."""
    # Only allow registration if current user is admin, or if it's the very first user
    if users_collection.count_documents({}) > 0 and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admins can register new operators.")

    if users_collection.find_one({"id_number": user.id_number}):
        raise HTTPException(status_code=400, detail="ID number already registered")
    
    # First user becomes admin, subsequent users registered by admin become operators
    if users_collection.count_documents({}) == 0:
        user.role = "admin"
    else:
        user.role = "operator" # Role is already 'operator' by default in Pydantic model

    hashed_password = get_password_hash(user.id_number) # Initial password is ID number
    user_dict = {
        "id_number": user.id_number,
        "name": user.name,
        "role": user.role,
        "hashed_password": hashed_password,
        "must_change_password": True # New users must change password
    }
    users_collection.insert_one(user_dict)
    return {"message": "User registered successfully"}

@app.get("/admin/operators", response_model=List[User])
async def get_operators(admin: dict = Depends(is_admin)):
    """Retrieves a list of all operators. Admin access required."""
    operators = users_collection.find({"role": "operator"})
    return [{"id_number": op["id_number"], "name": op["name"], "role": op["role"]} for op in operators]

@app.delete("/admin/operators/{operator_id}")
async def delete_operator(operator_id: str, admin: dict = Depends(is_admin)):
    """Deletes an operator by ID. Admin access required."""
    result = users_collection.delete_one({"id_number": operator_id, "role": "operator"})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Operator not found")
    return {"message": "Operator deleted successfully"}

# Consolidated User login endpoint
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticates a user and returns an access token."""
    user = users_collection.find_one({"id_number": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect ID number or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Handle legacy users without role field (if any exist)
    if "role" not in user:
        # If it's the first user ever, make them admin. Otherwise, operator.
        # This logic should ideally only run once during initial setup.
        if users_collection.count_documents({}) == 1:
            role = "admin"
        else:
            role = "operator"
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"role": role}}
        )
        user["role"] = role # Update user object in memory

    access_token = create_access_token(data={"sub": form_data.username})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "must_change_password": user.get("must_change_password", False) # Default to False if not set
    }
    
@app.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    """Allows a user to change their password."""
    # Allow password change regardless of 'must_change_password' flag,
    # but set it to False after successful change.
    hashed_password = get_password_hash(password_data.new_password)
    users_collection.update_one(
        {"id_number": current_user["id_number"]},
        {"$set": {"hashed_password": hashed_password, "must_change_password": False}}
    )
    return {"message": "Password changed successfully"}

@app.post("/items/", response_model=ItemInDB)
async def create_item(item: Item, current_user: dict = Depends(get_current_user)):
    """Creates a new inventory item."""
    if item.category == "cigarette" and item.bottle_size:
        raise HTTPException(status_code=400, detail="Cigarettes do not have bottle sizes")
    
    # Check if custom ID already exists
    if inventory_collection.find_one({"_id": item.id}):
        raise HTTPException(status_code=400, detail="Item ID already exists")
    
    item_dict = item.dict()
    item_dict["_id"] = item_dict.pop("id")  # Use custom ID as _id
    item_dict["last_updated"] = datetime.utcnow()
    
    inventory_collection.insert_one(item_dict)
    return item_to_dict(item_dict)

@app.get("/items/", response_model=List[ItemInDB])
async def get_items(current_user: dict = Depends(get_current_user)):
    """Retrieves all inventory items."""
    items = inventory_collection.find()
    return [item_to_dict(item) for item in items]

@app.get("/items/{item_id}", response_model=ItemInDB)
async def get_item(item_id: str, current_user: dict = Depends(get_current_user)):
    """Retrieves a single inventory item by ID."""
    item = inventory_collection.find_one({"_id": item_id})
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item_to_dict(item)

@app.put("/items/{item_id}", response_model=ItemInDB)
async def update_item(item_id: str, item: Item, current_user: dict = Depends(get_current_user)):
    """Updates an existing inventory item."""
    if item.category == "cigarette" and item.bottle_size:
        raise HTTPException(status_code=400, detail="Cigarettes do not have bottle sizes")
    
    # Ensure the item exists before attempting to update
    existing_item = inventory_collection.find_one({"_id": item_id})
    if not existing_item:
        raise HTTPException(status_code=404, detail="Item not found")

    item_dict = item.dict(exclude_unset=True) # Only update provided fields
    item_dict.pop("id", None) # Remove 'id' if present, as _id is immutable
    item_dict["last_updated"] = datetime.utcnow()
    
    result = inventory_collection.update_one(
        {"_id": item_id},
        {"$set": item_dict}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found or no changes made")
    
    # Fetch the updated item to return
    updated_item = inventory_collection.find_one({"_id": item_id})
    return item_to_dict(updated_item)

@app.delete("/items/{item_id}")
async def delete_item(item_id: str, user: dict = Depends(is_admin)):
    """Deletes an inventory item by ID. Admin access required."""
    result = inventory_collection.delete_one({"_id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted successfully"}

@app.post("/sales/", response_model=SaleInDB)
async def record_sale(sale: Sale, current_user: dict = Depends(get_current_user)):
    """Records a new sale."""
    if sale.quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity must be positive")
    
    item = inventory_collection.find_one({"_id": sale.item_id})
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    
    if item["quantity"] < sale.quantity:
        raise HTTPException(status_code=400, detail="Insufficient stock")
    
    sale_dict = sale.dict()
    sale_dict["timestamp"] = datetime.utcnow()
    sale_dict["user_id"] = current_user["id_number"]
    # Ensure payment_method is stored, default "Cash" handled by Pydantic model
    
    result = sales_collection.insert_one(sale_dict)
    
    inventory_collection.update_one(
        {"_id": sale.item_id},
        {"$inc": {"quantity": -sale.quantity}, "$set": {"last_updated": datetime.utcnow()}}
    )
    
    user_info = users_collection.find_one({"id_number": current_user["id_number"]})
    user_name = user_info["name"] if user_info and "name" in user_info else "Unknown"
    
    return {
        "id": str(result.inserted_id),
        "item_id": sale.item_id,
        "quantity": sale.quantity,
        "payment_method": sale.payment_method, # Include payment method in response
        "user_id": current_user["id_number"],
        "user_name": user_name,
        "timestamp": sale_dict["timestamp"]
    }

@app.post("/expenses/", response_model=ExpenseInDB)
async def record_expense(expense: Expense, current_user: dict = Depends(get_current_user)):
    """Records a new expense."""
    expense_dict = expense.dict()
    expense_dict["timestamp"] = datetime.utcnow()
    result = expenses_collection.insert_one(expense_dict)
    expense_dict["_id"] = result.inserted_id
    return expense_to_dict(expense_dict)

@app.get("/expenses/", response_model=List[ExpenseInDB])
async def get_expenses(current_user: dict = Depends(get_current_user)):
    """Retrieves all recorded expenses."""
    expenses = expenses_collection.find().sort("timestamp", -1) # Sort by most recent
    return [expense_to_dict(expense) for expense in expenses]

@app.get("/financials/")
async def get_financials(current_user: dict = Depends(get_current_user)):
    """Retrieves a financial summary, separating Mpesa and Cash funds."""
    sales = sales_collection.find()
    total_revenue = 0
    total_cost = 0
    total_revenue_mpesa = 0
    total_revenue_cash = 0

    for sale in sales:
        item = inventory_collection.find_one({"_id": sale["item_id"]})
        if item:
            revenue_from_sale = sale["quantity"] * item["price"]
            total_revenue += revenue_from_sale
            total_cost += sale["quantity"] * item.get("cost_price", 0)
            
            # Separate revenue by payment method
            payment_method = sale.get("payment_method", "Cash") # Default to Cash for older sales
            if payment_method == "Mpesa":
                total_revenue_mpesa += revenue_from_sale
            else: # Default to Cash
                total_revenue_cash += revenue_from_sale

    total_expenses = sum(expense["amount"] for expense in expenses_collection.find())
    profit = total_revenue - total_cost
    
    # Assuming expenses are deducted from total available funds, not specific payment methods
    # For simplicity, we'll deduct from Cash first, then Mpesa if Cash is insufficient.
    # A more complex model might track specific Mpesa/Cash expenses.
    
    # Calculate available funds for each method
    # This is a simplified model. In a real scenario, you'd track cash/mpesa balances.
    # Here, we're distributing total revenue and deducting total expenses.
    
    # Distribute total expenses proportionally or from a primary fund
    # For now, let's just show total available funds, and break down revenue.
    # If the user explicitly wants expenses to reduce a specific fund, we'd need to add payment_method to expenses.
    
    # Let's refine available funds calculation:
    # Available funds = (Total Revenue - Total Expenses)
    # We can then show the breakdown of how that total revenue was collected.
    
    # A more accurate representation of "available funds" by method would require tracking initial balances
    # and individual expense payment methods. For now, let's show total revenue breakdown and overall available funds.
    
    # Re-evaluating: The user asked for "mpesa available funds and the cash". This implies tracking balances.
    # Since expenses don't have a payment method, we'll assume they reduce "Cash" funds primarily.
    
    available_funds_cash = total_revenue_cash - total_expenses
    available_funds_mpesa = total_revenue_mpesa
    
    # If cash goes negative, it implies drawing from Mpesa or a general pool.
    # For simplicity, let's ensure total available funds is correct, and then show the breakdown of where it came from.
    # A simple approach: total available funds = total revenue - total expenses.
    # Then, show how much of that total revenue came from Mpesa vs Cash.
    
    # Let's stick to showing the revenue breakdown by method and a combined available funds for now,
    # or assume expenses primarily reduce cash.
    # Given the request "mpesa available funds and the cash", let's make a simple assumption:
    # All expenses reduce the 'Cash' fund first. If cash goes negative, it means overall profit is reduced.
    
    # Let's calculate total available funds first.
    net_profit_before_expenses = total_revenue - total_cost
    overall_available_funds = total_revenue - total_expenses

    # To show separate available funds, we need to decide how expenses are paid.
    # If expenses are always cash:
    final_available_cash = total_revenue_cash - total_expenses
    final_available_mpesa = total_revenue_mpesa
    
    # If expenses can be paid by either, and we don't track it, it's ambiguous.
    # For this iteration, let's assume all expenses are paid from the 'Cash' pool for simplicity,
    # as the `Expense` model doesn't have a payment method.
    
    # If `total_revenue_cash` is less than `total_expenses`, `available_funds_cash` will be negative.
    # This is a valid financial state (e.g., if you paid more in cash than you earned in cash,
    # you covered it from Mpesa or other sources, or took a loss).
    
    return {
        "total_revenue": total_revenue,
        "total_cost": total_cost,
        "profit": profit,
        "total_expenses": total_expenses,
        "available_funds_cash": final_available_cash, # Funds from cash sales minus total expenses
        "available_funds_mpesa": final_available_mpesa, # Funds from Mpesa sales (expenses not deducted from here)
        "overall_available_funds": overall_available_funds # Total revenue - total expenses
    }

@app.get("/analytics/frequent-sales/")
async def get_frequent_sales(current_user: dict = Depends(get_current_user)):
    """Retrieves the most frequently sold items."""
    pipeline = [
        {"$group": {"_id": "$item_id", "total_quantity": {"$sum": "$quantity"}}},
        {"$sort": {"total_quantity": -1}},
        {"$limit": 5}
    ]
    top_items = sales_collection.aggregate(pipeline)
    result = []
    for item in top_items:
        item_data = inventory_collection.find_one({"_id": item["_id"]})
        if item_data:
            result.append({
                "item": item_to_dict(item_data),
                "total_sold": item["total_quantity"]
            })
    return result

@app.get("/analytics/daily-sales/")
async def get_daily_sales(date: str, current_user: dict = Depends(get_current_user)):
    """Retrieves sales data for a specific date."""
    try:
        start_date = datetime.strptime(date, "%Y-%m-%d")
        end_date = start_date + timedelta(days=1)
        sales = sales_collection.find({
            "timestamp": {"$gte": start_date, "$lt": end_date}
        })
        result = [sale_to_dict(sale) for sale in sales]
        
        total_revenue = 0
        for sale in result:
            item = inventory_collection.find_one({"_id": sale["item_id"]})
            if item:
                total_revenue += sale["quantity"] * item["price"]

        return {"date": date, "sales": result, "total_revenue": total_revenue}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Please use YYYY-MM-DD.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve daily sales: {str(e)}")

@app.get("/analytics/weekly-sales/")
async def get_weekly_sales(start_date: str, current_user: dict = Depends(get_current_user)):
    """Retrieves sales data for a specific week."""
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = start + timedelta(days=7)
        sales = sales_collection.find({
            "timestamp": {"$gte": start, "$lt": end}
        })
        result = [sale_to_dict(sale) for sale in sales]
        
        total_revenue = 0
        for sale in result:
            item = inventory_collection.find_one({"_id": sale["item_id"]})
            if item:
                total_revenue += sale["quantity"] * item["price"]

        return {"start_date": start_date, "sales": result, "total_revenue": total_revenue}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid start date format. Please use YYYY-MM-DD.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve weekly sales: {str(e)}")
    
# Root endpoint
@app.get("/")
async def root():
    """Root endpoint for the API."""
    return {"message": "Welcome to the Liquor Store Inventory API"}
