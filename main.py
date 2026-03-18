import json
import os
import shutil
import hashlib
import base64
import uuid
import logging
import mimetypes
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager, asynccontextmanager
import sqlite3
import asyncio

from fastapi import FastAPI, Depends, HTTPException, status, Query, Body, File, UploadFile, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
import uvicorn

# Optional PIL
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("PIL not installed. Image preview features disabled.")

# ────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("realestate-api")

DATABASE_FILE = "realestate.db"
SECRET_KEY = "realestate-secret-key-2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
DOCUMENTS_DIR = UPLOAD_DIR / "documents"
PROPERTY_IMAGES_DIR = UPLOAD_DIR / "property_images"
TEMP_DIR = BASE_DIR / "temp"

for dir_path in [UPLOAD_DIR, DOCUMENTS_DIR, PROPERTY_IMAGES_DIR, TEMP_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

DOC_TYPES = ['contract', 'invoice', 'receipt', 'id_card', 'other']
for doc_type in DOC_TYPES:
    (DOCUMENTS_DIR / doc_type).mkdir(exist_ok=True)

# ────────────────────────────────────────────────
# Database Connection
# ────────────────────────────────────────────────
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()

# ────────────────────────────────────────────────
# Password Hasher
# ────────────────────────────────────────────────
class PasswordHasher:
    @staticmethod
    def hash(password: str) -> str:
        salt = base64.b64encode(uuid.uuid4().bytes).decode('utf-8')[:16]
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 60000, dklen=32)
        key_b64 = base64.b64encode(key).decode('utf-8')
        return f"{salt}${key_b64}"

    @staticmethod
    def verify(password: str, hashed_password: str) -> bool:
        try:
            if not hashed_password or '$' not in hashed_password:
                return password == hashed_password
            salt, stored_hash = hashed_password.split('$', 1)
            password_bytes = password.encode('utf-8')
            salt_bytes = salt.encode('utf-8')
            key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 60000, dklen=32)
            key_b64 = base64.b64encode(key).decode('utf-8')
            return key_b64 == stored_hash
        except Exception as e:
            logger.error(f"Password verify error: {e}")
            return False

password_hasher = PasswordHasher()

# ────────────────────────────────────────────────
# Database Initialization
# ────────────────────────────────────────────────
def init_database():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if cursor.fetchone():
            logger.info("Database already initialized")
            return

        logger.info("Creating database schema...")

        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                email TEXT,
                role TEXT DEFAULT 'staff',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                id_card TEXT,
                address TEXT,
                customer_type TEXT DEFAULT 'individual',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE property_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                icon TEXT DEFAULT '🏠',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE properties (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                type_id INTEGER NOT NULL,
                bedrooms INTEGER,
                bathrooms INTEGER,
                area REAL,
                customer_id INTEGER,
                status TEXT DEFAULT 'available',
                address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (type_id) REFERENCES property_types(id),
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE property_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                property_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                is_primary BOOLEAN DEFAULT FALSE,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (property_id) REFERENCES properties(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE contracts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_number TEXT UNIQUE NOT NULL,
                customer_id INTEGER NOT NULL,
                property_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                start_date DATE NOT NULL,
                end_date DATE NOT NULL,
                total_amount REAL NOT NULL,
                currency TEXT DEFAULT 'LAK',
                installments INTEGER DEFAULT 1,
                terms TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (property_id) REFERENCES properties(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE payment_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_id INTEGER NOT NULL,
                due_date DATE NOT NULL,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'LAK',
                installment_number INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                paid_date DATE,
                transaction_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (contract_id) REFERENCES contracts(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_date DATE NOT NULL,
                invoice_number TEXT,
                description TEXT NOT NULL,
                customer_id INTEGER,
                property_id INTEGER,
                contract_id INTEGER,
                document_id INTEGER,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT DEFAULT 'LAK',
                payment_method TEXT DEFAULT 'cash',
                note TEXT,
                status TEXT DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (property_id) REFERENCES properties(id),
                FOREIGN KEY (contract_id) REFERENCES contracts(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                document_type TEXT NOT NULL,
                description TEXT,
                tags TEXT,
                customer_id INTEGER,
                property_id INTEGER,
                contract_id INTEGER,
                transaction_id INTEGER,
                uploaded_by INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (property_id) REFERENCES properties(id),
                FOREIGN KEY (contract_id) REFERENCES contracts(id),
                FOREIGN KEY (transaction_id) REFERENCES transactions(id),
                FOREIGN KEY (uploaded_by) REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE TABLE activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                user_id INTEGER,
                type TEXT DEFAULT 'info',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Insert default property types
        default_types = [
            ('ເຮືອນດຽວ', '🏠'),
            ('ຄອນໂດ', '🏢'),
            ('ທີ່ດິນ', '🌲'),
            ('ອາພາດເມັນ', '🏬'),
            ('ຮ້ານຄ້າ', '🏪')
        ]
        
        for name, icon in default_types:
            cursor.execute(
                "INSERT INTO property_types (name, icon) VALUES (?, ?)",
                (name, icon)
            )

        # Insert admin user
        admin_password = password_hasher.hash("admin123")
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, email, role)
            VALUES (?, ?, ?, ?, ?)
        """, ("admin", admin_password, "System Administrator", "admin@example.com", "admin"))

        # Insert sample customer
        cursor.execute("""
            INSERT INTO customers (name, phone, email, id_card, address, customer_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("ທ້າວ ສົມຊາຍ ດີຫຼາຍ", "020 5555 1234", "somchai@email.com", 
              "123456789", "ບ້ານ ໂພນສີສະຫວ່າງ, ນະຄອນຫຼວງວຽງຈັນ", "individual"))

        conn.commit()
        logger.info("Database schema created successfully with sample data")

# ────────────────────────────────────────────────
# Lifespan
# ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application starting...")
    try:
        await asyncio.to_thread(init_database)
        logger.info("Database ready")
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    yield
    logger.info("Application shutting down")

app = FastAPI(
    title="Lao Real Estate API",
    description="Complete Real Estate Management System with Enhanced File Handling",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = BASE_DIR / "static"
if not static_dir.exists():
    static_dir.mkdir(parents=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# ────────────────────────────────────────────────
# Pydantic Models
# ────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str

class UserOut(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: str

class CustomerBase(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None
    id_card: Optional[str] = None
    address: Optional[str] = None
    customer_type: str = "individual"

class CustomerCreate(CustomerBase):
    pass

class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    id_card: Optional[str] = None
    address: Optional[str] = None
    customer_type: Optional[str] = None

class CustomerOut(CustomerBase):
    id: int
    created_at: str
    total_contracts: Optional[int] = 0
    total_properties: Optional[int] = 0
    total_paid: Optional[float] = 0

class PropertyTypeBase(BaseModel):
    name: str
    icon: str = "🏠"

class PropertyTypeCreate(PropertyTypeBase):
    pass

class PropertyTypeOut(PropertyTypeBase):
    id: int
    created_at: str
    property_count: Optional[int] = 0

class PropertyBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float = Field(..., gt=0)
    type_id: int
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    area: Optional[float] = None
    customer_id: Optional[int] = None
    status: str = "available"
    address: Optional[str] = None

class PropertyCreate(PropertyBase):
    pass

class PropertyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = Field(None, gt=0)
    type_id: Optional[int] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[int] = None
    area: Optional[float] = None
    customer_id: Optional[int] = None
    status: Optional[str] = None
    address: Optional[str] = None

class PropertyOut(PropertyBase):
    id: int
    type_name: Optional[str] = None
    customer_name: Optional[str] = None
    image_urls: List[str] = []
    created_at: str
    active_contracts: Optional[int] = 0

class ContractBase(BaseModel):
    contract_number: str
    customer_id: int
    property_id: int
    type: str
    status: str = "pending"
    start_date: str
    end_date: str
    total_amount: float
    currency: str = "LAK"
    installments: int = 1
    terms: Optional[str] = None

class ContractCreate(ContractBase):
    pass

class ContractUpdate(BaseModel):
    status: Optional[str] = None
    end_date: Optional[str] = None
    total_amount: Optional[float] = None
    terms: Optional[str] = None

class ContractOut(ContractBase):
    id: int
    customer_name: Optional[str] = None
    property_name: Optional[str] = None
    created_at: str
    paid_amount: Optional[float] = 0
    remaining_amount: Optional[float] = 0
    payment_progress: Optional[int] = 0

class PaymentScheduleBase(BaseModel):
    contract_id: int
    due_date: str
    amount: float
    currency: str = "LAK"
    installment_number: int
    status: str = "pending"

class PaymentScheduleCreate(PaymentScheduleBase):
    pass

class PaymentScheduleUpdate(BaseModel):
    status: Optional[str] = None
    paid_date: Optional[str] = None
    transaction_id: Optional[int] = None

class PaymentScheduleOut(PaymentScheduleBase):
    id: int
    paid_date: Optional[str] = None
    transaction_id: Optional[int] = None
    customer_name: Optional[str] = None
    property_name: Optional[str] = None
    contract_number: Optional[str] = None
    created_at: str
    days_overdue: Optional[int] = 0

class TransactionBase(BaseModel):
    transaction_date: str
    description: str
    customer_id: Optional[int] = None
    property_id: Optional[int] = None
    contract_id: Optional[int] = None
    document_id: Optional[int] = None
    type: str
    amount: float = Field(..., gt=0)
    currency: str = "LAK"
    payment_method: str = "cash"
    note: Optional[str] = None
    status: str = "completed"

class TransactionCreate(TransactionBase):
    pass

class TransactionUpdate(BaseModel):
    description: Optional[str] = None
    amount: Optional[float] = None
    note: Optional[str] = None
    status: Optional[str] = None

class TransactionOut(TransactionBase):
    id: int
    invoice_number: Optional[str] = None
    customer_name: Optional[str] = None
    property_name: Optional[str] = None
    contract_number: Optional[str] = None
    document_name: Optional[str] = None
    created_at: str

class DocumentBase(BaseModel):
    filename: str
    original_filename: str
    file_path: str
    file_size: int
    mime_type: str
    document_type: str
    description: Optional[str] = None
    customer_id: Optional[int] = None
    property_id: Optional[int] = None
    contract_id: Optional[int] = None
    transaction_id: Optional[int] = None
    tags: List[str] = []

class DocumentCreate(DocumentBase):
    pass

class DocumentOut(DocumentBase):
    id: int
    uploaded_at: str
    uploaded_by: Optional[int] = None
    uploaded_by_name: Optional[str] = None
    last_accessed: Optional[str] = None
    access_count: int = 0
    url: str
    thumbnail_url: Optional[str] = None
    customer_name: Optional[str] = None
    property_name: Optional[str] = None
    contract_number: Optional[str] = None

class DocumentUpdate(BaseModel):
    document_type: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    customer_id: Optional[int] = None
    property_id: Optional[int] = None
    contract_id: Optional[int] = None
    transaction_id: Optional[int] = None

class DashboardSummary(BaseModel):
    total_properties: int
    available_properties: int
    rented_properties: int
    sold_properties: int
    total_customers: int
    total_income: float
    total_expense: float
    net_balance: float
    outstanding_payments: float
    active_contracts: int
    total_documents: int
    total_document_size: int
    overdue_payments: int
    monthly_income: float
    monthly_expense: float

class MonthlyData(BaseModel):
    labels: List[str]
    income: List[float]
    expense: List[float]
    typeLabels: List[str]
    typeCounts: List[int]
    customer_growth: List[int]
    contract_growth: List[int]

class ActivityOut(BaseModel):
    id: int
    description: str
    created_at: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    type: Optional[str] = None

class CustomerFolio(BaseModel):
    customer: CustomerOut
    properties: List[PropertyOut]
    contracts: List[ContractOut]
    transactions: List[TransactionOut]
    documents: List[DocumentOut]
    upcoming_payments: List[PaymentScheduleOut]
    overdue_payments: List[PaymentScheduleOut]
    total_paid: float
    total_due: float
    balance: float
    payment_history: List[Dict[str, Any]]

class UploadResponse(BaseModel):
    id: int
    filename: str
    original_filename: str
    url: str
    thumbnail_url: Optional[str]
    file_size: int
    mime_type: str
    document_type: str
    customer_id: Optional[int]
    property_id: Optional[int]
    contract_id: Optional[int]
    transaction_id: Optional[int]

# ────────────────────────────────────────────────
# JWT & Auth Functions
# ────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
       
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, full_name, email, role FROM users WHERE username = ?",
                (username,)
            )
            user = cursor.fetchone()
       
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return dict(user)
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def require_staff_or_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["admin", "staff"]:
        raise HTTPException(status_code=403, detail="Staff or admin access required")
    return current_user

# ────────────────────────────────────────────────
# Activity Logging
# ────────────────────────────────────────────────
async def log_activity(description: str, user_id: Optional[int] = None, activity_type: str = "info"):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO activities (description, user_id, type) VALUES (?, ?, ?)",
                (description, user_id, activity_type)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")

# ────────────────────────────────────────────────
# File Helper Functions
# ────────────────────────────────────────────────
def format_file_size(bytes):
    if bytes == 0:
        return "0 Bytes"
    k = 1024
    sizes = ["Bytes", "KB", "MB", "GB"]
    i = int(math.floor(math.log(bytes) / math.log(k)))
    return f"{round(bytes / math.pow(k, i), 2)} {sizes[i]}"

def generate_filename(original_filename: str) -> str:
    now = datetime.now()
    date_str = now.strftime("%Y%m%d_%H%M%S")
    file_parts = os.path.splitext(original_filename)
    base_name = file_parts[0]
    extension = file_parts[1] if len(file_parts) > 1 else ""
    base_name = "".join(c for c in base_name if c.isalnum() or c in (' ', '-', '_')).strip()
    if not base_name:
        base_name = "file"
    unique_filename = f"{base_name}_{date_str}{extension}"
    return unique_filename

def validate_file_type(filename: str, file_size: int) -> Dict[str, Any]:
    max_size = 50 * 1024 * 1024
    if file_size > max_size:
        return {"valid": False, "error": f"File too large. Maximum size is {max_size // (1024*1024)}MB"}
    return {"valid": True}

# ────────────────────────────────────────────────
# Auth Endpoints
# ────────────────────────────────────────────────
@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (form_data.username,)
        )
        user = cursor.fetchone()
   
    if not user or not password_hasher.verify(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
   
    access_token = create_access_token(
        data={"sub": user["username"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
   
    await log_activity(f"User {form_data.username} logged in", user["id"], "auth")
   
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/auth/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

# ────────────────────────────────────────────────
# Customer Endpoints
# ────────────────────────────────────────────────
@app.post("/customers", response_model=CustomerOut, status_code=201)
async def create_customer(
    customer: CustomerCreate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO customers (name, phone, email, id_card, address, customer_type)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (customer.name, customer.phone, customer.email, customer.id_card,
             customer.address, customer.customer_type)
        )
        conn.commit()
        new_id = cursor.lastrowid
       
        cursor.execute("""
            SELECT c.*,
                   COUNT(DISTINCT ct.id) as total_contracts,
                   COUNT(DISTINCT p.id) as total_properties,
                   COALESCE(SUM(t.amount), 0) as total_paid
            FROM customers c
            LEFT JOIN contracts ct ON c.id = ct.customer_id
            LEFT JOIN properties p ON c.id = p.customer_id
            LEFT JOIN transactions t ON c.id = t.customer_id AND t.type = 'income'
            WHERE c.id = ?
            GROUP BY c.id
            """, (new_id,))
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
       
        await log_activity(f"Created customer: {customer.name}", current_user['id'], "create")
       
        return result

@app.get("/customers", response_model=List[CustomerOut])
async def get_customers(
    search: Optional[str] = Query(None),
    customer_type: Optional[str] = Query(None),
    include_stats: bool = Query(False),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        if include_stats:
            query = """
                SELECT c.*,
                       COUNT(DISTINCT ct.id) as total_contracts,
                       COUNT(DISTINCT p.id) as total_properties,
                       COALESCE(SUM(CASE WHEN t.type = 'income' THEN t.amount ELSE 0 END), 0) as total_paid,
                       COALESCE(SUM(ps.amount), 0) as total_due
                FROM customers c
                LEFT JOIN contracts ct ON c.id = ct.customer_id
                LEFT JOIN properties p ON c.id = p.customer_id
                LEFT JOIN transactions t ON c.id = t.customer_id
                LEFT JOIN contracts ct2 ON c.id = ct2.customer_id
                LEFT JOIN payment_schedules ps ON ct2.id = ps.contract_id AND ps.status = 'pending'
                WHERE 1=1
            """
        else:
            query = """
                SELECT c.*,
                       COUNT(DISTINCT ct.id) as total_contracts,
                       COUNT(DISTINCT p.id) as total_properties,
                       COALESCE(SUM(t.amount), 0) as total_paid
                FROM customers c
                LEFT JOIN contracts ct ON c.id = ct.customer_id
                LEFT JOIN properties p ON c.id = p.customer_id
                LEFT JOIN transactions t ON c.id = t.customer_id AND t.type = 'income'
                WHERE 1=1
            """
        
        params = []
       
        if search:
            query += " AND (c.name LIKE ? OR c.phone LIKE ? OR c.email LIKE ? OR c.id_card LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like, like])
       
        if customer_type:
            query += " AND c.customer_type = ?"
            params.append(customer_type)
       
        query += " GROUP BY c.id ORDER BY c.id DESC"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at'])
            if 'total_due' in row_dict:
                row_dict['total_due'] = row_dict['total_due'] or 0
            results.append(row_dict)
        return results

@app.get("/customers/{customer_id}", response_model=CustomerOut)
async def get_customer(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*,
                   COUNT(DISTINCT ct.id) as total_contracts,
                   COUNT(DISTINCT p.id) as total_properties,
                   COALESCE(SUM(t.amount), 0) as total_paid
            FROM customers c
            LEFT JOIN contracts ct ON c.id = ct.customer_id
            LEFT JOIN properties p ON c.id = p.customer_id
            LEFT JOIN transactions t ON c.id = t.customer_id AND t.type = 'income'
            WHERE c.id = ?
            GROUP BY c.id
            """, (customer_id,))
        customer = cursor.fetchone()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        result = dict(customer)
        result['created_at'] = str(result['created_at'])
        return result

@app.put("/customers/{customer_id}", response_model=CustomerOut)
async def update_customer(
    customer_id: int,
    update_data: CustomerUpdate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Customer not found")
       
        updates = []
        params = []
       
        for field in ['name', 'phone', 'email', 'id_card', 'address', 'customer_type']:
            value = getattr(update_data, field)
            if value is not None:
                updates.append(f"{field} = ?")
                params.append(value)
       
        if updates:
            query = "UPDATE customers SET " + ", ".join(updates) + " WHERE id = ?"
            params.append(customer_id)
            cursor.execute(query, params)
            conn.commit()
       
        cursor.execute("""
            SELECT c.*,
                   COUNT(DISTINCT ct.id) as total_contracts,
                   COUNT(DISTINCT p.id) as total_properties,
                   COALESCE(SUM(t.amount), 0) as total_paid
            FROM customers c
            LEFT JOIN contracts ct ON c.id = ct.customer_id
            LEFT JOIN properties p ON c.id = p.customer_id
            LEFT JOIN transactions t ON c.id = t.customer_id AND t.type = 'income'
            WHERE c.id = ?
            GROUP BY c.id
            """, (customer_id,))
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
       
        await log_activity(f"Updated customer ID: {customer_id}", current_user['id'], "update")
       
        return result

@app.delete("/customers/{customer_id}")
async def delete_customer(
    customer_id: int,
    current_user: dict = Depends(require_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Customer not found")
        conn.commit()
       
        await log_activity(f"Deleted customer ID: {customer_id}", current_user['id'], "delete")
   
    return {"message": "Customer deleted successfully"}

# ────────────────────────────────────────────────
# Property Type Endpoints
# ────────────────────────────────────────────────
@app.post("/property-types", response_model=PropertyTypeOut, status_code=201)
async def create_property_type(
    type_data: PropertyTypeCreate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO property_types (name, icon) VALUES (?, ?)",
            (type_data.name, type_data.icon)
        )
        conn.commit()
        new_id = cursor.lastrowid
       
        cursor.execute("""
            SELECT pt.*, COUNT(p.id) as property_count
            FROM property_types pt
            LEFT JOIN properties p ON pt.id = p.type_id
            WHERE pt.id = ?
            GROUP BY pt.id
            """, (new_id,))
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
        return result

@app.get("/property-types", response_model=List[PropertyTypeOut])
async def get_property_types():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pt.*, COUNT(p.id) as property_count
            FROM property_types pt
            LEFT JOIN properties p ON pt.id = p.type_id
            GROUP BY pt.id
            ORDER BY pt.name
        """)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at'])
            results.append(row_dict)
        return results

# ────────────────────────────────────────────────
# Property Endpoints
# ────────────────────────────────────────────────
@app.post("/properties", response_model=PropertyOut, status_code=201)
async def create_property(
    property_data: PropertyCreate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("""
            INSERT INTO properties
            (name, description, price, type_id, bedrooms, bathrooms, area, customer_id, status, address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                property_data.name,
                property_data.description,
                property_data.price,
                property_data.type_id,
                property_data.bedrooms,
                property_data.bathrooms,
                property_data.area,
                property_data.customer_id,
                property_data.status,
                property_data.address
            )
        )
        conn.commit()
        new_id = cursor.lastrowid
       
        cursor.execute("""
            SELECT p.*, pt.name as type_name, c.name as customer_name,
                   COUNT(ct.id) as active_contracts
            FROM properties p
            LEFT JOIN property_types pt ON p.type_id = pt.id
            LEFT JOIN customers c ON p.customer_id = c.id
            LEFT JOIN contracts ct ON p.id = ct.property_id AND ct.status IN ('active', 'pending')
            WHERE p.id = ?
            GROUP BY p.id
            """,
            (new_id,)
        )
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
        result['image_urls'] = []
       
        await log_activity(f"Created property: {property_data.name}", current_user['id'], "create")
       
        return result

@app.get("/properties", response_model=List[PropertyOut])
async def get_properties(
    type_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    customer_id: Optional[int] = Query(None),
    min_price: Optional[float] = Query(None),
    max_price: Optional[float] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT p.*, pt.name as type_name, c.name as customer_name,
                   COUNT(ct.id) as active_contracts
            FROM properties p
            LEFT JOIN property_types pt ON p.type_id = pt.id
            LEFT JOIN customers c ON p.customer_id = c.id
            LEFT JOIN contracts ct ON p.id = ct.property_id AND ct.status IN ('active', 'pending')
            WHERE 1=1
        """
        params = []
       
        if type_id:
            query += " AND p.type_id = ?"
            params.append(type_id)
        if status:
            query += " AND p.status = ?"
            params.append(status)
        if search:
            query += " AND (p.name LIKE ? OR p.description LIKE ? OR p.address LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])
        if customer_id:
            query += " AND p.customer_id = ?"
            params.append(customer_id)
        if min_price:
            query += " AND p.price >= ?"
            params.append(min_price)
        if max_price:
            query += " AND p.price <= ?"
            params.append(max_price)
       
        query += " GROUP BY p.id ORDER BY p.id DESC"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at'])
           
            cursor.execute("SELECT filename FROM property_images WHERE property_id = ? ORDER BY is_primary DESC", (row_dict['id'],))
            images = cursor.fetchall()
            row_dict['image_urls'] = [
                f"/static/uploads/property_images/{img['filename']}" for img in images
            ]
           
            results.append(row_dict)
        return results

@app.get("/properties/{property_id}", response_model=PropertyOut)
async def get_property(
    property_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.*, pt.name as type_name, c.name as customer_name,
                   COUNT(ct.id) as active_contracts
            FROM properties p
            LEFT JOIN property_types pt ON p.type_id = pt.id
            LEFT JOIN customers c ON p.customer_id = c.id
            LEFT JOIN contracts ct ON p.id = ct.property_id AND ct.status IN ('active', 'pending')
            WHERE p.id = ?
            GROUP BY p.id
            """,
            (property_id,)
        )
        property = cursor.fetchone()
        if not property:
            raise HTTPException(status_code=404, detail="Property not found")
       
        result = dict(property)
        result['created_at'] = str(result['created_at'])
       
        cursor.execute("SELECT filename FROM property_images WHERE property_id = ? ORDER BY is_primary DESC", (property_id,))
        images = cursor.fetchall()
        result['image_urls'] = [
            f"/static/uploads/property_images/{img['filename']}" for img in images
        ]
       
        return result

@app.put("/properties/{property_id}", response_model=PropertyOut)
async def update_property(
    property_id: int,
    update_data: PropertyUpdate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM properties WHERE id = ?", (property_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Property not found")
       
        updates = []
        params = []
       
        fields = ['name', 'description', 'price', 'type_id', 'bedrooms', 'bathrooms',
                  'area', 'customer_id', 'status', 'address']
       
        for field in fields:
            value = getattr(update_data, field)
            if value is not None:
                updates.append(f"{field} = ?")
                params.append(value)
       
        if updates:
            query = "UPDATE properties SET " + ", ".join(updates) + " WHERE id = ?"
            params.append(property_id)
            cursor.execute(query, params)
            conn.commit()
       
        cursor.execute("""
            SELECT p.*, pt.name as type_name, c.name as customer_name,
                   COUNT(ct.id) as active_contracts
            FROM properties p
            LEFT JOIN property_types pt ON p.type_id = pt.id
            LEFT JOIN customers c ON p.customer_id = c.id
            LEFT JOIN contracts ct ON p.id = ct.property_id AND ct.status IN ('active', 'pending')
            WHERE p.id = ?
            GROUP BY p.id
            """,
            (property_id,)
        )
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
       
        cursor.execute("SELECT filename FROM property_images WHERE property_id = ? ORDER BY is_primary DESC", (property_id,))
        images = cursor.fetchall()
        result['image_urls'] = [
            f"/static/uploads/property_images/{img['filename']}" for img in images
        ]
       
        await log_activity(f"Updated property ID: {property_id}", current_user['id'], "update")
       
        return result

@app.delete("/properties/{property_id}")
async def delete_property(
    property_id: int,
    current_user: dict = Depends(require_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("SELECT file_path FROM property_images WHERE property_id = ?", (property_id,))
        images = cursor.fetchall()
        for img in images:
            try:
                if os.path.exists(img['file_path']):
                    os.remove(img['file_path'])
            except Exception as e:
                logger.error(f"Failed to delete image file: {e}")
       
        cursor.execute("DELETE FROM properties WHERE id = ?", (property_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Property not found")
        conn.commit()
       
        await log_activity(f"Deleted property ID: {property_id}", current_user['id'], "delete")
   
    return {"message": "Property deleted successfully"}

# ────────────────────────────────────────────────
# Contract Endpoints
# ────────────────────────────────────────────────
@app.post("/contracts", response_model=ContractOut, status_code=201)
async def create_contract(
    contract: ContractCreate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("""
            INSERT INTO contracts
            (contract_number, customer_id, property_id, type, status, start_date, end_date,
             total_amount, currency, installments, terms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                contract.contract_number,
                contract.customer_id,
                contract.property_id,
                contract.type,
                contract.status,
                contract.start_date,
                contract.end_date,
                contract.total_amount,
                contract.currency,
                contract.installments,
                contract.terms
            )
        )
        conn.commit()
        new_id = cursor.lastrowid
       
        if contract.status == 'active':
            new_status = 'rented' if contract.type == 'rental' else 'sold'
            cursor.execute(
                "UPDATE properties SET status = ?, customer_id = ? WHERE id = ?",
                (new_status, contract.customer_id, contract.property_id)
            )
            conn.commit()
       
        if contract.installments > 1:
            amount_per_installment = contract.total_amount / contract.installments
            start = datetime.strptime(contract.start_date, '%Y-%m-%d')
           
            for i in range(contract.installments):
                due_date = start + timedelta(days=30 * i)
                due_date_str = due_date.strftime('%Y-%m-%d')
               
                cursor.execute("""
                    INSERT INTO payment_schedules
                    (contract_id, due_date, amount, currency, installment_number, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (new_id, due_date_str, amount_per_installment, contract.currency, i + 1, 'pending')
                )
            conn.commit()
        else:
            cursor.execute("""
                INSERT INTO payment_schedules
                (contract_id, due_date, amount, currency, installment_number, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (new_id, contract.start_date, contract.total_amount, contract.currency, 1, 'pending')
            )
            conn.commit()
       
        cursor.execute("""
            SELECT c.*, cust.name as customer_name, p.name as property_name,
                   COALESCE(SUM(ps.amount), 0) as paid_amount,
                   COALESCE(SUM(CASE WHEN ps.status = 'pending' THEN ps.amount ELSE 0 END), 0) as remaining_amount,
                   COUNT(CASE WHEN ps.status = 'paid' THEN 1 END) as paid_count,
                   COUNT(ps.id) as total_count
            FROM contracts c
            LEFT JOIN customers cust ON c.customer_id = cust.id
            LEFT JOIN properties p ON c.property_id = p.id
            LEFT JOIN payment_schedules ps ON c.id = ps.contract_id
            WHERE c.id = ?
            GROUP BY c.id
            """,
            (new_id,)
        )
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
        result['paid_amount'] = result['paid_amount'] or 0
        result['remaining_amount'] = result['remaining_amount'] or 0
        result['payment_progress'] = int((result['paid_amount'] / result['total_amount']) * 100) if result['total_amount'] > 0 else 0
       
        await log_activity(f"Created contract: {contract.contract_number}", current_user['id'], "create")
       
        return result

@app.get("/contracts", response_model=List[ContractOut])
async def get_contracts(
    type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    customer_id: Optional[int] = Query(None),
    property_id: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT c.*, cust.name as customer_name, p.name as property_name,
                   COALESCE(SUM(CASE WHEN ps.status = 'paid' THEN ps.amount ELSE 0 END), 0) as paid_amount,
                   COALESCE(SUM(CASE WHEN ps.status = 'pending' THEN ps.amount ELSE 0 END), 0) as remaining_amount,
                   COUNT(CASE WHEN ps.status = 'paid' THEN 1 END) as paid_count,
                   COUNT(ps.id) as total_count
            FROM contracts c
            LEFT JOIN customers cust ON c.customer_id = cust.id
            LEFT JOIN properties p ON c.property_id = p.id
            LEFT JOIN payment_schedules ps ON c.id = ps.contract_id
            WHERE 1=1
        """
        params = []
       
        if type:
            query += " AND c.type = ?"
            params.append(type)
        if status:
            query += " AND c.status = ?"
            params.append(status)
        if customer_id:
            query += " AND c.customer_id = ?"
            params.append(customer_id)
        if property_id:
            query += " AND c.property_id = ?"
            params.append(property_id)
        if search:
            query += " AND (c.contract_number LIKE ? OR cust.name LIKE ? OR p.name LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])
       
        query += " GROUP BY c.id ORDER BY c.created_at DESC"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at'])
            row_dict['paid_amount'] = row_dict['paid_amount'] or 0
            row_dict['remaining_amount'] = row_dict['remaining_amount'] or 0
            row_dict['payment_progress'] = int((row_dict['paid_amount'] / row_dict['total_amount']) * 100) if row_dict['total_amount'] > 0 else 0
            results.append(row_dict)
        return results

@app.get("/contracts/{contract_id}", response_model=ContractOut)
async def get_contract(
    contract_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, cust.name as customer_name, p.name as property_name,
                   COALESCE(SUM(CASE WHEN ps.status = 'paid' THEN ps.amount ELSE 0 END), 0) as paid_amount,
                   COALESCE(SUM(CASE WHEN ps.status = 'pending' THEN ps.amount ELSE 0 END), 0) as remaining_amount,
                   COUNT(CASE WHEN ps.status = 'paid' THEN 1 END) as paid_count,
                   COUNT(ps.id) as total_count
            FROM contracts c
            LEFT JOIN customers cust ON c.customer_id = cust.id
            LEFT JOIN properties p ON c.property_id = p.id
            LEFT JOIN payment_schedules ps ON c.id = ps.contract_id
            WHERE c.id = ?
            GROUP BY c.id
            """,
            (contract_id,)
        )
        contract = cursor.fetchone()
        if not contract:
            raise HTTPException(status_code=404, detail="Contract not found")
        result = dict(contract)
        result['created_at'] = str(result['created_at'])
        result['paid_amount'] = result['paid_amount'] or 0
        result['remaining_amount'] = result['remaining_amount'] or 0
        result['payment_progress'] = int((result['paid_amount'] / result['total_amount']) * 100) if result['total_amount'] > 0 else 0
        return result

@app.put("/contracts/{contract_id}", response_model=ContractOut)
async def update_contract(
    contract_id: int,
    update_data: ContractUpdate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,))
        existing = cursor.fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Contract not found")
       
        updates = []
        params = []
       
        if update_data.status is not None:
            updates.append("status = ?")
            params.append(update_data.status)
           
            if update_data.status == 'active':
                new_status = 'rented' if existing['type'] == 'rental' else 'sold'
                cursor.execute(
                    "UPDATE properties SET status = ?, customer_id = ? WHERE id = ?",
                    (new_status, existing['customer_id'], existing['property_id'])
                )
            elif update_data.status in ['completed', 'cancelled']:
                cursor.execute(
                    "UPDATE properties SET status = 'available', customer_id = NULL WHERE id = ?",
                    (existing['property_id'],)
                )
            conn.commit()
       
        if update_data.end_date is not None:
            updates.append("end_date = ?")
            params.append(update_data.end_date)
        if update_data.total_amount is not None:
            updates.append("total_amount = ?")
            params.append(update_data.total_amount)
        if update_data.terms is not None:
            updates.append("terms = ?")
            params.append(update_data.terms)
       
        if updates:
            query = "UPDATE contracts SET " + ", ".join(updates) + " WHERE id = ?"
            params.append(contract_id)
            cursor.execute(query, params)
            conn.commit()
       
        cursor.execute("""
            SELECT c.*, cust.name as customer_name, p.name as property_name,
                   COALESCE(SUM(CASE WHEN ps.status = 'paid' THEN ps.amount ELSE 0 END), 0) as paid_amount,
                   COALESCE(SUM(CASE WHEN ps.status = 'pending' THEN ps.amount ELSE 0 END), 0) as remaining_amount,
                   COUNT(CASE WHEN ps.status = 'paid' THEN 1 END) as paid_count,
                   COUNT(ps.id) as total_count
            FROM contracts c
            LEFT JOIN customers cust ON c.customer_id = cust.id
            LEFT JOIN properties p ON c.property_id = p.id
            LEFT JOIN payment_schedules ps ON c.id = ps.contract_id
            WHERE c.id = ?
            GROUP BY c.id
            """,
            (contract_id,)
        )
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
        result['paid_amount'] = result['paid_amount'] or 0
        result['remaining_amount'] = result['remaining_amount'] or 0
        result['payment_progress'] = int((result['paid_amount'] / result['total_amount']) * 100) if result['total_amount'] > 0 else 0
       
        await log_activity(f"Updated contract ID: {contract_id}", current_user['id'], "update")
       
        return result

@app.delete("/contracts/{contract_id}")
async def delete_contract(
    contract_id: int,
    current_user: dict = Depends(require_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,))
        contract = cursor.fetchone()
        if not contract:
            raise HTTPException(status_code=404, detail="Contract not found")
       
        cursor.execute(
            "UPDATE properties SET status = 'available', customer_id = NULL WHERE id = ?",
            (contract['property_id'],)
        )
       
        cursor.execute("DELETE FROM contracts WHERE id = ?", (contract_id,))
        conn.commit()
       
        await log_activity(f"Deleted contract ID: {contract_id}", current_user['id'], "delete")
   
    return {"message": "Contract deleted successfully"}

# ────────────────────────────────────────────────
# Payment Schedule Endpoints
# ────────────────────────────────────────────────
@app.get("/contracts/{contract_id}/payments", response_model=List[PaymentScheduleOut])
async def get_contract_payments(
    contract_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        today = datetime.now().date()
       
        cursor.execute("""
            SELECT ps.*, c.contract_number, cust.name as customer_name, p.name as property_name,
                   julianday(?) - julianday(ps.due_date) as days_overdue
            FROM payment_schedules ps
            JOIN contracts c ON ps.contract_id = c.id
            JOIN customers cust ON c.customer_id = cust.id
            JOIN properties p ON c.property_id = p.id
            WHERE ps.contract_id = ?
            ORDER BY ps.due_date
            """,
            (today.isoformat(), contract_id)
        )
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at']) if row_dict['created_at'] else None
            if row_dict['paid_date']:
                row_dict['paid_date'] = str(row_dict['paid_date'])
            row_dict['days_overdue'] = max(0, int(row_dict['days_overdue'] or 0)) if row_dict['status'] == 'pending' else 0
            results.append(row_dict)
        return results

@app.get("/payments/upcoming")
async def get_upcoming_payments(
    days: int = Query(30, ge=1),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        future = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
       
        cursor.execute("""
            SELECT ps.*, c.contract_number, cust.name as customer_name, p.name as property_name
            FROM payment_schedules ps
            JOIN contracts c ON ps.contract_id = c.id
            JOIN customers cust ON c.customer_id = cust.id
            JOIN properties p ON c.property_id = p.id
            WHERE ps.status = 'pending' AND ps.due_date BETWEEN ? AND ?
            ORDER BY ps.due_date
            """,
            (today, future)
        )
       
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            results.append(row_dict)
        return results

@app.get("/payments/overdue")
async def get_overdue_payments(
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
       
        cursor.execute("""
            SELECT ps.*, c.contract_number, cust.name as customer_name, p.name as property_name,
                   julianday(?) - julianday(ps.due_date) as days_overdue
            FROM payment_schedules ps
            JOIN contracts c ON ps.contract_id = c.id
            JOIN customers cust ON c.customer_id = cust.id
            JOIN properties p ON c.property_id = p.id
            WHERE ps.status = 'pending' AND ps.due_date < ?
            ORDER BY ps.due_date
            """,
            (today, today)
        )
       
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['days_overdue'] = int(row_dict['days_overdue'])
            results.append(row_dict)
        return results

@app.post("/payments/{payment_id}/mark-paid")
async def mark_payment_paid(
    payment_id: int,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("SELECT * FROM payment_schedules WHERE id = ?", (payment_id,))
        payment = cursor.fetchone()
        if not payment:
            raise HTTPException(status_code=404, detail="Payment not found")
       
        if payment['status'] == 'paid':
            raise HTTPException(status_code=400, detail="Payment already marked as paid")
       
        cursor.execute("""
            SELECT c.*, cust.name as customer_name
            FROM contracts c
            JOIN customers cust ON c.customer_id = cust.id
            WHERE c.id = ?
            """, (payment['contract_id'],))
        contract = cursor.fetchone()
       
        today = datetime.now().strftime('%Y-%m-%d')
       
        cursor.execute("""
            INSERT INTO transactions
            (transaction_date, description, type, amount, currency, customer_id, contract_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                today,
                f"ລາຍການສຳລັບສັນຍາ{contract['contract_number']}ຜ່ອນ{payment['installment_number']}",
                'income',
                payment['amount'],
                payment['currency'],
                contract['customer_id'],
                payment['contract_id'],
                'completed'
            )
        )
        conn.commit()
        transaction_id = cursor.lastrowid
       
        cursor.execute("""
            UPDATE payment_schedules
            SET status = 'paid', paid_date = ?, transaction_id = ?
            WHERE id = ?
            """,
            (today, transaction_id, payment_id)
        )
        conn.commit()
       
        await log_activity(f"Marked payment {payment_id} as paid", current_user['id'], "payment")
       
        return {"message": "Payment marked as paid", "transaction_id": transaction_id}

# ────────────────────────────────────────────────
# Transaction Endpoints
# ────────────────────────────────────────────────
@app.post("/transactions", response_model=TransactionOut, status_code=201)
async def create_transaction(
    transaction: TransactionCreate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        year = datetime.now().strftime('%Y')
        month = datetime.now().strftime('%m')
        cursor.execute("""
            SELECT COUNT(*) FROM transactions
            WHERE strftime('%Y', transaction_date) = ? AND strftime('%m', transaction_date) = ?
            """,
            (year, month)
        )
        count = cursor.fetchone()[0] + 1
        invoice_number = f"INV-{year}{month}-{count:04d}"
       
        cursor.execute("""
            INSERT INTO transactions
            (transaction_date, invoice_number, description, customer_id, property_id,
             contract_id, document_id, type, amount, currency, payment_method, note, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transaction.transaction_date,
                invoice_number,
                transaction.description,
                transaction.customer_id,
                transaction.property_id,
                transaction.contract_id,
                transaction.document_id,
                transaction.type,
                transaction.amount,
                transaction.currency,
                transaction.payment_method,
                transaction.note,
                transaction.status
            )
        )
        conn.commit()
        new_id = cursor.lastrowid
       
        cursor.execute("""
            SELECT t.*, c.name as customer_name, p.name as property_name, ct.contract_number, d.filename as document_name
            FROM transactions t
            LEFT JOIN customers c ON t.customer_id = c.id
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN contracts ct ON t.contract_id = ct.id
            LEFT JOIN documents d ON t.document_id = d.id
            WHERE t.id = ?
            """,
            (new_id,)
        )
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
        result['transaction_date'] = str(result['transaction_date'])
       
        await log_activity(f"Created transaction: {invoice_number}", current_user['id'], "transaction")
       
        return result

@app.get("/transactions", response_model=List[TransactionOut])
async def get_transactions(
    type: Optional[str] = Query(None),
    customer_id: Optional[int] = Query(None),
    contract_id: Optional[int] = Query(None),
    document_id: Optional[int] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT t.*, c.name as customer_name, p.name as property_name, ct.contract_number, d.filename as document_name
            FROM transactions t
            LEFT JOIN customers c ON t.customer_id = c.id
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN contracts ct ON t.contract_id = ct.id
            LEFT JOIN documents d ON t.document_id = d.id
            WHERE 1=1
        """
        params = []
       
        if type:
            query += " AND t.type = ?"
            params.append(type)
        if customer_id:
            query += " AND t.customer_id = ?"
            params.append(customer_id)
        if contract_id:
            query += " AND t.contract_id = ?"
            params.append(contract_id)
        if document_id:
            query += " AND t.document_id = ?"
            params.append(document_id)
        if start_date:
            query += " AND t.transaction_date >= ?"
            params.append(start_date)
        if end_date:
            query += " AND t.transaction_date <= ?"
            params.append(end_date)
       
        query += " ORDER BY t.transaction_date DESC"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at'])
            row_dict['transaction_date'] = str(row_dict['transaction_date'])
            results.append(row_dict)
        return results

@app.get("/transactions/{transaction_id}", response_model=TransactionOut)
async def get_transaction(
    transaction_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.*, c.name as customer_name, p.name as property_name, ct.contract_number, d.filename as document_name
            FROM transactions t
            LEFT JOIN customers c ON t.customer_id = c.id
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN contracts ct ON t.contract_id = ct.id
            LEFT JOIN documents d ON t.document_id = d.id
            WHERE t.id = ?
            """,
            (transaction_id,)
        )
        transaction = cursor.fetchone()
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")
       
        result = dict(transaction)
        result['created_at'] = str(result['created_at'])
        result['transaction_date'] = str(result['transaction_date'])
        return result

@app.put("/transactions/{transaction_id}", response_model=TransactionOut)
async def update_transaction(
    transaction_id: int,
    update_data: TransactionUpdate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM transactions WHERE id = ?", (transaction_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Transaction not found")
       
        updates = []
        params = []
       
        if update_data.description:
            updates.append("description = ?")
            params.append(update_data.description)
        if update_data.amount:
            updates.append("amount = ?")
            params.append(update_data.amount)
        if update_data.note is not None:
            updates.append("note = ?")
            params.append(update_data.note)
        if update_data.status:
            updates.append("status = ?")
            params.append(update_data.status)
       
        if updates:
            query = "UPDATE transactions SET " + ", ".join(updates) + " WHERE id = ?"
            params.append(transaction_id)
            cursor.execute(query, params)
            conn.commit()
       
        cursor.execute("""
            SELECT t.*, c.name as customer_name, p.name as property_name, ct.contract_number, d.filename as document_name
            FROM transactions t
            LEFT JOIN customers c ON t.customer_id = c.id
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN contracts ct ON t.contract_id = ct.id
            LEFT JOIN documents d ON t.document_id = d.id
            WHERE t.id = ?
            """,
            (transaction_id,)
        )
        result = dict(cursor.fetchone())
        result['created_at'] = str(result['created_at'])
        result['transaction_date'] = str(result['transaction_date'])
       
        await log_activity(f"Updated transaction ID: {transaction_id}", current_user['id'], "update")
       
        return result

@app.delete("/transactions/{transaction_id}")
async def delete_transaction(
    transaction_id: int,
    current_user: dict = Depends(require_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM transactions WHERE id = ?", (transaction_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Transaction not found")
        conn.commit()
       
        await log_activity(f"Deleted transaction ID: {transaction_id}", current_user['id'], "delete")
   
    return {"message": "Transaction deleted successfully"}

# ────────────────────────────────────────────────
# Report Endpoints
# ────────────────────────────────────────────────
@app.get("/reports/transactions")
async def get_transaction_report(
    start_date: str = Query(...),
    end_date: str = Query(...),
    customer_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT t.*, c.name as customer_name, p.name as property_name, ct.contract_number
            FROM transactions t
            LEFT JOIN customers c ON t.customer_id = c.id
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN contracts ct ON t.contract_id = ct.id
            WHERE t.transaction_date BETWEEN ? AND ?
        """
        params = [start_date, end_date]
       
        if customer_id:
            query += " AND t.customer_id = ?"
            params.append(customer_id)
        if status:
            query += " AND t.status = ?"
            params.append(status)
       
        query += " ORDER BY t.transaction_date DESC"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['transaction_date'] = str(row_dict['transaction_date'])
            results.append(row_dict)
        return results

@app.get("/reports/payments")
async def get_payment_report(
    start_date: str = Query(...),
    end_date: str = Query(...),
    customer_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT ps.*, c.contract_number, cust.name as customer_name, p.name as property_name
            FROM payment_schedules ps
            JOIN contracts c ON ps.contract_id = c.id
            JOIN customers cust ON c.customer_id = cust.id
            JOIN properties p ON c.property_id = p.id
            WHERE ps.due_date BETWEEN ? AND ?
        """
        params = [start_date, end_date]
       
        if customer_id:
            query += " AND cust.id = ?"
            params.append(customer_id)
        if status:
            query += " AND ps.status = ?"
            params.append(status)
       
        query += " ORDER BY ps.due_date"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            if row_dict['paid_date']:
                row_dict['paid_date'] = str(row_dict['paid_date'])
            results.append(row_dict)
        return results

# ────────────────────────────────────────────────
# Document Endpoints
# ────────────────────────────────────────────────
@app.post("/documents/upload", response_model=UploadResponse, status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    document_type: str = Form(...),
    description: Optional[str] = Form(None),
    customer_id: Optional[int] = Form(None),
    property_id: Optional[int] = Form(None),
    contract_id: Optional[int] = Form(None),
    transaction_id: Optional[int] = Form(None),
    tags: Optional[str] = Form(None),
    current_user: dict = Depends(require_staff_or_admin)
):
    # Get file size
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
   
    mime_type = file.content_type
    if not mime_type or mime_type == 'application/octet-stream':
        mime_type, _ = mimetypes.guess_type(file.filename)
        if not mime_type:
            mime_type = 'application/octet-stream'
   
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 50MB")
   
    unique_filename = generate_filename(file.filename)
   
    type_folder = DOCUMENTS_DIR / document_type
    type_folder.mkdir(exist_ok=True)
   
    file_path = type_folder / unique_filename
   
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save file: {e}")
   
    tag_list = [tag.strip() for tag in tags.split(',')] if tags else []
   
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        if customer_id:
            cursor.execute("SELECT 1 FROM customers WHERE id = ?", (customer_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Customer not found")
       
        if property_id:
            cursor.execute("SELECT 1 FROM properties WHERE id = ?", (property_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Property not found")
       
        if contract_id:
            cursor.execute("SELECT 1 FROM contracts WHERE id = ?", (contract_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Contract not found")
       
        if transaction_id:
            cursor.execute("SELECT 1 FROM transactions WHERE id = ?", (transaction_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Transaction not found")
       
        cursor.execute("""
            INSERT INTO documents
            (filename, original_filename, file_path, file_size, mime_type, document_type,
             description, customer_id, property_id, contract_id, transaction_id, tags, uploaded_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                unique_filename,
                file.filename,
                str(file_path),
                file_size,
                mime_type,
                document_type,
                description,
                customer_id,
                property_id,
                contract_id,
                transaction_id,
                json.dumps(tag_list),
                current_user['id']
            )
        )
        conn.commit()
        doc_id = cursor.lastrowid
       
        if transaction_id:
            cursor.execute(
                "UPDATE transactions SET document_id = ? WHERE id = ?",
                (doc_id, transaction_id)
            )
            conn.commit()
       
        await log_activity(f"Uploaded document: {file.filename}", current_user['id'], "upload")
       
        return {
            "id": doc_id,
            "filename": unique_filename,
            "original_filename": file.filename,
            "url": f"/static/uploads/documents/{document_type}/{unique_filename}",
            "thumbnail_url": None,
            "file_size": file_size,
            "mime_type": mime_type,
            "document_type": document_type,
            "customer_id": customer_id,
            "property_id": property_id,
            "contract_id": contract_id,
            "transaction_id": transaction_id
        }

@app.get("/documents", response_model=List[DocumentOut])
async def get_documents(
    document_type: Optional[str] = Query(None),
    customer_id: Optional[int] = Query(None),
    property_id: Optional[int] = Query(None),
    contract_id: Optional[int] = Query(None),
    transaction_id: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
            SELECT d.*,
                   u.username as uploaded_by_name,
                   c.name as customer_name,
                   p.name as property_name,
                   ct.contract_number
            FROM documents d
            LEFT JOIN users u ON d.uploaded_by = u.id
            LEFT JOIN customers c ON d.customer_id = c.id
            LEFT JOIN properties p ON d.property_id = p.id
            LEFT JOIN contracts ct ON d.contract_id = ct.id
            WHERE 1=1
        """
        params = []
       
        if document_type:
            query += " AND d.document_type = ?"
            params.append(document_type)
       
        if customer_id:
            query += " AND d.customer_id = ?"
            params.append(customer_id)
       
        if property_id:
            query += " AND d.property_id = ?"
            params.append(property_id)
       
        if contract_id:
            query += " AND d.contract_id = ?"
            params.append(contract_id)
       
        if transaction_id:
            query += " AND d.transaction_id = ?"
            params.append(transaction_id)
       
        if search:
            query += " AND (d.original_filename LIKE ? OR d.description LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like])
       
        query += " ORDER BY d.uploaded_at DESC"
       
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['uploaded_at'] = str(row_dict['uploaded_at'])
            if row_dict['last_accessed']:
                row_dict['last_accessed'] = str(row_dict['last_accessed'])
           
            if row_dict['tags']:
                row_dict['tags'] = json.loads(row_dict['tags'])
            else:
                row_dict['tags'] = []
           
            row_dict['url'] = f"/static/uploads/documents/{row_dict['document_type']}/{row_dict['filename']}"
           
            results.append(row_dict)
        return results

@app.get("/documents/{document_id}", response_model=DocumentOut)
async def get_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.*,
                   u.username as uploaded_by_name,
                   c.name as customer_name,
                   p.name as property_name,
                   ct.contract_number
            FROM documents d
            LEFT JOIN users u ON d.uploaded_by = u.id
            LEFT JOIN customers c ON d.customer_id = c.id
            LEFT JOIN properties p ON d.property_id = p.id
            LEFT JOIN contracts ct ON d.contract_id = ct.id
            WHERE d.id = ?
            """, (document_id,))
        doc = cursor.fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
       
        cursor.execute("""
            UPDATE documents
            SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1
            WHERE id = ?
            """, (document_id,))
        conn.commit()
       
        doc_dict = dict(doc)
        doc_dict['uploaded_at'] = str(doc_dict['uploaded_at'])
        if doc_dict['last_accessed']:
            doc_dict['last_accessed'] = str(doc_dict['last_accessed'])
       
        if doc_dict['tags']:
            doc_dict['tags'] = json.loads(doc_dict['tags'])
        else:
            doc_dict['tags'] = []
       
        doc_dict['url'] = f"/static/uploads/documents/{doc_dict['document_type']}/{doc_dict['filename']}"
       
        return doc_dict

@app.get("/documents/{document_id}/download")
async def download_document(
    document_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ?", (document_id,))
        doc = cursor.fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
       
        doc_dict = dict(doc)
        file_path = doc_dict['file_path']
       
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Document file not found")
       
        cursor.execute("""
            UPDATE documents
            SET last_accessed = CURRENT_TIMESTAMP, access_count = access_count + 1
            WHERE id = ?
            """, (document_id,))
        conn.commit()
       
        await log_activity(f"Downloaded document: {doc_dict['original_filename']}", current_user['id'], "download")
       
        return FileResponse(
            file_path,
            filename=doc_dict['original_filename'],
            media_type=doc_dict['mime_type']
        )

@app.put("/documents/{document_id}")
async def update_document(
    document_id: int,
    update_data: DocumentUpdate,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ?", (document_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Document not found")
       
        updates = []
        params = []
       
        if update_data.document_type:
            updates.append("document_type = ?")
            params.append(update_data.document_type)
        if update_data.description is not None:
            updates.append("description = ?")
            params.append(update_data.description)
        if update_data.tags is not None:
            updates.append("tags = ?")
            params.append(json.dumps(update_data.tags))
        if update_data.customer_id is not None:
            updates.append("customer_id = ?")
            params.append(update_data.customer_id)
        if update_data.property_id is not None:
            updates.append("property_id = ?")
            params.append(update_data.property_id)
        if update_data.contract_id is not None:
            updates.append("contract_id = ?")
            params.append(update_data.contract_id)
        if update_data.transaction_id is not None:
            updates.append("transaction_id = ?")
            params.append(update_data.transaction_id)
       
        if updates:
            query = "UPDATE documents SET " + ", ".join(updates) + " WHERE id = ?"
            params.append(document_id)
            cursor.execute(query, params)
            conn.commit()
       
        await log_activity(f"Updated document ID: {document_id}", current_user['id'], "update")
       
        return {"message": "Document updated successfully"}

@app.delete("/documents/{document_id}")
async def delete_document(
    document_id: int,
    current_user: dict = Depends(require_staff_or_admin)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ?", (document_id,))
        doc = cursor.fetchone()
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
       
        doc_dict = dict(doc)
       
        try:
            if os.path.exists(doc_dict['file_path']):
                os.remove(doc_dict['file_path'])
        except Exception as e:
            logger.error(f"Failed to delete document file: {e}")
       
        cursor.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        conn.commit()
       
        await log_activity(f"Deleted document: {doc_dict['original_filename']}", current_user['id'], "delete")
   
    return {"message": "Document deleted successfully"}

@app.get("/customers/{customer_id}/documents")
async def get_customer_documents(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.*,
                   u.username as uploaded_by_name,
                   p.name as property_name,
                   ct.contract_number
            FROM documents d
            LEFT JOIN users u ON d.uploaded_by = u.id
            LEFT JOIN properties p ON d.property_id = p.id
            LEFT JOIN contracts ct ON d.contract_id = ct.id
            WHERE d.customer_id = ?
            ORDER BY d.uploaded_at DESC
            """, (customer_id,))
       
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['uploaded_at'] = str(row_dict['uploaded_at'])
            if row_dict['last_accessed']:
                row_dict['last_accessed'] = str(row_dict['last_accessed'])
           
            if row_dict['tags']:
                row_dict['tags'] = json.loads(row_dict['tags'])
            else:
                row_dict['tags'] = []
           
            row_dict['url'] = f"/static/uploads/documents/{row_dict['document_type']}/{row_dict['filename']}"
           
            results.append(row_dict)
        return results

# ────────────────────────────────────────────────
# Dashboard & Analytics
# ────────────────────────────────────────────────
@app.get("/dashboard/summary", response_model=DashboardSummary)
async def get_dashboard_summary(current_user: dict = Depends(get_current_user)):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("SELECT COUNT(*) FROM properties")
        total_properties = cursor.fetchone()[0]
       
        cursor.execute("SELECT COUNT(*) FROM properties WHERE status = 'available'")
        available_properties = cursor.fetchone()[0]
       
        cursor.execute("SELECT COUNT(*) FROM properties WHERE status = 'rented'")
        rented_properties = cursor.fetchone()[0]
       
        cursor.execute("SELECT COUNT(*) FROM properties WHERE status = 'sold'")
        sold_properties = cursor.fetchone()[0]
       
        cursor.execute("SELECT COUNT(*) FROM customers")
        total_customers = cursor.fetchone()[0]
       
        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'income'")
        total_income = cursor.fetchone()[0]
       
        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'expense'")
        total_expense = cursor.fetchone()[0]
       
        cursor.execute("SELECT COALESCE(SUM(amount), 0) FROM payment_schedules WHERE status = 'pending'")
        outstanding_payments = cursor.fetchone()[0]
       
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COUNT(*) FROM payment_schedules
            WHERE status = 'pending' AND due_date < ?
            """, (today,))
        overdue_payments = cursor.fetchone()[0]
       
        cursor.execute("SELECT COUNT(*) FROM contracts WHERE status = 'active'")
        active_contracts = cursor.fetchone()[0]
       
        cursor.execute("SELECT COUNT(*) FROM documents")
        total_documents = cursor.fetchone()[0]
       
        cursor.execute("SELECT COALESCE(SUM(file_size), 0) FROM documents")
        total_document_size = cursor.fetchone()[0]
       
        month_start = datetime.now().replace(day=1).strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COALESCE(SUM(amount), 0) FROM transactions
            WHERE type = 'income' AND transaction_date >= ?
            """, (month_start,))
        monthly_income = cursor.fetchone()[0]
       
        cursor.execute("""
            SELECT COALESCE(SUM(amount), 0) FROM transactions
            WHERE type = 'expense' AND transaction_date >= ?
            """, (month_start,))
        monthly_expense = cursor.fetchone()[0]
       
        return {
            "total_properties": total_properties,
            "available_properties": available_properties,
            "rented_properties": rented_properties,
            "sold_properties": sold_properties,
            "total_customers": total_customers,
            "total_income": total_income,
            "total_expense": total_expense,
            "net_balance": total_income - total_expense,
            "outstanding_payments": outstanding_payments,
            "active_contracts": active_contracts,
            "total_documents": total_documents,
            "total_document_size": total_document_size,
            "overdue_payments": overdue_payments,
            "monthly_income": monthly_income,
            "monthly_expense": monthly_expense
        }

@app.get("/dashboard/monthly")
async def get_monthly_data(
    months: int = Query(6, ge=1, le=24),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        labels = []
        income_data = []
        expense_data = []
        customer_growth = []
        contract_growth = []
       
        for i in range(months - 1, -1, -1):
            date = datetime.now() - timedelta(days=30 * i)
            month_start = date.replace(day=1).strftime('%Y-%m-%d')
           
            if i == 0:
                month_end = datetime.now().strftime('%Y-%m-%d')
            else:
                next_month = (date.replace(day=28) + timedelta(days=4)).replace(day=1)
                month_end = (next_month - timedelta(days=1)).strftime('%Y-%m-%d')
           
            month_label = date.strftime('%b %Y')
            labels.append(month_label)
           
            cursor.execute("""
                SELECT COALESCE(SUM(amount), 0) FROM transactions
                WHERE type = 'income' AND transaction_date BETWEEN ? AND ?
                """,
                (month_start, month_end)
            )
            income_data.append(cursor.fetchone()[0])
           
            cursor.execute("""
                SELECT COALESCE(SUM(amount), 0) FROM transactions
                WHERE type = 'expense' AND transaction_date BETWEEN ? AND ?
                """,
                (month_start, month_end)
            )
            expense_data.append(cursor.fetchone()[0])
           
            cursor.execute("""
                SELECT COUNT(*) FROM customers
                WHERE created_at <= ?
                """, (month_end,))
            customer_growth.append(cursor.fetchone()[0])
           
            cursor.execute("""
                SELECT COUNT(*) FROM contracts
                WHERE created_at <= ?
                """, (month_end,))
            contract_growth.append(cursor.fetchone()[0])
       
        cursor.execute("""
            SELECT pt.name, COUNT(*) as count
            FROM properties p
            JOIN property_types pt ON p.type_id = pt.id
            GROUP BY pt.id
            ORDER BY count DESC
        """)
        type_data = cursor.fetchall()
        type_labels = [t['name'] for t in type_data]
        type_counts = [t['count'] for t in type_data]
       
        return {
            "labels": labels,
            "income": income_data,
            "expense": expense_data,
            "typeLabels": type_labels,
            "typeCounts": type_counts,
            "customer_growth": customer_growth,
            "contract_growth": contract_growth
        }

@app.get("/activities/recent")
async def get_recent_activities(
    limit: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT a.*, u.username
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.created_at DESC
            LIMIT ?
            """,
            (limit,)
        )
       
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            row_dict['created_at'] = str(row_dict['created_at'])
            results.append(row_dict)
        return results

# ────────────────────────────────────────────────
# Customer Folio
# ────────────────────────────────────────────────
@app.get("/customers/{customer_id}/folio", response_model=CustomerFolio)
async def get_customer_folio(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
       
        cursor.execute("""
            SELECT c.*,
                   COUNT(DISTINCT ct.id) as total_contracts,
                   COUNT(DISTINCT p.id) as total_properties,
                   COALESCE(SUM(t.amount), 0) as total_paid
            FROM customers c
            LEFT JOIN contracts ct ON c.id = ct.customer_id
            LEFT JOIN properties p ON c.id = p.customer_id
            LEFT JOIN transactions t ON c.id = t.customer_id AND t.type = 'income'
            WHERE c.id = ?
            GROUP BY c.id
            """, (customer_id,))
        customer = cursor.fetchone()
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
       
        customer_dict = dict(customer)
        customer_dict['created_at'] = str(customer_dict['created_at'])
       
        cursor.execute("""
            SELECT p.*, pt.name as type_name
            FROM properties p
            LEFT JOIN property_types pt ON p.type_id = pt.id
            WHERE p.customer_id = ?
            """,
            (customer_id,)
        )
        properties = []
        for row in cursor.fetchall():
            prop_dict = dict(row)
            prop_dict['created_at'] = str(prop_dict['created_at'])
           
            cursor.execute("SELECT filename FROM property_images WHERE property_id = ?", (prop_dict['id'],))
            images = cursor.fetchall()
            prop_dict['image_urls'] = [
                f"/static/uploads/property_images/{img['filename']}" for img in images
            ]
           
            properties.append(prop_dict)
       
        cursor.execute("""
            SELECT c.*, p.name as property_name,
                   COALESCE(SUM(CASE WHEN ps.status = 'paid' THEN ps.amount ELSE 0 END), 0) as paid_amount,
                   COALESCE(SUM(CASE WHEN ps.status = 'pending' THEN ps.amount ELSE 0 END), 0) as remaining_amount,
                   COUNT(CASE WHEN ps.status = 'paid' THEN 1 END) as paid_count,
                   COUNT(ps.id) as total_count
            FROM contracts c
            JOIN properties p ON c.property_id = p.id
            LEFT JOIN payment_schedules ps ON c.id = ps.contract_id
            WHERE c.customer_id = ?
            GROUP BY c.id
            ORDER BY c.start_date DESC
            """,
            (customer_id,)
        )
        contracts = []
        for row in cursor.fetchall():
            contract_dict = dict(row)
            contract_dict['created_at'] = str(contract_dict['created_at'])
            contract_dict['paid_amount'] = contract_dict['paid_amount'] or 0
            contract_dict['remaining_amount'] = contract_dict['remaining_amount'] or 0
            contract_dict['payment_progress'] = int((contract_dict['paid_amount'] / contract_dict['total_amount']) * 100) if contract_dict['total_amount'] > 0 else 0
            contracts.append(contract_dict)
       
        cursor.execute("""
            SELECT t.*, p.name as property_name, ct.contract_number, d.filename as document_name
            FROM transactions t
            LEFT JOIN properties p ON t.property_id = p.id
            LEFT JOIN contracts ct ON t.contract_id = ct.id
            LEFT JOIN documents d ON t.document_id = d.id
            WHERE t.customer_id = ?
            ORDER BY t.transaction_date DESC
            """,
            (customer_id,)
        )
        transactions = []
        for row in cursor.fetchall():
            trans_dict = dict(row)
            trans_dict['created_at'] = str(trans_dict['created_at'])
            trans_dict['transaction_date'] = str(trans_dict['transaction_date'])
            transactions.append(trans_dict)
       
        cursor.execute("""
            SELECT ps.*, c.contract_number, p.name as property_name
            FROM payment_schedules ps
            JOIN contracts c ON ps.contract_id = c.id
            JOIN properties p ON c.property_id = p.id
            WHERE c.customer_id = ? AND ps.status = 'pending' AND ps.due_date >= date('now')
            ORDER BY ps.due_date
            """,
            (customer_id,)
        )
        upcoming_payments = []
        for row in cursor.fetchall():
            payment_dict = dict(row)
            payment_dict['created_at'] = str(payment_dict['created_at']) if payment_dict['created_at'] else None
            upcoming_payments.append(payment_dict)
       
        cursor.execute("""
            SELECT ps.*, c.contract_number, p.name as property_name,
                   julianday('now') - julianday(ps.due_date) as days_overdue
            FROM payment_schedules ps
            JOIN contracts c ON ps.contract_id = c.id
            JOIN properties p ON c.property_id = p.id
            WHERE c.customer_id = ? AND ps.status = 'pending' AND ps.due_date < date('now')
            ORDER BY ps.due_date
            """,
            (customer_id,)
        )
        overdue_payments = []
        for row in cursor.fetchall():
            payment_dict = dict(row)
            payment_dict['created_at'] = str(payment_dict['created_at']) if payment_dict['created_at'] else None
            payment_dict['days_overdue'] = int(payment_dict['days_overdue'])
            overdue_payments.append(payment_dict)
       
        cursor.execute("""
            SELECT d.*,
                   u.username as uploaded_by_name,
                   p.name as property_name,
                   ct.contract_number
            FROM documents d
            LEFT JOIN users u ON d.uploaded_by = u.id
            LEFT JOIN properties p ON d.property_id = p.id
            LEFT JOIN contracts ct ON d.contract_id = ct.id
            WHERE d.customer_id = ?
            ORDER BY d.uploaded_at DESC
            """, (customer_id,))
       
        documents = []
        for row in cursor.fetchall():
            doc_dict = dict(row)
            doc_dict['uploaded_at'] = str(doc_dict['uploaded_at'])
            if doc_dict['last_accessed']:
                doc_dict['last_accessed'] = str(doc_dict['last_accessed'])
           
            if doc_dict['tags']:
                doc_dict['tags'] = json.loads(doc_dict['tags'])
            else:
                doc_dict['tags'] = []
           
            doc_dict['url'] = f"/static/uploads/documents/{doc_dict['document_type']}/{doc_dict['filename']}"
           
            documents.append(doc_dict)
       
        cursor.execute("""
            SELECT strftime('%Y-%m', transaction_date) as month,
                   SUM(amount) as total
            FROM transactions
            WHERE customer_id = ? AND type = 'income' AND transaction_date >= date('now', '-12 months')
            GROUP BY strftime('%Y-%m', transaction_date)
            ORDER BY month
            """, (customer_id,))
        payment_history = [dict(row) for row in cursor.fetchall()]
       
        total_paid = sum(t["amount"] for t in transactions if t["type"] == "income")
        total_due = sum(p["amount"] for p in upcoming_payments) + sum(p["amount"] for p in overdue_payments)
       
        return {
            "customer": customer_dict,
            "properties": properties,
            "contracts": contracts,
            "transactions": transactions,
            "documents": documents,
            "upcoming_payments": upcoming_payments,
            "overdue_payments": overdue_payments,
            "total_paid": total_paid,
            "total_due": total_due,
            "balance": total_paid - total_due,
            "payment_history": payment_history
        }

# ────────────────────────────────────────────────
# Health Check
# ────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            return {
                "status": "healthy",
                "database": "connected",
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

# ────────────────────────────────────────────────
# Run the application
# ────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )