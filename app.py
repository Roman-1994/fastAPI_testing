import base64
import uuid
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Form, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi_babel import Babel, BabelConfigs, BabelMiddleware, _
from itsdangerous import Signer

import config
from logger import logger
from models.models import Feedback, Password, Product, User, Worker


print(base64.b64encode(bytes("user1:pass1", "utf-8")))

app = FastAPI()
security = HTTPBasic()

# Создаем объект конфигурации для Babel:
babel_configs = BabelConfigs(
    ROOT_DIR=__file__,
    BABEL_DEFAULT_LOCALE="en",  # Язык по умолчанию
    BABEL_TRANSLATION_DIRECTORY="locales",  # Папка с переводами
)

# Инициализируем объект Babel с использованием конфигурации
babel = Babel(configs=babel_configs)

# Добавляем мидлварь, который будет устанавливать локаль для каждого запроса
app.add_middleware(BabelMiddleware, babel_configs=babel_configs)


@app.get("/")
async def root():
    logger.info("Handling request to root endpoint")
    return FileResponse("start.html")
    return {"message": _("Hello World")}


@app.post("/calculate")
async def calculate(num1, num2):
    return {"result": int(num1) + int(num2)}


@app.get("/db")
async def get_db_info():
    logger.info(f"Connecting to database: {config.load_config().db.database_url}")
    return {"database_url": config.load_config().db.database_url}


@app.get("/users")
async def get_user():
    user = User(id=1, name="John Doe")
    logger.info("get users")
    return {"user_name": user.name, "user_id": user.id}


@app.post("/user")
async def post_user(user: User):
    return user


fake_db = [{"username": "vasya", "user_info": "любит колбасу"}, {"username": "katya", "user_info": "любит петь"}]


# Обрабатываем GET-запрос, чтобы вернуть список пользователей
@app.get("/get_users")
async def get_all_users():
    return fake_db


@app.get("/get_user/{user_id}")
async def get_user_id(user_id: int):
    return {"username": fake_db[user_id]["username"], "user_info": fake_db[user_id]["user_info"]}


# Обрабатываем POST-запрос, чтобы добавить нового пользователя
@app.post("/add_user", response_model=Worker)
async def add_user(user: Worker):
    fake_db.append({"username": user.username, "user_info": user.user_info})
    print(fake_db)
    return user


fake_feedback = []


@app.post("/feedback")
async def add_feedback(feedback: Feedback, is_premium=False):
    if is_premium:
        return {
            "response": feedback.check_message(),
            "name": feedback.name,
            "message": feedback.message,
            "email": feedback.contact.email,
            "phone": feedback.contact.phone,
            "is_premium": "Ваш отзыв будет рассмотрен в приоритетном порядке",
        }
    else:
        return {
            "response": feedback.check_message(),
            "name": feedback.name,
            "message": feedback.message,
            "email": feedback.contact.email,
            "phone": feedback.contact.phone,
        }


@app.post("/submit/")
async def submit_form(username: str = Form(...), password: str = Form(...)):
    return {"username": username, "password_length": len(password)}


sample_product_1 = {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99}

sample_product_2 = {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99}

sample_product_3 = {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99}

sample_product_4 = {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99}

sample_product_5 = {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99}

sample_products = [sample_product_1, sample_product_2, sample_product_3, sample_product_4, sample_product_5]

session_token = []

secret = config.load_login()
secret_user = Signer(secret_key=secret, sep=".")


@app.post("/login")
async def user_login(password: Password, response: Response, user_agent: Annotated[str | None, Header()] = None):
    if password.username == "admin" and password.password == "123qwe":
        user_uuid = uuid.uuid4()
        secret_user.sign(str(user_uuid))
        response.set_cookie(key="session_token", value=secret_user.sign(str(user_uuid)), httponly=True, max_age=360)
        print(user_uuid)
        print(secret_user.sign(str(user_uuid)))
        print(secret_user.unsign(secret_user.sign(str(user_uuid))))
        return {"message": "Get user_id", "user_agent": user_agent}
    else:
        return {"message": "Error login"}


@app.get("/product/{product_id}")
async def get_product(product_id: int, session_token=Cookie()):
    print(secret_user.get_signature(session_token))
    if secret_user.get_signature(session_token):
        for product in sample_products:
            if product_id == product["product_id"]:
                return product
    else:
        return {"ERROR": "ERROR"}


@app.get("/products/search/")
async def product_search(keyword: str, category: str = "", limit: int = 10):
    product_list = []
    for product in sample_products:
        if keyword.lower() in product["name"].lower() and category.lower() == product["category"].lower():
            product_list.append(product)
    return product_list[:limit]


@app.get("/headers")
async def get_headers(headers: Request):
    if "Accept-Language" not in headers.headers:
        raise HTTPException(
            status_code=400, detail="Not headers accept_language", headers={"X-Error": "Not headers accept-language"}
        )
    return {"user_agent": headers.headers["user-agent"], "accept_language": headers.headers["accept-language"]}


USER_DATA = [
    Password(**{"username": "user1", "password": "pass1"}),
    Password(**{"username": "user2", "password": "pass2"}),
]


def get_user_from_db(username: str):
    for user in USER_DATA:
        if user.username == username:
            return user
    return None


def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = get_user_from_db(credentials.username)
    if user is None or user.password != credentials.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


@app.get("/protected_resource/")
async def get_protected_resource(user: Password = Depends(authenticate_user)):
    return {"message": "You have access to the protected resource!", "user_info": user}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"message": "Invalid input", "errors": exc.errors()},
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"error": "Manual validation failed", "message": str(exc)})


@app.post("/prod")
async def post_product(product: Product):
    if len(product.name) < 3 or len(product.name) > 10:
        raise ValueError("ERROR Len name product")
    return {"message": "Added product", "product": product}
