import jwt  # тут используем библиотеку PyJWT


# Секретный ключ для подписи и верификации токенов JWT
SECRET_KEY = "mysecretkey"  # в реальной практике используем что-нибудь вроде команды Bash (Linux) 'openssl rand -hex 32' и храним очень защищённо
ALGORITHM = "HS256"  # плюс в реальной жизни устанавливаем "время жизни" токена

# Пример информации из БД
USERS_DATA = [
    {"username": "admin", "password": "adminpass"}
]  # в реальной БД храним только ХЭШИ паролей (например, с помощью библиотеки 'passlib') + соль (известная только нам добавка к паролю)


# Функция для создания JWT токена
def create_jwt_token(data: dict):
    return jwt.encode(
        data, SECRET_KEY, algorithm=ALGORITHM
    )  # кодируем токен, передавая в него наш словарь с нужной информацией


# Функция получения User'а по токену
def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # декодируем токен
        return payload.get(
            "sub"
        )  # извлекаем утверждение о пользователе (subject); можем также использовать другие данные, например, "iss" (issuer) или "exp" (expiration time)
    except jwt.ExpiredSignatureError:
        pass  # логика обработки ошибки истечения срока действия токена
    except jwt.InvalidTokenError:
        pass  # логика обработки ошибки декодирования токена


# Функция для получения пользовательских данных на основе имени пользователя
def get_user(username: str):
    for user in USERS_DATA:
        if user.get("username") == username:
            return user
    return None


# Пример использования
# Закодируем токен с утверждением о пользователе
token = create_jwt_token({"sub": "admin"})

print(token)  # Выведем токен JWT для просмотра

# Декодируем токен и извлекаем информацию о пользователе
username = get_user_from_token(token)

print(username)  # Проверим, что мы извлекли правильное имя пользователя

# Ищем пользователя по имени в нашей базе данных
current_user = get_user(username)

print(current_user)  # Проверяем, что нашли нужного пользователя
