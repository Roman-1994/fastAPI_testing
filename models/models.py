from pydantic import BaseModel, EmailStr, Field, computed_field, field_validator
from pydantic_extra_types.phone_numbers import PhoneNumber


class User(BaseModel):
    id: int
    name: str
    age: int

    @computed_field
    @property
    def check_age(self) -> bool:
        return self.age >= 18


class Worker(BaseModel):
    username: str
    user_info: str


class Contact(BaseModel):
    email: EmailStr
    phone: PhoneNumber


class Feedback(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    message: str = Field(min_length=10, max_length=500)
    contact: Contact

    @field_validator("message")
    def check_message(msg):
        if "редис" in msg:
            raise ValueError("Сообщение содержит запретное слово")
        return "Ваш отзыв сохранён."


class Password(BaseModel):
    username: str
    password: str


class Product(BaseModel):
    name: str = (Field(min_length=3, max_length=10),)
    price: int = Field(gt=0)
