# FastAPI Authentication API

This is a simple authentication API built with FastAPI. The API provides two endpoints, one for creating a user and the other for generating a token. The user's password is hashed before it is stored in the database for security purpose. The API also includes a JWT-based (JSON Web Tokens) authentication system.

## Dependencies

- FastAPI
- SQLAlchemy
- Pydantic
- Passlib
- jose
- python-multipart
- python-jose[cryptography]
- bcrypt
- PostgreSQL

## Models

- `User`: SQLAlchemy model with id, username and password.
- `UserIn`: Pydantic model with username and password for user input.
- `UserOut`: Pydantic model with username for output response.
- `Token`: Pydantic model for JWT token with access_token and token_type.
- `TokenData`: Pydantic model for token data with username.

## Functions

- `get_db()`: Creates a new SQLAlchemy session and closes it after use.
- `hash_password(password: str)`: Hashes the given password.
- `verify_password(plain_password, hashed_password)`: Verifies a plain password with a hashed password.
- `authenticate_user(db: Session, username: str, password: str)`: Authenticates a user with the given username and password.
- `create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None)`: Creates a new access token with given data and expiry time.

## Endpoints

- `POST /token`: Authenticates a user and returns a JWT token if authentication is successful.
- `POST /users/`: Creates a new user with the provided username and password.

## Usage

1. Create a new user:

```bash
curl -X POST "http://localhost:8000/users/" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{\"username\":\"JohnDoe\",\"password\":\"johnspassword\"}"
```

2. Get a token:

```bash
curl -X POST "http://localhost:8000/token" -H  "accept: application/json" -H  "Content-Type: application/x-www-form-urlencoded" -d "username=JohnDoe&password=johnspassword"
```

## Important Notes

1. Make sure to replace `"YOUR_SECRET_KEY"` with your actual secret key.
2. Replace `'postgresql://user:password@localhost:5432/dbname'` with your actual PostgreSQL database URL.
3. The hashed password is stored in the database, not the plain password.
4. Tokens expire after 30 minutes by default. You can change this by modifying `ACCESS_TOKEN_EXPIRE_MINUTES`.
5. In case of failed authentication, the API returns a 401 Unauthorized status code.